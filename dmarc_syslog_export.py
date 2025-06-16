import imaplib
import email
import gzip
import zipfile
import tarfile
import io
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
import logging
import logging.handlers
import configparser
import os
import socket
import argparse
import json
import time
from datetime import datetime
import sys

# === Argumente (optional) ===
parser = argparse.ArgumentParser(description='DMARC-Parser: verarbeitet Reports via IMAP oder lokale Datei')
parser.add_argument('--loglevel', default='INFO', help='Logging-Level (z. B. INFO, DEBUG)')
parser.add_argument('--file', help='Lokale Datei zur Verarbeitung (.xml, .zip, .gz, .tgz, .tar.gz)')
args = parser.parse_args()

# === Konfiguration einlesen ===
config = configparser.ConfigParser()
config.read("config.ini")

# === Konfigurationsprüfung ===
required_sections = ['imap', 'options']
for section in required_sections:
    if not config.has_section(section):
        print(f"Fehlende Konfigurationssektion: [{section}]. Bitte config.ini prüfen.")
        sys.exit(1)

IMAP_HOST = config.get("imap", "host")
IMAP_USER = config.get("imap", "user")
IMAP_PASS = config.get("imap", "password")
IMAP_FOLDER = config.get("imap", "folder", fallback="INBOX")
IMAP_ARCHIVE = config.get("imap", "archive_folder", fallback=None)

SYSLOG_ENABLED = config.getboolean("syslog", "enable", fallback=True)
SYSLOG_HOST = config.get("syslog", "host", fallback="localhost")
SYSLOG_PORT = config.getint("syslog", "port", fallback=514)
SYSLOG_PROTO = config.get("syslog", "protocol", fallback="tcp").lower()

SAVE_JSON = config.getboolean("options", "save_json", fallback=True)
XML_OUTPUT_DIR = config.get("options", "xml_output_dir", fallback="/tmp/dmarc_xml")
DAYS_TO_KEEP = config.getint("options", "days_to_keep", fallback=7)
DRY_RUN = config.getboolean("options", "dry_run", fallback=False)
LOG_RECORDS = config.getboolean("options", "log_records", fallback=True)
WRITE_TEXT_LOG = config.getboolean("options", "write_text_log", fallback=False)
TEXT_LOG_PATH = config.get("options", "text_log_path", fallback="dmarc_data.log")

# === Zwei getrennte Logger ===
logger_script = logging.getLogger("DMARC_SCRIPT")
logger_script.setLevel(args.loglevel.upper())

logger_data = logging.getLogger("DMARC_DATA")
logger_data.setLevel(logging.INFO)

formatter_script = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
formatter_syslog = logging.Formatter('DMARC: %(message)s')

# === File Logging für Script-Protokollierung ===
if config.getboolean("logging", "enable_file", fallback=False):
    file_path = config.get("logging", "file_path", fallback="dmarc_parser.log")
    file_handler = logging.FileHandler(file_path)
    file_handler.setFormatter(formatter_script)
    logger_script.addHandler(file_handler)

# === Syslog Logging für strukturierte DMARC-Daten ===
if SYSLOG_ENABLED:
    try:
        socktype = socket.SOCK_STREAM if SYSLOG_PROTO == "tcp" else socket.SOCK_DGRAM
        syslog_handler = logging.handlers.SysLogHandler(address=(SYSLOG_HOST, SYSLOG_PORT), socktype=socktype)
        syslog_handler.setFormatter(formatter_syslog)
        logger_data.addHandler(syslog_handler)
    except Exception as e:
        logger_script.error(f"[DMARC] Fehler beim Einrichten des Syslog-Handlers: {e}")

# === Verbesserte Version von ensure_mailbox_exists ===
def ensure_mailbox_exists(mail, folder):
    typ, _ = mail.select(folder)
    if typ != 'OK':
        mail.create(folder)

# === Weitere benötigte Funktionen und Hauptlogik ===
def write_record_to_file(record):
    try:
        line = (
            f"{datetime.now().isoformat()} | "
            f"org={record['org']} | report_id={record['report_id']} | domain={record['domain']} | "
            f"policy={record['policy']} | ip={record['ip']} | count={record['count']} | "
            f"disposition={record['disposition']} | dkim={record['dkim']} | spf={record['spf']} | "
            f"header_from={record['header_from']} | "
            f"dkim_domain={record['dkim_domain']} | dkim_result={record['dkim_result']} | "
            f"spf_domain={record['spf_domain']} | spf_result={record['spf_result']}"
        )
        with open(TEXT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        logger_script.error(f"[DMARC] Fehler beim Schreiben der Datei-Ausgabe: {e}")

def move_message(mail, msg_id, target_folder):
    ensure_mailbox_exists(mail, target_folder)
    mail.copy(msg_id, target_folder)
    mail.store(msg_id, '+FLAGS', '\\Deleted')

def parse_dmarc_report(xml_data):
    results = []
    try:
        root = ET.fromstring(xml_data)
        org = root.findtext("report_metadata/org_name")
        report_id = root.findtext("report_metadata/report_id")
        begin = root.findtext("report_metadata/date_range/begin")
        end = root.findtext("report_metadata/date_range/end")
        domain = root.findtext("policy_published/domain")
        policy = root.findtext("policy_published/p")

        for record in root.findall("record"):
            result = {
                "org": org,
                "report_id": report_id,
                "domain": domain,
                "policy": policy,
                "begin": begin,
                "end": end,
                "ip": record.findtext("row/source_ip"),
                "count": record.findtext("row/count"),
                "disposition": record.findtext("row/policy_evaluated/disposition"),
                "dkim": record.findtext("row/policy_evaluated/dkim"),
                "spf": record.findtext("row/policy_evaluated/spf"),
                "header_from": record.findtext("identifiers/header_from"),
                "dkim_domain": record.findtext("auth_results/dkim/domain"),
                "dkim_result": record.findtext("auth_results/dkim/result"),
                "spf_domain": record.findtext("auth_results/spf/domain"),
                "spf_result": record.findtext("auth_results/spf/result")
            }
            results.append(result)
        return results

    except ParseError as e:
        logger_script.error(f"[DMARC] Ungültiges XML-Format: {e}")
    except Exception as e:
        logger_script.exception(f"[DMARC] Fehler beim Parsen von XML: {e}")
    return []

def log_record_to_syslog(record):
    log_line = (
        f"org={record['org']} report_id={record['report_id']} domain={record['domain']} "
        f"policy={record['policy']} ip={record['ip']} count={record['count']} "
        f"disposition={record['disposition']} dkim={record['dkim']} spf={record['spf']} "
        f"header_from={record['header_from']} begin={record['begin']} end={record['end']} "
        f"dkim_domain={record['dkim_domain']} dkim_result={record['dkim_result']} "
        f"spf_domain={record['spf_domain']} spf_result={record['spf_result']}"
    )
    logger_data.info(log_line)

# === Hauptlogik ===
if __name__ == "__main__":
    if args.file:
        try:
            filename = args.file
            if not os.path.exists(filename):
                logger_script.error(f"[DMARC] Datei nicht gefunden: {filename}")
                exit(1)

            with open(filename, "rb") as f:
                payload = f.read()

            xml_list = []

            if filename.lower().endswith(".xml"):
                xml_list = [payload.decode("utf-8")]
            elif is_supported_archive(filename):
                xml_list = extract_xml_from_archive(filename, payload)
            else:
                logger_script.error(f"[DMARC] Nicht unterstütztes Dateiformat: {filename}")
                exit(1)

            total_records = 0
            for xml in xml_list:
                records = parse_dmarc_report(xml)
                if records:
                    total_records += len(records)
                    if LOG_RECORDS and not DRY_RUN:
                        for r in records:
                            log_record_to_syslog(r)
                            if WRITE_TEXT_LOG:
                                write_record_to_file(r)
                    if SAVE_JSON and not DRY_RUN:
                        append_to_daily_json(records)

            if total_records > 0:
                logger_script.info(f"[DMARC] {total_records} Datensätze aus {filename} verarbeitet.")
            else:
                logger_script.warning(f"[DMARC] Keine gültigen DMARC-Daten in {filename} gefunden.")

        except Exception as e:
            logger_script.exception(f"[DMARC] Fehler beim Verarbeiten der Datei {args.file}: {e}")
    else:
        process_dmarc_reports()
