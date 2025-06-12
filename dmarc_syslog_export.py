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

# === Argumente (optional) ===
parser = argparse.ArgumentParser()
parser.add_argument('--loglevel', default='INFO')
args = parser.parse_args()

# === Konfiguration einlesen ===
config = configparser.ConfigParser()
config.read("config.ini")

IMAP_HOST = config.get("imap", "host")
IMAP_USER = config.get("imap", "user")
IMAP_PASS = config.get("imap", "password")
IMAP_FOLDER = config.get("imap", "folder", fallback="INBOX")
IMAP_ARCHIVE = config.get("imap", "archive_folder", fallback=None)

SYSLOG_ENABLED = config.getboolean("syslog", "enable", fallback=True)
SYSLOG_HOST = config.get("syslog", "host")
SYSLOG_PORT = config.getint("syslog", "port")
SYSLOG_PROTO = config.get("syslog", "protocol", fallback="tcp").lower()

SAVE_JSON = config.getboolean("options", "save_json", fallback=True)
XML_OUTPUT_DIR = config.get("options", "xml_output_dir", fallback="/tmp/dmarc_xml")
DAYS_TO_KEEP = config.getint("options", "days_to_keep", fallback=7)
DRY_RUN = config.getboolean("options", "dry_run", fallback=False)

# === Logging Setup ===
logger = logging.getLogger("DMARC")
logger.setLevel(args.loglevel.upper())
formatter = logging.Formatter('%(name)s: %(message)s')

if SYSLOG_ENABLED:
    socktype = socket.SOCK_STREAM if SYSLOG_PROTO == "tcp" else socket.SOCK_DGRAM
    syslog_handler = logging.handlers.SysLogHandler(address=(SYSLOG_HOST, SYSLOG_PORT), socktype=socktype)
    syslog_handler.setFormatter(formatter)
    logger.addHandler(syslog_handler)

if config.getboolean("logging", "enable_file", fallback=False):
    file_path = config.get("logging", "file_path", fallback="dmarc_parser.log")
    file_handler = logging.FileHandler(file_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

def ensure_mailbox_exists(mail, folder):
    try:
        mail.select(folder)
    except Exception:
        mail.create(folder)

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
        logger.error(f"[DMARC] Ungültiges XML-Format: {e}")
    except Exception as e:
        logger.exception(f"[DMARC] Fehler beim Parsen von XML: {e}")
    return []

def load_existing_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return []

def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def append_to_daily_json(records):
    try:
        os.makedirs(XML_OUTPUT_DIR, exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d")
        filename = f"{date_str}_all.json"
        path = os.path.join(XML_OUTPUT_DIR, filename)
        data = load_existing_json(path)
        data.extend(records)
        write_json(path, data)
        logger.info(f"[DMARC] Tages-JSON aktualisiert: {path}")
    except Exception as e:
        logger.exception(f"[DMARC] Fehler beim Schreiben der JSON-Datei: {e}")

def cleanup_old_reports():
    now = time.time()
    cutoff = now - DAYS_TO_KEEP * 86400

    for fname in os.listdir(XML_OUTPUT_DIR):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(XML_OUTPUT_DIR, fname)
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                logger.info(f"[DMARC] Alte Datei gelöscht: {fname}")
        except Exception as e:
            logger.error(f"[DMARC] Fehler beim Löschen von {fname}: {e}")

def is_supported_archive(filename):
    return any(filename.endswith(ext) for ext in [".gz", ".zip", ".tgz", ".tar.gz"])

def extract_xml_from_archive(filename, payload):
    xml_list = []
    try:
        if filename.endswith(".gz") and not filename.endswith(".tar.gz"):
            xml_list.append(gzip.decompress(payload).decode("utf-8"))
        elif filename.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                for zipinfo in zf.infolist():
                    if zipinfo.filename.endswith(".xml"):
                        with zf.open(zipinfo) as file:
                            xml_list.append(file.read().decode("utf-8"))
        elif filename.endswith(".tar.gz") or filename.endswith(".tgz"):
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith(".xml"):
                        f = tar.extractfile(member)
                        if f:
                            xml_list.append(f.read().decode("utf-8"))
    except Exception as e:
        logger.error(f"[DMARC] Fehler beim Entpacken von {filename}: {e}")
    return xml_list

def process_dmarc_reports():
    mail = imaplib.IMAP4_SSL(IMAP_HOST)
    mail.login(IMAP_USER, IMAP_PASS)
    mail.select(IMAP_FOLDER)

    typ, data = mail.search(None, "UNSEEN")
    for num in data[0].split():
        try:
            typ, msg_data = mail.fetch(num, "(RFC822)")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            processed = False

            for part in msg.walk():
                filename = part.get_filename()
                if not filename:
                    continue
                payload = part.get_payload(decode=True)

                if is_supported_archive(filename):
                    xml_texts = extract_xml_from_archive(filename, payload)
                    for xml_text in xml_texts:
                        records = parse_dmarc_report(xml_text)
                        if records and SAVE_JSON and not DRY_RUN:
                            append_to_daily_json(records)
                            processed = True
                elif filename.lower().endswith(".xml"):
                    try:
                        xml_text = payload.decode("utf-8")
                        records = parse_dmarc_report(xml_text)
                        if records and SAVE_JSON and not DRY_RUN:
                            append_to_daily_json(records)
                            processed = True
                    except Exception as e:
                        logger.exception(f"[DMARC] Fehler beim Verarbeiten von {filename}: {e}")

            if processed and IMAP_ARCHIVE and not DRY_RUN:
                move_message(mail, num, IMAP_ARCHIVE)

        except Exception as e:
            logger.exception(f"[DMARC] Fehler bei Mail-ID {num}: {e}")

    mail.expunge()
    mail.logout()
    if not DRY_RUN:
        cleanup_old_reports()
    logger.info("[DMARC] Verarbeitung abgeschlossen.")

if __name__ == "__main__":
    process_dmarc_reports()
