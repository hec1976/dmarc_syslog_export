import imaplib
import email
import gzip
import xml.etree.ElementTree as ET
import logging
import logging.handlers
import configparser
import os
import socket
import argparse
import json
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

SYSLOG_HOST = config.get("syslog", "host")
SYSLOG_PORT = config.getint("syslog", "port")
SYSLOG_PROTO = config.get("syslog", "protocol", fallback="tcp").lower()

SAVE_XML = config.getboolean("options", "save_xml", fallback=False)
XML_OUTPUT_DIR = config.get("options", "xml_output_dir", fallback="/tmp/dmarc_xml")

# === Logging Setup ===
logger = logging.getLogger("DMARC")
logger.setLevel(args.loglevel.upper())

socktype = socket.SOCK_STREAM if SYSLOG_PROTO == "tcp" else socket.SOCK_DGRAM
syslog_handler = logging.handlers.SysLogHandler(address=(SYSLOG_HOST, SYSLOG_PORT), socktype=socktype)
formatter = logging.Formatter('%(name)s: %(message)s')
syslog_handler.setFormatter(formatter)
logger.addHandler(syslog_handler)

def ensure_mailbox_exists(mail, folder):
    try:
        mail.select(folder)
    except:
        mail.create(folder)

def move_message(mail, msg_id, target_folder):
    ensure_mailbox_exists(mail, target_folder)
    mail.copy(msg_id, target_folder)
    mail.store(msg_id, '+FLAGS', '\\Deleted')

def save_xml_to_file(xml_data, report_id):
    try:
        os.makedirs(XML_OUTPUT_DIR, exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d")
        filename = f"{date_str}_{report_id}.xml"
        path = os.path.join(XML_OUTPUT_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(xml_data)
        logger.info(f"[DMARC] XML gespeichert: {path}")
    except Exception as e:
        logger.exception(f"[DMARC] Fehler beim Speichern der XML-Datei: {e}")

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
        return results, report_id

    except Exception as e:
        logger.exception(f"[DMARC] Fehler beim Parsen von XML: {e}")
        return [], None

def log_dmarc_records(records):
    for rec in records:
        logger.info(f"[DMARC] {json.dumps(rec)}")

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

                if filename.endswith(".xml") or filename.endswith(".xml.gz"):
                    try:
                        payload = part.get_payload(decode=True)
                        if filename.endswith(".gz"):
                            payload = gzip.decompress(payload)
                        xml_text = payload.decode("utf-8")
                        records, report_id = parse_dmarc_report(xml_text)
                        if records:
                            log_dmarc_records(records)
                            if SAVE_XML and report_id:
                                save_xml_to_file(xml_text, report_id)
                            processed = True
                    except Exception as e:
                        logger.exception(f"[DMARC] Fehler beim Verarbeiten von {filename}: {e}")

            if processed and IMAP_ARCHIVE:
                move_message(mail, num, IMAP_ARCHIVE)

        except Exception as e:
            logger.exception(f"[DMARC] Fehler bei Mail-ID {num}: {e}")

    mail.expunge()
    mail.logout()

if __name__ == "__main__":
    process_dmarc_reports()
