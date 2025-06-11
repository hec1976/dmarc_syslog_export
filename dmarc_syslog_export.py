import imaplib
import email
import gzip
import xml.etree.ElementTree as ET
import logging
import logging.handlers
import configparser
import os
import socket
from datetime import datetime

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
logger.setLevel(logging.INFO)

socktype = socket.SOCK_STREAM if SYSLOG_PROTO == "tcp" else socket.SOCK_DGRAM
syslog_handler = logging.handlers.SysLogHandler(address=(SYSLOG_HOST, SYSLOG_PORT), socktype=socktype)
formatter = logging.Formatter('%(name)s: %(message)s')
syslog_handler.setFormatter(formatter)
logger.addHandler(syslog_handler)

def ensure_mailbox_exists(mail, folder):
    code, boxes = mail.list()
    existing_folders = [box.split()[-1].strip('"') for box in boxes if box]
    if folder not in existing_folders:
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
        logger.error(f"[DMARC] Fehler beim Speichern der XML-Datei: {str(e)}")

def parse_and_log(xml_data):
    try:
        root = ET.fromstring(xml_data)
        org = root.findtext("report_metadata/org_name")
        report_id = root.findtext("report_metadata/report_id")
        begin = root.findtext("report_metadata/date_range/begin")
        end = root.findtext("report_metadata/date_range/end")
        domain = root.findtext("policy_published/domain")
        policy = root.findtext("policy_published/p")

        for record in root.findall("record"):
            ip = record.findtext("row/source_ip")
            count = record.findtext("row/count")
            disposition = record.findtext("row/policy_evaluated/disposition")
            dkim_result = record.findtext("row/policy_evaluated/dkim")
            spf_result = record.findtext("row/policy_evaluated/spf")
            header_from = record.findtext("identifiers/header_from")

            dkim_domain = record.findtext("auth_results/dkim/domain")
            dkim_eval = record.findtext("auth_results/dkim/result")
            spf_domain = record.findtext("auth_results/spf/domain")
            spf_eval = record.findtext("auth_results/spf/result")

            log_line = (
                f"[DMARC] org={org} report_id={report_id} domain={domain} "
                f"policy={policy} ip={ip} count={count} disposition={disposition} "
                f"dkim={dkim_result} spf={spf_result} header_from={header_from} "
                f"begin={begin} end={end} "
                f"dkim_domain={dkim_domain} dkim_result={dkim_eval} "
                f"spf_domain={spf_domain} spf_result={spf_eval}"
            )
            logger.info(log_line)

        if SAVE_XML and report_id:
            save_xml_to_file(xml_data, report_id)

        return True

    except Exception as e:
        logger.error(f"[DMARC] Fehler beim Parsen: {str(e)}")
        return False

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
                    payload = part.get_payload(decode=True)
                    if filename.endswith(".gz"):
                        try:
                            payload = gzip.decompress(payload)
                        except:
                            continue
                    try:
                        xml_text = payload.decode("utf-8")
                        success = parse_and_log(xml_text)
                        if success:
                            processed = True
                    except Exception as e:
                        logger.error(f"[DMARC] Fehler beim Dekodieren von {filename}: {str(e)}")

            if processed and IMAP_ARCHIVE:
                move_message(mail, num, IMAP_ARCHIVE)

        except Exception as e:
            logger.error(f"[DMARC] Fehler bei Verarbeitung der Mail {num}: {str(e)}")

    mail.expunge()
    mail.logout()

if __name__ == "__main__":
    process_dmarc_reports()
