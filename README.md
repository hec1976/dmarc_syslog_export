# DMARC Syslog Exporter

Dieses Tool liest automatisch **DMARC-Aggregatberichte** (XML/XML.GZ) per IMAP aus einem Postfach, verarbeitet sie, loggt relevante Informationen über **Syslog (TCP/UDP)** an einen zentralen Server (z. B. Splunk) und archiviert die Berichte optional lokal.

---

## Features

- IMAP-Zugriff auf DMARC-Postfach (`UNSEEN`-Mails)
- Syslog-Ausgabe (TCP oder UDP) an zentrales Logsystem
- Verschieben verarbeiteter Mails in IMAP-Archivordner
- Lokales Speichern der XML-Berichte (optional)
- Erweiterte Felder für Splunk: Zeitraum, DKIM/SPF-Ergebnisse
- Geeignet für GeoIP-Analysen in Splunk

---

## Voraussetzungen

- Python 3.x
- Zugriff auf ein IMAP-Postfach mit DMARC-Berichten
- Netzwerkzugriff auf den Remote-Syslog-Server (z. B. Splunk, rsyslog, syslog-ng)

---

## Installation

```bash  
git clone https://github.com/hec1976/dmarc-syslog-export.git  
cd dmarc-syslog-export  
python3 -m venv venv  
source venv/bin/activate  
pip install -r requirements.txt  
```

---

## Konfiguration (`config.ini`)

```ini  
[imap]  
host = imap.example.com  
user = dmarc@example.com  
password = geheim  
folder = INBOX  
archive_folder = Processed  

[syslog]  
host = splunk.syslog.example.com  
port = 514  
protocol = tcp  ; oder udp  

[options]  
save_xml = true  
xml_output_dir = /var/log/dmarc/reports  
```

---

## Ausführung

```bash  
python3 dmarc_syslog_export.py  
```

---

## Beispiel-Logausgabe

```text  
DMARC: [DMARC] org=google report_id=123456 domain=example.com policy=reject ip=203.0.113.15 count=12 disposition=reject dkim=fail spf=fail header_from=example.com begin=1718044800 end=1718131200 dkim_domain=gmail.com dkim_result=fail spf_domain=google.com spf_result=fail  
```

---

## Splunk-Integration

- Empfange Logs via `tcp://514` oder `udp://514`
- Nutze `sourcetype = dmarc:report`
- Empfohlene Field Extraction (Regulärer Ausdruck):

```regex  
org=(?<org>[^ ]+) report_id=(?<report_id>[^ ]+) domain=(?<domain>[^ ]+) policy=(?<policy>[^ ]+) ip=(?<ip>[^ ]+) count=(?<count>\d+) disposition=(?<disposition>[^ ]+) dkim=(?<dkim>[^ ]+) spf=(?<spf>[^ ]+) header_from=(?<header_from>[^ ]+) begin=(?<begin>\d+) end=(?<end>\d+) dkim_domain=(?<dkim_domain>[^ ]+) dkim_result=(?<dkim_result>[^ ]+) spf_domain=(?<spf_domain>[^ ]+) spf_result=(?<spf_result>[^ ]+)  
```

---

## Automatischer Betrieb via systemd

**`/etc/systemd/system/dmarc-parser.service`**  
```ini  
[Unit]  
Description=DMARC Syslog Export  

[Service]  
WorkingDirectory=/opt/dmarc-syslog-export  
ExecStart=/usr/bin/python3 dmarc_syslog_export.py  
```

**`/etc/systemd/system/dmarc-parser.timer`**  
```ini  
[Unit]  
Description=Run DMARC parser every hour  

[Timer]  
OnBootSec=5min  
OnUnitActiveSec=1h  

[Install]  
WantedBy=timers.target  
```

Aktivieren:

```bash  
sudo systemctl enable --now dmarc-parser.timer  
```

---

## Projektstruktur

```text  
dmarc_syslog_export/  
├── dmarc_syslog_export.py  
├── config.ini  
└── README.md  
```

---

## Sicherheitshinweise

- Verwende App-Passwörter oder Token statt Klartextpasswörter, wenn möglich
- Stelle sicher, dass XML-Ausgabeordner (`xml_output_dir`) nicht öffentlich zugänglich ist
- Verwende TLS/SSL-Verbindungen bei Syslog-Übertragungen in sensiblen Umgebungen

---


