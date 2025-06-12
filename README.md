# DMARC Syslog Exporter

Dieses Tool verarbeitet automatisch **DMARC-Aggregatberichte** (XML oder gezippt) per **IMAP**, analysiert sie, überträgt strukturierte Logs via **Syslog (TCP/UDP)** an zentrale Logserver (z. B. Splunk, Graylog) und speichert Berichte optional lokal als JSON.

---

## Funktionen

- Abruf von `UNSEEN`-Nachrichten über IMAP
- Extraktion und Dekompression von XML-, ZIP- und GZ-Archiven
- Analyse von DMARC-Daten inkl. SPF/DKIM-Ergebnissen
- Syslog-Ausgabe im Klartextformat zur einfachen Integration in SIEM-Systeme
- Lokales Speichern der aggregierten Berichte im JSON-Format (optional)
- Archivierung verarbeiteter Mails in IMAP-Zielordner (optional)
- Automatische Bereinigung alter Dateien (konfigurierbar)

---

## Voraussetzungen

- Python 3.x
- Zugriff auf ein IMAP-Postfach mit DMARC-Reports
- Netzwerkzugang zum Syslog-Zielsystem (z. B. Splunk, rsyslog, syslog-ng)

---

## Installation

```bash
git clone https://github.com/hec1976/dmarc-syslog-export.git
cd dmarc-syslog-export
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

> **Hinweis:** Für `python-magic` (optional) ist evtl. `libmagic` als Systempaket notwendig.

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
enable = true
host = syslog.example.com
port = 514
protocol = udp

[logging]
enable_file = true
file_path = dmarc_parser.log

[options]
save_json = true
xml_output_dir = /var/log/dmarc/reports
days_to_keep = 7
dry_run = false
```

---

##  Ausführung

```bash
python3 dmarc_syslog_export.py --loglevel INFO
```

---

## Beispiel-Logausgabe

```text
DMARC: [DMARC] org=google report_id=123456 domain=example.com policy=reject ip=203.0.113.15 count=12 disposition=reject dkim=fail spf=fail header_from=example.com begin=1718044800 end=1718131200 dkim_domain=gmail.com dkim_result=fail spf_domain=google.com spf_result=fail
```

---

## Splunk-Integration

- Empfange Logs über `tcp://514` oder `udp://514`
- Verwende `sourcetype = dmarc:report`
- Beispiel für Field Extraction mit Regex:

```regex
org=(?<org>[^ ]+) report_id=(?<report_id>[^ ]+) domain=(?<domain>[^ ]+) policy=(?<policy>[^ ]+) ip=(?<ip>[^ ]+) count=(?<count>\d+) disposition=(?<disposition>[^ ]+) dkim=(?<dkim>[^ ]+) spf=(?<spf>[^ ]+) header_from=(?<header_from>[^ ]+) begin=(?<begin>\d+) end=(?<end>\d+) dkim_domain=(?<dkim_domain>[^ ]+) dkim_result=(?<dkim_result>[^ ]+) spf_domain=(?<spf_domain>[^ ]+) spf_result=(?<spf_result>[^ ]+)
```

---

## Log-Attribute im Detail

| Feld           | Beschreibung                                                         |
|----------------|----------------------------------------------------------------------|
| `org`          | Organisation, die den DMARC-Report versendet hat                     |
| `report_id`    | Eindeutige Kennung des Reports                                       |
| `domain`       | Die betroffene Empfänger-Domain                                      |
| `policy`       | Veröffentlichtes DMARC-Policy-Ziel                                   |
| `ip`           | IP-Adresse des sendenden Servers                                     |
| `count`        | Anzahl gemeldeter Mails von dieser IP                                |
| `disposition`  | Entscheidung des Empfängers (none/quarantine/reject)                 |
| `dkim`         | Ergebnis der DKIM-Validierung                                        |
| `spf`          | Ergebnis der SPF-Prüfung                                             |
| `header_from`  | Absenderdomain im Header                                             |
| `begin`, `end` | Start-/Endzeit als Unix-Timestamp                                    |
| `dkim_domain`  | Domain, die DKIM signiert hat                                        |
| `dkim_result`  | Ergebnis dieser DKIM-Prüfung                                         |
| `spf_domain`   | Domain, auf die sich die SPF-Prüfung bezog                           |
| `spf_result`   | Ergebnis dieser SPF-Prüfung                                          |

---

## Automatischer Betrieb via `systemd`

### Service-Datei `/etc/systemd/system/dmarc-parser.service`

```ini
[Unit]
Description=DMARC Syslog Export

[Service]
WorkingDirectory=/opt/dmarc-syslog-export
ExecStart=/usr/bin/python3 dmarc_syslog_export.py
```

### Timer-Datei `/etc/systemd/system/dmarc-parser.timer`

```ini
[Unit]
Description=Run DMARC parser every hour

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h

[Install]
WantedBy=timers.target
```

### Aktivieren:

```bash
sudo systemctl daemon-reexec
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

- Verwende App-Passwörter oder Tokens statt Klartextpasswörter
- Beschränke Zugriffsrechte auf `config.ini` und `xml_output_dir`
- Nutze TLS (z.B. syslog over TLS) in sicherheitskritischen Umgebungen

---
