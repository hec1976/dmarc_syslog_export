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
## Log-Attribute

Das Skript generiert für jeden verarbeiteten DMARC-Eintrag eine strukturierte Logzeile mit folgenden Attributen:

| Attribut       | Beschreibung                                                                 |
|----------------|------------------------------------------------------------------------------|
| `org`          | Absenderorganisation des DMARC-Berichts (z. B. Google, Microsoft)            |
| `report_id`    | Eindeutige ID des Berichts                                                   |
| `domain`       | Die Ziel-Domain, für die der Bericht erstellt wurde                          |
| `policy`       | DMARC-Policy, die veröffentlicht wurde (`none`, `quarantine`, `reject`)      |
| `ip`           | IP-Adresse des sendenden Mailservers                                         |
| `count`        | Anzahl der E-Mails von dieser IP im Bericht                                  |
| `disposition`  | Entscheidung des empfangenden Servers (`none`, `quarantine`, `reject`)       |
| `dkim`         | Ergebnis der DKIM-Prüfung (`pass`, `fail`, `none`)                           |
| `spf`          | Ergebnis der SPF-Prüfung (`pass`, `fail`, `none`)                            |
| `header_from`  | Absenderdomain im E-Mail-Header (sollte mit `domain` übereinstimmen)         |
| `begin`        | Startzeitpunkt des Berichts (Unix-Timestamp)                                 |
| `end`          | Endzeitpunkt des Berichts (Unix-Timestamp)                                   |
| `dkim_domain`  | Domain, aus der die DKIM-Signatur stammt (wenn vorhanden)                    |
| `dkim_result`  | Ergebnis der DKIM-Authentifizierung pro Domain (`pass`, `fail`)              |
| `spf_domain`   | Domain, gegen die SPF-Prüfung erfolgt ist                                    |
| `spf_result`   | Ergebnis der SPF-Prüfung pro Domain (`pass`, `fail`)                         |

### Beispiel-Logzeile

```text
DMARC: [DMARC] org=google report_id=abc123 domain=example.com policy=reject ip=203.0.113.15 count=15 disposition=reject dkim=fail spf=fail header_from=example.com begin=1718000000 end=1718086399 dkim_domain=gmail.com dkim_result=fail spf_domain=google.com spf_result=fail
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
