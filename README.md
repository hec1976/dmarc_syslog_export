# DMARC Syslog Exporter

Dieses Tool verarbeitet automatisch **DMARC-Aggregatberichte** (XML oder gezippt) per **IMAP**, analysiert sie, überträgt strukturierte Logs via **Syslog (TCP/UDP)** an zentrale Logserver (z. B. Splunk, Graylog) und speichert Berichte optional lokal als JSON oder Textdatei.

---

## Funktionen

- Abruf von `UNSEEN`-Nachrichten über IMAP
- Extraktion und Dekompression von XML-, ZIP-, GZ- und TAR.GZ-Archiven
- Analyse von DMARC-Daten inkl. SPF/DKIM-Ergebnissen
- Syslog-Ausgabe im Klartextformat zur einfachen Integration in SIEM-Systeme
- Lokales Speichern der aggregierten Berichte im JSON- und optional Text-Format
- Archivierung verarbeiteter Mails in IMAP-Zielordner (optional)
- Automatische Bereinigung alter JSON-Dateien (konfigurierbar)
- Dry-Run-Modus zur sicheren Testausführung
- Unterstützung von Log-Rotation über `logrotate`

---

## Voraussetzungen

- Python 3.6 oder neuer (empfohlen: 3.8+)
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
host = imap.example.com     ; IMAP-Server für den Abruf der Reports
user = dmarc@example.com    ; Benutzername
password = geheim           ; Passwort (verwende möglichst App-Passwort)
folder = INBOX              ; Quellordner (Standard: INBOX)
archive_folder = Processed  ; Zielordner für verarbeitete Mails (optional)

[syslog]
enable = true               ; Aktiviert Syslog-Ausgabe (true/false)
host = syslog.example.com   ; Syslog-Zielhost
port = 514                  ; Syslog-Port
protocol = udp              ; Protokoll: udp oder tcp

[logging]
enable_file = true          ; Script-Log in Datei schreiben (true/false)
file_path = dmarc_parser.log; Pfad zur Logdatei des Skripts

[options]
save_json = true            ; Berichte als JSON-Dateien speichern
xml_output_dir = /var/log/dmarc/reports ; Zielverzeichnis für JSON
days_to_keep = 7            ; Anzahl Tage zur Aufbewahrung der JSON-Dateien
dry_run = false             ; Keine Änderungen durchführen (nur Testlauf)
log_records = true          ; DMARC-Datensätze verarbeiten und loggen?
write_text_log = true       ; DMARC-Datensätze zusätzlich in Textdatei schreiben
text_log_path = dmarc_data.log ; Pfad zur Textdatei (falls write_text_log aktiv)
```

---

## Log-Rotation (`logrotate` Beispiel für Textdatei)

Wenn `write_text_log = true` gesetzt ist, wird `dmarc_data.log` kontinuierlich beschrieben. Um ein unbegrenztes Wachstum zu verhindern, verwende `logrotate`:

```bash
sudo nano /etc/logrotate.d/dmarc_data
```

```conf
/var/log/dmarc/dmarc_data.log {
    daily
    rotate 14
    compress
    missingok
    notifempty
    create 640 root adm
    postrotate
        systemctl reload dmarc-parser.service > /dev/null 2>&1 || true
    endscript
}
```

> Passe den Pfad zu deiner `text_log_path`-Datei an. `rotate 14` bedeutet: 14 Tage aufbewahren.

---

## Ausführung

```bash
python3 dmarc_syslog_export.py --loglevel INFO
```

---

## 🔍 Offline-Test mit XML- oder Archivdateien

Du kannst das Skript auch **ohne IMAP-Zugriff** nutzen, um einzelne DMARC-Reports lokal zu testen. Ideal für Debugging oder Entwicklung.

```bash
python3 dmarc_syslog_export.py --file test.zip
```

### Unterstützte Dateiformate

- `.xml` – reine XML-Dateien mit DMARC-Daten  
- `.zip` – ZIP-Archive mit einer oder mehreren XML-Dateien  
- `.gz` – gzip-komprimierte Einzel-XML  
- `.tar.gz` / `.tgz` – Tarball mit mehreren XML-Dateien

---

## Beispiel-Logausgabe (Syslog oder Datei)

```text
org=google report_id=123456 domain=example.com policy=reject ip=203.0.113.15 count=12 disposition=reject dkim=fail spf=fail header_from=example.com begin=1718044800 end=1718131200 dkim_domain=gmail.com dkim_result=fail spf_domain=google.com spf_result=fail
```

---

## Splunk-Integration

### Variante 1: Syslog

- Empfange Logs über `tcp://514` oder `udp://514`
- Verwende `sourcetype = dmarc:report`
- Beispiel für Field Extraction mit Regex:

```regex
org=(?<org>[^ ]+) report_id=(?<report_id>[^ ]+) domain=(?<domain>[^ ]+) policy=(?<policy>[^ ]+) ip=(?<ip>[^ ]+) count=(?<count>\d+) disposition=(?<disposition>[^ ]+) dkim=(?<dkim>[^ ]+) spf=(?<spf>[^ ]+) header_from=(?<header_from>[^ ]+) begin=(?<begin>\d+) end=(?<end>\d+) dkim_domain=(?<dkim_domain>[^ ]+) dkim_result=(?<dkim_result>[^ ]+) spf_domain=(?<spf_domain>[^ ]+) spf_result=(?<spf_result>[^ ]+)
```

### Variante 2: Dateiüberwachung (z. B. Forwarder)

Falls `write_text_log = true` aktiviert ist, schreibt das Skript alle DMARC-Einträge zeilenweise in eine Datei (z. B. `dmarc_data.log`). Diese Datei kann mit dem Splunk Universal Forwarder überwacht werden:

```ini
[monitor:///var/log/dmarc/dmarc_data.log]
sourcetype = dmarc:report
index = mail
```

> Achte auf korrekte Dateiberechtigungen und Rotation der Logdatei

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
