AdBlock Script
Dieses Skript dient zur Verwaltung und Aktualisierung von Ad-Blocker-Host-Dateien. Es lädt Blocklisten asynchron herunter, überprüft die Erreichbarkeit von Domains, optimiert die Listen durch Entfernung von Duplikaten und Subdomains und generiert eine optimierte hosts.txt-Datei für DNS-Blocking. Das Skript ist für hohe Performance und Ressourceneffizienz optimiert und eignet sich für den Einsatz auf Einzelgeräten oder Netzwerken.
Funktionen

Asynchroner Download von Blocklisten mit aiohttp für maximale Geschwindigkeit.
DNS-Überprüfung der Domains mit aiodns zur Sicherstellung der Erreichbarkeit.
Optimierung der Listen durch Entfernung von Duplikaten und redundanten Subdomains.
Dynamische Ressourcenverwaltung mit Betriebsmodi (NORMAL, LOW_MEMORY, EMERGENCY) basierend auf RAM, CPU und Netzwerklatenz.
Systemzustandsübersicht in der Konsole (RAM, CPU, Latenz, Batch-Größe) beim Start und alle 5 Minuten.
Erstellung von hosts.txt und dnsmasq.conf für lokales oder netzwerkweites DNS-Blocking.
Integration mit GitHub für automatische Uploads der generierten Hosts-Datei (optional).
Umfassendes Logging mit konfigurierbarem Log-Level und JSON-/Text-Format.
Statistikexport in CSV- und Prometheus-Format für Monitoring.
E-Mail-Benachrichtigungen bei Fehlern oder erfolgreicher Ausführung (optional).
Cache-Management mit HybridStorage (RAM/Disk) und SQLite für Effizienz.

Voraussetzungen

Python 3.11+
Abhängigkeiten (mit pip installieren):pip install aiohttp aiodns psutil backoff aiofiles


dnsmasq (für netzwerkweites Blocking, optional).
git (für automatische GitHub-Uploads, optional).
Schreibrechte für das Log-Verzeichnis (z. B. /var/log/adblock.log).

Installation

Repository klonengit clone https://github.com/CoYoDuDe/AdBlock.git
cd AdBlock


Abhängigkeiten installierenpip install -r requirements.txt

Erstelle eine requirements.txt mit:aiohttp
aiodns
psutil
backoff
aiofiles


Konfiguration anpassenBearbeite config.json, um Einstellungen wie DNS-Server, GitHub-Uploads, E-Mail-Benachrichtigungen und Logging-Level zu setzen. Beispiel:{
    "log_file": "/var/log/adblock.log",
    "logging_level": "INFO",
    "dns_servers": ["8.8.8.8", "1.1.1.1"],
    "send_email": false,
    "github_upload": false,
    "resource_thresholds": {
        "low_memory_mb": 150,
        "emergency_memory_mb": 50
    }
}



Nutzung
Manuelle Ausführung
Starte das Skript mit:
python3 adblock.py

Automatische Updates einrichten (Linux)
Für regelmäßige Ausführung erstelle einen Cron-Job:
crontab -e

Füge hinzu, um das Skript täglich um 2:00 Uhr auszuführen:
0 2 * * * /usr/bin/python3 /path/to/AdBlock/adblock.py

Konfigurationsoptionen (config.json)



Parameter
Beschreibung



log_file
Pfad zur Log-Datei (z. B. /var/log/adblock.log).


logging_level
Log-Level (DEBUG, INFO, WARNING, ERROR).


log_format
Log-Format (text oder json).


dns_servers
Liste der DNS-Server für Erreichbarkeitsprüfung (z. B. ["8.8.8.8"]).


send_email
Aktiviert E-Mail-Benachrichtigungen (true/false).


email_sender
Absender-E-Mail-Adresse.


email_recipient
Empfänger-E-Mail-Adresse.


smtp_server
SMTP-Server für E-Mails (z. B. smtp.example.com).


smtp_port
SMTP-Port (z. B. 587).


github_upload
Aktiviert automatische GitHub-Uploads (true/false).


github_repo
GitHub-Repository-URL (z. B. git@github.com:CoYoDuDe/AdBlock.git).


resource_thresholds
Schwellwerte für RAM, CPU und Latenz zur Modusumschaltung.


cache_flush_interval
Intervall für Cache-Flush (in Sekunden, z. B. 300).


remove_redundant_subdomains
Entfernt redundante Subdomains (true/false).


use_ipv4_output
Generiert IPv4-Einträge für dnsmasq.conf (true/false).


use_ipv6_output
Generiert IPv6-Einträge für dnsmasq.conf (true/false).


Fehlerbehandlung
Falls das Skript fehlschlägt:

Prüfe die Logs in der angegebenen log_file (z. B. /var/log/adblock.log).
Stelle sicher, dass config.json und hosts_sources.conf korrekt sind.
Führe das Skript im Debug-Modus aus:python3 adblock.py --debug

(Hinweis: Setze "logging_level": "DEBUG" in config.json.)
Überprüfe die Schreibrechte für tmp/-Verzeichnis und Log-Datei:chmod -R 755 tmp/
chown root:root /var/log/adblock.log



Beispielausgabe
Bei erfolgreicher Ausführung siehst du in der Konsole:
Systemzustandsübersicht:
- Aktueller Modus: normal
- Freier RAM: 343.39 MB
- CPU-Last: 0.0%
- DNS-Latenz: 0.01s
- Angepasste Batch-Größe: 200 Domains

Logs in /var/log/adblock.log enthalten detaillierte Informationen, z. B.:
2025-04-27 15:41:59,573 - INFO - Logging erfolgreich konfiguriert
2025-04-27 15:41:59,580 - INFO - CacheManager initialisiert: Initiale Cache-Größe=1716

Lizenz
MIT License – Nutze und modifiziere das Skript frei!
