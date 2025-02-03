# AdBlock Script

Dieses Skript dient zur Verwaltung und Aktualisierung von Ad-Blocker-Host-Dateien. Es lädt Hosts-Listen herunter, prüft die Erreichbarkeit der Domains und generiert daraus eine optimierte Hosts-Datei für DNS-Blocking.

## Funktionen
- **Automatischer Download und Aktualisierung** von Hosts-Listen
- **DNS-Überprüfung** der Domains auf Erreichbarkeit
- **Optimierung durch Duplikat-Entfernung**
- **Erstellung einer `hosts.txt`-Datei** für lokale DNS-Blocking-Nutzung
- **Integration mit dnsmasq** für effektive Werbeblockierung auf Netzwerkebene
- **Automatisches Hochladen auf GitHub** (optional)
- **Logging & Fehlerbehandlung** mit umfassender Statistik

## Voraussetzungen
- **Python 3.x**
- Abhängigkeiten (können mit `pip` installiert werden):
  ```sh
  pip install requests dnspython
  ```
- `dnsmasq` (falls für Netzwerknutzung gewünscht)
- `git` (falls automatische GitHub-Uploads genutzt werden sollen)

## Installation
1. **Repository klonen**
   ```sh
   git clone https://github.com/CoYoDuDe/AdBlock.git
   cd AdBlock
   ```
2. **Abhängigkeiten installieren**
   ```sh
   pip install -r requirements.txt
   ```
3. **Konfiguration anpassen**
   Bearbeite die Datei `config.json`, um Einstellungen wie DNS-Server, GitHub-Uploads und Logging-Level zu setzen.

## Nutzung
### Manuelle Ausführung
Starte das Skript mit:
```sh
python3 adblock.py
```

### Automatische Updates einrichten (Linux)
Falls du das Skript regelmäßig ausführen möchtest, kannst du einen Cron-Job erstellen:
```sh
crontab -e
```
Füge folgende Zeile hinzu, um das Skript täglich auszuführen:
```sh
0 2 * * * /usr/bin/python3 /path/to/adblock.py
```

## Konfigurationsoptionen (`config.json`)
| Parameter                 | Beschreibung |
|---------------------------|-------------|
| `log_datei`               | Pfad zur Log-Datei |
| `send_email`              | Benachrichtigung per E-Mail aktivieren |
| `email`                   | Zieladresse für Fehlerbenachrichtigungen |
| `max_retries`             | Anzahl der Wiederholungen für DNS-Tests |
| `parallel_aktiviert`      | Parallele Verarbeitung aktivieren |
| `max_parallel_jobs`       | Maximale parallele Threads |
| `dns_server_list`         | Liste der zu nutzenden DNS-Server |
| `github_upload`           | Automatisches Hochladen auf GitHub |
| `github_repo`             | GitHub-Repository für Uploads |

## Fehlerbehandlung
Falls das Skript Probleme hat:
- Prüfe die Logs unter `/var/log/adblock.log`
- Stelle sicher, dass `config.json` korrekt konfiguriert ist
- Versuche das Skript mit `python3 adblock.py --debug` auszuführen

## Lizenz
MIT License – Feel free to use and modify!