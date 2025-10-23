# 🛡️ AdBlock

Ein minimalistisches Tool zur Generierung von `hosts.txt`-basierten Werbeblockerlisten.

## 🚀 Features

- Lädt und verarbeitet Blocklisten
- Generiert `hosts.txt` mit geblockten Domains
- Unterstützt Filter- & Duplikatbehandlung
- Kompatibel mit Pi-hole, AdGuard, etc.

## ▶️ Start

```bash
python adblock.py [--config path/zur/config.json] [--debug]
```

* `--config` – optionaler Pfad zu einer alternativen `config.json`
* `--debug` – aktiviert detailliertes Logging

## 🔧 Voraussetzungen

### Laufzeitumgebung

- Python 3.8+
- Setze die Umgebungsvariable `SMTP_PASSWORD`, falls SMTP-E-Mails aktiviert sind

### Laufzeitabhängigkeiten (`requirements.txt`)

- [aiohttp](https://docs.aiohttp.org/) – Asynchroner HTTP-Client/-Server zum Laden externer Blocklisten
- [aiodns](https://github.com/saghul/aiodns) – DNS-Lookups mit asyncio, u. a. für Reachability-Checks
- [aiofiles](https://github.com/Tinche/aiofiles) – Asynchrone Dateizugriffe beim Schreiben der Ergebnisdateien
- [backoff](https://github.com/litl/backoff) – Strategien für wiederholte Netzwerkversuche bei Fehlern
- [psutil](https://psutil.readthedocs.io/) – Systemressourcen-Erfassung für Speicher-/Lastentscheidungen
- [pybloom_live](https://github.com/jaybaird/python-bloomfilter) – Bloom-Filter zur effizienten Duplikaterkennung
- [idna](https://github.com/kjd/idna) – IDNA-Konvertierung für internationale Domains
- [requests](https://requests.readthedocs.io/en/latest/) – Klassischer HTTP-Client für Hilfsskripte & SetupHelper-Kompatibilität

### Entwicklungs- & Test-Tooling (`requirements-dev.txt`)

- [pytest](https://docs.pytest.org/en/latest/) – Test-Runner für Modul- und Integrationstests
- [ruff](https://docs.astral.sh/ruff/) – Schnelles Linting mit Fokus auf Fehlerprävention
- [black](https://black.readthedocs.io/en/stable/) – Konsistente Code-Formatierung
- [flake8](https://flake8.pycqa.org/en/latest/) – Ergänzendes Linting & Style-Prüfungen

### Referenzprojekte & Kompatibilitätsziele

- [Pi-hole](https://pi-hole.net/) – Primäre Inspiration für hostbasierte Werbeblocker
- [AdGuard Home](https://adguard.com/) – Vergleichsreferenz für DNS-basierte Filterlösungen
- [SetupHelper (kwindrem)](https://github.com/kwindrem/SetupHelper) – Maßgebliche Basis für Installer-/Updater-Kompatibilität

## 🛠️ Setup

```bash
./setup_env.sh
```

Das Skript erstellt eine virtuelle Umgebung, installiert alle Basisabhängigkeiten aus `requirements.txt` und ergänzt anschließend die Entwicklungswerkzeuge aus `requirements-dev.txt`.

## 👩‍💻 Entwicklung

Die Entwicklungswerkzeuge `ruff`, `black`, `flake8` und `pytest` werden über `requirements-dev.txt` verwaltet. Das Setup-Skript installiert sie automatisch; alternativ können sie manuell mit `pip install -r requirements-dev.txt` nachinstalliert werden. Für weitergehende Konfigurationsmöglichkeiten siehe die offiziellen Dokumentationen:

- [Ruff – Konfiguration & Rules](https://docs.astral.sh/ruff/)
- [Black – Formatierungsoptionen](https://black.readthedocs.io/en/stable/)
- [Flake8 – Linting-Regeln & Plugins](https://flake8.pycqa.org/en/latest/)
- [Pytest – Test- und Plugin-Referenz](https://docs.pytest.org/en/latest/)

## ❓ Troubleshooting

Sollte das Laden der Blocklisten fehlschlagen, prüfe die Internetverbindung
des Systems. Das Skript speichert eine Fehlermeldung in `statistics.json` unter
`error_message`. Bei mehrfachen Fehlschlägen kann eine instabile Netzwerk-
verbindung oder ein falsch konfigurierter Proxy die Ursache sein.

## 📄 Ausgabe

Die Datei `hosts.txt` wird automatisch generiert.

## 📁 Struktur

```
adblock.py      # Hauptskript
hosts.txt       # Generierte Hostdatei
```

## 🧪 Tests

Die Tests werden mit `pytest` ausgeführt:

```bash
pytest
```

## 📄 Lizenz

MIT © CoYoDuDe

## Agent Guide
Für Code-Assistenten siehe [agents.md](./agents.md).
