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

- Python 3.8+
- `requests`, `re`, `os` (Standard oder per `requirements.txt`)
- Setze die Umgebungsvariable `SMTP_PASSWORD`, falls SMTP-E-Mails aktiviert sind

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
