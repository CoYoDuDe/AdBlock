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

| Paket | Primärquelle | Verwendung im Projekt |
| --- | --- | --- |
| aiohttp | [docs.aiohttp.org](https://docs.aiohttp.org/) | Asynchroner HTTP-Client für Blocklisten-Downloads in `adblock.py` |
| aiodns | [github.com/saghul/aiodns](https://github.com/saghul/aiodns) | DNS-Resolver in `adblock.py`, `networking.py` und `monitoring.py` |
| aiofiles | [github.com/Tinche/aiofiles](https://github.com/Tinche/aiofiles) | Asynchrone Dateizugriffe für Exportpfade in `adblock.py` |
| backoff | [github.com/litl/backoff](https://github.com/litl/backoff) | Wiederholungsstrategien für Netzwerkversuche in `adblock.py` und Tests |
| psutil | [psutil.readthedocs.io](https://psutil.readthedocs.io/) | Ressourcen- und Speichernutzung in `adblock.py`, `caching.py`, `monitoring.py` |
| pybloom_live | [github.com/jaybaird/python-bloomfilter](https://github.com/jaybaird/python-bloomfilter) | Bloom-Filter zur Duplikaterkennung in `caching.py` |
| idna | [github.com/kjd/idna](https://github.com/kjd/idna) | IDNA-Konvertierung in `filter_engine.py` |
| requests | [requests.readthedocs.io](https://requests.readthedocs.io/en/latest/) | Zusätzlicher HTTP-Client für SetupHelper-/Hilfsskripte |

Alle oben genannten Pakete sind in `requirements.txt` hinterlegt und decken die externen Imports in `adblock.py`, `networking.py`, `caching.py` und den übrigen Modulen vollständig ab.

### Entwicklungs- & Test-Tooling (`requirements-dev.txt`)

- [pytest](https://docs.pytest.org/en/latest/) – Test-Runner für Modul- und Integrationstests
- [ruff](https://docs.astral.sh/ruff/) – Schnelles Linting mit Fokus auf Fehlerprävention
- [black](https://black.readthedocs.io/en/stable/) – Konsistente Code-Formatierung
- [flake8](https://flake8.pycqa.org/en/latest/) – Ergänzendes Linting & Style-Prüfungen

> 💡 Hinweis: Für lokale Entwicklungsumgebungen lassen sich die Tools bequem mit `pip install -r requirements-dev.txt` installieren.

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
