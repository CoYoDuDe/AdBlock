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
pip install -r requirements.txt
```

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

## 📄 Lizenz

MIT © CoYoDuDe
