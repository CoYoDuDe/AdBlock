# 🛡️ AdBlock

Ein minimalistisches Tool zur Generierung von `hosts.txt`-basierten Werbeblockerlisten.

## 🚀 Features

- Lädt und verarbeitet Blocklisten
- Generiert `hosts.txt` mit geblockten Domains
- Unterstützt Filter- & Duplikatbehandlung
- Kompatibel mit Pi-hole, AdGuard, etc.

## ▶️ Start

```bash
python adblock.py
```

## 🔧 Voraussetzungen

- Python 3.8+
- `requests`, `tqdm`, `re`, `os` (Standard oder per `requirements.txt`)
- Setze die Umgebungsvariable `SMTP_PASSWORD`, falls SMTP-E-Mails aktiviert sind

## 🛠️ Setup

```bash
pip install -r requirements.txt
```

## 📄 Ausgabe

Die Datei `hosts.txt` wird automatisch generiert.

## 📁 Struktur

```
adblock.py      # Hauptskript
hosts.txt       # Generierte Hostdatei
```

## 📄 Lizenz

MIT © CoYoDuDe
