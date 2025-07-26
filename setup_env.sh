#!/bin/bash
# Einfaches Setup-Skript zum Erstellen einer virtuellen Umgebung
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt

# Code automatisch formatieren und linten
ruff check . --fix
black .
flake8 .
