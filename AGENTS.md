# 🧠 `agents.md` – Codex Copilot Cheat Sheet für AdBlock

**Projektname:**  
🛡️ **AdBlock** – Host-basiertes Werbeblockersystem (generiert `hosts.txt`)

---

## 🚧 1. Syntax- und Lint-Fehler beheben

```plaintext
Prompt:
Fix all syntax errors in this file.

Prompt:
Fix all ruff and flake8 errors in this file.
```

---

## ⚙️ 2. Globale Variablen in config auslagern

```plaintext
Prompt:
Move all constants and global variables into config.py and import them.
```

---

## 🔁 3. Duplikate vereinheitlichen

```plaintext
Prompt:
Find and remove duplicate logic or functions.
```

---

## 🧩 4. Modularisieren

```plaintext
Prompt:
Split this script into smaller modules: e.g. source_loader.py, filter_engine.py, writer.py
```

---

## 🎨 5. Automatische Formatierung

```bash
ruff check . --fix
black .
flake8 .
```

---

## ✅ 6. Start- und Testbefehl

```bash
python adblock.py
```

Erzeugt eine neue `hosts.txt` mit gefilterten Domains.
