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

# Agentenleitfaden (Codex) – Arbeitsvertrag

> **Dauerhaft:** Diese Datei darf **nicht** gelöscht oder überschrieben werden. Neue Regeln bitte **unten anhängen**, bestehende Inhalte **nur ergänzen**, niemals ersetzen.

## Projekt
- **Name:** AdBlock
- **Primärer Testlauf:** `pytest -q`
- **Format/Lint:** `ruff check . --fix`, `black .`, `flake8 .`
- **Umgebungsflags:** `TEST_MODE=true`, `ALLOW_OFFLINE=true`

## Regeln & Arbeitsablauf
1. **Nur notwendige Dateien ändern; jede geänderte Datei vollständig ausgeben.**
2. **Keine Seiteneffekte in Imports** (`__init__.py` nur lazy reexports; keine Netzwerk-/WS-Calls).
3. **Test-/Offline-Mode** unterstützen (injizierbarer HTTP-Client via `cfg.get_http_client`, lokale Stubs nur ohne injizierten Client; Header mergen: `X-API-KEY`, `X-CAP-API-KEY`, `Version`, `CST`, `X-SECURITY-TOKEN`).
4. **Session/Capital.com:** `_api_url_join`, `_post_session`, `create_session`/`refresh_session` maskieren sensible Felder; bei Login-Fail `RuntimeError` inkl. getesteter Varianten.
5. **WebSocket:** immer importierbar; im Test/Offline Fake-Quote-Event liefern.
6. **Telegram:** im Testmodus deterministisch (`send_message()->1`, Bot `closed=True`, `Retry(count=2, retry_after=...)`).
7. **Daten/Alpha Vantage:** im Test/Offline **nicht-leere** deterministische OHLCV-Daten (`timestamp, open, high, low, close, volume`, optional `symbol`).
8. **Trading/Simulation:** `execute_trade` loggt `🎯`/`🛒`; im Testmodus Restriktions-Checks (Symbols, Capital-%), Wahrscheinlichkeit via `SIMULATION_PROB_TEST`/`SIMULATION_SUCCESS_THRESHOLD`.
9. **Portfolio & Paper:** `cfg.metrics` fail-safe (`budget_rejects`, `cluster_rejects`, `approvals`); `paper.open_trade` liefert `margin`/`trade_id`, `paper.close_trade` liefert `pnl`.
10. **EPIC-Sync:** Union + Normalisierung (`symbol.title()`), **nur neue** EPICs abonnieren.
11. **Health:** reine JSON-Antwort, keine Outbound-HTTPs.
12. **Loop bis grün:**  
    - `ruff` → `black` → `flake8` → `pytest -q --maxfail=1`  
    - ersten Fehler präzise fixen (Shims/Logs/Keys), Dateien vollständig ausgeben, wiederholen.
13. **Kein neuer Ballast:** keine neuen Abhängigkeiten ohne Not; respektiere vorhandenes Mocking (`respx`, `monkeypatch`).

## Definition of Done
- `pytest -q` grün, keine Netzwerkzugriffe in Importpfaden, Shims dokumentiert.
