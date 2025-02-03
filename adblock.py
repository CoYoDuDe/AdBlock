#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# =============================================================================
# 1. GLOBALE KONFIGURATION UND INITIALISIERUNG
# =============================================================================

import os
import time
import subprocess
import hashlib
import requests
import re
import logging
from logging.handlers import RotatingFileHandler
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import json
from collections import defaultdict
import random
import filecmp
import dns.resolver
from threading import Lock

# Globale Variablen und Lock für Threads
CONFIG = {}
DNS_CACHE = {}
dns_cache_lock = Lock()

STATISTIK = {
    "getestete_domains": 0,
    "erreichbare_domains": 0,
    "nicht_erreichbare_domains": 0,
    "fehlerhafte_lists": 0,
    "gesamt_domains": 0,
    "durchlauf_fehlgeschlagen": False,
    "fehlermeldung": "",
    "duplikate": 0,
    "duplikate_pro_liste": defaultdict(int),
    "nicht_erreichbare_pro_liste": defaultdict(int),
    "erreichbare_pro_liste": defaultdict(int),
    "gesamtstatistik": [],
    "list_bewertung": []
}

# Logging-Konfiguration
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'

# Standardkonfiguration erstellen
STANDARD_CONFIG = {
    "log_datei": "/var/log/adblock.log",
    "send_email": False,
    "email": "example@example.com",
    "email_absender": "no-reply@example.com",
    "max_retries": 3,
    "retry_delay": 5,
    "parallel_aktiviert": True,
    "max_parallel_jobs": 5,
    "batch_größe": 100,
    "dns_konfiguration": "adblock.conf",
    "web_server_ipv4": "127.0.0.1",
    "web_server_ipv6": "::1",
    "github_upload": False,
    "github_repo": "git@github.com:example/repo.git",
    "github_branch": "main",
    "git_user": "",
    "git_email": "",
    "dns_server_list": [
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844"
    ],
    "logging_level": "INFO",
    "detailed_log": False,
    "speichere_nicht_erreichbare": True,
    "priorisiere_listen": True,
    "domain_timeout": 5
}

# Standardinhalt für die Hosts-Quellen (Beispiel)
STANDARD_HOSTS_SOURCES = """https://example.com/hosts1
https://example.com/hosts2"""

# Bestimmen des Verzeichnisses, in dem sich das Skript befindet
skript_verzeichnis = os.path.dirname(os.path.realpath(__file__))

# =============================================================================
# 2. GIT UND SSH-SCHLÜSSEL MANAGEMENT
# =============================================================================

def setup_git():
    """
    Überprüft und richtet Git inkl. SSH-Schlüssel ein, falls erforderlich.
    Legt einen neuen SSH-Schlüssel an, falls keiner existiert, 
    und weist diesen Schlüssel GitHub zu.
    """
    if not os.path.exists(os.path.join(skript_verzeichnis, '.git')):
        try:
            subprocess.run(['git', '--version'], check=True)

            user_name = CONFIG.get('git_user', "")
            user_email = CONFIG.get('git_email', "")

            # Git-Konfiguration abfragen, falls noch nicht in config.json
            if not user_name or not user_email:
                print("Git-Konfiguration erforderlich. Bitte geben Sie die folgenden Informationen ein:")
                user_name = input("Git-Benutzername: ")
                user_email = input("Git-E-Mail: ")
                CONFIG['git_user'] = user_name
                CONFIG['git_email'] = user_email
                with open(os.path.join(skript_verzeichnis, 'config.json'), 'w', encoding='utf-8') as config_file:
                    json.dump(CONFIG, config_file, indent=4)

            subprocess.run(['git', 'config', '--global', 'user.name', user_name], check=True)
            subprocess.run(['git', 'config', '--global', 'user.email', user_email], check=True)

            ssh_key_path = os.path.expanduser('~/.ssh/adblock_rsa')

            # SSH-Key erzeugen, falls er noch nicht existiert
            if not os.path.exists(ssh_key_path):
                log("Erstelle neuen SSH-Schlüssel")
                subprocess.run(['ssh-keygen', '-t', 'rsa', '-b', '4096', '-C', user_email, '-N', '', '-f', ssh_key_path], check=True)
                with open(ssh_key_path + '.pub', 'r', encoding='utf-8') as pubkey_file:
                    pubkey = pubkey_file.read()
                log(f"SSH-Schlüssel erstellt: {pubkey}")
                print(f"Fügen Sie den folgenden SSH-Schlüssel zu Ihrem GitHub-Konto hinzu:\n{pubkey}")
                print("Starten Sie das Skript neu, nachdem Sie den Schlüssel hinzugefügt haben.")
                exit(0)

            # SSH-Agent hinzufügen
            agent_status = subprocess.run(['ssh-add', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if b'adblock_rsa' not in agent_status.stdout:
                if 'SSH_AUTH_SOCK' not in os.environ:
                    agent_output = subprocess.check_output(['ssh-agent', '-s']).decode('utf-8')
                    _ = re.search(r'Agent pid (\d+)', agent_output)  # agent_pid ggf. nicht zwingend nötig
                    subprocess.run(['ssh-add', ssh_key_path], check=True)
                else:
                    subprocess.run(['ssh-add', ssh_key_path], check=True)

            # ~/.ssh/config anpassen
            with open(os.path.expanduser('~/.ssh/config'), 'w', encoding='utf-8') as ssh_config_file:
                ssh_config_file.write(f"""
Host github.com
    HostName github.com
    User git
    IdentityFile {ssh_key_path}
    IdentitiesOnly yes
""")

            # Git-Repo initialisieren und auf gewünschten Branch wechseln
            subprocess.run(['git', 'init'], check=True)
            subprocess.run(['git', 'checkout', '-b', CONFIG['github_branch']], check=True)

            # Remote origin setzen
            remotes = subprocess.check_output(['git', 'remote']).decode('utf-8').strip().split('\n')
            if 'origin' in remotes:
                subprocess.run(['git', 'remote', 'remove', 'origin'], check=True)

            subprocess.run(['git', 'remote', 'add', 'origin', CONFIG['github_repo']], check=True)

        except Exception as e:
            fehler_beenden(f"Fehler bei der Git-Konfiguration: {e}")

# =============================================================================
# 3. GITHUB UPLOAD
# =============================================================================

def upload_to_github():
    """
    Lässt die Datei 'hosts.txt' ins Git-Repository einfließen und pusht sie auf GitHub.
    """
    try:
        hosts_path = os.path.join(skript_verzeichnis, 'hosts.txt')
        if not os.path.exists(hosts_path):
            log("Die hosts.txt-Datei fehlt. Upload wird übersprungen.", logging.WARNING)
            return

        subprocess.run(['git', 'add', 'hosts.txt'], check=True)
        subprocess.run(['git', 'commit', '-m', 'Automatische Aktualisierung der Hosts-Datei'], check=True)
        subprocess.run(['git', 'push', 'origin', CONFIG['github_branch']], check=True)
        log("hosts.txt erfolgreich auf GitHub hochgeladen.", logging.INFO)
    except subprocess.CalledProcessError as e:
        log(f"Fehler beim Hochladen der hosts.txt-Datei: {e}", logging.ERROR)

# =============================================================================
# 4. HILFSFUNKTIONEN FÜR SYSTEMINFORMATIONEN
# =============================================================================

def get_cpu_load():
    """
    Liest die CPU-Last (Load Average) aus /proc/loadavg und gibt 
    den 1-Minuten-Durchschnitt zurück.
    """
    try:
        with open('/proc/loadavg', 'r', encoding='utf-8') as f:
            loadavg = f.read().strip().split()
        cpu_load_1_min = float(loadavg[0])  # 1-Minuten-Load Average
        return cpu_load_1_min
    except Exception as e:
        log(f"Fehler beim Lesen von /proc/loadavg: {e}", logging.ERROR)
        return 0.0

def get_free_memory():
    """
    Ermittelt den verfügbaren Speicher in Bytes aus /proc/meminfo.
    Liefert 0 bei Fehler.
    """
    try:
        with open('/proc/meminfo', 'r', encoding='utf-8') as f:
            meminfo = f.readlines()
        mem_available = next((line for line in meminfo if "MemAvailable" in line), None)
        if mem_available:
            free_memory_kb = int(mem_available.split()[1])  # Wert in kB
            return free_memory_kb * 1024  # Umrechnung in Bytes
    except Exception as e:
        log(f"Fehler beim Lesen von /proc/meminfo: {e}", logging.ERROR)
    return 0

def berechne_md5(text):
    """Berechnet den MD5-Hash eines gegebenen Textes."""
    return hashlib.md5(text.encode('utf-8')).hexdigest()

# =============================================================================
# 5. FORTSCHRITTS- UND KONFIGURATIONSMANAGEMENT
# =============================================================================

def lade_domain_md5():
    """
    Lädt die Datei domain_md5.json, die pro URL den MD5-Hash und 
    die Domains speichert, um Änderungen erkennen zu können.
    """
    try:
        pfad = os.path.join(skript_verzeichnis, 'tmp', 'domain_md5.json')
        with open(pfad, 'r', encoding='utf-8') as json_datei:
            return json.load(json_datei)
    except FileNotFoundError:
        log("domain_md5.json nicht gefunden, initialisiere neu.", logging.WARNING)
        return {}
    except json.JSONDecodeError:
        log("domain_md5.json ist beschädigt, initialisiere neu.", logging.WARNING)
        return {}

def sicher_speichern(dateipfad, inhalt, is_json=False):
    """
    Sicheres Speichern in eine Datei mit Fehlerbehandlung.
    :param dateipfad: Pfad zur Zieldatei
    :param inhalt: String oder Python-Struktur
    :param is_json: True, wenn 'inhalt' als JSON zu speichern ist
    """
    try:
        # Schreibzugriff immer mit UTF-8
        with open(dateipfad, 'w', encoding='utf-8') as file:
            if is_json:
                json.dump(inhalt, file, indent=4, ensure_ascii=False)
            else:
                file.write(inhalt)
        log(f"Datei erfolgreich gespeichert: {dateipfad}", logging.INFO)
    except Exception as e:
        log(f"Fehler beim Speichern der Datei {dateipfad}: {e}", logging.ERROR)

def speichere_domain_md5(domain_md5):
    """Speichert das Dictionary 'domain_md5' in domain_md5.json."""
    pfad = os.path.join(skript_verzeichnis, 'tmp', 'domain_md5.json')
    sicher_speichern(pfad, domain_md5, is_json=True)

def speichere_liste_temporär(url, domains):
    """
    Speichert getestete Domains einer Liste temporär ab, 
    falls man bei Abbrüchen später anknüpfen möchte.
    """
    try:
        temp_path = os.path.join(skript_verzeichnis, 'tmp', f"{url.replace('://', '_').replace('/', '_')}.tmp")
        inhalt = "\n".join(domains)
        sicher_speichern(temp_path, inhalt, is_json=False)
        log(f"Liste {url} wurde temporär gespeichert.")
    except Exception as e:
        log(f"Fehler beim Speichern der temporären Liste {url}: {e}", logging.ERROR)

def calculate_batch_size():
    """
    Berechnet die dynamische Batch-Größe basierend auf verfügbaren 
    System-Ressourcen (v.a. RAM) und der in config.json eingestellten 
    Obergrenze (batch_größe).
    """
    free_memory = get_free_memory()

    # Grobe Schätzung: ~70 Bytes pro Domain im Speicher
    estimated_domains_per_batch = free_memory // 1024 // 70
    max_batch_size = CONFIG.get("batch_größe", 100)

    batch_size = max(1, min(max_batch_size, estimated_domains_per_batch))
    if batch_size < max_batch_size:
        log(f"Warnung: Batch-Größe reduziert auf {batch_size} basierend auf verfügbaren Ressourcen.", logging.WARNING)
        log(f"Grund: Verfügbarer Speicher: {free_memory / (1024 * 1024):.2f} MB", logging.WARNING)
    
    log(f"Berechneter verfügbarer Speicher: {free_memory / (1024 * 1024):.2f} MB", logging.DEBUG)
    log(f"Geschätzte Domains pro Batch: {estimated_domains_per_batch}", logging.DEBUG)
    log(f"Empfohlene Batch-Größe: {batch_size} (Maximal erlaubt: {max_batch_size})", logging.DEBUG)

    return batch_size

def calculate_dynamic_resources(domain_count, max_jobs=None):
    """
    Berechnet dynamisch die Anzahl paralleler Jobs basierend auf 
    CPU-Last, CPU-Kernen und verfügbarem Speicher.
    """
    max_jobs = max_jobs or CONFIG.get('max_parallel_jobs', 10)

    cpu_load_value = get_cpu_load()
    cpu_cores = os.cpu_count() or 1
    free_memory = get_free_memory()

    # Weniger parallele Jobs bei hoher Last
    max_jobs_by_cpu = max(1, int(cpu_cores / (cpu_load_value + 1)))
    # Weniger parallele Jobs bei wenig RAM
    max_jobs_by_memory = max(1, int((free_memory * 0.75) / (domain_count * 70)))

    max_parallel_jobs = min(max_jobs_by_cpu, max_jobs_by_memory, max_jobs)

    log(f"Aktuelle CPU-Auslastung: {cpu_load_value:.2f}, verfügbare CPU-Kerne: {cpu_cores}", logging.DEBUG)
    log(f"Verfügbarer Speicher: {free_memory / (1024 * 1024):.2f} MB", logging.DEBUG)
    log(f"Berechnete parallele Jobs basierend auf CPU: {max_jobs_by_cpu}", logging.DEBUG)
    log(f"Berechnete parallele Jobs basierend auf Speicher: {max_jobs_by_memory}", logging.DEBUG)
    log(f"Empfohlene parallele Jobs: {max_parallel_jobs} (Maximal erlaubt: {max_jobs})", logging.DEBUG)

    if max_parallel_jobs < max_jobs:
        log(f"Warnung: Parallele Jobs reduziert auf {max_parallel_jobs} basierend auf aktuellen Ressourcen.", logging.DEBUG)
        log("Hinweis: Mehr parallele Jobs möglich, wenn Ressourcen angepasst werden.", logging.DEBUG)

    return max_parallel_jobs

# =============================================================================
# 6. LOGGING UND FEHLERBEHANDLUNG
# =============================================================================

def konfiguriere_logging(log_datei):
    """
    Setzt das Logging anhand der config.json (z.B. INFO/DEBUG).
    Im 'detailed_log'-Modus wird immer DEBUG verwendet.
    """
    level = CONFIG.get('logging_level', 'INFO').upper()
    numeric_level = getattr(logging, level, logging.INFO)

    if CONFIG.get("detailed_log", False):
        numeric_level = logging.DEBUG

    logging.basicConfig(
        level=numeric_level,
        format=LOG_FORMAT,
        filename=log_datei,
        filemode='w'
    )
    log(f"Logging-Level auf {level} gesetzt.", logging.INFO)

def log(nachricht, level=logging.INFO):
    """
    Schreibt eine Nachricht ins Log. 
    Nutzt den globalen Logger mit dem in konfiguriere_logging gesetzten Level.
    """
    logger = logging.getLogger()
    if level >= logger.getEffectiveLevel():
        logger.log(level, nachricht)

def fehler_beenden(nachricht):
    """
    Beendet das Skript bei einem Fehler, setzt entsprechende Statistik-Flags 
    und versucht, eine E-Mail zu senden (falls aktiviert).
    """
    log(nachricht, logging.ERROR)
    STATISTIK["durchlauf_fehlgeschlagen"] = True
    STATISTIK["fehlermeldung"] = nachricht
    if CONFIG.get("send_email", False):
        try:
            sende_email("Fehler im AdBlock-Skript", erstelle_email_text())
        except Exception as e:
            log(f"Fehler beim Senden der Fehler-E-Mail: {e}", logging.ERROR)
    exit(1)

# =============================================================================
# 7. DATEI- UND VERZEICHNISMANAGEMENT
# =============================================================================

def erstelle_standard_datei(dateipfad, inhalt=None, leer=False):
    """
    Erzeugt eine Datei mit Standardwerten oder leerem Inhalt, falls sie nicht existiert.
    """
    if not os.path.exists(dateipfad):
        if leer:
            sicher_speichern(dateipfad, "", is_json=False)
        else:
            # Wenn 'inhalt' z.B. ein dict/list ist => JSON
            sicher_speichern(dateipfad, inhalt, is_json=not isinstance(inhalt, str))

def initialisiere_verzeichnisse_und_dateien():
    """
    Erzeugt die benötigten tmp-Verzeichnisse und Standarddateien,
    falls sie nicht existieren.
    """
    tmp_dir = os.path.join(skript_verzeichnis, 'tmp')
    os.makedirs(tmp_dir, exist_ok=True)

    fehlende_dateien = [
        ('config.json', STANDARD_CONFIG),
        ('tmp/statistik.json', STATISTIK),
        ('hosts_sources.conf', STANDARD_HOSTS_SOURCES),
        ('tmp/domain_md5.json', {}),
        ('whitelist.txt', ''),
        ('blacklist.txt', ''),
        ('tmp/bewertung.json', [])
    ]
    for rel_path, inhalt in fehlende_dateien:
        dateipfad = os.path.join(skript_verzeichnis, rel_path)
        if not os.path.exists(dateipfad):
            # Wenn 'inhalt' z.B. dict, => JSON
            sicher_speichern(dateipfad, inhalt, is_json=not isinstance(inhalt, str))

def bereinige_obsolete_dateien():
    """
    Löscht temporäre Dateien aus dem tmp-Verzeichnis, die nicht mehr 
    benötigt werden (z.B. alte .tmp-Dateien, wenn Listen entfernt wurden).
    """
    global DNS_CACHE
    DNS_CACHE.clear()

    temp_verzeichnis = os.path.join(skript_verzeichnis, 'tmp')
    aktuelle_urls = set(lade_domain_md5().keys())

    for datei in os.listdir(temp_verzeichnis):
        dateipfad = os.path.join(temp_verzeichnis, datei)
        if not datei.endswith(".tmp"):
            continue

        # Rückumwandlung: Das ist etwas ungenau, da "://"
        # zu "_" gemacht wurde, usw.
        zugehoerige_url = datei.replace(".tmp", "").replace("_", "://")
        if zugehoerige_url not in aktuelle_urls:
            try:
                os.remove(dateipfad)
                log(f"Obsolete Datei gelöscht: {dateipfad}", logging.INFO)
            except Exception as e:
                log(f"Fehler beim Löschen von {dateipfad}: {e}", logging.ERROR)

# =============================================================================
# 8. DNS UND DOMAIN-VALIDIERUNG
# =============================================================================

def ist_gueltige_domain(domain):
    """
    Überprüft anhand eines Regex, ob eine Domain-Notation gültig erscheint.
    """
    domain_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$"
    )
    return bool(domain_regex.match(domain))

def test_dns_entry(domain, record_type='A'):
    """
    Testet einen spezifischen DNS-Record (A/AAAA). Falls DNS-Timeout/NXDOMAIN,
    wird ggf. ein Fallback getestet. Ergebnisse werden gecachet.
    """
    global DNS_CACHE, dns_cache_lock

    # Zuerst Cache prüfen
    with dns_cache_lock:
        if domain in DNS_CACHE:
            log(f"Domain {domain} aus Cache geladen: {DNS_CACHE[domain]}", logging.DEBUG)
            return DNS_CACHE[domain]

    resolver = dns.resolver.Resolver()
    resolver.nameservers = CONFIG['dns_server_list']
    max_retries = CONFIG.get("max_retries", 3)
    retry_delay = CONFIG.get("retry_delay", 5)

    # Erst A, dann AAAA versuchen
    record_types = [record_type, 'AAAA'] if record_type == 'A' else [record_type]

    for record in record_types:
        for attempt in range(max_retries):
            try:
                resolver.resolve(domain, record, lifetime=CONFIG.get('domain_timeout', 5))
                with dns_cache_lock:
                    DNS_CACHE[domain] = True
                log(f"Domain {domain} erfolgreich getestet mit {record}-Record.", logging.DEBUG)
                return True
            except dns.resolver.Timeout:
                log(f"Timeout für {domain} bei {record}-Record (Versuch {attempt + 1}/{max_retries}).", logging.DEBUG)
            except dns.resolver.NXDOMAIN:
                log(f"Domain {domain} existiert nicht (NXDOMAIN) für {record}-Record.", logging.DEBUG)
                break  # Keine weiteren Versuche, Domain existiert nicht
            except Exception as e:
                log(f"Unbekannter Fehler bei {domain} ({record}-Record, Versuch {attempt + 1}/{max_retries}): {e}", logging.DEBUG)

            # Resolver-Fallback
            resolver.nameservers = resolver.nameservers[1:] + resolver.nameservers[:1]
            log(f"Wechsle Resolver zu {resolver.nameservers[0]}.", logging.DEBUG)

            if attempt < max_retries - 1:
                time.sleep(retry_delay)

        log(f"{record}-Record für {domain} nach {max_retries} Versuchen fehlgeschlagen.", logging.DEBUG)

    with dns_cache_lock:
        DNS_CACHE[domain] = False
    return False

# =============================================================================
# 9. BATCH-VERARBEITUNG UND DOMAIN-EXTRAKTION
# =============================================================================

def messen(func):
    """
    Einfacher Dekorator, der die Laufzeit einer Funktion misst und ausgibt.
    """
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        print(f"Die Funktion '{func.__name__}' dauerte {end_time - start_time:.2f} Sekunden.")
        return result
    return wrapper

@messen
def teste_domains_batch(domains):
    """
    Testet eine Menge an Domains in Batches (Größe wird dynamisch bestimmt)
    und nutzt parallele Threads (Anzahl wird ebenfalls dynamisch bestimmt).
    """
    results = {}
    resolver_index = random.randint(0, len(CONFIG['dns_server_list']) - 1)
    total_domains = len(domains)
    batch_index = 0
    erreichbare_count = 0
    nicht_erreichbare_count = 0

    while batch_index < total_domains:
        batch_size = calculate_batch_size()
        max_jobs = calculate_dynamic_resources(total_domains)

        current_batch = domains[batch_index:batch_index + batch_size]
        log(
            f"Starte Batch {batch_index // batch_size + 1} von {(total_domains + batch_size - 1) // batch_size} "
            f"mit Größe {batch_size} und {max_jobs} parallelen Jobs.", 
            logging.INFO
        )

        with ThreadPoolExecutor(max_workers=max_jobs) as executor:
            futures = {
                executor.submit(test_single_or_batch, domain, resolver_index): domain
                for domain in current_batch
            }
            for future in concurrent.futures.as_completed(futures):
                domain = futures[future]
                try:
                    reachable = future.result()
                    results[domain] = reachable

                    if reachable:
                        erreichbare_count += 1
                    else:
                        nicht_erreichbare_count += 1

                except Exception as e:
                    log(f"Fehler beim Testen der Domain {domain}: {e}", logging.DEBUG)
                    results[domain] = False

        batch_index += len(current_batch)
        log(f"Fortschritt: {batch_index}/{total_domains} Domains getestet (Batch abgeschlossen)", logging.INFO)
        log(f"Erreichbar: {erreichbare_count} | Nicht erreichbar: {nicht_erreichbare_count}", logging.INFO)

    return results

def test_single_or_batch(domain, resolver_index):
    """
    Führt den DNS-Test für eine einzelne Domain durch, wechselt bei Fehlern 
    den Resolver und probiert mehrere Versuche (max_retries).
    """
    retries = CONFIG.get("max_retries", 3)
    for attempt in range(retries):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [CONFIG['dns_server_list'][resolver_index]]
            return test_dns_entry(domain, 'A')
        except Exception as e:
            log(f"Fehler beim Testen der Domain {domain} (Versuch {attempt + 1}/{retries}): {e}", logging.DEBUG)
            resolver_index = (resolver_index + 1) % len(CONFIG['dns_server_list'])
            if attempt < retries - 1:
                time.sleep(CONFIG.get("retry_delay", 2))
    log(f"Domain {domain} konnte nach {retries} Versuchen nicht erfolgreich getestet werden.", logging.DEBUG)
    return False

def extrahiere_domains_aus_liste(url):
    """
    Lädt eine Hosts-Datei von URL, ermittelt deren MD5-Summe und extrahiert
    daraus die Domains. Prüft per If-None-Match oder MD5, ob sich die Liste
    geändert hat, um unnötige Arbeit zu sparen.
    """
    try:
        log(f"Beginne Extrahieren der Domains von {url}")
        domain_md5 = lade_domain_md5()

        # Wenn bereits gespeichert, zuerst mittels Header If-None-Match (ETag) oder MD5 versuchen
        if url in domain_md5:
            saved_md5 = domain_md5[url]['md5']
            log(f"Prüfe, ob sich die Liste {url} geändert hat...")
            retries = CONFIG.get("max_retries", 3)
            for versuch in range(retries):
                try:
                    # Falls Server ETag unterstützt, kann man es so machen:
                    response = requests.get(url, headers={"If-None-Match": saved_md5}, timeout=10)
                    if response.status_code == 304:
                        # Keine Änderung
                        log(f"Keine Änderungen in {url}, überspringe Verarbeitung. "
                            f"({len(domain_md5[url]['domains'])} Domains)")
                        return url, set(domain_md5[url]['domains']), saved_md5
                    break
                except requests.exceptions.RequestException as e:
                    log(f"Fehler bei Anfrage {url} (Versuch {versuch+1}/{retries}): {e}", logging.WARNING)
                    if versuch == retries - 1:
                        raise
                    time.sleep(CONFIG.get("retry_delay", 5))
        else:
            log(f"Keine gespeicherte MD5-Prüfsumme für {url}. Starte Download.")

        # Liste herunterladen
        retries = CONFIG.get("max_retries", 3)
        for versuch in range(retries):
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                break
            except requests.exceptions.RequestException as e:
                log(f"Fehler bei Anfrage {url} (Versuch {versuch+1}/{retries}): {e}", logging.WARNING)
                if versuch == retries - 1:
                    raise
                time.sleep(CONFIG.get("retry_delay", 5))

        content = response.text
        current_md5 = berechne_md5(content)

        if url in domain_md5 and domain_md5[url]['md5'] == current_md5:
            log(f"Keine Änderungen in {url}, überspringe Verarbeitung. "
                f"({len(domain_md5[url]['domains'])} Domains)")
            return url, set(domain_md5[url]['domains']), current_md5

        # Domains extrahieren
        lines = content.splitlines()
        domains = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            teile = line.split()
            if len(teile) > 1 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", teile[0]):
                domain = teile[1].strip()
                domain = re.sub(r'^www\.', '', domain)
                if ist_gueltige_domain(domain):
                    domains.add(domain)

        log(f"Extrahierte {len(domains)} Domains aus {url}")
        return url, domains, current_md5

    except Exception as e:
        log(f"Fehler beim Extrahieren der Domains von {url}: {e}", logging.ERROR)
        STATISTIK["fehlerhafte_lists"] += 1
        return url, set(), None

def aktualisiere_und_verarbeite_hosts_sources():
    """
    Liest hosts_sources.conf ein, lädt/aktualisiert die enthaltenen Quellen 
    parallel und aktualisiert domain_md5.json. Entfernt veraltete Quellen.
    """
    # Aktuelle URLs aus hosts_sources.conf
    with open(os.path.join(skript_verzeichnis, 'hosts_sources.conf'), 'r', encoding='utf-8') as f:
        aktuelle_urls = {line.strip() for line in f if line.strip() and not line.startswith('#')}

    # domain_md5 laden, um Änderungen zu erkennen
    domain_md5 = lade_domain_md5()
    gespeicherte_urls = set(domain_md5.keys())

    neue_urls = aktuelle_urls - gespeicherte_urls
    entfernte_urls = gespeicherte_urls - aktuelle_urls

    # Entfernte URLs bereinigen
    for url in entfernte_urls:
        log(f"URL entfernt: {url}. Bereinige zugehörige Daten...")
        del domain_md5[url]

    speichere_domain_md5(domain_md5)

    domains_dict = {}
    # Listen parallel extrahieren
    with ThreadPoolExecutor(max_workers=CONFIG.get('max_parallel_jobs', 10)) as executor:
        futures = {executor.submit(extrahiere_domains_aus_liste, url): url for url in aktuelle_urls}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                _, domains, current_md5 = future.result()
                if current_md5 is None:
                    # Fehlgeschlagen, leere Menge
                    domains = set()
                # Aktualisieren
                if url in domain_md5 and domain_md5[url]['md5'] == current_md5:
                    # Keine Änderung
                    domains_dict[url] = {
                        "domains": set(domain_md5[url]["domains"]),
                        "md5": current_md5
                    }
                else:
                    # Neue oder geänderte Liste
                    domains_dict[url] = {
                        "domains": domains,
                        "md5": current_md5
                    }
                    domain_md5[url] = {
                        "domains": list(domains),
                        "md5": current_md5
                    }
            except Exception as e:
                log(f"Fehler beim Verarbeiten von {url}: {e}", logging.ERROR)
                STATISTIK["fehlerhafte_lists"] += 1

    # domain_md5 nach Änderungen speichern
    speichere_domain_md5(domain_md5)

    return domains_dict

# =============================================================================
# 10. DATENVERARBEITUNG UND DUPLIKATMANAGEMENT
# =============================================================================

def entferne_duplikate_mit_prioritaet(domains_dict):
    """
    Entfernt Duplikate zwischen verschiedenen Listen. 
    Höher priorisierte Listen (im Reihenfolgennach Sinn) werden bevorzugt. 
    """
    priorisierte_domains = set()
    bearbeitete_domains_dict = {}

    for url, data in domains_dict.items():
        domains = data["domains"]
        unique_domains = []
        for domain in domains:
            if domain not in priorisierte_domains:
                unique_domains.append(domain)
                priorisierte_domains.add(domain)

        bearbeitete_domains_dict[url] = {
            "domains": unique_domains,
            "md5": data["md5"]
        }
        anzahl_duplikate = len(domains) - len(unique_domains)
        STATISTIK["duplikate_pro_liste"][url] = anzahl_duplikate
        STATISTIK["duplikate"] += anzahl_duplikate

    return bearbeitete_domains_dict

def pruefe_und_entferne_leere_listen(domains_dict):
    """
    Prüft, welche Listen nach der Verarbeitung leer sind, 
    und entfernt diese ggf. aus dem Dictionary.
    """
    leere_listen = []
    for url, data in domains_dict.items():
        if not data["domains"]:
            leere_listen.append(url)

    for url in leere_listen:
        log(f"Liste {url} ist leer und wird entfernt/ignoriert.", logging.WARNING)
        del domains_dict[url]

    return domains_dict

# =============================================================================
# 11. BEWERTUNGS- UND STATISTIKFUNKTIONEN
# =============================================================================

def bewerte_listen():
    """
    Bewertet die Hosts-Listen basierend auf den Statistiken (erreichbar, 
    nicht erreichbar, Duplikate). 
    Speicherung im Feld STATISTIK["list_bewertung"].
    """
    bewertung = []
    for url in STATISTIK["erreichbare_pro_liste"].keys():
        erreichbar = STATISTIK["erreichbare_pro_liste"][url]
        nicht_erreichbar = STATISTIK["nicht_erreichbare_pro_liste"].get(url, 0)
        duplikate = STATISTIK["duplikate_pro_liste"].get(url, 0)

        gesamt = erreichbar + nicht_erreichbar
        effizient = 0
        if gesamt > 0:
            effizient = erreichbar / gesamt

        wert = erreichbar - (duplikate + nicht_erreichbar)
        bewertung.append((url, gesamt, erreichbar, nicht_erreichbar, duplikate, effizient, wert))

    # Nach Bewertungswert sortieren (absteigend)
    bewertung.sort(key=lambda x: x[-1], reverse=True)

    # Beispielhafter Ansatz: Schlechte Listen entfernen
    for item in bewertung:
        if item[1] == 0 or item[-1] < 0:
            log(f"Liste {item[0]} wird entfernt, da ineffizient oder leer (Bewertung < 0).")
            if item[0] in STATISTIK["erreichbare_pro_liste"]:
                del STATISTIK["erreichbare_pro_liste"][item[0]]

    STATISTIK["list_bewertung"].extend(bewertung)
    return bewertung

def speichere_bewertung(bewertung):
    """
    Speichert die Bewertung in tmp/bewertung.json.
    """
    bewertung_datei = os.path.join(skript_verzeichnis, 'tmp', 'bewertung.json')
    sicher_speichern(bewertung_datei, bewertung, is_json=True)
    log(f"Bewertung der Listen erfolgreich in {bewertung_datei} gespeichert.", logging.INFO)

def lade_bewertung():
    """
    Lädt die Bewertung aus tmp/bewertung.json (falls vorhanden).
    """
    bewertung_datei = os.path.join(skript_verzeichnis, 'tmp', 'bewertung.json')
    try:
        with open(bewertung_datei, 'r', encoding='utf-8') as file:
            bewertung = json.load(file)
        log(f"Bewertung aus {bewertung_datei} geladen.", logging.INFO)
        return bewertung
    except FileNotFoundError:
        log("Keine Bewertung gefunden. Erstelle neue Bewertungsliste.", logging.INFO)
        return []
    except Exception as e:
        log(f"Fehler beim Laden der Bewertung: {e}", logging.ERROR)
        return []

# =============================================================================
# 12. STATISTIKAKTUALISIERUNG UND EMAIL
# =============================================================================

def aktualisiere_gesamtstatistik():
    """
    Hängt die aktuellen Kennzahlen an die Gesamtstatistik 
    (STATISTIK["gesamtstatistik"]) an.
    """
    laufstatistik = {
        "getestete_domains": STATISTIK["getestete_domains"],
        "erreichbare_domains": STATISTIK["erreichbare_domains"],
        "nicht_erreichbare_domains": STATISTIK["nicht_erreichbare_domains"],
        "fehlerhafte_lists": STATISTIK["fehlerhafte_lists"],
        "duplikate": STATISTIK["duplikate"],
        "durchlauf_fehlgeschlagen": STATISTIK["durchlauf_fehlgeschlagen"]
    }
    STATISTIK.setdefault("gesamtstatistik", []).append(laufstatistik)

def aktualisiere_intervall_statistik(domains_dict):
    """
    Beispielfunktion, um ein ideales Intervall (in Tagen) zu errechnen,
    wie oft man das Skript laufen lassen könnte. 
    (Basierend auf Änderungsfrequenz, Effizienz etc.)
    """
    listen_statistiken = []
    for url, daten in domains_dict.items():
        domains = len(daten["domains"])
        nicht_erreichbar = STATISTIK["nicht_erreichbare_pro_liste"].get(url, 0)

        gesamt = domains + nicht_erreichbar
        effizient = domains / gesamt if gesamt else 0

        # Einfacher Standardwert für Änderungen pro Jahr
        aenderungen_pro_jahr = daten.get("änderungen_pro_jahr", 12)

        listen_statistiken.append({
            "url": url,
            "änderungen_pro_jahr": aenderungen_pro_jahr,
            "domains": domains,
            "effizienz": effizient,
        })

    idealer_intervall = berechne_ideal_intervall(listen_statistiken)
    STATISTIK["empfohlener_intervall"] = idealer_intervall
    log(f"Berechneter idealer Intervall: {idealer_intervall} Tage.", logging.INFO)
    return idealer_intervall

def berechne_ideal_intervall(liste_statistiken):
    """
    Berechnet den idealen Intervall in Tagen. 
    Hier ein sehr vereinfachtes Beispiel.
    """
    mindest_intervall = 7
    maximal_intervall = 90

    gewichtet_summen = []
    for liste in liste_statistiken:
        durchschnitts_intervall = 365 / max(1, liste["änderungen_pro_jahr"])
        wichtigkeit = liste["domains"] * liste["effizienz"]
        gewichteter_intervall = durchschnitts_intervall / max(1, wichtigkeit)
        gewichtet_summen.append(gewichteter_intervall)

    if gewichtet_summen:
        global_intervall = sum(gewichtet_summen) / len(gewichtet_summen)
    else:
        global_intervall = maximal_intervall

    global_intervall = max(mindest_intervall, min(maximal_intervall, global_intervall))
    return round(global_intervall)

def erstelle_email_text():
    """
    Erstellt den Text für die E-Mail-Benachrichtigung am Ende des Skriptlaufs.
    """
    status = "Erfolgreich" if not STATISTIK["durchlauf_fehlgeschlagen"] else "Fehlgeschlagen"
    fehlermeldung = STATISTIK["fehlermeldung"] if STATISTIK["durchlauf_fehlgeschlagen"] else "Keine"

    email_text = f"Der aktuelle Durchlauf des AdBlock-Skripts ist {status}.\n\n"
    if STATISTIK["durchlauf_fehlgeschlagen"]:
        email_text += f"Fehlermeldung: {fehlermeldung}\n\n"
        email_text += "Folgende Listen haben Fehler verursacht:\n"
        for url, count in STATISTIK["nicht_erreichbare_pro_liste"].items():
            email_text += f"- {url}: {count} nicht erreichbare Domains\n"

    email_text += "\nGesamtstatistik (alle bisherigen Läufe):\n"
    email_text += "---------------------------------------\n"
    if not STATISTIK["gesamtstatistik"]:
        email_text += "Keine Daten.\n"
    else:
        gesamt_statistik = {
            "getestete_domains": sum(lauf['getestete_domains'] for lauf in STATISTIK["gesamtstatistik"]),
            "erreichbare_domains": sum(lauf['erreichbare_domains'] for lauf in STATISTIK["gesamtstatistik"]),
            "nicht_erreichbare_domains": sum(lauf['nicht_erreichbare_domains'] for lauf in STATISTIK["gesamtstatistik"]),
            "fehlerhafte_lists": sum(lauf['fehlerhafte_lists'] for lauf in STATISTIK["gesamtstatistik"]),
            "duplikate": sum(lauf['duplikate'] for lauf in STATISTIK["gesamtstatistik"]),
        }
        for key, value in gesamt_statistik.items():
            email_text += f"{key.replace('_', ' ').capitalize()}: {value}\n"

    email_text += f"\nEmpfohlener Intervall für nächste Ausführung: {STATISTIK.get('empfohlener_intervall', 'N/A')} Tage\n"

    email_text += "\nStatistik dieses Laufs:\n"
    email_text += "-----------------------\n"
    aktuelle_statistik = {
        "getestete_domains": STATISTIK["getestete_domains"],
        "erreichbare_domains": STATISTIK["erreichbare_domains"],
        "nicht_erreichbare_domains": STATISTIK["nicht_erreichbare_domains"],
        "fehlerhafte_lists": STATISTIK["fehlerhafte_lists"],
        "gesamtanzahl_domains_in_den_listen": STATISTIK["gesamt_domains"],
        "duplikate": STATISTIK["duplikate"],
    }
    for key, value in aktuelle_statistik.items():
        email_text += f"{key.replace('_', ' ').capitalize()}: {value}\n"

    email_text += "\nErgebnisse pro Liste (Bewertungen):\n"
    email_text += "----------------------------------\n"
    for eintrag in STATISTIK["list_bewertung"]:
        url, gesamt, erreichbar, nicht_erreichbar, duplikate, effizient, wert = eintrag
        email_text += f"Liste: {url}\n"
        email_text += f"   Gesamt: {gesamt}\n"
        email_text += f"   Erreichbar: {erreichbar}\n"
        email_text += f"   Nicht erreichbar: {nicht_erreichbar}\n"
        email_text += f"   Duplikate: {duplikate}\n"
        email_text += f"   Bewertung: {wert}\n\n"

    return email_text

def sende_email(betreff, text, fehler=False):
    """
    Sendet eine E-Mail mit dem gegebenen Betreff und Text 
    über das lokale sendmail-Kommando (sofern aktiviert).
    """
    if CONFIG.get('send_email', False):
        try:
            EMAIL = CONFIG['email']
            ABSENDER = CONFIG['email_absender']
            nachricht = f"Subject: {betreff}\nFrom: {ABSENDER}\nTo: {EMAIL}\n\n{text}"
            p = subprocess.Popen(["/usr/sbin/sendmail", "-t"], stdin=subprocess.PIPE)
            p.communicate(nachricht.encode('utf-8'))
            log(f"E-Mail gesendet an {EMAIL}: {betreff}")
        except Exception as e:
            log(f"Fehler beim Senden der E-Mail: {e}", logging.ERROR)

# =============================================================================
# 13. HAUPTPROZESS
# =============================================================================

def erstelle_dnsmasq_conf(domains):
    """
    Erzeugt aus den finalen erreichbaren Domains eine dnsmasq-Konfigurationsdatei 
    (z.B. adblock.conf). Startet dnsmasq neu, falls Änderungen erkannt werden.
    """
    temp_conf_path = os.path.join(skript_verzeichnis, 'tmp', 'temp_adblock.conf')
    inhalt = ""
    for domain in sortiere_domains(domains):
        inhalt += f"address=/{domain}/{CONFIG['web_server_ipv4']}\n"
        inhalt += f"address=/{domain}/{CONFIG['web_server_ipv6']}\n"

    sicher_speichern(temp_conf_path, inhalt, is_json=False)

    ziel_conf = CONFIG['dns_konfiguration']
    if not os.path.exists(ziel_conf) or os.stat(ziel_conf).st_size == 0:
        log("Aktuelle dnsmasq-Konfiguration fehlt oder ist leer. Erstelle neu und starte dnsmasq.")
        os.replace(temp_conf_path, ziel_conf)
        subprocess.run(['systemctl', 'restart', 'dnsmasq'])
        return

    if not filecmp.cmp(temp_conf_path, ziel_conf):
        log("dnsmasq-Konfiguration hat sich geändert. Erstelle neu und starte dnsmasq.")
        os.replace(temp_conf_path, ziel_conf)
        subprocess.run(['systemctl', 'restart', 'dnsmasq'])
    else:
        log("Keine Änderungen in der dnsmasq-Konfiguration. Neustart wird übersprungen.")
        os.remove(temp_conf_path)

def sortiere_domains(domains):
    """
    Sortiert Domains alphabetisch, bei Bedarf könnte man 
    z.B. TLD-basiert sortieren.
    """
    return sorted(domains, key=lambda x: (x.split('.')[-1], x))

def erstelle_hosts_datei(domains):
    """
    Erzeugt eine 'hosts.txt'-Datei im Skriptverzeichnis 
    mit 0.0.0.0 <domain>.
    """
    log("Beginne mit der Erstellung der 'hosts.txt'-Datei.")
    hosts_datei_pfad = os.path.join(skript_verzeichnis, 'hosts.txt')
    inhalt = ""
    for domain in sortiere_domains(domains):
        inhalt += f"0.0.0.0 {domain}\n"

    sicher_speichern(hosts_datei_pfad, inhalt, is_json=False)

def hauptprozess():
    """
    Hauptprozess des Skripts. Lädt Konfiguration, initialisiert Dateien,
    aktualisiert Listen, testet Domains, erstellt Hosts- und dnsmasq-Datei,
    speichert Statistiken und verschickt (optional) E-Mails.
    """
    try:
        initialisiere_verzeichnisse_und_dateien()

        log("Bereinige temporäre Dateien und Cache vor dem Start...", logging.INFO)
        bereinige_obsolete_dateien()

        global CONFIG
        CONFIG = lade_konfiguration(os.path.join(skript_verzeichnis, 'config.json'))
        konfiguriere_logging(CONFIG['log_datei'])

        log("Starte den Hauptprozess...", logging.INFO)

        if CONFIG['github_upload']:
            setup_git()

        # Hosts-Quellen aktualisieren und verarbeiten
        domains_dict = aktualisiere_und_verarbeite_hosts_sources()

        # Duplikate entfernen (Priorisierung)
        domains_dict = entferne_duplikate_mit_prioritaet(domains_dict)

        # Leere Listen entfernen
        domains_dict = pruefe_und_entferne_leere_listen(domains_dict)

        # Empfohlenes Intervall berechnen
        idealer_intervall = aktualisiere_intervall_statistik(domains_dict)
        log(f"Empfohlener Intervall für nächste Ausführung: {idealer_intervall} Tage.", logging.INFO)

        # Alle Domains sammeln
        alle_domains = set()
        for data in domains_dict.values():
            alle_domains.update(data["domains"])
        STATISTIK["gesamt_domains"] = len(alle_domains)

        log(f"Extrahiert: {len(alle_domains)} Domains aus den Quellen.")

        # Whitelist / Blacklist
        with open(os.path.join(skript_verzeichnis, 'whitelist.txt'), 'r', encoding='utf-8') as whitelist_file:
            whitelist = {line.strip() for line in whitelist_file if line.strip()}
        with open(os.path.join(skript_verzeichnis, 'blacklist.txt'), 'r', encoding='utf-8') as blacklist_file:
            blacklist = {line.strip() for line in blacklist_file if line.strip()}

        # Domains filtern
        alle_domains.difference_update(whitelist)  # Whitelist raus
        alle_domains.update(blacklist)             # Blacklist rein
        log(f"Domains nach Whitelist/Blacklist gefiltert: {len(alle_domains)} verbleibend.")

        # Domains testen
        erreichbare_domains = set()
        nicht_erreichbare_domains = set()

        batch_results = teste_domains_batch(list(alle_domains))
        for domain, erreichbar in batch_results.items():
            STATISTIK["getestete_domains"] += 1
            if erreichbar:
                erreichbare_domains.add(domain)
                STATISTIK["erreichbare_domains"] += 1
                # Pro Liste statistisch abbilden
                for url, data in domains_dict.items():
                    if domain in data["domains"]:
                        STATISTIK["erreichbare_pro_liste"][url] += 1
            else:
                nicht_erreichbare_domains.add(domain)
                STATISTIK["nicht_erreichbare_domains"] += 1
                for url, data in domains_dict.items():
                    if domain in data["domains"]:
                        STATISTIK["nicht_erreichbare_pro_liste"][url] += 1

        log(f"Test abgeschlossen: {len(erreichbare_domains)} erreichbare Domains, "
            f"{len(nicht_erreichbare_domains)} nicht erreichbar.")

        # domain_md5.json speichern (falls wir es aktualisiert haben)
        speichere_domain_md5(lade_domain_md5())

        # dnsmasq neu erstellen
        erstelle_dnsmasq_conf(erreichbare_domains)
        # hosts.txt-Datei erstellen
        erstelle_hosts_datei(erreichbare_domains)

        # Auf GitHub hochladen (falls aktiviert)
        if CONFIG['github_upload']:
            upload_to_github()

        # Listen bewerten, Ergebnis speichern
        bewertung = bewerte_listen()
        speichere_bewertung(bewertung)

        # Gesamtstatistik aktualisieren
        aktualisiere_gesamtstatistik()

        log("Hauptprozess erfolgreich abgeschlossen.", logging.INFO)
        log("Bereinige temporäre Dateien nach erfolgreichem Durchlauf...", logging.INFO)
        bereinige_obsolete_dateien()

    except Exception as e:
        fehler_beenden(f"Unerwarteter Fehler im Hauptprozess: {e}")
    finally:
        # E-Mail am Ende (Erfolg/Misserfolg)
        if CONFIG.get("send_email", False):
            sende_email("AdBlock Skript abgeschlossen", erstelle_email_text())

# =============================================================================
# 14. EINSTIEGSPUNKT
# =============================================================================

def lade_konfiguration(dateipfad):
    """
    Lädt und validiert die Konfiguration aus JSON (UTF-8).
    """
    try:
        with open(dateipfad, 'r', encoding='utf-8') as file:
            config = json.load(file)

        if config.get("max_parallel_jobs") < 1:
            raise ValueError("max_parallel_jobs muss >= 1 sein.")
        if config.get("batch_größe") < 1:
            raise ValueError("batch_größe muss >= 1 sein.")
        
        return config
    except json.JSONDecodeError as e:
        fehler_beenden(f"Fehler beim Laden der Konfiguration: {e}")
    except KeyError as e:
        fehler_beenden(f"Konfigurationsfehler: {e}")
    except Exception as e:
        fehler_beenden(f"Allgemeiner Fehler bei der Konfiguration: {e}")

if __name__ == "__main__":
    try:
        hauptprozess()
    except Exception as e:
        fehler_beenden(f"Unerwarteter Fehler: {str(e)}")