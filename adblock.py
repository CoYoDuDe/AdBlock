#!/usr/bin/env python3
import os
import subprocess
import time
import hashlib
import requests
import schedule
from datetime import datetime
import re

LOG_FILE = "/root/AdBlock/update.log"
EMAIL = "example@example.com"
MAX_RETRIES = 3
RETRY_DELAY = 5
ENABLE_PARALLEL = True
HOSTS_SOURCES_FILE = "/root/AdBlock/hosts_sources.conf"
WHITELIST_FILE = "/root/AdBlock/whitelist.txt"
BLACKLIST_FILE = "/root/AdBlock/blacklist.txt"
TMP_DIR = "/root/AdBlock/tmp"
HASH_DIR = f"{TMP_DIR}/hash_files"
COMBINED_HOSTS = f"{TMP_DIR}/hosts_combined.txt"
FINAL_HOSTS = f"{TMP_DIR}/final_hosts.txt"
DNS_CONFIG = "/etc/dnsmasq.d/adblock.conf"
ADBLOCK_DIR = "/root/AdBlock"
WEB_SERVER_IPV4 = "217.160.24.118"  # Die tatsächliche IPv4-Adresse Ihres VPS
WEB_SERVER_IPV6 = "2a01:239:27b:a700::1"  # Die tatsächliche IPv6-Adresse Ihres VPS
WEB_SERVER_URL = "tue-hauptclan.eu/adblock"  # URL des Webservers mit Unterordner
MAIL_INSTALLED = True
ERRORS = []  # Liste zum Speichern von Fehlern

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f"{timestamp} - {message}\n")
    print(f"{timestamp} - {message}")

def error_exit(message):
    log(message)
    ERRORS.append(message)
    if MAIL_INSTALLED:
        send_email("Fehler im AdBlock-Skript", "\n".join(ERRORS))
    exit(1)

def send_email(subject, body):
    try:
        message = f"Subject: {subject}\n\n{body}"
        subprocess.run(['mail', '-s', subject, EMAIL], input=message.encode(), check=True)
    except FileNotFoundError:
        global MAIL_INSTALLED
        MAIL_INSTALLED = False
        log("E-Mail-Benachrichtigung nicht gesendet, da 'mail' nicht installiert ist.")

def check_dependencies():
    dependencies = ['curl', 'git', 'parallel']
    for dep in dependencies:
        try:
            subprocess.run(['which', dep], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            error_exit(f"{dep} ist nicht installiert. Bitte installieren Sie {dep}.")

def download_and_process_file(url):
    log(f"Starting download for {url}")
    url_hash = hashlib.md5(url.encode()).hexdigest()
    file_name = os.path.basename(url)
    host_file = f"{TMP_DIR}/hosts_individual/{url_hash}_{file_name}"
    hash_file = f"{HASH_DIR}/hash_{url_hash}_{file_name}"

    old_hash = ""
    if os.path.exists(hash_file):
        with open(hash_file, 'r') as f:
            old_hash = f.read().strip()

    success = False
    for i in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url)
            response.raise_for_status()
            content = response.text
            new_hash = hashlib.md5(content.encode()).hexdigest()
            success = True
            break
        except requests.RequestException:
            log(f"Fehler beim Herunterladen von {url}, Versuch {i} von {MAX_RETRIES}, erneuter Versuch in {RETRY_DELAY} Sekunden...")
            time.sleep(RETRY_DELAY)

    if not success:
        error_message = f"Fehler beim Herunterladen von {url} nach {MAX_RETRIES} Versuchen"
        log(error_message)
        ERRORS.append(error_message)
        return

    if new_hash != old_hash:
        log(f"Änderungen erkannt in {url}. Neue Datei gespeichert: {host_file}")
        with open(host_file, 'w') as f:
            f.write(content)
        with open(hash_file, 'w') as f:
            f.write(new_hash)
    else:
        log(f"Keine Änderungen in {url}. Datei wird nicht heruntergeladen: {url}")

def is_valid_domain(domain):
    # Gültige Domain-Namen überprüfen
    regex = re.compile(
        r'^(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE
    )
    parts = domain.split(".")
    return all(regex.match(part) for part in parts)

def apply_whitelist_blacklist():
    with open(WHITELIST_FILE, 'r') as f:
        whitelist = set(line.strip() for line in f if line.strip() and not line.startswith('#'))

    with open(BLACKLIST_FILE, 'r') as f:
        blacklist = set(line.strip() for line in f if line.strip() and not line.startswith('#'))

    valid_domains = set()
    with open(COMBINED_HOSTS, 'r') as infile, open(FINAL_HOSTS, 'w') as outfile:
        seen = set()
        for line in infile:
            parts = line.split()
            if len(parts) >= 2 and is_valid_domain(parts[1].strip()):
                domain = parts[1].lower()
                if domain not in seen and domain not in whitelist:
                    seen.add(domain)
                    valid_domains.add(domain)

    valid_domains.update(blacklist)
    sorted_domains = sorted(valid_domains)

    with open(FINAL_HOSTS, 'w') as outfile:
        for domain in sorted_domains:
            outfile.write(f"0.0.0.0 {domain}\n")

    # Hosts-Datei für die DNS-Umleitung erstellen
    with open(f"{ADBLOCK_DIR}/hosts.txt", 'w') as hosts_file:
        for domain in sorted_domains:
            hosts_file.write(f"0.0.0.0 {domain}\n")

def generate_dns_config():
    log("Generating DNS config")
    valid_domains = []
    with open(f"{ADBLOCK_DIR}/hosts.txt", 'r') as hosts_file:
        for line in hosts_file:
            parts = line.split()
            if len(parts) == 2 and is_valid_domain(parts[1]):
                valid_domains.append(parts[1])
    
    with open(DNS_CONFIG, 'w') as dns_config:
        for domain in valid_domains:
            dns_config.write(f"address=/{domain}/{WEB_SERVER_IPV4}\n")  # Umleitung zum Webserver (IPv4)
            dns_config.write(f"address=/{domain}/{WEB_SERVER_IPV6}\n")  # Umleitung zum Webserver (IPv6)
    log(f"Generated DNS config: {DNS_CONFIG}")

def upload_to_github():
    try:
        os.chdir(ADBLOCK_DIR)
        subprocess.run(['git', 'stash', 'push', '-m', "Stash all changes"], check=True)
        subprocess.run(['git', 'checkout', 'stash@{0}', '--', 'hosts.txt'], check=True)
        if subprocess.call(['git', 'diff', '--quiet', 'hosts.txt']) != 0:
            subprocess.run(['git', 'add', 'hosts.txt'], check=True)
            subprocess.run(['git', 'commit', '-m', "Update Hosts-Datei"], check=True)
            subprocess.run(['git', 'push', 'origin', 'main'], check=True)
            send_email("Erfolg: AdBlock-Skript", "Die Hosts-Datei wurde erfolgreich zu GitHub hochgeladen.")
        subprocess.run(['git', 'stash', 'drop'], check=True)
    except subprocess.CalledProcessError as e:
        error_exit(f"Fehler beim Hochladen zu GitHub: {str(e)}")

def check_network_connection():
    try:
        requests.get("https://github.com", timeout=10)
        return True
    except requests.RequestException:
        return False

def main():
    try:
        log("Starting main process")
        check_dependencies()

        if not os.path.exists(HOSTS_SOURCES_FILE):
            with open(HOSTS_SOURCES_FILE, 'w') as f:
                f.write("# Beispiel Hosts-Quellen für das AdBlock Skript\n")
                f.write("# Fügen Sie hier Ihre Hosts-Datei URLs hinzu\n")
                f.write("# Jede URL sollte in einer neuen Zeile stehen\n\n")
                f.write("https://example.com/hosts1.txt\n")
                f.write("https://example.com/hosts2.txt\n")
                f.write("# Fügen Sie weitere URLs nach demselben Muster hinzu\n")
            log("Die Datei hosts_sources.conf wurde erstellt. Fügen Sie Ihre Hosts-Datei URLs hinzu und führen Sie das Skript erneut aus.")
            return

        with open(HOSTS_SOURCES_FILE, 'r') as f:
            hosts_sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        os.makedirs(TMP_DIR, exist_ok=True)
        os.makedirs(f"{TMP_DIR}/hosts_individual", exist_ok=True)
        os.makedirs(HASH_DIR, exist_ok=True)

        log("Starte den Download-Prozess der Hosts-Dateien...")

        if ENABLE_PARALLEL:
            from multiprocessing import Pool
            with Pool() as pool:
                pool.map(download_and_process_file, hosts_sources)
        else:
            for url in hosts_sources:
                download_and_process_file(url)

        with open(COMBINED_HOSTS, 'w') as combined_hosts:
            for file in os.listdir(f"{TMP_DIR}/hosts_individual"):
                file_path = os.path.join(f"{TMP_DIR}/hosts_individual", file)
                with open(file_path, 'r') as f:
                    combined_hosts.write(f.read())

        apply_whitelist_blacklist()
        generate_dns_config()

        subprocess.run(['systemctl', 'restart', 'dnsmasq'], check=True)
        upload_to_github()

    except Exception as e:
        error_exit(f"Ein Fehler ist aufgetreten: {str(e)}")

if __name__ == "__main__":
    main()
