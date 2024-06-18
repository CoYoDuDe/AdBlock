import os
import subprocess
import time
import hashlib
import requests
import schedule
from datetime import datetime

LOG_FILE = "/home/pi/AdBlock/update.log"
EMAIL = "example@example.com"
MAX_RETRIES = 3
RETRY_DELAY = 5
ENABLE_PARALLEL = True
HOSTS_SOURCES_FILE = "/home/pi/AdBlock/hosts_sources.conf"
TMP_DIR = "/home/pi/AdBlock/tmp"
HASH_DIR = f"{TMP_DIR}/hash_files"
COMBINED_HOSTS = f"{TMP_DIR}/hosts_combined.txt"
FINAL_HOSTS = f"{TMP_DIR}/final_hosts.txt"
SORTED_FINAL_HOSTS = f"{TMP_DIR}/sorted_final_hosts.txt"
PIHOLE_DB = "/etc/pihole/gravity.db"
ADBLOCK_DIR = "/home/pi/AdBlock"
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
    dependencies = ['curl', 'sqlite3', 'git', 'sponge', 'parallel']
    for dep in dependencies:
        try:
            subprocess.run(['which', dep], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            error_exit(f"{dep} ist nicht installiert. Bitte installieren Sie {dep}.")


def download_and_process_file(url):
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

        subprocess.run(['sqlite3', PIHOLE_DB, "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 1;"], stdout=open(COMBINED_HOSTS, 'a'), check=True)
        subprocess.run(['sqlite3', PIHOLE_DB, "SELECT DISTINCT domain FROM domainlist WHERE type=0;"], stdout=open(f"{TMP_DIR}/whitelist.txt", 'w'), check=True)

        with open(FINAL_HOSTS, 'w') as final_hosts:
            subprocess.run(['grep', '-E', '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .*\.[a-zA-Z]+$', COMBINED_HOSTS], stdout=final_hosts, check=True)

        grep_result = subprocess.run(['grep', '-Fvx', '-f', f"{TMP_DIR}/whitelist.txt", FINAL_HOSTS], stdout=subprocess.PIPE, check=True)
        with open(FINAL_HOSTS, 'wb') as f:
            f.write(grep_result.stdout)

        subprocess.run(['sort', FINAL_HOSTS], stdout=open(SORTED_FINAL_HOSTS, 'w'), check=True)

        previous_hash = ""
        if os.path.exists(f"{ADBLOCK_DIR}/hosts.txt"):
            with open(f"{ADBLOCK_DIR}/hosts.txt", 'rb') as f:
                previous_hash = hashlib.md5(f.read()).hexdigest()

        with open(SORTED_FINAL_HOSTS, 'rb') as f:
            new_hash = hashlib.md5(f.read()).hexdigest()

        if new_hash != previous_hash:
            log("Die Hosts-Datei hat sich geändert. Hochladen...")
            subprocess.run(['sudo', 'mv', '-f', SORTED_FINAL_HOSTS, f"{ADBLOCK_DIR}/hosts.txt"], check=True)
            upload_to_github()
        else:
            log("Keine Änderungen in der Hosts-Datei. Nicht hochladen.")

        for file in [COMBINED_HOSTS, FINAL_HOSTS, f"{TMP_DIR}/whitelist.txt"]:
            if os.path.exists(file):
                os.remove(file)

        log("Updating Pi-Hole...")
        if check_network_connection():
            subprocess.run(['sudo', 'pihole', '-up'], check=True)
        else:
            log("Netzwerkverbindung fehlgeschlagen. Pi-hole-Update übersprungen.")
            ERRORS.append("Netzwerkverbindung fehlgeschlagen. Pi-hole-Update übersprungen.")

        log("Getting update list...")
        subprocess.run(['sudo', 'apt-get', 'update', '--fix-missing'], check=True)
        log("Updating...")
        subprocess.run(['sudo', 'apt-get', '-y', 'upgrade'], check=True)

        log("Rebooting...")
        subprocess.run(['sudo', 'systemctl', 'reboot', '-i'], check=True)

        if ERRORS:
            send_email("AdBlock-Skript Fehlerbericht", "\n".join(ERRORS))

    except Exception as e:
        error_exit(f"Ein Fehler ist aufgetreten: {str(e)}")


schedule.every().sunday.at("03:00").do(main)

if __name__ == "__main__":
    while True:
        schedule.run_pending()
        time.sleep(1)
