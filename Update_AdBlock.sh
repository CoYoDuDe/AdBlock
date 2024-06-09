#!/bin/bash -e

# Konfigurationseinstellungen
LOG_FILE="/home/pi/AdBlock/update.log"
EMAIL="lothar.scheer@gmail.com" # Ersetze dies durch die tatsächliche E-Mail-Adresse für Benachrichtigungen
MAX_RETRIES=3
RETRY_DELAY=5
ENABLE_PARALLEL=0  # Deaktivieren Sie die parallele Verarbeitung vorerst
HOSTS_SOURCES_FILE="/home/pi/AdBlock/hosts_sources.conf"
TMP_DIR="/home/pi/AdBlock/tmp"
HASH_DIR="$TMP_DIR/hash_files"
COMBINED_HOSTS="$TMP_DIR/hosts_combined.txt"
FINAL_HOSTS="$TMP_DIR/final_hosts.txt"
SORTED_FINAL_HOSTS="$TMP_DIR/sorted_final_hosts.txt"
PIHOLE_DB="/etc/pihole/gravity.db"
ADBLOCK_DIR="/home/pi/AdBlock"

MAIL_INSTALLED=1

log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

error_exit() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" 1>&2 | tee -a "$LOG_FILE"
    send_email "Fehler im AdBlock-Skript" "$1"
    exit 1
}

send_email() {
    SUBJECT=$1
    BODY=$2
    if [ $MAIL_INSTALLED -eq 1 ]; then
        echo "$BODY" | mail -s "$SUBJECT" "$EMAIL"
    else
        log "E-Mail-Benachrichtigung nicht gesendet, da 'mail' nicht installiert ist."
    fi
}

# Überprüfe, ob notwendige Programme installiert sind
command -v curl >/dev/null 2>&1 || error_exit "curl ist nicht installiert. Bitte installieren Sie curl."
command -v sqlite3 >/dev/null 2>&1 || error_exit "sqlite3 ist nicht installiert. Bitte installieren Sie sqlite3."
command -v git >/dev/null 2>&1 || error_exit "git ist nicht installiert. Bitte installieren Sie git."
command -v sponge >/dev/null 2>&1 || error_exit "sponge ist nicht installiert. Bitte installieren Sie moreutils."

# Überprüfe, ob 'mail' installiert ist
if ! command -v mail >/dev/null 2>&1; then
    log "'mail' ist nicht installiert. E-Mail-Benachrichtigungen werden deaktiviert."
    MAIL_INSTALLED=0
fi

# Funktion zum Herunterladen und Verarbeiten von Hosts-Dateien
download_and_process_file() {
    URL=$1
    URL_HASH=$(echo -n "$URL" | md5sum | awk '{print $1}')
    FILE_NAME=$(basename "$URL")
    HOST_FILE="$TMP_DIR/hosts_individual/${URL_HASH}_${FILE_NAME}"
    HASH_FILE="$HASH_DIR/hash_${URL_HASH}_${FILE_NAME}"

    if [ -f "$HASH_FILE" ]; then
        OLD_HASH=$(cat "$HASH_FILE")
    else
        OLD_HASH=""
    fi

    for ((i=1; i<=MAX_RETRIES; i++)); do
        CONTENT=$(curl -sL "$URL")
        NEW_HASH=$(echo -n "$CONTENT" | md5sum | awk '{print $1}')
        if [ $? -eq 0 ]; then
            break
        elif [ $i -eq $MAX_RETRIES ]; then
            error_exit "Fehler beim Herunterladen von $URL nach $MAX_RETRIES Versuchen"
        else
            log "Fehler beim Herunterladen von $URL, Versuch $i von $MAX_RETRIES, erneuter Versuch in $RETRY_DELAY Sekunden..."
            sleep $RETRY_DELAY
        fi
    done

    if [ "$NEW_HASH" != "$OLD_HASH" ]; then
        log "Änderungen erkannt in $URL. Neue Datei gespeichert: $HOST_FILE"
        echo "$CONTENT" > "$HOST_FILE" || error_exit "Fehler beim Speichern von $URL"
        echo "$NEW_HASH" > "$HASH_FILE"
    else
        log "Keine Änderungen in $URL. Datei wird nicht heruntergeladen: $URL"
    fi
}

# Funktion zum Hochladen der Datei zu GitHub
upload_to_github() {
    cd "$ADBLOCK_DIR" || error_exit "Fehler beim Wechseln in das Verzeichnis $ADBLOCK_DIR"

    # Abrufen der neuesten Änderungen von GitHub und Zurücksetzen auf die neueste Version
    git fetch origin main || error_exit "Fehler beim Abrufen der neuesten Änderungen von GitHub"
    git reset --hard origin/main || error_exit "Fehler beim Zurücksetzen auf die neueste Version"

    # Überprüfen, ob es Änderungen in der hosts.txt gibt
    if ! git diff --quiet -- hosts.txt; then
        git add hosts.txt || error_exit "Fehler beim Hinzufügen der Datei hosts.txt"
        git commit -m "Update Hosts-Datei" || error_exit "Fehler beim Commit der Änderungen"
        git push origin main || error_exit "Fehler beim Push zu GitHub"
        send_email "Erfolg: AdBlock-Skript" "Die Hosts-Datei wurde erfolgreich zu GitHub hochgeladen."
    else
        log "Keine Änderungen in der hosts.txt, daher wird nichts hochgeladen."
    fi
}

# Prüfen, ob die Datei hosts_sources.conf existiert, andernfalls erstellen Sie sie mit Beispieldaten
if [ ! -f "$HOSTS_SOURCES_FILE" ]; then
    echo "# Beispiel Hosts-Quellen für das AdBlock Skript" > "$HOSTS_SOURCES_FILE"
    echo "# Fügen Sie hier Ihre Hosts-Datei URLs hinzu" >> "$HOSTS_SOURCES_FILE"
    echo "# Jede URL sollte in einer neuen Zeile stehen" >> "$HOSTS_SOURCES_FILE"
    echo "" >> "$HOSTS_SOURCES_FILE"
    echo "https://example.com/hosts1.txt" >> "$HOSTS_SOURCES_FILE"
    echo "https://example.com/hosts2.txt" >> "$HOSTS_SOURCES_FILE"
    echo "# Fügen Sie weitere URLs nach demselben Muster hinzu" >> "$HOSTS_SOURCES_FILE"

    log "Die Datei hosts_sources.conf wurde erstellt. Fügen Sie Ihre Hosts-Datei URLs hinzu und führen Sie das Skript erneut aus."
    exit 1
fi

# Lese HOSTS_SOURCES aus der externen Datei
readarray -t HOSTS_SOURCES < "$HOSTS_SOURCES_FILE"

# Erstelle erforderliche Verzeichnisse
mkdir -p "$TMP_DIR"
mkdir -p "$TMP_DIR/hosts_individual"
mkdir -p "$HASH_DIR"

log "Starte den Download-Prozess der Hosts-Dateien..."

# Herunterladen und Verarbeiten der Hosts-Dateien
if [ "$ENABLE_PARALLEL" -eq 1 ] && command -v parallel >/dev/null 2>&1; then
    export -f download_and_process_file log error_exit
    parallel download_and_process_file ::: "${HOSTS_SOURCES[@]}"
else
    for URL in "${HOSTS_SOURCES[@]}"; do
        download_and_process_file "$URL"
    done
fi

# Kombinieren aller gespeicherten Hosts-Listen in eine Datei
> "$COMBINED_HOSTS"
for FILE in "$TMP_DIR/hosts_individual"/*; do
    log "Füge Datei hinzu: $FILE"
    cat "$FILE" | sort | uniq >> "$COMBINED_HOSTS"
done

# Exportiere Blacklist und Whitelist aus Pi-hole
sudo sqlite3 "$PIHOLE_DB" "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 1;" >> "$COMBINED_HOSTS"
sudo sqlite3 "$PIHOLE_DB" "SELECT DISTINCT domain FROM domainlist WHERE type=0;" > "$TMP_DIR/whitelist.txt"

# Bereinige und formatiere die kombinierte Hosts-Datei
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .*\.[a-zA-Z]+$' "$COMBINED_HOSTS" | awk '{print "127.0.0.1 " $2}' > "$FINAL_HOSTS"

# Entferne Whitelist-Einträge
grep -Fvx -f "$TMP_DIR/whitelist.txt" "$FINAL_HOSTS" | sponge "$FINAL_HOSTS"

# Sortieren und Duplikate entfernen
sort "$FINAL_HOSTS" | uniq > "$SORTED_FINAL_HOSTS"

# Prüfe, ob sich die Hosts-Datei geändert hat
if [ -f "$ADBLOCK_DIR/hosts.txt" ]; then
    PREVIOUS_HASH=$(md5sum "$ADBLOCK_DIR/hosts.txt" | awk '{print $1}')
else
    PREVIOUS_HASH=""
fi

NEW_HASH=$(md5sum "$SORTED_FINAL_HOSTS" | awk '{print $1}')

if [ "$NEW_HASH" != "$PREVIOUS_HASH" ]; then
    log "Die Hosts-Datei hat sich geändert. Hochladen..."

    # Verschieben der neuen Datei
    sudo mv -f "$SORTED_FINAL_HOSTS" "$ADBLOCK_DIR/hosts.txt"

    # Upload zu GitHub
    upload_to_github
else
    log "Keine Änderungen in der Hosts-Datei. Nicht hochladen."
fi

# Bereinige temporäre Dateien, aber nicht die Hash-Dateien
rm -f "$COMBINED_HOSTS" "$FINAL_HOSTS" "$TMP_DIR/whitelist.txt"

# Update Pi-Hole und System NACH dem Erstellen der Hosts-Datei
log "Updating Pi-Hole..."
/usr/bin/sudo pihole -up || error_exit "Fehler beim Aktualisieren von Pi-Hole"
log "Getting update list..."
/usr/bin/sudo apt-get update --fix-missing || error_exit "Fehler beim Abrufen der Update-Liste"
log "Updating..."
/usr/bin/sudo apt-get -y upgrade || error_exit "Fehler beim Aktualisieren des Systems"

# Reboot
log "Rebooting..."
/usr/bin/sudo systemctl reboot -i
