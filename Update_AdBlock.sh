#!/bin/bash -e

# Konfigurationseinstellungen
ENABLE_PARALLEL=1  # Parallelisierung aktivieren (1 für ja, 0 für nein)
TMP_DIR="/home/pi/AdBlock/tmp"  # Temporärer Ordner für individuelle Hosts-Dateien
HASH_DIR="$TMP_DIR/hash_files"  # Ordner für Hash-Dateien
COMBINED_HOSTS="$TMP_DIR/hosts_combined.txt"  # Kombinierte Hosts-Datei
FINAL_HOSTS="$TMP_DIR/final_hosts.txt"  # Endgültige Hosts-Datei
SORTED_FINAL_HOSTS="$TMP_DIR/sorted_final_hosts.txt"  # Sortierte und bereinigte Hosts-Datei
PIHOLE_DB="/etc/pihole/gravity.db"  # Pi-hole Datenbankpfad
ADBLOCK_DIR="/home/pi/AdBlock"  # Hauptverzeichnis für AdBlock

# Lese HOSTS_SOURCES aus einer externen Datei
readarray -t HOSTS_SOURCES < hosts_sources.conf

download_and_process_file() {
    URL=$1
    URL_HASH=$(echo -n "$URL" | md5sum | awk '{print $1}')
    FILE_NAME=$(basename ${URL})
    HOST_FILE="$TMP_DIR/hosts_individual/${URL_HASH}_${FILE_NAME}"
    HASH_FILE="$HASH_DIR/hash_${URL_HASH}_${FILE_NAME}"

    if [ -f "$HASH_FILE" ]; then
        OLD_HASH=$(cat $HASH_FILE)
    else
        OLD_HASH=""
    fi

    NEW_HASH=$(curl -sL $URL | md5sum | awk '{print $1}')
    if [ "$NEW_HASH" != "$OLD_HASH" ]; then
        echo "Lade Hosts von $URL herunter, da Änderungen erkannt wurden..."
        curl -sL $URL > "$HOST_FILE"
        echo $NEW_HASH > $HASH_FILE
    else
        echo "Keine Änderungen in $URL"
    fi
}

# Erstelle erforderliche Verzeichnisse
mkdir -p $TMP_DIR  # Erstellt das Hauptverzeichnis für temporäre Dateien
mkdir -p $TMP_DIR/hosts_individual  # Erstellt den Unterordner für individuelle Hosts-Dateien
mkdir -p $HASH_DIR  # Erstellt den Ordner für Hash-Dateien

# Herunterladen und Verarbeiten der Hosts-Dateien
if [ "$ENABLE_PARALLEL" -eq 1 ]; then
    for URL in "${HOSTS_SOURCES[@]}"; do
        (download_and_process_file $URL) &
    done
    wait
else
    for URL in "${HOSTS_SOURCES[@]}"; do
        download_and_process_file $URL
    done
fi

# Kombinieren aller gespeicherten Hosts-Listen in eine Datei
> "$COMBINED_HOSTS"
for FILE in $TMP_DIR/hosts_individual/*; do
    cat "$FILE" | sort | uniq >> "$COMBINED_HOSTS"
done

# Exportiere Blacklist und Whitelist aus Pi-hole
sudo sqlite3 $PIHOLE_DB "SELECT domain FROM domainlist WHERE enabled = 1 AND type = 1;" >> "$COMBINED_HOSTS"
sudo sqlite3 $PIHOLE_DB "SELECT DISTINCT domain FROM domainlist WHERE type=0;" > "$TMP_DIR/whitelist.txt"

# Bereinige und formatiere die kombinierte Hosts-Datei
grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .*\.[a-zA-Z]+$' "$COMBINED_HOSTS" | awk '{print "127.0.0.1 " $2}' > "$FINAL_HOSTS"

# Entferne Whitelist-Einträge
grep -Fvx -f "$TMP_DIR/whitelist.txt" "$FINAL_HOSTS" | sponge "$FINAL_HOSTS"

# Sortieren und Duplikate entfernen
sort "$FINAL_HOSTS" | uniq > "$SORTED_FINAL_HOSTS"

# Prüfe, ob sich die Hosts-Datei geändert hat
PREVIOUS_HASH=$(md5sum $ADBLOCK_DIR/hosts.txt | awk '{print $1}')
NEW_HASH=$(md5sum "$SORTED_FINAL_HOSTS" | awk '{print $1}')

if [ "$NEW_HASH" != "$PREVIOUS_HASH" ]; then
    echo "Die Hosts-Datei hat sich geändert. Hochladen..."

# Verschieben der neuen Datei
sudo mv -f $SORTED_FINAL_HOSTS $ADBLOCK_DIR/hosts.txt

# Upload zur Dropbox
$ADBLOCK_DIR/Dropbox-Uploader/dropbox_uploader.sh upload $ADBLOCK_DIR/hosts.txt /

# Upload zur GitHub
git add Update_AdBlock.sh hosts.txt
git commit -m "Update Hosts-Datei und Skript"
git push origin main

else
    echo "Keine Änderungen in der Hosts-Datei. Nicht hochladen."
fi

# Bereinige temporäre Dateien
rm $COMBINED_HOSTS
rm $FINAL_HOSTS
rm -r $TMP_DIR/whitelist.txt

# Update Pi-Hole und System NACH dem Erstellen der Hosts-Datei
echo "Updating Pi-Hole..."
/usr/bin/sudo pihole -up
echo "Getting update list..."
/usr/bin/sudo apt-get update --fix-missing
echo "Updating..."
/usr/bin/sudo apt-get -y upgrade

# Reboot
echo "Rebooting..."
/usr/bin/sudo systemctl reboot -i
