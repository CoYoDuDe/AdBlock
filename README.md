
# Update_AdBlock Skript

## Beschreibung
Das `Update_AdBlock.sh` Skript automatisiert die Erstellung und Aktualisierung einer Adblocker-Hosts-Datei durch Herunterladen, Kombinieren und Filtern mehrerer Hosts-Quellen. Zusätzlich integriert es Pi-hole Blacklist- und Whitelist-Einträge und führt System- und Pi-hole-Updates durch.

## Hauptfunktionen
- **Automatisches Herunterladen** von Hosts-Dateien von definierten URLs.
- **Erstellen einer kombinierten Hosts-Datei** unter Berücksichtigung von Duplikaten.
- **Integration von Pi-hole Blacklist und Whitelist** in die `hosts.txt`-Datei.
- **Automatisches Update** von Pi-hole und dem System.
- **Automatischer Upload** von Änderungen an der `hosts.txt` und dem Skript selbst auf GitHub.

## Automatischer GitHub Upload
Das Skript kann Änderungen an `hosts.txt` und am Skript selbst automatisch auf GitHub hochladen. Dies kann in den Einstellungen des Skripts angepasst oder deaktiviert werden.

### Anpassung des automatischen Uploads
Um den automatischen Upload zu deaktivieren oder anzupassen, suchen Sie im Skript nach dem Abschnitt `# Upload zur GitHub` und kommentieren Sie ihn aus oder passen Sie ihn entsprechend an.

## Sicherheitshinweise
- Stellen Sie sicher, dass keine sensiblen Informationen hochgeladen werden.
- Überprüfen Sie die Skriptinhalte sorgfältig.

## Installation und Verwendung
Beschreiben Sie hier die Schritte zur Installation und Verwendung des Skripts.
