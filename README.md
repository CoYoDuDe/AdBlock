
# Update_AdBlock Skript

## Beschreibung
Das `Update_AdBlock.sh` Skript automatisiert die Erstellung und Aktualisierung einer Adblocker-Hosts-Datei durch Herunterladen, Kombinieren und Filtern mehrerer Hosts-Quellen. Zus�tzlich integriert es Pi-hole Blacklist- und Whitelist-Eintr�ge und f�hrt System- und Pi-hole-Updates durch.

## Hauptfunktionen
- **Automatisches Herunterladen** von Hosts-Dateien von definierten URLs.
- **Erstellen einer kombinierten Hosts-Datei** unter Ber�cksichtigung von Duplikaten.
- **Integration von Pi-hole Blacklist und Whitelist** in die `hosts.txt`-Datei.
- **Automatisches Update** von Pi-hole und dem System.
- **Automatischer Upload** von �nderungen an der `hosts.txt` auf GitHub.

## Automatischer GitHub Upload
Das Skript kann �nderungen an `hosts.txt` und am Skript selbst automatisch auf GitHub hochladen. Dies kann in den Einstellungen des Skripts angepasst oder deaktiviert werden.

### Anpassung des automatischen Uploads
Um den automatischen Upload zu deaktivieren oder anzupassen, suchen Sie im Skript nach dem Abschnitt `# Upload zur GitHub` und kommentieren Sie ihn aus oder passen Sie ihn entsprechend an.

## Sicherheitshinweise
- Stellen Sie sicher, dass keine sensiblen Informationen hochgeladen werden.
- �berpr�fen Sie die Skriptinhalte sorgf�ltig.

## Installation und Verwendung
# Bash-Skript ausf�hrbar machen:
chmod chmod +x Update_AdBlock.sh

# Bash-Skript ausf�hren:
./Update_AdBlock.sh

## Geplante Funktionen
- [ ] Integration von Adblocking mit dnsmasq
- [ ] Verbesserung der Parallelisierungslogik
- [ ] Hinzuf�gen von automatisierten Tests

