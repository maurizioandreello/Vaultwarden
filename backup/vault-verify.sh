#!/usr/bin/env bash
# vault-verify.sh <archivio.tar.gz.gpg> — prova di ripristino.
#
# Verifica lo sha256 dell'archivio, lo decifra in una directory temporanea
# (niente scritture altrove), esegue integrity_check sul DB contenuto ed
# elenca i file dell'archivio. Da lanciare periodicamente a mano:
#   sudo /opt/vaultwarden/backup/vault-verify.sh \
#       /mnt/nas-vaultwarden/vaultwarden/vaultwarden-YYYYMMDD-HHMMSS.tar.gz.gpg
#
# Usa la stessa configurazione di vault-backup.sh (/etc/default/vault-backup).
set -euo pipefail

CONFIG=/etc/default/vault-backup
if [[ -r "$CONFIG" ]]; then
    # shellcheck source=/etc/default/vault-backup
    # shellcheck disable=SC1091
    . "$CONFIG"
fi

PASSPHRASE_FILE=${PASSPHRASE_FILE:-/srv/vaultwarden/secrets/backup_passphrase}

die() { echo "vault-verify: $*" >&2; exit 1; }

ARCHIVIO=${1:-}
[[ -n "$ARCHIVIO" ]] || die "uso: $0 <archivio.tar.gz.gpg>"
[[ -r "$ARCHIVIO" ]] || die "archivio non leggibile: $ARCHIVIO"
[[ -r "$PASSPHRASE_FILE" ]] || die "passphrase non leggibile: $PASSPHRASE_FILE"
[[ -f "$ARCHIVIO.sha256" ]] || die "manca il checksum: $ARCHIVIO.sha256"

echo "== verifica sha256 =="
( cd "$(dirname "$ARCHIVIO")" && \
    sha256sum --check "$(basename "$ARCHIVIO").sha256" )

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# gpg vuole un homedir scrivibile anche solo per decifrare.
GNUPGHOME="$TMP_DIR/gnupg"
install -d -m 700 "$GNUPGHOME"
export GNUPGHOME

echo "== decifra =="
gpg --batch --yes --decrypt --pinentry-mode loopback \
    --passphrase-file "$PASSPHRASE_FILE" \
    --output "$TMP_DIR/backup.tar.gz" "$ARCHIVIO"
[[ -s "$TMP_DIR/backup.tar.gz" ]] || die "decifra fallita o archivio vuoto"

echo "== contenuto dell'archivio =="
tar -tzf "$TMP_DIR/backup.tar.gz"

mkdir "$TMP_DIR/x"
tar -C "$TMP_DIR/x" -xzf "$TMP_DIR/backup.tar.gz"

[[ -f "$TMP_DIR/x/db.sqlite3" ]] || die "db.sqlite3 assente nell'archivio"

echo "== integrity_check su db.sqlite3 =="
python3 - "$TMP_DIR/x/db.sqlite3" <<'PYEOF'
import sqlite3
import sys

conn = sqlite3.connect(sys.argv[1])
risultato = conn.execute("PRAGMA integrity_check").fetchone()[0]
conn.close()
print(f"integrity_check: {risultato}")
sys.exit(0 if risultato == "ok" else 1)
PYEOF

echo "== verifica completata =="
