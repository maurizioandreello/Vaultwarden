#!/usr/bin/env bash
# vault-backup.sh — backup cifrato di Vaultwarden su NAS.
#
# Crea una copia consistente del DB sqlite (backup API di python3, NON un
# semplice cp: il file e' aperto dal container), ci aggiunge chiavi RSA,
# config.json, attachments/, sends/ e il .env, impacchetta in tar.gz e
# cifra con gpg simmetrico AES256 verso $DEST sul NAS.
# Eseguito da systemd vault-backup.timer (giornaliero 02:30).
#
# Configurazione in /etc/default/vault-backup (sourced, override dei
# default qui sotto):
#   DATA_DIR         dati vaultwarden        /srv/vaultwarden/data
#   ENV_FILE         configurazione          /srv/vaultwarden/.env
#   NAS_MOUNT        mountpoint del NAS      /mnt/nas-vaultwarden
#   DEST             dir destinazione        $NAS_MOUNT/vaultwarden
#   PASSPHRASE_FILE  file con la passphrase  /srv/vaultwarden/secrets/backup_passphrase
#   RETENTION_DAYS   giorni di retention     30
set -euo pipefail

CONFIG=/etc/default/vault-backup
if [[ -r "$CONFIG" ]]; then
    # shellcheck source=/etc/default/vault-backup
    # shellcheck disable=SC1091
    . "$CONFIG"
fi

DATA_DIR=${DATA_DIR:-/srv/vaultwarden/data}
ENV_FILE=${ENV_FILE:-/srv/vaultwarden/.env}
NAS_MOUNT=${NAS_MOUNT:-/mnt/nas-vaultwarden}
DEST=${DEST:-$NAS_MOUNT/vaultwarden}
PASSPHRASE_FILE=${PASSPHRASE_FILE:-/srv/vaultwarden/secrets/backup_passphrase}
RETENTION_DAYS=${RETENTION_DAYS:-30}

die() { echo "vault-backup: $*" >&2; exit 1; }

# Se il NAS non e' montato si rischia di riempire il disco locale in
# silenzio: meglio fallire rumorosi (systemd marca il servizio failed).
mountpoint -q "$NAS_MOUNT" || die "$NAS_MOUNT non e' un mountpoint: NAS non montato"
[[ -r "$PASSPHRASE_FILE" ]] || die "passphrase non leggibile: $PASSPHRASE_FILE"
[[ -f "$DATA_DIR/db.sqlite3" ]] || die "DB non trovato: $DATA_DIR/db.sqlite3"
[[ -r "$ENV_FILE" ]] || die ".env non leggibile: $ENV_FILE"

mkdir -p "$DEST"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
STAGE="$TMP_DIR/stage"
mkdir -p "$STAGE"

# Copia consistente del DB con la backup API sqlite (stdlib python3:
# gestisce i lock del DB aperto dal container in WAL). integrity_check
# sulla copia, cosi' un backup corrotto fallisce subito.
python3 - "$DATA_DIR/db.sqlite3" "$STAGE/db.sqlite3" <<'PYEOF'
import sqlite3
import sys

src_path, dst_path = sys.argv[1], sys.argv[2]
src = sqlite3.connect(src_path)
src.execute("PRAGMA query_only=ON")
dst = sqlite3.connect(dst_path)
try:
    src.backup(dst)
finally:
    src.close()
risultato = dst.execute("PRAGMA integrity_check").fetchone()[0]
dst.close()
if risultato != "ok":
    sys.exit(f"integrity_check sulla copia fallito: {risultato}")
print(f"integrity_check: {risultato}")
PYEOF

# Chiavi RSA (necessarie a ripristinare le sessioni/token), config admin,
# allegati e send se esistono.
for f in "$DATA_DIR"/rsa_key*; do
    [[ -e "$f" ]] && cp -a "$f" "$STAGE/"
done
[[ -f "$DATA_DIR/config.json" ]] && cp -a "$DATA_DIR/config.json" "$STAGE/"
[[ -d "$DATA_DIR/attachments" ]] && cp -a "$DATA_DIR/attachments" "$STAGE/"
[[ -d "$DATA_DIR/sends" ]] && cp -a "$DATA_DIR/sends" "$STAGE/"
# Il .env contiene segreti in chiaro: va nel backup (cifrato) per un
# ripristino completo. L'archivio gpg protegge tutto il contenuto.
cp -a "$ENV_FILE" "$STAGE/.env"

STAMP=$(date +%Y%m%d-%H%M%S)
NAME="vaultwarden-$STAMP"
tar -C "$STAGE" -czf "$TMP_DIR/$NAME.tar.gz" .

gpg --batch --yes --symmetric --cipher-algo AES256 \
    --passphrase-file "$PASSPHRASE_FILE" \
    --output "$DEST/$NAME.tar.gz.gpg" "$TMP_DIR/$NAME.tar.gz"
chmod 600 "$DEST/$NAME.tar.gz.gpg"

sha256sum "$DEST/$NAME.tar.gz.gpg" > "$DEST/$NAME.tar.gz.gpg.sha256"
chmod 600 "$DEST/$NAME.tar.gz.gpg.sha256"

# Retention: elimina solo gli archivi vaultwarden (e i loro .sha256)
# piu' vecchi di RETENTION_DAYS.
find "$DEST" -maxdepth 1 -type f \
    -name 'vaultwarden-*.tar.gz.gpg*' -mtime "+$RETENTION_DAYS" -delete

echo "vault-backup: $DEST/$NAME.tar.gz.gpg"
