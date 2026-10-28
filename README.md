# Vaultwarden aziendale — pass.gatet1.it

Gestore password aziendale Gate T1 (Vaultwarden 1.37.4) su
`wsportal.gatet1.it` (185.18.240.123). Reachable solo dalle sorgenti
della address-list `TRUSTED` del router CCR-1: la lista e' riflessa in un
file `allow/deny` di nginx generato automaticamente dal DB di secmon.

## Architettura

```
browser (solo IP in TRUSTED)
    |
    v  https pass.gatet1.it:443
nginx (host)  [allow/deny da /etc/nginx/snippets/vault-trusted.conf]
    |         [/admin, /api/public -> 404]
    v  http://127.0.0.1:8081
container vaultwarden (uid 10003, porta 8080,
rete docker `vault` 10.201.200.0/24, gw 10.201.200.1)
    |
    +-> /data  -> bind mount /srv/vaultwarden/data (db sqlite, allegati...)

CCR-1 --(ssh poll ogni 120s)--> secmon --> /srv/secmon/data/secmon.db
                                              |
                                              v (ogni 2 min, vault-trusted.timer)
                                  trusted/vault_trusted.py (fail-static)
                                              |
                                              v
                          /etc/nginx/snippets/vault-trusted.conf
                                              +-> nginx -t -> systemctl reload nginx

Fase 2 (non attiva): backend wsportal --(rete docker `vault`)-->
    http://vaultwarden:8080/api/public/organization/import
```

## Layout del repository

```
compose.yaml              stack (immagine pinnata tag+digest)
.env.example              modello per /srv/vaultwarden/.env
nginx/pass.gatet1.it.conf vhost (da copiare in sites-enabled)
trusted/vault_trusted.py  generatore dello snippet allow/deny
trusted/test_vault_trusted.py
backup/vault-backup.sh    backup cifrato giornaliero su NAS
backup/vault-verify.sh    prova di ripristino di un archivio
systemd/                  unit+timer per trusted e backup
.github/workflows/ci.yml  test python + shellcheck
```

Percorsi sul server: sorgenti `/opt/vaultwarden` (clone di questo repo),
dati `/srv/vaultwarden/data`, configurazione `/srv/vaultwarden/.env`
(root:root 600), segreti in `/srv/vaultwarden/secrets/` (root, 600).

## Decisioni di sicurezza

- **Registrazioni chiuse** (`SIGNUPS_ALLOWED=false`): gli utenti entrano
  solo su invito. **`SIGNUPS_DOMAINS_WHITELIST` non va MAI impostata**:
  permetterebbe a chiunque abbia una casella sul dominio di registrarsi
  da solo anche con signups chiusi.
- **Accesso per sorgente**: il vhost include `vault-trusted.conf`
  (`allow` dalle reti TRUSTED + `deny all`): la web vault non e' esposta
  a internet anche se il DNS e' pubblico. Il firewall del router rimane
  comunque la prima barriera.
- **`/admin` e `/api/public` rispondono 404** via nginx: il pannello
  admin si raggiunge solo in tunnel SSH, l'API pubblica dell'org solo
  dalla rete docker interna `vault` (fase 2).
- **Container non-root** (uid 10003, `no-new-privileges`, `cap_drop ALL`,
  porta interna non privilegiata 8080): una compromissione del processo
  non da' privilegi nel container.
- **Fail-static della lista**: se il DB di secmon e' vecchio (>15 min),
  la lista vuota o `nginx -t` fallisce, `vault_trusted.py` non tocca il
  file esistente: un guasto a monte non apre il servizio a tutti ne'
  blocca gli amministratori. In caso contrario l'ultimo file buono resta.
- **`IP_HEADER_TRUSTED_PROXIES=10.201.200.1`**: `X-Real-IP` e' accettato
  SOLO se il peer diretto e' il gateway del bridge `vault` (l'unica via
  attraverso cui nginx -> 127.0.0.1:8081 -> docker-proxy/DNAT raggiunge
  il container). Gli altri container della stessa rete — fase 2: backend
  wsportal — NON sono fidati: se impostassero X-Real-IP, l'header
  verrebbe ignorato e verrebbe usato il loro IP reale. L'IP client
  governa rate limit e log dei login.
- **ADMIN_TOKEN hash Argon2** (mai in chiaro), sessione admin 20 minuti.
- Backup **cifrato** (gpg AES256) fuori dal server, sul NAS.

## Nota sui `$` nel file .env

Docker Compose (v2+) **interpola** i valori dei file `env_file` che non
sono tra apici singoli: `$qualcosa` verrebbe espanso come variabile
(`$$` restituirebbe un `$` letterale, ma e' fragile). Per i valori che
contengono `$` — l'hash Argon2 di `ADMIN_TOKEN` ne e' pieno — usare gli
apici singoli: il parser dotenv li toglie e il valore arriva letterale.
Nel `.env`: `ADMIN_TOKEN='$argon2id$v=19$m=...'`.

## Prerequisito: NAS

I backup vanno su una condivisione NFS dedicata del QNAP, montata in
`/mnt/nas-vaultwarden`. Configurare sul QNAP una share NFS per l'IP di
wsportal, poi una riga fstab di esempio (adattare host/percorso):

```
<IP-QNAP>:/vaultwarden  /mnt/nas-vaultwarden  nfs  defaults,_netdev,noatime  0  0
```

`vault-backup.sh` verifica con `mountpoint -q` che sia montato: se non lo
e' fallisce (meglio un servizio failed che il disco locale pieno).

## Installazione (prima volta)

Tutto come root (o `sudo`) su `wsportal`, salvo dove indicato.

1. **Utente e directory**

   ```bash
   useradd --system --uid 10003 --shell /usr/sbin/nologin vaultwarden
   mkdir -p /srv/vaultwarden/{data,secrets}
   chown -R 10003:10003 /srv/vaultwarden/data
   chmod 700 /srv/vaultwarden/secrets
   ```

   L'uid 10003 deve corrispondere a `user: "10003:10003"` in compose.yaml.

2. **Codice**

   ```bash
   git clone https://github.com/maurizioandreello/Vaultwarden.git /opt/vaultwarden
   chmod +x /opt/vaultwarden/backup/*.sh /opt/vaultwarden/trusted/vault_trusted.py
   ```

3. **`.env`** — copiare `.env.example` in `/srv/vaultwarden/.env`,
   valorizzare `ADMIN_TOKEN` e `SMTP_PASSWORD`, poi `chown root:root` +
   `chmod 600`. Generare l'hash Argon2:

   ```bash
   docker run --rm -it vaultwarden/server:1.37.4 /vaultwarden hash
   # incollare l'output nella riga ADMIN_TOKEN='$argon2id$...' del .env
   ```

4. **Primo snippet trusted** — generare `vault-trusted.conf` PRIMA di
   installare il vhost (senza il file `nginx -t` fallirebbe):

   ```bash
   /usr/bin/python3 /opt/vaultwarden/trusted/vault_trusted.py --dry-run   # verifica output
   /usr/bin/python3 /opt/vaultwarden/trusted/vault_trusted.py
   cat /etc/nginx/snippets/vault-trusted.conf   # deve contenere allow ... + deny all;
   ```

   La directory dello stato (`/var/lib/vault-trusted`, cache DNS) viene
   creata dallo script stesso / da `StateDirectory=` dell'unit.

   In produzione lo scrive il timer (passo 8) ogni 2 minuti.

5. **Certificato** — certbot webroot sullo stesso webroot usato da
   wsportal. Installare PRIMA una versione del vhost con **solo** il
   server :80 (il primo blocco `server {}` di
   `nginx/pass.gatet1.it.conf`), poi `nginx -t && systemctl reload nginx`
   e:

   ```bash
   certbot certonly --webroot -w /var/www/letsencrypt -d pass.gatet1.it
   ```

   Ottenuto il certificato in `/etc/letsencrypt/live/pass.gatet1.it/`,
   copiare il file completo (con il server :443) e di nuovo
   `nginx -t && systemctl reload nginx`. Il rinnovo passa dallo stesso
   webroot e non richiede modifiche.

6. **Stack**

   ```bash
   cd /opt/vaultwarden
   docker compose up -d
   docker compose ps        # healthy dopo ~1 min (healthcheck su /alive)
   docker compose logs -f vaultwarden
   ```

7. **Backup**: passphrase in `/srv/vaultwarden/secrets/backup_passphrase`
   (root 600, es. `openssl rand -base64 48 > .../backup_passphrase`).
   **Conservare una copia della passphrase FUORI dal server** (cassetta/
   gestore documentale): non dentro questo stesso Vaultwarden — sarebbe
   circolare (servirebbe il backup per recuperare la chiave del backup).
   Config eventuale in `/etc/default/vault-backup` (default nel file).
   Primo giro a mano:

   ```bash
   /opt/vaultwarden/backup/vault-backup.sh
   ls -l /mnt/nas-vaultwarden/vaultwarden/
   /opt/vaultwarden/backup/vault-verify.sh /mnt/nas-vaultwarden/vaultwarden/vaultwarden-*.tar.gz.gpg
   ```

8. **Timer systemd**

   ```bash
   install -m 644 /opt/vaultwarden/systemd/vault-trusted.{service,timer} \
       /opt/vaultwarden/systemd/vault-backup.{service,timer} /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now vault-trusted.timer vault-backup.timer
   systemctl list-timers vault-*
   ```

9. **Email di prova**: dal pannello admin (tunnel, vedi sotto) →
   Diagnostics → "Test SMTP", oppure invitare un utente e verificare
   l'arrivo dell'invito da `pass@gatet1.com`.

10. **Controllo IP client reale**: dopo il primo login da browser,
    nei log deve comparire l'IP pubblico del client e NON 10.201.200.1
    (il gateway): se compare il gateway, `IP_HEADER_TRUSTED_PROXIES`
    non sta funzionando e rate limit/log registrerebbero l'IP sbagliato.

    ```bash
    docker compose logs vaultwarden | grep -i "login\|failed"
    # atteso: l'IP sorgente del client reale, mai 10.201.200.1
    ```

## Organizzazione "Gate T1"

1. Registrare l'utente `maurizio.andreello@gatet1.it` (le registrazioni
   sono chiuse: si fa SOLO da admin panel → Users → "Invite", oppure da
   web vault se si abilita temporaneamente `SIGNUPS_ALLOWED`; meglio
   l'invito admin) e verificare l'email.
2. Da web vault → organizzazioni → "New organization" → nome **Gate T1**
   (solo lui puo' crearla: `ORG_CREATION_USERS`).
3. Creare le **collezioni** (es. "Infrastruttura", "Servizi clienti",
   "Amministrazione") e i **gruppi** omonimi (feature beta attivata con
   `ORG_GROUPS_ENABLED=true`, usata dall'import di fase 2).
4. **Policy da attivare** nell'organizzazione. Elenco verificato sul
   sorgente del tag 1.37.4 (`src/db/models/org_policy.rs` enum
   `OrgPolicyType` + punti di applicazione in `src/api/`):
   - *Require two-step login* — 2FA obbligatoria: all'attivazione revoca
     i membri senza 2FA e la richiede ai nuovi
     (`two_factor::enforce_2fa_policy_for_org`, `accounts.rs`);
   - *Master password* — complessita' minima (es. score >= 3, len >= 12):
     il server fonde le policy attive e le invia ai client che le
     applicano (`api/mod.rs::master_password_policy`);
   - *Single organization* — gli utenti non possono entrare/creare altre
     org e all'attivazione rimuove i membri che sono in altre
     (`organizations.rs`);
   - *Disable Send* — vieta la creazione di Send ai membri
     (`sends.rs::enforce_disable_send_policy`; coerente con
     `SENDS_ALLOWED=false` globale);
   - *Remove individual vault* ("Personal ownership") — forza il
     salvataggio solo in collezioni aziendali
     (`ciphers.rs::enforce_personal_ownership_policy`);
   - *Send options* — opzione "disable hide email" applicata
     (`sends.rs::enforce_disable_hide_email_policy`);
   - *Account recovery* ("Reset password") — reset master password da
     admin (`organizations.rs::check_reset_password_applicable`); il
     vincolo "richiede Single organization" scatta solo se si attiva la
     config `ENFORCE_SINGLE_ORG_WITH_RESET_PW_POLICY` (default false).
   - Presenti nell'enum ma **applicazione non verificata** nel codice
     (probabilmente solo lato client): *Password generator*, *Remove
     unlock with PIN*, *Restricted item types*, *URI match defaults*,
     *Organization user notification*.
   - Non presenti proprio nell'enum (marcate "not supported" nel
     sorgente, alcune "Not AGPLv3 Licensed"): Require SSO, Vault timeout,
     Disable personal vault export e altre — non cercarle in UI.

## Pannello admin via tunnel SSH

`/admin` e' 404 via nginx. Per usarlo:

```bash
ssh -L 8081:127.0.0.1:8081 wsportal
# poi nel browser: http://localhost:8081/admin  (token = ADMIN_TOKEN)
```

Limiti noti del tunnel: `DOMAIN=https://pass.gatet1.it`, quindi eventuali
link generati dal pannello (es. inviti, diagnostica) puntano al nome
pubblico https, non a localhost — ricopiarli a mano se serve. La sessione
admin dura `ADMIN_SESSION_LIFETIME` minuti. Finito il setup iniziale si
puo' svuotare `ADMIN_TOKEN` nel .env e riavviare il container per
disattivare il pannello.

## Uscita di un tecnico

1. Org "Gate T1" → Members → revocare l'utente (la revoca rimuove
   l'accesso alle collezioni condivise).
2. **Rotazione**: le password delle collezioni a cui aveva accesso vanno
   ruotate (le ha potenzialmente esportate prima dell'uscita). L'export
   organizzazione e l'event log (`ORG_EVENTS_ENABLED`) aiutano a capire
   il perimetro.
3. Se era admin di organizzazione: ruotare anche la API key
   dell'organizzazione (Admin panel → Organizations → edit → "Rotate
   API key") e verificare i log eventi per export recenti.

## Backup, ripristino, prova di ripristino

- **Backup**: timer giornaliero 02:30 → `/mnt/nas-vaultwarden/vaultwarden/
  vaultwarden-<ts>.tar.gz.gpg` (+ `.sha256`), retention 30 giorni.
  Contiene: `db.sqlite3` (copia consistente via backup API), `rsa_key*`,
  `config.json`, `attachments/`, `sends/`, `.env`.
- **Verifica periodica** (fare ogni tanto, anche mensile):
  `backup/vault-verify.sh <archivio>` — sha256, decifra, integrity_check.
- **Ripristino** (a servizio fermo): l'archivio contiene `.env` e il DB
  in chiaro — lavorare solo in un `mktemp -d` (700) e rimuoverlo alla
  fine. I dati attuali non vengono sovrascritti ma spostati da parte.

  ```bash
  docker compose -f /opt/vaultwarden/compose.yaml down

  TMP_R=$(mktemp -d)   # 700: qui finiscono DB e .env in chiaro
  gpg --batch --yes --decrypt --pinentry-mode loopback \
      --passphrase-file /srv/vaultwarden/secrets/backup_passphrase \
      -o "$TMP_R/vault.tar.gz" \
      /mnt/nas-vaultwarden/vaultwarden/<archivio>.tar.gz.gpg
  mkdir "$TMP_R/x" && tar -C "$TMP_R/x" -xzf "$TMP_R/vault.tar.gz"

  # per sicurezza: niente file journal sqlite eventualmente presenti
  rm -f "$TMP_R"/x/db.sqlite3-wal "$TMP_R"/x/db.sqlite3-shm

  # dati attuali da parte (NON sovrascrivere), data/ vuota
  mv /srv/vaultwarden/data "/srv/vaultwarden/data.prev-$(date +%Y%m%d-%H%M%S)"
  mkdir -p /srv/vaultwarden/data

  # copia tutto TRANNE .env, poi proprieta' all'uid del container
  find "$TMP_R/x" -mindepth 1 -maxdepth 1 ! -name .env \
      -exec cp -a {} /srv/vaultwarden/data/ \;
  chown -R 10003:10003 /srv/vaultwarden/data

  # .env: copiarlo in /srv/vaultwarden/.env (root:root 600) SOLO se si
  # ripristina su un server nuovo; altrimenti confrontarlo con quello
  # esistente (diff "$TMP_R/x/.env" /srv/vaultwarden/.env) e decidere.

  rm -rf "$TMP_R"
  docker compose -f /opt/vaultwarden/compose.yaml up -d
  docker compose ps        # attendere "healthy"
  ```

## Aggiornamento di versione

1. Backup: `backup/vault-backup.sh` a mano.
2. Leggere le release note del nuovo tag (var `.env` nuove/rimosse).
3. Aggiornare **insieme** tag e digest in `compose.yaml`
   (`docker buildx imagetools inspect vaultwarden/server:<tag>` per il
   digest), e i riferimenti nel .env.example/README.
4. `docker compose pull && docker compose up -d`.

## Dipendenza da secmon

`vault_trusted.py` legge la tabella `list_entries` del DB sqlite di
secmon (`/srv/secmon/data/secmon.db`, schema:
`list_name, address, first_seen, last_seen, removed_at`). Semantica
verificata su secmon (`db.aggiorna_lista` chiamata a ogni poll riuscito,
ogni 120s): `last_seen` = ultimo poll, `removed_at` = voce sparita dalla
lista. Se lo schema cambia, aggiornare la query in `leggi_lista`. Se
secmon si ferma, dopo `--max-age` (default 900s) il generatore smette di
aggiornare il file nginx (fail-static, exit 2).

## Fase 2 (non ancora implementata)

Sync utenti da wsportal: il backend chiamerà
`POST /api/public/organization/import` con la chiave API
dell'organizzazione "Gate T1" (da ruotare periodicamente, Admin →
Organizations → Rotate API key). Il backend si aggancerà alla rete docker
`vault` e raggiungerà il servizio come `http://vaultwarden:8080`, senza
passare da nginx (per questo `/api/public` e' chiuso nel vhost).
`ORG_GROUPS_ENABLED=true` e' gia' attivo per i gruppi dell'import.

## Test e CI

```bash
python -m unittest discover -s trusted -v   # test del generatore
shellcheck backup/*.sh                       # lint script (CI)
```

La CI (GitHub Actions) esegue entrambi su push/PR.
