# AGENTS.md

Repo del gestore password aziendale Gate T1 (Vaultwarden su
`wsportal.gatet1.it`, FQDN `pass.gatet1.it`). Solo codice: il deploy e'
manuale seguendo il README.

## Layout

- `compose.yaml`, `.env.example` — stack e modello config
  (`/srv/vaultwarden` sul server)
- `nginx/pass.gatet1.it.conf` — vhost allow-list TRUSTED
- `trusted/vault_trusted.py` + test — generatore snippet nginx da
  secmon.db (stdlib only)
- `backup/` — script bash backup/verify (gpg su NAS)
- `systemd/` — unit+timer di trusted e backup

## Guardrail

- Mai segreti nel repo (`.env` e' ignorato; solo `.env.example` con
  CHANGEME). Mai stampare committando il contenuto di un .env reale.
- Sul server solo comandi in sola lettura, salvo approvazione esplicita
  di Maurizio; mai stampare file .env/segreti.
- Nessun push diretto se non richiesto; niente push su main forzati.
- Tag e digest dell'immagine in `compose.yaml` si aggiornano SEMPRE
  insieme (README: sezione aggiornamenti).
- Testo (README, commenti, commit) in italiano, stile dei repo esistenti.

## Verifiche

```bash
python -m unittest discover -s trusted -v
shellcheck backup/*.sh
docker compose config          # serve un env_file accessibile: copia
                               # temporanea con env_file relativo
```

CI: `.github/workflows/ci.yml` (unittest + shellcheck).
