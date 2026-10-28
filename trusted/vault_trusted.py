#!/usr/bin/env python3
"""Genera lo snippet nginx allow/deny dalla lista TRUSTED del router CCR-1.

Legge in SOLA LETTURA il DB sqlite di secmon (/srv/secmon/data/secmon.db,
tabella list_entries) e produce /etc/nginx/snippets/vault-trusted.conf:

    allow <rete>;   una riga per voce
    deny all;

Il file e' incluso dal vhost pass.gatet1.it: l'accesso alla web vault e'
limitato alle sorgenti fidate. Gira da timer systemd ogni 2 minuti.

Fail-static: se i dati non sono freschi (secmon non aggiorna last_seen da
piu' di --max-age secondi) o l'insieme risulta vuoto, il file esistente
NON viene toccato: un guasto a monte non deve ne' aprire a tutti ne'
chiudere fuori gli amministratori per errore.

Codici di uscita:
    0  ok (file scritto, oppure gia' identico)
    1  errore generico (db illeggibile, scrittura, reload fallito...)
    2  dati non freschi (ultimo poll secmon oltre --max-age)
    3  insieme risultante vuoto (escluso --always-allow)
    4  nginx -t fallito: ripristinato il file precedente
"""
import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

DB_DEFAULT = "/srv/secmon/data/secmon.db"
OUT_DEFAULT = "/etc/nginx/snippets/vault-trusted.conf"
STATE_DEFAULT = "/var/lib/vault-trusted/state.json"

# Nome DNS valido (etichette RFC-952/1123, TLD non tutto numerico).
_DNS_RE = re.compile(
    r"^(?=.{1,253}\.?$)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
_TS_LINE = "# aggiornato:"


def warn(msg):
    print(f"vault_trusted: {msg}", file=sys.stderr)


def resolve_dns(name):
    """Risoluzioni A+AAAA di `name` -> insieme di stringhe IP."""
    return {info[4][0] for info in socket.getaddrinfo(name, None)}


def apri_db(percorso):
    """Apre il DB secmon in sola lettura (URI mode=ro)."""
    uri = "file:" + percorso.replace(os.sep, "/") + "?mode=ro"
    return sqlite3.connect(uri, uri=True)


def leggi_lista(db_path, list_name):
    """-> lista di (address, last_seen). Solleva sqlite3.Error."""
    conn = apri_db(db_path)
    try:
        return conn.execute(
            "SELECT address, last_seen FROM list_entries "
            "WHERE list_name=? AND removed_at IS NULL",
            (list_name,)).fetchall()
    finally:
        conn.close()


def carica_state(percorso):
    try:
        with open(percorso, encoding="utf-8") as f:
            state = json.load(f)
        if isinstance(state, dict) and isinstance(state.get("dns"), dict):
            return state
    except (OSError, ValueError):
        pass
    return {"dns": {}}


def salva_state(percorso, state):
    os.makedirs(os.path.dirname(os.path.abspath(percorso)), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(percorso)),
                               prefix=".state.", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.write("\n")
        os.replace(tmp, percorso)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def voce_a_reti(voce, state, state_dirty):
    """Converte una voce TRUSTED in reti.

    -> (lista di network, commento provenienza). Lista vuota se la voce e'
    invalida o irrisolvibile (con warning su stderr)."""
    voce = voce.strip()
    # IP singolo o CIDR (v4/v6): il caso piu' comune.
    try:
        return [ipaddress.ip_network(voce, strict=False)], None
    except ValueError:
        pass
    # Intervallo "ip1-ip2" -> uno o piu' CIDR.
    if "-" in voce:
        a, _, b = voce.partition("-")
        try:
            return list(ipaddress.summarize_address_range(
                ipaddress.ip_address(a.strip()),
                ipaddress.ip_address(b.strip()))), voce
        except ValueError:
            pass
    # Nome DNS (in TRUSTED ci sono es. intra.gatet1.it): risolvi A e AAAA.
    if _DNS_RE.match(voce) and not voce.replace("-", "").replace(".", "").isdigit():
        try:
            ips = resolve_dns(voce)
        except OSError as e:
            ips = set()
            motivo = str(e)
        else:
            motivo = ""
        if ips:
            cache = state["dns"]
            if sorted(cache.get(voce, [])) != sorted(ips):
                cache[voce] = sorted(ips)
                state_dirty[0] = True
            return ([ipaddress.ip_network(ip, strict=False) for ip in sorted(
                ips, key=lambda x: (ipaddress.ip_address(x).version,
                                    int(ipaddress.ip_address(x))))], voce)
        cached = state["dns"].get(voce)
        if cached:
            warn(f"DNS {voce}: risoluzione fallita ({motivo or 'nessun record'}), "
                 f"uso gli IP in cache")
            return [ipaddress.ip_network(ip, strict=False) for ip in cached], voce
        warn(f"voce saltata: DNS {voce} non risolvibile "
             f"({motivo or 'nessun record'}) e nessun IP in cache")
        return [], None
    warn(f"voce saltata: {voce!r} non e' ne' IP/CIDR ne' intervallo ne' DNS")
    return [], None


def costruisci(reti, db_path, list_name, last_seen):
    """-> testo del file nginx. `reti`: dict {net: set(commenti)}."""
    def chiave(net):
        return (net.version, int(net.network_address), net.prefixlen)

    righe = ["# generato da vault_trusted.py - non modificare a mano",
             f"# sorgente: {db_path} lista {list_name} "
             f"(ultimo poll {datetime.fromtimestamp(last_seen, tz=timezone.utc).isoformat(timespec='seconds')})",
             f"{_TS_LINE} {datetime.now(tz=timezone.utc).isoformat(timespec='seconds')}"]
    for net in sorted(reti, key=chiave):
        comm = ", ".join(sorted(c for c in reti[net] if c))
        riga = f"allow {net};"
        if comm:
            riga += f" # {comm}"
        righe.append(riga)
    righe.append("deny all;")
    return "\n".join(righe) + "\n"


def senza_timestamp(testo):
    """Contenuto senza la riga d'ora, per il confronto col file esistente."""
    return "\n".join(r for r in testo.splitlines()
                     if not r.startswith(_TS_LINE))


def reti_da_file(testo):
    return {r.split()[1] for r in testo.splitlines() if r.startswith("allow ")}


def esegui(cmd_stringa):
    argv = shlex.split(cmd_stringa)
    if not argv:
        return 1
    try:
        return subprocess.run(argv, check=False).returncode
    except OSError as e:
        warn(f"impossibile eseguire {cmd_stringa!r}: {e}")
        return 1


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Genera lo snippet nginx allow/deny dalla lista TRUSTED "
                    "del DB di secmon (fail-static).")
    p.add_argument("--db", default=DB_DEFAULT,
                   help=f"DB sqlite di secmon (default {DB_DEFAULT})")
    p.add_argument("--list", default="TRUSTED",
                   help="address-list da leggere (default TRUSTED)")
    p.add_argument("--out", default=OUT_DEFAULT,
                   help=f"file nginx da generare (default {OUT_DEFAULT})")
    p.add_argument("--state", default=STATE_DEFAULT,
                   help=f"stato/cache DNS (default {STATE_DEFAULT})")
    p.add_argument("--max-age", type=int, default=900, metavar="SEC",
                   help="eta' massima dell'ultimo poll secmon (default 900)")
    p.add_argument("--always-allow", default="127.0.0.1,::1",
                   help="IP/CIDR sempre permessi, separati da virgola "
                        "(default 127.0.0.1,::1)")
    p.add_argument("--nginx-test-cmd", default="nginx -t",
                   help="comando di validazione config (default 'nginx -t')")
    p.add_argument("--reload-cmd", default="systemctl reload nginx",
                   help="comando di reload (default 'systemctl reload nginx')")
    p.add_argument("--dry-run", action="store_true",
                   help="stampa il file su stdout senza scrivere nulla")
    args = p.parse_args(argv)

    # -- lettura DB (sola lettura) --------------------------------------
    try:
        righe = leggi_lista(args.db, args.list)
    except (sqlite3.Error, OSError) as e:
        warn(f"impossibile leggere {args.db}: {e}")
        return 1

    # -- freschezza: max(last_seen) = ultimo poll secmon riuscito --------
    if not righe:
        warn(f"lista {args.list} vuota o assente in {args.db}: "
             "file esistente non toccato")
        return 3
    newest = max(r[1] for r in righe)
    if time.time() - newest > args.max_age:
        warn(f"dati non freschi: ultimo poll "
             f"{datetime.fromtimestamp(newest, tz=timezone.utc).isoformat(timespec='seconds')} "
             f"oltre --max-age {args.max_age}s: file esistente non toccato")
        return 2

    # -- risoluzione voci -----------------------------------------------
    state = carica_state(args.state)
    dirty = [False]
    reti = {}
    for voce, _ in righe:
        nets, prov = voce_a_reti(voce, state, dirty)
        for net in nets:
            reti.setdefault(net, set())
            if prov:
                reti[net].add(prov)

    n_lista = len(reti)
    always = []
    for voce in (args.always_allow or "").split(","):
        voce = voce.strip()
        if not voce:
            continue
        try:
            net = ipaddress.ip_network(voce, strict=False)
        except ValueError:
            warn(f"--always-allow: voce ignorata {voce!r}")
            continue
        always.append(net)
        reti.setdefault(net, set()).add("always-allow")

    if n_lista == 0:
        warn(f"lista {args.list}: nessuna voce utilizzabile "
             "(escluso always-allow): file esistente non toccato")
        return 3

    # -- stato: salva le risoluzioni DNS riuscite ------------------------
    if dirty[0] and not args.dry_run:
        try:
            salva_state(args.state, state)
        except OSError as e:
            warn(f"impossibile salvare lo stato {args.state}: {e}")

    contenuto = costruisci(reti, args.db, args.list, newest)

    if args.dry_run:
        sys.stdout.write(contenuto)
        return 0

    # -- confronto col file esistente (ignorando la riga d'ora) ----------
    vecchio = None
    try:
        with open(args.out, encoding="utf-8") as f:
            vecchio = f.read()
    except FileNotFoundError:
        pass
    except OSError as e:
        warn(f"impossibile leggere {args.out}: {e}")
        return 1

    if vecchio is not None and senza_timestamp(vecchio) == senza_timestamp(contenuto):
        print("vault_trusted: invariato, nessuna scrittura")
        return 0

    # -- scrittura atomica + validazione nginx ---------------------------
    out_dir = os.path.dirname(os.path.abspath(args.out))
    try:
        if vecchio is not None:
            shutil.copy2(args.out, args.out + ".prev")
        fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".vault-trusted.",
                                   text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(contenuto)
            os.replace(tmp, args.out)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError as e:
        warn(f"scrittura di {args.out} fallita: {e}")
        return 1

    if esegui(args.nginx_test_cmd) != 0:
        warn(f"'{args.nginx_test_cmd}' fallito: ripristino il file precedente")
        try:
            if vecchio is not None:
                os.replace(args.out + ".prev", args.out)
            else:
                os.unlink(args.out)
        except OSError as e:
            warn(f"ripristino fallito: {e}")
        return 4

    if esegui(args.reload_cmd) != 0:
        warn(f"'{args.reload_cmd}' fallito: il file e' aggiornato ma nginx "
             "non e' stato ricaricato")
        return 1

    # -- report reti aggiunte/rimosse ------------------------------------
    prima = reti_da_file(vecchio) if vecchio else set()
    dopo = reti_da_file(contenuto)
    for net in sorted(dopo - prima):
        print(f"+ {net}")
    for net in sorted(prima - dopo):
        print(f"- {net}")
    if not (dopo - prima) and not (prima - dopo):
        print("vault_trusted: riscritto (solo metadati cambiati)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
