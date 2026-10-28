"""Test di vault_trusted.py — sqlite temporaneo, DNS e comandi simulati."""
import contextlib
import io
import json
import os
import shlex
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import vault_trusted

SCHEMA = """CREATE TABLE list_entries(
    list_name TEXT NOT NULL, address TEXT NOT NULL,
    first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    removed_at REAL, PRIMARY KEY(list_name, address));"""


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        d = Path(self._tmp.name)
        self.db = d / "secmon.db"
        self.out = d / "vault-trusted.conf"
        self.state = d / "state.json"
        self.cmdlog = d / "cmd.log"
        # Comando stub: appende il tag al log ed esce col codice dato.
        self.stub = d / "stubcmd.py"
        self.stub.write_text(
            "import sys, pathlib\n"
            "pathlib.Path(sys.argv[1]).open('a').write(sys.argv[2] + '\\n')\n"
            "sys.exit(int(sys.argv[3]))\n", encoding="utf-8")

    def make_db(self, entries, last_seen=None, list_name="TRUSTED"):
        ts = time.time() if last_seen is None else last_seen
        conn = sqlite3.connect(self.db)
        conn.execute(SCHEMA)
        for i, addr in enumerate(entries):
            conn.execute("INSERT INTO list_entries VALUES(?,?,?,?,NULL)",
                         (list_name, addr, ts - 100, ts))
        conn.commit()
        conn.close()

    def args(self, test_rc=0, reload_rc=0, extra=None):
        def cmd(tag, rc):
            return " ".join(shlex.quote(x) for x in (
                sys.executable, str(self.stub), str(self.cmdlog), tag, str(rc)))
        return ["--db", str(self.db), "--out", str(self.out),
                "--state", str(self.state),
                "--nginx-test-cmd", cmd("test", test_rc),
                "--reload-cmd", cmd("reload", reload_rc)] + (extra or [])

    def leggi_out(self):
        return self.out.read_text(encoding="utf-8")

    def reload_count(self):
        if not self.cmdlog.exists():
            return 0
        return sum(1 for r in self.cmdlog.read_text().splitlines()
                   if r == "reload")


class TestNormale(Base):
    def test_caso_normale(self):
        self.make_db(["185.18.240.0/22", "77.239.128.13", "2a00:1450::/64"])
        rc = vault_trusted.main(self.args())
        self.assertEqual(rc, 0)
        testo = self.leggi_out()
        self.assertIn("allow 185.18.240.0/22;", testo)
        self.assertIn("allow 77.239.128.13/32;", testo)
        self.assertIn("allow 2a00:1450::/64;", testo)
        self.assertIn("allow 127.0.0.1/32;", testo)
        self.assertIn("allow ::1/128;", testo)
        self.assertTrue(testo.rstrip().endswith("deny all;"))
        self.assertIn("non modificare a mano", testo)
        self.assertEqual(self.cmdlog.read_text().splitlines(),
                         ["test", "reload"])

    def test_intervallo(self):
        self.make_db(["192.168.5.10-192.168.5.11"])
        rc = vault_trusted.main(self.args())
        self.assertEqual(rc, 0)
        testo = self.leggi_out()
        self.assertIn("allow 192.168.5.10/31; # 192.168.5.10-192.168.5.11",
                      testo)

    def test_voci_non_valide_saltate(self):
        self.make_db(["!!nonvalida..", "999.999.999.999", "10.9.8.7"])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = vault_trusted.main(self.args())
        self.assertEqual(rc, 0)
        testo = self.leggi_out()
        self.assertIn("allow 10.9.8.7/32;", testo)
        self.assertNotIn("999.999", testo)
        self.assertIn("saltata", err.getvalue())

    def test_dns_risolto(self):
        self.make_db(["intra.gatet1.it", "10.0.0.1"])
        with mock.patch.object(vault_trusted, "resolve_dns",
                               return_value={"93.62.100.5", "2a00:1450::5"}):
            rc = vault_trusted.main(self.args())
        self.assertEqual(rc, 0)
        testo = self.leggi_out()
        self.assertIn("allow 93.62.100.5/32; # intra.gatet1.it", testo)
        self.assertIn("allow 2a00:1450::5/128; # intra.gatet1.it", testo)
        state = json.loads(self.state.read_text())
        self.assertEqual(state["dns"]["intra.gatet1.it"],
                         ["2a00:1450::5", "93.62.100.5"])

    def test_dns_fallback_cache(self):
        self.state.write_text(json.dumps(
            {"dns": {"mauri.gatet1.it": ["93.62.100.9"]}}))
        self.make_db(["mauri.gatet1.it"])
        with mock.patch.object(vault_trusted, "resolve_dns",
                               side_effect=OSError("DNS giu'")):
            rc = vault_trusted.main(self.args())
        self.assertEqual(rc, 0)
        self.assertIn("allow 93.62.100.9/32; # mauri.gatet1.it",
                      self.leggi_out())

    def test_dns_fallito_senza_cache(self):
        self.make_db(["irrisolvibile.gatet1.it"])
        with mock.patch.object(vault_trusted, "resolve_dns",
                               side_effect=OSError("NXDOMAIN")):
            rc = vault_trusted.main(self.args())
        self.assertEqual(rc, 3)
        self.assertFalse(self.out.exists())


class TestFailStatic(Base):
    def test_dati_vecchi_exit2(self):
        self.make_db(["10.0.0.1"], last_seen=time.time() - 2000)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = vault_trusted.main(self.args(extra=["--max-age", "900"]))
        self.assertEqual(rc, 2)
        self.assertFalse(self.out.exists())
        self.assertIn("non freschi", err.getvalue())

    def test_lista_vuota_exit3(self):
        self.make_db([])
        rc = vault_trusted.main(self.args())
        self.assertEqual(rc, 3)
        self.assertFalse(self.out.exists())

    def test_voci_rimosse_ignorate(self):
        # Voce con removed_at: non deve comparire anche se last_seen fresco.
        self.make_db(["10.0.0.1"])
        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE list_entries SET removed_at=? WHERE address=?",
                     (time.time(), "10.0.0.1"))
        conn.commit()
        conn.close()
        rc = vault_trusted.main(self.args())
        self.assertEqual(rc, 3)


class TestScrittura(Base):
    def test_contenuto_identico_niente_reload(self):
        self.make_db(["10.0.0.1"])
        self.assertEqual(vault_trusted.main(self.args()), 0)
        self.assertEqual(self.reload_count(), 1)
        # Seconda esecuzione: stesso insieme -> nessuna scrittura/reload.
        self.assertEqual(vault_trusted.main(self.args()), 0)
        self.assertEqual(self.reload_count(), 1)

    def test_nginx_fail_rollback(self):
        self.make_db(["10.0.0.1"])
        self.assertEqual(vault_trusted.main(self.args()), 0)
        v1 = self.leggi_out()
        # Nuova voce + nginx -t che fallisce -> file ripristinato.
        conn = sqlite3.connect(self.db)
        conn.execute(
            "INSERT INTO list_entries VALUES('TRUSTED',?,?,?,NULL)",
            ("10.0.0.2", time.time() - 10, time.time()))
        conn.commit()
        conn.close()
        rc = vault_trusted.main(self.args(test_rc=1))
        self.assertEqual(rc, 4)
        self.assertEqual(self.leggi_out(), v1)

    def test_dry_run_non_scrive(self):
        self.make_db(["10.0.0.1"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = vault_trusted.main(self.args(extra=["--dry-run"]))
        self.assertEqual(rc, 0)
        self.assertIn("deny all;", out.getvalue())
        self.assertFalse(self.out.exists())
        self.assertFalse(self.cmdlog.exists())

    def test_aggiunta_voce_reload(self):
        self.make_db(["10.0.0.1"])
        self.assertEqual(vault_trusted.main(self.args()), 0)
        conn = sqlite3.connect(self.db)
        conn.execute(
            "INSERT INTO list_entries VALUES('TRUSTED',?,?,?,NULL)",
            ("10.0.0.2", time.time() - 10, time.time()))
        conn.commit()
        conn.close()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(vault_trusted.main(self.args()), 0)
        self.assertIn("+ 10.0.0.2/32", out.getvalue())
        self.assertEqual(self.reload_count(), 2)


if __name__ == "__main__":
    unittest.main()
