"""SQLite persistence (WAL mode). All state changes are atomic, guarded transitions,
so a late callback can never resurrect a cancelled/expired session."""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Iterator

ACTIVE = ("starting", "waiting_for_login")
TERMINAL = ("success", "failed", "timeout", "cancelled")

# Persistent browser states (one row per account in `browsers`):
#   live       Chrome is running and signed in; the keeper sends heartbeats
#   waking     a container was started on the saved profile, not yet reported
#   sleeping   no container; the profile volume keeps the sign-in
#   crashed    heartbeats stopped; restarted by the supervisor (next_restart_at)
#              or given up (next_restart_at NULL)
#   logged_out X ended the session; the owner must log in again
B_RUNNING = ("live", "waking")      # states that hold a container (and a slot)
B_STATES = ("live", "waking", "sleeping", "crashed", "logged_out")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id                  TEXT PRIMARY KEY,
    account_id          TEXT NOT NULL,
    status              TEXT NOT NULL,
    container_name      TEXT,
    ws_token_hash       TEXT NOT NULL UNIQUE,
    ws_token_enc        TEXT,
    vnc_password_enc    TEXT,
    callback_token_hash TEXT NOT NULL,
    username            TEXT,
    expected_user_id    TEXT,
    redirect_url        TEXT,
    x_user_id           TEXT,
    last_error          TEXT,
    created_at          REAL NOT NULL,
    expires_at          REAL NOT NULL,
    ready_at            REAL,
    finished_at         REAL
);
CREATE INDEX IF NOT EXISTS ix_sessions_account_status ON sessions(account_id, status);

CREATE TABLE IF NOT EXISTS browsers (
    account_id          TEXT PRIMARY KEY,
    node                TEXT NOT NULL,
    state               TEXT NOT NULL,
    container_name      TEXT,
    run_id              TEXT UNIQUE,
    callback_token_hash TEXT,
    vnc_password_enc    TEXT,
    vnc_host            TEXT,
    vnc_port            INTEGER,
    proxy_url_enc       TEXT,
    user_agent          TEXT,
    cookies_hash        TEXT,
    view_token_hash     TEXT,
    view_expires_at     REAL,
    last_heartbeat_at   REAL,
    last_used_at        REAL,
    last_refresh_at     REAL,
    last_webhook_at     REAL,
    refresh_pending     INTEGER NOT NULL DEFAULT 0,
    restarts            INTEGER NOT NULL DEFAULT 0,
    next_restart_at     REAL,
    last_error          TEXT,
    device              TEXT,
    started_at          REAL,
    created_at          REAL NOT NULL,
    updated_at          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_browsers_node_state ON browsers(node, state);
CREATE INDEX IF NOT EXISTS ix_sessions_status ON sessions(status);

CREATE TABLE IF NOT EXISTS credentials (
    account_id     TEXT PRIMARY KEY,
    auth_token_enc TEXT NOT NULL,
    ct0_enc        TEXT NOT NULL,
    cookies_enc    TEXT NOT NULL,
    user_agent     TEXT,
    x_user_id      TEXT,
    session_id     TEXT NOT NULL,
    captured_at    REAL NOT NULL
);
"""

_SESSION_COLUMNS = {
    "status", "container_name", "ws_token_enc", "vnc_password_enc", "x_user_id",
    "last_error", "ready_at", "finished_at", "expires_at", "node", "vnc_host", "vnc_port",
}

_BROWSER_COLUMNS = {
    "node", "state", "container_name", "run_id", "callback_token_hash", "vnc_password_enc",
    "vnc_host", "vnc_port", "proxy_url_enc", "user_agent", "cookies_hash", "view_token_hash",
    "view_expires_at", "last_heartbeat_at", "last_used_at", "last_refresh_at", "last_webhook_at",
    "refresh_pending", "restarts", "next_restart_at", "last_error", "started_at", "device",
}


class Store:
    def __init__(self, path: str):
        self.path = path
        with self._conn() as c:
            c.executescript(SCHEMA)
            self._migrate(c)

    @staticmethod
    def _migrate(c: sqlite3.Connection) -> None:
        # Add columns introduced after a DB was first created. CREATE TABLE
        # IF NOT EXISTS won't touch an existing table, so bring it up to date.
        have = {r["name"] for r in c.execute("PRAGMA table_info(sessions)")}
        for col, decl in (("redirect_url", "TEXT"), ("node", "TEXT"), ("vnc_host", "TEXT"),
                          ("vnc_port", "INTEGER"), ("proxy_url_enc", "TEXT"), ("device", "TEXT")):
            if col not in have:
                c.execute(f"ALTER TABLE sessions ADD COLUMN {col} {decl}")

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=30000")
        c.execute("PRAGMA synchronous=NORMAL")
        return c

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        c = self._conn()
        try:
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.execute("COMMIT")
        except BaseException:
            c.execute("ROLLBACK")
            raise
        finally:
            c.close()

    def _one(self, sql: str, args: tuple = ()) -> dict | None:
        c = self._conn()
        try:
            row = c.execute(sql, args).fetchone()
            return dict(row) if row else None
        finally:
            c.close()

    def _all(self, sql: str, args: tuple = ()) -> list[dict]:
        c = self._conn()
        try:
            return [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()

    def ping(self) -> bool:
        return self._one("SELECT 1 AS ok") is not None

    # ---- sessions ---------------------------------------------------------
    def reserve_session(self, row: dict, max_active: int, node_slots: int | None = None) -> tuple[str, dict | None]:
        """Atomically: return ('exists', s) if the account already has an active session,
        ('full', None) if the global limit is reached, ('node_full', None) if the
        session's node has no free slot, else insert and return ('created', row)."""
        marks = ",".join("?" * len(ACTIVE))
        with self._tx() as c:
            existing = c.execute(
                f"SELECT * FROM sessions WHERE account_id=? AND status IN ({marks})",
                (row["account_id"], *ACTIVE),
            ).fetchone()
            if existing:
                return "exists", dict(existing)
            (active,) = c.execute(
                f"SELECT COUNT(*) FROM sessions WHERE status IN ({marks})", ACTIVE
            ).fetchone()
            if active >= max_active:
                return "full", None
            if node_slots is not None and self._node_usage(c, row.get("node")) >= node_slots:
                return "node_full", None
            cols = ",".join(row)
            c.execute(f"INSERT INTO sessions ({cols}) VALUES ({','.join('?' * len(row))})", tuple(row.values()))
            return "created", row

    def get_session(self, session_id: str) -> dict | None:
        return self._one("SELECT * FROM sessions WHERE id=?", (session_id,))

    def get_session_by_ws_hash(self, ws_hash: str) -> dict | None:
        return self._one("SELECT * FROM sessions WHERE ws_token_hash=?", (ws_hash,))

    def update_session(self, session_id: str, **fields: Any) -> None:
        self._check(fields)
        sets = ",".join(f"{k}=?" for k in fields)
        with self._tx() as c:
            c.execute(f"UPDATE sessions SET {sets} WHERE id=?", (*fields.values(), session_id))

    def transition(self, session_id: str, from_status: tuple[str, ...], to_status: str, **fields: Any) -> bool:
        """Move to `to_status` only if currently in `from_status`. Entering a terminal
        state also wipes the per-session secrets. Returns whether it happened."""
        self._check(fields)
        if to_status in TERMINAL:
            fields.setdefault("finished_at", time.time())
            fields.update(ws_token_enc=None, vnc_password_enc=None)
        fields["status"] = to_status
        sets = ",".join(f"{k}=?" for k in fields)
        marks = ",".join("?" * len(from_status))
        with self._tx() as c:
            cur = c.execute(
                f"UPDATE sessions SET {sets} WHERE id=? AND status IN ({marks})",
                (*fields.values(), session_id, *from_status),
            )
            return cur.rowcount == 1

    def complete_success(self, session_id: str, creds: dict) -> bool:
        """Mark the session successful and upsert credentials in ONE transaction."""
        marks = ",".join("?" * len(ACTIVE))
        now = time.time()
        with self._tx() as c:
            cur = c.execute(
                f"UPDATE sessions SET status='success', finished_at=?, x_user_id=?, last_error=NULL, "
                f"ws_token_enc=NULL, vnc_password_enc=NULL WHERE id=? AND status IN ({marks})",
                (now, creds.get("x_user_id"), session_id, *ACTIVE),
            )
            if cur.rowcount != 1:
                return False
            c.execute(
                """INSERT INTO credentials (account_id, auth_token_enc, ct0_enc, cookies_enc, user_agent,
                                            x_user_id, session_id, captured_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(account_id) DO UPDATE SET
                     auth_token_enc=excluded.auth_token_enc, ct0_enc=excluded.ct0_enc,
                     cookies_enc=excluded.cookies_enc, user_agent=excluded.user_agent,
                     x_user_id=excluded.x_user_id, session_id=excluded.session_id,
                     captured_at=excluded.captured_at""",
                (creds["account_id"], creds["auth_token_enc"], creds["ct0_enc"], creds["cookies_enc"],
                 creds.get("user_agent"), creds.get("x_user_id"), session_id, now),
            )
            return True

    def active_sessions(self) -> list[dict]:
        marks = ",".join("?" * len(ACTIVE))
        return self._all(f"SELECT * FROM sessions WHERE status IN ({marks})", ACTIVE)

    def purge_sessions(self, older_than: float) -> int:
        marks = ",".join("?" * len(TERMINAL))
        with self._tx() as c:
            return c.execute(
                f"DELETE FROM sessions WHERE status IN ({marks}) AND finished_at < ?", (*TERMINAL, older_than)
            ).rowcount

    # ---- credentials ------------------------------------------------------
    def get_credentials(self, account_id: str) -> dict | None:
        return self._one("SELECT * FROM credentials WHERE account_id=?", (account_id,))

    def delete_credentials(self, account_id: str) -> bool:
        with self._tx() as c:
            return c.execute("DELETE FROM credentials WHERE account_id=?", (account_id,)).rowcount == 1

    def update_credentials(self, account_id: str, creds: dict, source_id: str) -> None:
        """Upsert the cookie jar reported by a live browser (no session involved)."""
        with self._tx() as c:
            c.execute(
                """INSERT INTO credentials (account_id, auth_token_enc, ct0_enc, cookies_enc, user_agent,
                                            x_user_id, session_id, captured_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(account_id) DO UPDATE SET
                     auth_token_enc=excluded.auth_token_enc, ct0_enc=excluded.ct0_enc,
                     cookies_enc=excluded.cookies_enc,
                     user_agent=COALESCE(excluded.user_agent, credentials.user_agent),
                     x_user_id=COALESCE(excluded.x_user_id, credentials.x_user_id),
                     session_id=excluded.session_id, captured_at=excluded.captured_at""",
                (account_id, creds["auth_token_enc"], creds["ct0_enc"], creds["cookies_enc"],
                 creds.get("user_agent"), creds.get("x_user_id"), source_id, time.time()),
            )

    # ---- browsers ---------------------------------------------------------
    @staticmethod
    def _node_usage(c: sqlite3.Connection, node: str | None) -> int:
        """Slots in use on a node: running browsers + active login sessions."""
        bm = ",".join("?" * len(B_RUNNING))
        am = ",".join("?" * len(ACTIVE))
        (b,) = c.execute(f"SELECT COUNT(*) FROM browsers WHERE node=? AND state IN ({bm})",
                         (node, *B_RUNNING)).fetchone()
        (s,) = c.execute(f"SELECT COUNT(*) FROM sessions WHERE node=? AND status IN ({am})",
                         (node, *ACTIVE)).fetchone()
        return b + s

    def node_usage(self, node: str) -> int:
        c = self._conn()
        try:
            return self._node_usage(c, node)
        finally:
            c.close()

    def get_browser(self, account_id: str) -> dict | None:
        return self._one("SELECT * FROM browsers WHERE account_id=?", (account_id,))

    def get_browser_by_run(self, run_id: str) -> dict | None:
        return self._one("SELECT * FROM browsers WHERE run_id=?", (run_id,))

    def browsers_in(self, states: tuple[str, ...]) -> list[dict]:
        marks = ",".join("?" * len(states))
        return self._all(f"SELECT * FROM browsers WHERE state IN ({marks})", states)

    def all_browsers(self) -> list[dict]:
        return self._all("SELECT * FROM browsers")

    def upsert_browser(self, account_id: str, **fields: Any) -> None:
        """Create or overwrite the account's browser row (used when a login
        container is adopted as the account's live browser)."""
        self._check_browser(fields)
        now = time.time()
        fields["updated_at"] = now
        cols = ["account_id", "created_at", *fields]
        vals = [account_id, now, *fields.values()]
        updates = ",".join(f"{k}=excluded.{k}" for k in fields)
        with self._tx() as c:
            c.execute(
                f"INSERT INTO browsers ({','.join(cols)}) VALUES ({','.join('?' * len(cols))}) "
                f"ON CONFLICT(account_id) DO UPDATE SET {updates}",
                vals,
            )

    def browser_transition(self, account_id: str, from_states: tuple[str, ...], to_state: str,
                           run_id: str | None = None, **fields: Any) -> bool:
        """Guarded state change. With run_id, only applies if that container run
        is still the account's current one, so a late callback from a replaced
        container can't change anything."""
        self._check_browser(fields)
        fields["state"] = to_state
        fields["updated_at"] = time.time()
        sets = ",".join(f"{k}=?" for k in fields)
        marks = ",".join("?" * len(from_states))
        sql = f"UPDATE browsers SET {sets} WHERE account_id=? AND state IN ({marks})"
        args = [*fields.values(), account_id, *from_states]
        if run_id is not None:
            sql += " AND run_id=?"
            args.append(run_id)
        with self._tx() as c:
            return c.execute(sql, args).rowcount == 1

    def update_browser(self, account_id: str, run_id: str | None = None, **fields: Any) -> bool:
        self._check_browser(fields)
        fields["updated_at"] = time.time()
        sets = ",".join(f"{k}=?" for k in fields)
        sql = f"UPDATE browsers SET {sets} WHERE account_id=?"
        args = [*fields.values(), account_id]
        if run_id is not None:
            sql += " AND run_id=?"
            args.append(run_id)
        with self._tx() as c:
            return c.execute(sql, args).rowcount == 1

    def reserve_wake(self, account_id: str, from_states: tuple[str, ...], node_slots: int,
                     **fields: Any) -> str:
        """Atomically take a slot on the browser's node and move it to `waking`.
        Returns 'ok', 'node_full', or 'bad_state'."""
        self._check_browser(fields)
        with self._tx() as c:
            row = c.execute("SELECT * FROM browsers WHERE account_id=?", (account_id,)).fetchone()
            if not row or row["state"] not in from_states:
                return "bad_state"
            if self._node_usage(c, row["node"]) >= node_slots:
                return "node_full"
            fields.update(state="waking", updated_at=time.time())
            sets = ",".join(f"{k}=?" for k in fields)
            c.execute(f"UPDATE browsers SET {sets} WHERE account_id=?", (*fields.values(), account_id))
            return "ok"

    def delete_browser(self, account_id: str) -> dict | None:
        with self._tx() as c:
            row = c.execute("SELECT * FROM browsers WHERE account_id=?", (account_id,)).fetchone()
            c.execute("DELETE FROM browsers WHERE account_id=?", (account_id,))
            return dict(row) if row else None

    @staticmethod
    def _check_browser(fields: dict) -> None:
        bad = set(fields) - _BROWSER_COLUMNS
        if bad:
            raise ValueError(f"unknown browser fields: {bad}")

    @staticmethod
    def _check(fields: dict) -> None:
        bad = set(fields) - _SESSION_COLUMNS
        if bad:
            raise ValueError(f"unknown session fields: {bad}")
