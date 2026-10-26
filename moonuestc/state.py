"""One shared execution lock; durable per-account/day POST claims."""
import contextlib
import os
import json
import sqlite3
import hashlib
import secrets
import time
import math
from pathlib import Path

from .errors import ToolError
from .diagnostics import submission_details
from .school_policy import SCHOOL_CLIENT_CODES, SCHOOL_CLIENT_REASON, requires_school_client

class InteractiveAuthCooldown(ToolError):
    def __init__(self,retry_after):
        super().__init__('interactive_auth_cooldown','local_auth_guard')
        self.retry_after=max(1,int(retry_after))


@contextlib.contextmanager
def execution_lock(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    handle = (directory / "execution.lock").open("a+b")
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(handle.fileno()).st_size == 0:
                handle.write(b"1")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
            except OSError:
                raise ToolError("another_run_active", "lock") from None
        else:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError:
                raise ToolError("another_run_active", "lock") from None
        yield
    finally:
        if acquired:
            handle.seek(0)
            if os.name == "nt":
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


class State:
    def __init__(self, directory):
        Path(directory).mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(Path(directory) / "state.sqlite3"), timeout=5)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS claims (
                account TEXT, day TEXT, outcome TEXT NOT NULL,
                PRIMARY KEY (account, day));
            CREATE TABLE IF NOT EXISTS submission_diagnostics (
                account TEXT, day TEXT, details TEXT NOT NULL,
                PRIMARY KEY (account, day));
            CREATE TABLE IF NOT EXISTS logins (
                account TEXT, day TEXT, count INTEGER NOT NULL,
                PRIMARY KEY (account, day));
            CREATE TABLE IF NOT EXISTS verified_login_counts (
                account TEXT,day TEXT,count INTEGER NOT NULL,
                PRIMARY KEY (account,day));
            CREATE TABLE IF NOT EXISTS readiness (account TEXT PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS auth_recovery (
                account TEXT PRIMARY KEY,reason TEXT NOT NULL,required_at REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS daily (
                account TEXT, day TEXT, result TEXT NOT NULL,
                PRIMARY KEY (account, day));
            CREATE TABLE IF NOT EXISTS interactive_auth_flows (
                token_hash TEXT PRIMARY KEY,account TEXT NOT NULL,started_at REAL NOT NULL,
                completed INTEGER NOT NULL DEFAULT 0);
            CREATE INDEX IF NOT EXISTS interactive_auth_account_time ON interactive_auth_flows(account,started_at);
            CREATE TABLE IF NOT EXISTS school_requirements (
                operation TEXT PRIMARY KEY,reason TEXT NOT NULL,api_code INTEGER NOT NULL,detected_at REAL NOT NULL);
        """)
        # Older runners kept explicit school rejections as unknown claims. Recover
        # the service requirement without rewriting claims or historical jobs.
        if not self.school_client_requirement():
            for row in self.db.execute('SELECT details FROM submission_diagnostics ORDER BY rowid DESC'):
                details=json.loads(row[0])
                if requires_school_client(details):
                    self.require_school_client(details['apiCode'])
                    break

    def school_client_requirement(self):
        row=self.db.execute("SELECT reason FROM school_requirements WHERE operation='checkin'").fetchone()
        return row[0] if row else None

    def require_school_client(self,api_code):
        if type(api_code) is not int or api_code not in SCHOOL_CLIENT_CODES:return False
        with self.db:
            self.db.execute('INSERT INTO school_requirements VALUES(?,?,?,?) ON CONFLICT(operation) DO NOTHING',
                            ('checkin',SCHOOL_CLIENT_REASON,api_code,time.time()))
        return True

    def begin_interactive_login(self,account):
        """One owner-operated flow per permit, including its final identity check.

        This rolling local guard is deliberately separate from the historical
        unattended consecutive-unconfirmed password retry guard. Raw daily
        totals remain in logins for audit.
        """
        stamp=time.time();token=secrets.token_urlsafe(32)
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('DELETE FROM interactive_auth_flows WHERE started_at<=?',(stamp-86400,))
            rows=self.db.execute('SELECT started_at FROM interactive_auth_flows WHERE account=? AND started_at>? ORDER BY started_at',(account,stamp-300)).fetchall()
            if len(rows)>=10:raise InteractiveAuthCooldown(math.ceil(rows[0][0]+300-stamp))
            self.db.execute('INSERT INTO interactive_auth_flows VALUES(?,?,?,0)',(hashlib.sha256(token.encode()).hexdigest(),account,stamp))
        return token

    def complete_interactive_login(self,token,account):
        """A private permit can authorize the final check only once, for its ID."""
        with self.db:
            changed=self.db.execute('UPDATE interactive_auth_flows SET completed=1 WHERE token_hash=? AND account=? AND completed=0 AND started_at>?',
                (hashlib.sha256(token.encode()).hexdigest(),account,time.time()-900)).rowcount
            if changed!=1:raise ToolError('interactive_flow_invalid','local_auth_guard')

    def release_unsubmitted_login(self,token,account):
        # Only caller-proven, never-submitted browser preparations are refunded.
        with self.db:
            self.db.execute('DELETE FROM interactive_auth_flows WHERE token_hash=? AND account=? AND completed=0',
                (hashlib.sha256(token.encode()).hexdigest(),account))

    def login_budget(self, account, day):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.check_unattended_login(account,day)
            self.db.execute("INSERT INTO logins VALUES (?,?,1) ON CONFLICT(account,day) "
                            "DO UPDATE SET count=count+1", (account, day))

    def auth_requirement(self,account):
        row=self.db.execute('SELECT reason FROM auth_recovery WHERE account=?',(account,)).fetchone()
        return row[0] if row else None

    def login_exhausted(self,account,day):
        row=self.db.execute('SELECT l.count-coalesce(v.count,0) FROM logins l LEFT JOIN verified_login_counts v ON v.account=l.account AND v.day=l.day WHERE l.account=? AND l.day=?',(account,day)).fetchone()
        return bool(row and row[0]>=3)

    def background_session_verified(self,account,day):
        """Checkpoint verified success; keep raw attempts and school challenges."""
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            reason=self.auth_requirement(account)
            if reason and reason!='daily_login_limit':return False
            count=self.db.execute('SELECT count FROM logins WHERE account=? AND day=?',(account,day)).fetchone()
            self.db.execute('INSERT INTO verified_login_counts VALUES(?,?,?) ON CONFLICT(account,day) DO UPDATE SET count=excluded.count',(account,day,count[0] if count else 0))
            if reason=='daily_login_limit':self.db.execute('DELETE FROM auth_recovery WHERE account=? AND reason=?',(account,'daily_login_limit'))
        return True

    def check_unattended_login(self,account,day):
        reason=self.auth_requirement(account)
        if reason:raise ToolError(reason,'local_auth_guard')
        if self.login_exhausted(account,day):raise ToolError('daily_login_limit','local_auth_guard')

    def require_interactive_auth(self,account,reason):
        if reason not in ('need_manual_captcha','need_manual_mfa','login_rejected','daily_login_limit'):return
        with self.db:self.db.execute('INSERT INTO auth_recovery VALUES(?,?,?) ON CONFLICT(account) DO NOTHING',(account,reason,time.time()))

    def authentication_recovered(self,account,day):
        """Only called after fresh, successful school identity verification."""
        with self.db:
            self.db.execute('DELETE FROM auth_recovery WHERE account=?',(account,))
            self.db.execute('DELETE FROM logins WHERE account=? AND day=?',(account,day))
            self.db.execute('DELETE FROM verified_login_counts WHERE account=? AND day=?',(account,day))

    def claim(self, account, day, submission=None):
        with self.db:
            row = self.db.execute("INSERT OR IGNORE INTO claims VALUES (?,?,?)",
                                  (account, day, "started"))
            if row.rowcount == 1 and submission is not None:
                safe=submission_details(submission)
                self.db.execute("INSERT INTO submission_diagnostics VALUES (?,?,?)",(account,day,json.dumps(safe,ensure_ascii=False,allow_nan=False)))
        return row.rowcount == 1

    def record_submission(self,account,day,details):
        safe=submission_details(details)
        with self.db:
            self.db.execute("UPDATE submission_diagnostics SET details=? WHERE account=? AND day=?",(json.dumps(safe,ensure_ascii=False,allow_nan=False),account,day))
        if requires_school_client(safe):self.require_school_client(safe['apiCode'])

    def submission(self,account,day):
        row=self.db.execute("SELECT details FROM submission_diagnostics WHERE account=? AND day=?",(account,day)).fetchone()
        return submission_details(json.loads(row[0])) if row else None

    def claimed(self, account, day):
        return self.db.execute("SELECT outcome FROM claims WHERE account=? AND day=?",
                               (account, day)).fetchone() is not None

    def outcome(self, account, day, outcome):
        with self.db:
            self.db.execute("UPDATE claims SET outcome=? WHERE account=? AND day=?",
                            (outcome, account, day))
            if outcome == "confirmed":
                self.db.execute("INSERT OR IGNORE INTO readiness VALUES (?)", (account,))

    def ready(self, account):
        return self.db.execute("SELECT 1 FROM readiness WHERE account=?", (account,)).fetchone() is not None

    def daily_done(self, account, day):
        return self.db.execute("SELECT 1 FROM daily WHERE account=? AND day=?", (account, day)).fetchone() is not None

    def save_daily(self, account, day, result):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO daily VALUES (?,?,?)", (account, day, result))

    def close(self):
        self.db.close()
