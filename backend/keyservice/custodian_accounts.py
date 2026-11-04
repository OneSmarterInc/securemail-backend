"""Independent custodian accounts; encrypted TOTP, durable replay/attempt controls.

Software custody only: Windows master material is current-user DPAPI protected;
other hosts require a private service-account directory and key-file custody.
This is separate from the sealed document root and contains no document keys.
"""

import base64
import ctypes
import os
import re
import secrets
import sqlite3
import subprocess
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from urllib.parse import quote

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django_otp.oath import TOTP


def dpapi(value: bytes, *, decrypt: bool = False) -> bytes:
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    buffer = ctypes.create_string_buffer(value)
    incoming = Blob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    outgoing = Blob()
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes = [
        ctypes.POINTER(Blob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(Blob),
    ]
    function.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    if not function(ctypes.byref(incoming), None, None, None, None, 1, ctypes.byref(outgoing)):
        raise OSError("Custodian credential key is unavailable to this service identity")
    try:
        return ctypes.string_at(outgoing.data, outgoing.size)
    finally:
        kernel.LocalFree(ctypes.cast(outgoing.data, ctypes.c_void_p))


def directory_for(policy: Path) -> Path:
    return Path(os.environ.get("KEY_SERVICE_CUSTODIAN_DIRECTORY") or policy.parent / "custodians")


class CustodianAccounts:
    def __init__(self, directory: Path):
        self.directory = directory
        self.path = directory / "accounts.sqlite3"
        self.key_path = directory / "credential.key"

    def initialize(self):
        if self.directory.is_symlink():
            raise ValueError("Custodian directory cannot be a symlink")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name == "nt":
            user = subprocess.check_output(["whoami"], text=True).strip()
            subprocess.run(
                [
                    "icacls",
                    str(self.directory),
                    "/inheritance:r",
                    "/grant:r",
                    user + ":(OI)(CI)F",
                    "/Q",
                ],
                check=True,
                capture_output=True,
            )
        else:
            self.directory.chmod(0o700)
        if not self.key_path.exists():
            if self.path.exists():
                raise ValueError("Missing credential key; refuse replacement for existing accounts")
            key = secrets.token_bytes(32)
            encoded = b"DPAPI1\0" + dpapi(key) if os.name == "nt" else b"FILE1\0" + key
            with os.fdopen(
                os.open(self.key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
            ) as out:
                out.write(encoded)
                out.flush()
                os.fsync(out.fileno())
        if not self.path.exists():
            with os.fdopen(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"):
                pass
        with closing(sqlite3.connect(self.path)) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
                    seed BLOB NOT NULL, enrolled INTEGER NOT NULL DEFAULT 0,
                    enrollment_until REAL NOT NULL, last_step INTEGER NOT NULL DEFAULT -1,
                    revision TEXT NOT NULL, created REAL NOT NULL, last_login REAL,
                    password_setup INTEGER NOT NULL DEFAULT 1,
                    failed_attempts INTEGER NOT NULL DEFAULT 0, blocked_until REAL NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
                    actor TEXT NOT NULL, operation TEXT NOT NULL, subject TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
                    BEGIN SELECT RAISE(ABORT,'append-only custodian events'); END;
                CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
                    BEGIN SELECT RAISE(ABORT,'append-only custodian events'); END;
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(accounts)")}
            if "password_setup" not in columns:
                db.execute(
                    "ALTER TABLE accounts ADD COLUMN password_setup INTEGER NOT NULL DEFAULT 1"
                )
                db.execute("UPDATE accounts SET password_setup=0 WHERE enrolled=1")

    def _key(self) -> bytes:
        value = self.key_path.read_bytes()
        if value.startswith(b"DPAPI1\0") and os.name == "nt":
            key = dpapi(value[7:], decrypt=True)
        elif value.startswith(b"FILE1\0") and os.name != "nt":
            if self.key_path.stat().st_mode & 0o077:
                raise PermissionError("Custodian key permissions are too broad")
            key = value[6:]
        else:
            raise ValueError("Unsupported credential-key custody")
        if len(key) != 32:
            raise ValueError("Invalid credential-key length")
        return key

    @contextmanager
    def transaction(self):
        # Missing storage never silently initializes a new account directory.
        if not self.path.is_file():
            raise PermissionError("Custodian accounts must be provisioned through the CLI")
        with closing(sqlite3.connect(self.path, timeout=10)) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA secure_delete=ON")
            with db:
                db.execute("BEGIN IMMEDIATE")
                yield db

    @staticmethod
    def _event(db, actor, operation, subject=""):
        db.execute(
            "INSERT INTO events(at,actor,operation,subject) VALUES (?,?,?,?)",
            (time.time(), actor, operation, subject),
        )

    def create(self, username: str, display_name: str, password: str, *, actor="operator-cli"):
        username = username.strip().lower()
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.@-]{2,99}", username):
            raise ValueError("Username must be 3–100 lowercase letters, digits or . _ @ -")
        if not 1 <= len(display_name.strip()) <= 100 or not 16 <= len(password) <= 256:
            raise ValueError("Provide a display name and a 16–256 character password")
        self.initialize()
        ident, revision = str(uuid.uuid4()), str(uuid.uuid4())
        nonce = secrets.token_bytes(12)
        seed = nonce + AESGCM(self._key()).encrypt(
            nonce, secrets.token_bytes(20), (ident + ":" + revision).encode()
        )
        password_hash = PasswordHasher().hash(password)
        with self.transaction() as db:
            db.execute(
                "INSERT INTO accounts(id,username,display_name,password_hash,seed,enrollment_until,revision,created) VALUES (?,?,?,?,?,?,?,?)",
                (
                    ident,
                    username,
                    display_name.strip(),
                    password_hash,
                    seed,
                    time.time() + 86400,
                    revision,
                    time.time(),
                ),
            )
            self._event(db, actor, "custodian_created", username)
        return ident

    def _seed(self, row) -> bytes:
        encrypted = row["seed"]
        return AESGCM(self._key()).decrypt(
            encrypted[:12], encrypted[12:], (row["id"] + ":" + row["revision"]).encode()
        )

    def login(self, username, password, code, *, new_password="", confirmation=""):
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not isinstance(code, str)
            or not isinstance(new_password, str)
            or not isinstance(confirmation, str)
        ):
            raise PermissionError("Login failed")
        if (
            len(username) > 100
            or len(password) > 256
            or len(new_password) > 256
            or len(confirmation) > 256
            or (code and not re.fullmatch(r"[0-9]{6}", code))
        ):
            raise PermissionError("Login failed")
        result = None
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM accounts WHERE username=?", (username.strip().lower(),)
            ).fetchone()
            if row is None or not row["active"] or row["blocked_until"] > time.time():
                raise PermissionError("Login failed")
            valid = False
            try:
                valid = PasswordHasher().verify(row["password_hash"], password)
            except VerificationError:
                pass
            if valid and not row["enrolled"] and row["enrollment_until"] > time.time() and not code:
                seed = base64.b32encode(self._seed(row)).decode().rstrip("=")
                return {
                    "enrollment_required": True,
                    "password_setup_required": bool(row["password_setup"]),
                    "secret": seed,
                    "uri": f"otpauth://totp/{quote('OneSmarter Custodian:' + row['username'])}?secret={seed}&issuer=OneSmarter%20Custodian&algorithm=SHA1&digits=6&period=30",
                }
            if valid and code and (row["enrolled"] or row["enrollment_until"] > time.time()):
                totp = TOTP(self._seed(row))
                valid = totp.verify(int(code), tolerance=1, min_t=row["last_step"] + 1)
            else:
                valid = False
            if row["password_setup"]:
                valid = (
                    valid
                    and 16 <= len(new_password) <= 256
                    and new_password == confirmation
                    and new_password != password
                )
            elif new_password or confirmation:
                valid = False
            if valid:
                revision = row["revision"]
                if row["password_setup"]:
                    revision, nonce = str(uuid.uuid4()), secrets.token_bytes(12)
                    seed = nonce + AESGCM(self._key()).encrypt(
                        nonce, self._seed(row), (row["id"] + ":" + revision).encode()
                    )
                    db.execute(
                        "UPDATE accounts SET password_hash=?,password_setup=0,revision=?,seed=? WHERE id=?",
                        (PasswordHasher().hash(new_password), revision, seed, row["id"]),
                    )
                    self._event(db, row["username"], "password_set")
                db.execute(
                    "UPDATE accounts SET enrolled=1,last_step=?,last_login=?,failed_attempts=0,blocked_until=0 WHERE id=?",
                    (totp.t(), time.time(), row["id"]),
                )
                self._event(
                    db, row["username"], "login_success" if row["enrolled"] else "totp_enrolled"
                )
                result = {
                    "id": row["id"],
                    "username": row["username"],
                    "display_name": row["display_name"],
                    "revision": revision,
                }
            else:
                attempts = row["failed_attempts"] + 1
                db.execute(
                    "UPDATE accounts SET failed_attempts=?,blocked_until=? WHERE id=?",
                    (
                        0 if attempts >= 5 else attempts,
                        time.time() + 300 if attempts >= 5 else 0,
                        row["id"],
                    ),
                )
                self._event(db, row["username"], "login_failed")
        if result is None:
            raise PermissionError("Login failed")
        return result

    def current(self, ident: str, revision: str) -> dict:
        with self.transaction() as db:
            row = db.execute(
                "SELECT id,username,display_name,active,enrolled,revision,password_setup FROM accounts WHERE id=?",
                (ident,),
            ).fetchone()
            if (
                row is None
                or not row["active"]
                or not row["enrolled"]
                or row["password_setup"]
                or row["revision"] != revision
            ):
                raise PermissionError("Sign in again")
            return dict(row)

    def event(self, actor: str, operation: str, subject=""):
        with self.transaction() as db:
            self._event(db, actor, operation, subject)

    def list_accounts(self):
        with self.transaction() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT id,username,display_name,active,enrolled,created,last_login FROM accounts ORDER BY username"
                )
            ]

    def import_legacy(self, username: str, password_hash: str, *, actor="operator-cli"):
        # Explicit offline migration preserves the existing Argon2 password;
        # legacy password-only HTTP login is never retained as a fallback.
        PasswordHasher().check_needs_rehash(password_hash)
        ident = self.create(username, username, secrets.token_urlsafe(32), actor=actor)
        with self.transaction() as db:
            db.execute("UPDATE accounts SET password_hash=? WHERE id=?", (password_hash, ident))
            self._event(db, actor, "legacy_password_imported", username)
        return ident

    def reset_totp(self, username: str, *, actor="operator-cli"):
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM accounts WHERE username=?", (username.lower(),)
            ).fetchone()
            if row is None:
                raise ValueError("Custodian not found")
            revision, nonce = str(uuid.uuid4()), secrets.token_bytes(12)
            seed = nonce + AESGCM(self._key()).encrypt(
                nonce, secrets.token_bytes(20), (row["id"] + ":" + revision).encode()
            )
            db.execute(
                "UPDATE accounts SET seed=?,revision=?,enrolled=0,last_step=-1,enrollment_until=?,failed_attempts=0,blocked_until=0 WHERE id=?",
                (seed, revision, time.time() + 86400, row["id"]),
            )
            self._event(db, actor, "totp_reset", username)

    def reset_setup(self, username: str, setup_code: str, *, actor="operator-cli"):
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM accounts WHERE username=?", (username.lower(),)
            ).fetchone()
            if row is None:
                raise ValueError("Custodian not found")
            revision, nonce = str(uuid.uuid4()), secrets.token_bytes(12)
            seed = nonce + AESGCM(self._key()).encrypt(
                nonce, secrets.token_bytes(20), (row["id"] + ":" + revision).encode()
            )
            db.execute(
                "UPDATE accounts SET password_hash=?,password_setup=1,seed=?,revision=?,enrolled=0,last_step=-1,enrollment_until=?,failed_attempts=0,blocked_until=0 WHERE id=?",
                (PasswordHasher().hash(setup_code), seed, revision, time.time() + 86400, row["id"]),
            )
            self._event(db, actor, "setup_reset", username)

    def set_active(self, username: str, active: bool, *, actor="operator-cli"):
        with self.transaction() as db:
            row = db.execute(
                "SELECT * FROM accounts WHERE username=?", (username.lower(),)
            ).fetchone()
            if row is None:
                raise ValueError("Custodian not found")
            revision, nonce = str(uuid.uuid4()), secrets.token_bytes(12)
            seed = nonce + AESGCM(self._key()).encrypt(
                nonce, self._seed(row), (row["id"] + ":" + revision).encode()
            )
            db.execute(
                "UPDATE accounts SET active=?,revision=?,seed=? WHERE id=?",
                (int(active), revision, seed, row["id"]),
            )
            self._event(
                db, actor, "custodian_activated" if active else "custodian_deactivated", username
            )

    def audit(self, store: Path, filters: dict) -> dict:
        sort = {"at": "at", "actor": "actor", "operation": "operation", "seq": "seq"}.get(
            filters["sort"]
        )
        direction = filters["direction"]
        page = filters["page"]
        if (
            sort is None
            or direction not in {"asc", "desc"}
            or type(page) is not int
            or not 1 <= page <= 100000
        ):
            raise ValueError("Invalid audit ordering or page")
        for name in ("query", "actor", "operation"):
            if not isinstance(filters[name], str) or len(filters[name]) > 100:
                raise ValueError("Invalid audit filter")
        for name in ("from", "to"):
            value = filters.get(name)
            if value is not None and (
                type(value) not in {int, float} or not 0 <= value <= 4102444800
            ):
                raise ValueError("Invalid audit time range")
        union = """WITH records AS (
            SELECT 'account' AS source,seq,at,actor,operation,subject FROM events
            UNION ALL
            SELECT 'key',seq,json_extract(body,'$.at')/1000000000.0,
                substr(json_extract(body,'$.actor'),48),json_extract(body,'$.operation'),''
            FROM keylog.audit WHERE json_extract(body,'$.actor') LIKE 'custodian:%'
        ) """
        clauses, params = ["1=1"], []
        for name in ("actor", "operation"):
            if filters[name]:
                clauses.append(name + "=?")
                params.append(filters[name])
        if filters["query"]:
            value = filters["query"].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            clauses.append(
                "(actor LIKE ? ESCAPE '\\' OR operation LIKE ? ESCAPE '\\' OR subject LIKE ? ESCAPE '\\')"
            )
            params.extend(["%" + value + "%"] * 3)
        for name, operator in (("from", ">="), ("to", "<=")):
            if filters.get(name) is not None:
                clauses.append("at" + operator + "?")
                params.append(filters[name])
        where = " WHERE " + " AND ".join(clauses)
        with closing(sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            db.execute("ATTACH DATABASE ? AS keylog", (store.resolve().as_uri() + "?mode=ro",))
            total = db.execute(union + "SELECT COUNT(*) FROM records" + where, params).fetchone()[0]
            rows = db.execute(
                union
                + "SELECT * FROM records"
                + where
                + f" ORDER BY {sort} {direction},source,seq {direction} LIMIT 25 OFFSET ?",
                [*params, (page - 1) * 25],
            ).fetchall()
            actors = [
                r[0]
                for r in db.execute(union + "SELECT DISTINCT actor FROM records ORDER BY actor")
            ]
            operations = [
                r[0]
                for r in db.execute(
                    union + "SELECT DISTINCT operation FROM records ORDER BY operation"
                )
            ]
        return {
            "rows": [dict(row) for row in rows],
            "total": total,
            "page": page,
            "page_size": 25,
            "actors": actors,
            "operations": operations,
        }
