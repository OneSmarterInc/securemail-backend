"""Offline operating-system-authorized custody account administration."""

import getpass
import json
import os
import secrets
import sqlite3
import uuid
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from backend.keyservice.custodian_accounts import CustodianAccounts, directory_for


class Command(BaseCommand):
    help = "Manage independent custodians. Creation saves a private temporary setup code; the custodian chooses their password on first sign-in."

    def add_arguments(self, parser):
        parser.add_argument(
            "action",
            choices=[
                "create",
                "list",
                "activate",
                "deactivate",
                "reset-totp",
                "reset-setup",
                "import-legacy",
            ],
        )
        parser.add_argument("--username")
        parser.add_argument("--name")
        parser.add_argument(
            "--policy",
            type=Path,
            default=Path(settings.BASE_DIR) / ".runtime/maintenance/policy.json",
        )

    def handle(self, *args, **options):
        accounts = CustodianAccounts(directory_for(options["policy"]))
        actor = "operator-cli:" + getpass.getuser()
        try:
            action = options["action"]
            if action == "list":
                for row in accounts.list_accounts():
                    self.stdout.write(
                        f"{row['username']} | {row['display_name']} | active={bool(row['active'])} | TOTP={'enrolled' if row['enrolled'] else 'pending'}"
                    )
                return
            username = options["username"]
            if not username:
                raise CommandError("--username is required")
            if action in {"create", "reset-setup"}:
                if action == "create" and not options["name"]:
                    raise CommandError("--name is required")
                setup_code = secrets.token_urlsafe(32)
                if action == "create":
                    accounts.create(username, options["name"], setup_code, actor=actor)
                else:
                    accounts.reset_setup(username, setup_code, actor=actor)
                destination = accounts.directory / ("setup-" + str(uuid.uuid4()) + ".txt")
                with os.fdopen(
                    os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600),
                    "w",
                    encoding="utf-8",
                ) as out:
                    out.write(
                        "Custodian: "
                        + username
                        + "\nTemporary setup code: "
                        + setup_code
                        + "\nExpires in 24 hours or when password/TOTP setup completes.\nDeliver privately and remove this file after handoff.\n"
                    )
                    out.flush()
                    os.fsync(out.fileno())
                self.stdout.write(
                    "Custodian setup prepared. Private setup instructions: "
                    + str(destination)
                    + "\nThe custodian must choose a password and confirm TOTP at /maintenance/. No setup code or seed was printed."
                )
            elif action == "import-legacy":
                policy = json.loads(options["policy"].read_text())
                matches = [
                    entry["password_hash"]
                    for entry in policy.get("identities", {}).values()
                    if entry.get("role") == "custodian"
                    and entry.get("name") == username
                    and "password_hash" in entry
                ]
                if not matches or len(set(matches)) != 1:
                    raise CommandError(
                        "No unique matching legacy custodian password in this policy"
                    )
                accounts.import_legacy(username, matches[0], actor=actor)
                self.stdout.write(
                    "Legacy password migrated. TOTP enrollment is now required before maintenance access."
                )
            elif action == "reset-totp":
                accounts.reset_totp(username, actor=actor)
                self.stdout.write(
                    "TOTP reset audited; sessions revoked. Enroll a new authenticator within 24 hours."
                )
            else:
                accounts.set_active(username, action == "activate", actor=actor)
                self.stdout.write("Custodian status updated; existing sessions are revoked.")
        except (ValueError, PermissionError, OSError, sqlite3.Error) as exc:
            raise CommandError(
                "Custodian operation failed; check the account, private directory and service identity."
            ) from exc
