# Custodian accounts

Custodians are independent named accounts, separate from portal staff accounts.
The maintenance page is `/maintenance/` on the application origin (locally,
`http://localhost:5173/maintenance/`). TLS gateway authorization remains required;
a human account does not replace service authentication.

## Create an account

Run from the repository using the configured application environment:

```powershell
python manage.py custodian create --username ammar --name "Ammar Aziz"
```

The command prints the path of a private setup file, not its secret. Deliver the
temporary setup code privately to the custodian and remove the handoff file.
The code expires after 24 hours. On first login the custodian must:

1. Enter their username and temporary setup code.
2. Scan the locally generated QR code with their authenticator.
3. Choose and confirm a new password of 16–256 characters, different from the code.
4. Enter the six-digit authenticator code to complete setup.

Password setup and TOTP enrollment complete atomically. No maintenance session is
issued before both succeed. The setup credential then stops working. Subsequent
logins require the chosen password and a fresh TOTP. Passwords use Argon2 hashes;
TOTP seeds are encrypted with AES-256-GCM. Accepted time steps are recorded to
prevent replay, with persistent failed-attempt throttling.

## Account administration

```powershell
python manage.py custodian list
python manage.py custodian deactivate --username ammar
python manage.py custodian activate --username ammar
python manage.py custodian reset-totp --username ammar
python manage.py custodian reset-setup --username ammar
```

Deactivation and resets revoke existing sessions. `reset-totp` retains the password
and requires a new authenticator; `reset-setup` issues a new temporary credential
and requires both a new password and authenticator. CLI access is an operating
system privilege: restrict it to authorized operators. Account events and key
operations identify the acting custodian. The activity tab supports search,
filters, sortable columns and pagination.

## Storage and limitations

`KEY_SERVICE_CUSTODIAN_DIRECTORY` optionally selects the private account directory;
otherwise it is `custodians` beside the key-service policy. The authentication
master key must remain available while document keys are sealed. On Windows it
is protected by current-user DPAPI and a restricted directory ACL; on Linux it
uses a mode-0600 key file within a mode-0700 directory. Run the CLI and service
under the intended service identity. Back up this credential store separately
and plan platform-specific recovery or re-enrollment.

The account event table rejects ordinary updates and deletes, but is not an
externally witnessed immutable archive. Privileged host compromise or rollback
of this separate authentication database remains a review concern. Do not claim
the document key-store checkpoint design protects it automatically.

The visible synthetic warning was removed from this page at the owner's request.
Production configuration checks and candidate startup warnings remain. This implementation is
local candidate functionality, pending independent security review; it is not
production approval.
