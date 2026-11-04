"""Startup configuration checks, not a substitute for deployment/security approval."""

from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured


def validate_production(config: Mapping, environment: Mapping[str, str]) -> None:
    problems = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            problems.append(message)

    def https(value: str, *, origin: bool = False) -> bool:
        try:
            url = urlsplit(value)
            return bool(
                url.scheme == "https"
                and url.hostname
                and not url.username
                and not url.password
                and not url.query
                and not url.fragment
                and (not origin or not url.path)
            )
        except ValueError:
            return False

    for name in (
        "SYNTHETIC_MODE",
        "ENABLE_DEV_TOOLS",
        "ENABLE_LEGACY_RECIPIENT_API",
        "ALLOW_LEGACY_SYNTHETIC_READS",
        "KEY_SERVICE_ALLOW_SYNTHETIC_IMPORT",
        "KEY_SERVICE_AUDIT_CANDIDATE",
    ):
        require(environment.get(name, "false").lower() == "false", f"{name} must be false")
    secrets = [
        config[name] for name in ("SECRET_KEY", "DOCUMENT_INTEGRITY_KEY", "SEARCH_INDEX_KEY")
    ]
    require(
        all(len(value) >= 32 for value in secrets),
        "Independent application secrets must each be at least 32 characters",
    )
    require(len(set(secrets)) == 3, "Application signing, integrity and search secrets must differ")
    require(
        config["DATABASES"]["default"]["ENGINE"] == "django.db.backends.postgresql",
        "PostgreSQL is required",
    )
    require(bool(environment.get("REDIS_URL")), "REDIS_URL must be explicit")
    broker = urlsplit(config["CELERY_BROKER_URL"])
    require(broker.scheme in {"redis", "rediss", "redis+socket"}, "A Redis broker is required")
    require(config["MAIL_PROVIDER"] == "smtp", "MAIL_PROVIDER must be smtp")
    require(bool(config["EMAIL_HOST"]), "EMAIL_HOST is required")
    require(https(config["PUBLIC_URL"]), "PUBLIC_URL must use HTTPS")
    require(https(config["RECIPIENT_PUBLIC_URL"]), "RECIPIENT_PUBLIC_URL must use HTTPS")
    require(
        bool(config["ALLOWED_HOSTS"])
        and all(
            host and "*" not in host and not host.startswith(".") and "://" not in host
            for host in config["ALLOWED_HOSTS"]
        ),
        "ALLOWED_HOSTS must contain exact hostnames",
    )
    require(
        bool(config["CSRF_TRUSTED_ORIGINS"])
        and all(
            https(origin, origin=True) and "*" not in origin
            for origin in config["CSRF_TRUSTED_ORIGINS"]
        ),
        "CSRF_TRUSTED_ORIGINS must contain exact HTTPS origins",
    )
    require(
        set(config["CORS_ALLOWED_ORIGINS"]) <= set(config["CSRF_TRUSTED_ORIGINS"]),
        "Every CORS origin must also be trusted for CSRF",
    )
    require(
        config["TRUSTED_PROXY_UNIX_SOCKET"],
        "Production API must use the restricted Unix-socket proxy profile",
    )
    require(
        config["KEY_PROTECTOR"] == "key-service" and config["PQ_TRANSPORT_REQUIRED"],
        "PQ key-service protection is required",
    )
    for prefix in ("KEY_SERVICE", "KEY_STATUS"):
        require(
            https(config[prefix + "_URL"], origin=True), f"{prefix}_URL must be an HTTPS origin"
        )
        for suffix in ("CA", "CERT", "KEY"):
            name = prefix + "_" + suffix
            require(
                bool(config[name]) and Path(config[name]).is_file(),
                f"{name} must name an existing file",
            )
    require(
        bool(environment.get("APP_RUNTIME_DIR")) and config["RUNTIME_DIR"].is_absolute(),
        "APP_RUNTIME_DIR must be an explicit absolute path",
    )
    require(config["STORAGE_PROVIDER"] in {"local", "s3"}, "Unsupported storage provider")
    if config["STORAGE_PROVIDER"] == "s3":
        require(
            bool(config["S3_BUCKET"] and config["AWS_REGION"]),
            "S3 storage requires bucket and region",
        )
    require(
        bool(config["AUDIT_BUCKET"] and config["AWS_REGION"])
        and config["AUDIT_RETENTION_DAYS"] > 0,
        "Audit archive bucket, region and positive retention are required",
    )
    if problems:
        # Report names/requirements only; never serialize configuration values.
        raise ImproperlyConfigured("Production configuration invalid: " + "; ".join(problems))
