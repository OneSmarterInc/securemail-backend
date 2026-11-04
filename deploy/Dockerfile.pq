# Candidate only: build and attest the resulting image before deployment.
FROM python:3.15-alpine@sha256:20a82dbc2783112ddb91d1534603f802d222a3e63e593cd002eb2ac534e70211
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock .
COPY requirements-test.lock .
ARG INSTALL_TEST_DEPENDENCIES=0
RUN apk add --no-cache openssl libstdc++
RUN pip install --require-hashes --only-binary=:all: --no-cache-dir -r requirements.lock && adduser -D -u 1000 app
RUN if [ "$INSTALL_TEST_DEPENDENCIES" = "1" ]; then pip install --require-hashes --only-binary=:all: --no-cache-dir -r requirements-test.lock; fi
# Keep package installers and their vendored libraries out of the runtime.
RUN pip uninstall -y pip && python -c "import ensurepip, pathlib, shutil; shutil.rmtree(pathlib.Path(ensurepip.__file__).parent)"
COPY --chown=app:app backend ./backend
COPY --chown=app:app secure_mail ./secure_mail
COPY --chown=app:app scripts ./scripts
COPY --chown=app:app manage.py pyproject.toml ./
RUN python -c "import ssl; from backend.transport.tls import configure; configure(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), required=True)"
USER app
# Provision this directory for app+gateway only. Do not publish an HTTP backend port.
CMD ["gunicorn", "backend.config.wsgi:application", "--bind", "unix:/run/onesmarter/app.sock", "--umask", "007", "--workers", "2", "--timeout", "90", "--error-logfile", "-"]
