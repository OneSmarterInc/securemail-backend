FROM python:3.12-alpine@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock .
RUN apk add --no-cache openssl libstdc++
RUN pip install --require-hashes --only-binary=:all: --no-cache-dir -r requirements.lock && adduser -D -u 1000 app
# Runtime images do not install packages; remove pip and its bundled dependencies.
RUN pip uninstall -y pip && python -c "import ensurepip, pathlib, shutil; shutil.rmtree(pathlib.Path(ensurepip.__file__).parent)"
COPY --chown=app:app backend ./backend
COPY --chown=app:app secure_mail ./secure_mail
COPY --chown=app:app scripts ./scripts
COPY --chown=app:app manage.py pyproject.toml ./
RUN mkdir /app/.runtime && chown app:app /app/.runtime
USER app
CMD ["gunicorn", "backend.config.wsgi:application", "--bind", "127.0.0.1:8000", "--workers", "2", "--timeout", "90", "--error-logfile", "-"]
