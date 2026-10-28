FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
RUN groupadd --system depguard && useradd --system --gid depguard --home-dir /app depguard
COPY --from=build /install /usr/local
COPY --chown=depguard:depguard src/depguard/web/static ./src/depguard/web/static
RUN mkdir -p /app/data /app/reports && chown -R depguard:depguard /app
USER depguard
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"
CMD ["depguard", "serve", "--host", "0.0.0.0", "--port", "8000"]
