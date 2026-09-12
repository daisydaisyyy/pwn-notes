FROM ghcr.io/madrhacks/jail:latest

COPY --from=ubuntu@sha256:278628f08d4979fb9af9ead44277dbc9c92c2465922310916ad0c46ec9999295 / /srv
COPY ./chall /srv/app/run

ENV FLAG_PATH=/app/flag
ENV TMP_SIZE=1M
ENV POW=30
ENV TIMEOUT=120
