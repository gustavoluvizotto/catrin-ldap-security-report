# Dockerfile
FROM alpine:latest

RUN apk update && \
    apk add --no-cache mtr && \
    rm -rf /var/cache/apk/*

# Args passed to `docker compose run mtr-runner ...` go straight to mtr.
ENTRYPOINT ["mtr"]
