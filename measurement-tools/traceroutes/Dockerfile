# Dockerfile
FROM alpine:latest

RUN apk update && \
    apk add --no-cache mtr bash && \
    rm -rf /var/cache/apk/*

WORKDIR /app

COPY perform_mtr.sh .

RUN chmod +x perform_mtr.sh

ENTRYPOINT ["./perform_mtr.sh"]
