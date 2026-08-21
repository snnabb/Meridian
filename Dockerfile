# Build stage
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=v1.12.2
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X main.appVersion=${VERSION}" -o meridian ./cmd/meridian

# Runtime stage
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN apk add --no-cache ca-certificates libcap su-exec tzdata

WORKDIR /app
RUN addgroup -S meridian && \
    adduser -S -D -H -u 10001 -G meridian meridian && \
    mkdir -p /app/data && \
    chown meridian:meridian /app/data && \
    chmod 0700 /app/data
COPY --from=builder --chown=root:root --chmod=0555 /app/meridian /app/meridian
COPY --chown=root:root --chmod=0555 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN setcap cap_net_bind_service=+ep /app/meridian && \
    getcap /app/meridian | grep -Fq 'cap_net_bind_service=ep'

EXPOSE 9090

ENV PORT=9090
ENV DB_PATH=/app/data/meridian.db

VOLUME ["/app/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/app/meridian", "--healthcheck"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["./meridian"]
