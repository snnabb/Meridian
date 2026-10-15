# Build stage
FROM golang:1.26.9-alpine@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=v1.14.0
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X main.appVersion=${VERSION}" -o meridian ./cmd/meridian

# Runtime stage
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

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
