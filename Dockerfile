# Build stage
FROM golang:1.26.5-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=v1.6.0
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X main.appVersion=${VERSION}" -o meridian .

# Runtime stage
FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
RUN addgroup -S meridian && \
    adduser -S -D -H -u 10001 -G meridian meridian && \
    mkdir -p /app/data && \
    chown meridian:meridian /app/data && \
    chmod 0700 /app/data
COPY --from=builder --chown=root:root --chmod=0555 /app/meridian /app/meridian

EXPOSE 9090

ENV PORT=9090
ENV DB_PATH=/app/data/meridian.db

VOLUME ["/app/data"]

USER meridian

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O - http://127.0.0.1:9090/api/auth/check >/dev/null || exit 1

ENTRYPOINT ["./meridian"]
