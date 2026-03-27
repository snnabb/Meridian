# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o meridian .

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/meridian .

EXPOSE 9090

ENV PORT=9090
ENV DB_PATH=/app/data/meridian.db

VOLUME ["/app/data"]

ENTRYPOINT ["./meridian"]
