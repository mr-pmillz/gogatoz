# Multi-stage Dockerfile for GoGatoZ
# Build stage
FROM golang:1.26.5-alpine AS builder
WORKDIR /src
RUN apk add --no-cache git ca-certificates && update-ca-certificates
# Cache deps
COPY go.mod go.sum ./
RUN go mod download
# Copy source
COPY . .
# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /out/gogatoz ./main.go

# Runtime stage
FROM alpine:3.24
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 gogatoz
COPY --from=builder /out/gogatoz /usr/local/bin/gogatoz
USER 10001
ENTRYPOINT ["/usr/local/bin/gogatoz"]
