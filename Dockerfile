# Multi-stage Dockerfile for GoGatoZ
# Build stage
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
RUN apk add --no-cache git ca-certificates && update-ca-certificates
# Cache deps
COPY go.mod go.sum ./
RUN go mod download
# Copy source
COPY . .
# Build static binary
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /out/gogatoz ./main.go

# Runtime stage
FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 gogatoz
COPY --from=builder /out/gogatoz /usr/local/bin/gogatoz
USER 10001
ENTRYPOINT ["/usr/local/bin/gogatoz"]
