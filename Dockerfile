# Multi-stage Dockerfile for GoGatoZ
# Build stage
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder
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
FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 gogatoz
COPY --from=builder /out/gogatoz /usr/local/bin/gogatoz
USER 10001
ENTRYPOINT ["/usr/local/bin/gogatoz"]
