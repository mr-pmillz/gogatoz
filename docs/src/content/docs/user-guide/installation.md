---
title: Installation
description: Install GoGatoZ via prebuilt binaries, from source, or Docker
---

GoGatoZ is a Go-based CLI that targets GitLab CI/CD. You can install it via prebuilt binaries, build from source, or use the Docker image.

## Prebuilt binaries

Download the latest release for your platform from the Releases page and place the binary on your PATH as `gogatoz`.

## Build from source

Prerequisites:
- Go 1.26+

Steps:
```bash
git clone https://github.com/mr-pmillz/gogatoz
cd gogatoz
make build # or: go build -o gogatoz ./...
```

Alternatively, install directly with Go:
```bash
go install github.com/mr-pmillz/gogatoz@latest
```

## Docker

You can run GoGatoZ using Docker:
```bash
docker run --rm -e GITLAB_TOKEN=$GITLAB_TOKEN ghcr.io/mr-pmillz/gogatoz:latest gogatoz --help
```

GoGatoZ reads configuration from flags, environment, then config file (`.gogatoz.yaml`) in that precedence (flags > env > config).

## CTF Lab (Docker Compose)

The `labs/` directory contains a full-stack CTF lab environment with a GitLab instance, CI/CD runners, vulnerable repos, and a flag submission server with a web UI.

Prerequisites:
- Docker and Docker Compose
- At least 8 GB RAM allocated to Docker

Steps:
```bash
cp ./labs/flagserver/.env.example ./labs/flagserver/.env
docker compose build --no-cache
docker compose up -d
```

The flag submission UI will be available at `http://localhost:31337`. The GitLab instance runs at `http://gitlab.local:8929` (add `gitlab.local` to your `/etc/hosts` pointing to `127.0.0.1` if needed).

To stop the lab:
```bash
docker compose down
```

## GitLab Token Setup

Set a GitLab Personal Access Token (PAT) with the required scopes:
- api
- read_repository
- write_repository

Create a token in your GitLab profile, then export it:
```bash
export GITLAB_TOKEN=<YOUR_GITLAB_PAT>
```

You can also set the GitLab instance URL (defaults to https://gitlab.com):
```bash
export GITLAB_URL=https://gitlab.local
```

GoGatoZ reads configuration from flags, environment, then config file (`.gogatoz.yaml`) in that precedence (flags > env > config).

## Verifying Installation

To verify that GoGatoZ is installed correctly, run:

```bash
gogatoz --help
```

This should display the help menu with available commands and options.
