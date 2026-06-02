#!/usr/bin/env bash

# In CI (e.g. GitHub Actions sets CI=true), drop to a shell; otherwise run the passed command
if [[ -n "$CI" ]]; then
    exec /bin/bash
else
    exec "$@"
fi