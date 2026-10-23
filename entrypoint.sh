#!/usr/bin/env bash

# Preserve shell mode for CI runners that start the image without arguments.
# Explicit commands must still run when the caller happens to set CI.
if [[ $# -eq 0 ]]; then
    if [[ -n "${CI:-}" ]]; then
        exec /bin/bash
    fi
    set -- gogatoz --help
elif [[ "$1" == -* ]]; then
    set -- gogatoz "$@"
fi

exec "$@"
