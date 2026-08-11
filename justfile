_default:
    just --list

# Unit tests. No directory needed — these cover the encoding, filter building,
# DN handling and tree assembly.
test:
    go test ./...

# Live tests against a real directory. Reads connection settings from .env.test
# (gitignored; copy .env.test.example). Everything it creates is namespaced and
# removed again, including on failure.
test-live:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ ! -f .env.test ]; then
        echo "no .env.test — copy .env.test.example and fill it in" >&2
        exit 1
    fi
    set -a; source .env.test; set +a
    go test -run Live -v ./...

vet:
    go vet ./...

fmt:
    gofmt -l -w .

# What a consumer runs before importing this: everything, from clean.
check: fmt vet test
