# Corpus dev commands. `just --list` to enumerate.

# Start PostgreSQL 16 in Docker.
up:
    docker compose up -d postgres

# Stop the compose stack (data volume kept).
down:
    docker compose down

# Drop the stack and the database volume.
reset:
    docker compose down -v
    rm -rf data testdata

build:
    cargo build

test:
    cargo test --workspace

clippy:
    cargo clippy --all-targets

fmt:
    cargo fmt --all

# Run corpus-server (applies migrations at boot).
serve:
    cargo run -p corpus-server

# Full end-to-end demo (compose, fixtures, import, hunt, report).
demo:
    bash scripts/demo.sh

# M1 agent demo (Linux agent in a privileged container, fanotify).
demo-agent:
    bash scripts/demo-agent.sh

# M3a similarity demo (variants, edges, blast-radius expansion).
demo-similarity:
    bash scripts/demo-similarity.sh

# Generate demo fixtures without running the demo.
fixtures:
    bash scripts/gen-testdata.sh testdata

# M4 vault bootstrap demo (snapshots, OCI, intel mocks).
demo-bootstrap:
    bash scripts/demo-bootstrap.sh

# M5 analyst surface demo (prevalence, opinions, triggers, droppers, MCP).
demo-analyst:
    bash scripts/demo-analyst.sh
