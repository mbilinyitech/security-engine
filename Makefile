.PHONY: build test omni-test omni-doctor omni-pipeline

build:
	cargo build --release -p sovereign-bridge

test:
	cargo test --release

omni-test:
	cd omni && python3 -m pytest -q

omni-doctor:
	cd omni && python3 -m omnishield doctor

omni-pipeline:
	cd omni && python3 -m omnishield sovereign pipeline --rights telemetry
