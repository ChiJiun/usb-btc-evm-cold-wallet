SHELL := /bin/sh
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: help test validate-config prepare-sources configure image verify reproducibility-check clean

help:
	@echo "USB BTC+EVM Cold Wallet"
	@echo "  make test             host unit tests (no real keys)"
	@echo "  make validate-config  statically resolve Buildroot Kconfig"
	@echo "  make prepare-sources  fetch hash-locked wheels + all Buildroot sources"
	@echo "  make configure        resolve the pinned Buildroot configuration"
	@echo "  make image            build x86_64 UEFI USB image"
	@echo "  make verify           static checks on a built image"
	@echo "  make reproducibility-check  two clean builds; require identical image/kernel hashes"
	@echo "  make clean            remove generated build/ artifacts"

test:
	@./.venv/bin/python -m pytest -q

validate-config:
	@./scripts/fetch_buildroot.sh >/dev/null
	@./.venv/bin/python ./scripts/validate_buildroot_config.py

prepare-sources:
	@./scripts/fetch_sources.sh

configure:
	@./scripts/fetch_wheelhouse.sh
	@./scripts/configure_buildroot.sh

image:
	@./scripts/build_image.sh

verify:
	@./scripts/verify_image.sh

reproducibility-check:
	@sh ./scripts/check_reproducible.sh

clean:
	@rm -rf "$(ROOT)/build"
