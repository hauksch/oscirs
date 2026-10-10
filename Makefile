.PHONY: all reference corpus oracle build test lint fmt clean

all: build

## reference: fetch the pinned Java reference clone (tag 2.6.1)
reference:
	./scripts/fetch-reference.sh

## corpus: extract golden fixtures, certs (incl. PEM dumps) and XSDs
corpus: reference
	./scripts/extract-testcorpus.sh

## oracle: compile the Java differential-testing harness (needs bcprov in ~/.m2)
oracle: corpus
	./scripts/build-oracle.sh

build:
	cargo build --workspace

## test: everything, including the Java cross-verification spike
test: oracle
	cargo test --workspace

lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

clean:
	cargo clean
