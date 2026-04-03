help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: ## Run core tests
	@cargo test --release --features=alloc,serde
	@cargo test --release --no-default-features --features=serde

test-no-std: ## Verify no_std compilation
	@cargo test --release --features=rkyv-impl,alloc --no-run
	@cargo build --release --no-default-features --features serde --target wasm32-unknown-unknown

no-std: ## Verify no_std compatibility on bare-metal target
	@rustup target add thumbv6m-none-eabi
	@cargo build --release --no-default-features --target thumbv6m-none-eabi
	@cargo build --release --no-default-features --features alloc --target thumbv6m-none-eabi

clippy: ## Run clippy
	@cargo clippy --release --features=alloc,serde -- -D warnings
	@cargo clippy --release --no-default-features -- -D warnings

.PHONY: help test test-no-std no-std clippy
