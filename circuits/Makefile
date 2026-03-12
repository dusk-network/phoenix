help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: ## Run circuit tests
	@cargo test --release

test-no-std: ## Verify no_std compilation
	@cargo test --release --no-default-features --features=rkyv-impl,rkyv/size_16 --no-run

no-std: ## Verify no_std compatibility on bare-metal target
	@rustup target add thumbv6m-none-eabi
	@cargo build --release --no-default-features --target thumbv6m-none-eabi

clippy: ## Run clippy
	@cargo clippy --release -- -D warnings

.PHONY: help test test-no-std no-std clippy
