help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

test: ## Run all tests
	@$(MAKE) -C ./core $@
	@$(MAKE) -C ./circuits $@

test-no-std: ## Verify no_std compilation
	@$(MAKE) -C ./core $@
	@$(MAKE) -C ./circuits $@

no-std: ## Verify no_std compatibility on bare-metal target
	@$(MAKE) -C ./core $@
	@$(MAKE) -C ./circuits $@

clippy: ## Run clippy
	@$(MAKE) -C ./core $@
	@$(MAKE) -C ./circuits $@

fmt: ## Format code (requires nightly)
	@cargo +nightly fmt --all

doc: ## Generate documentation
	@cargo doc --no-deps

clean: ## Clean build artifacts
	@cargo clean

.PHONY: help test test-no-std no-std clippy fmt doc clean
