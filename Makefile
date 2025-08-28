.PHONY: build-release clean-all install test help

# Default target
help:
	@echo "Available targets:"
	@echo "  build-release  - Full clean build and install process"
	@echo "  clean-all      - Clean all data and keychain entries"
	@echo "  install        - Install the binary to cargo bin"
	@echo "  test          - Test the installation with a sample key"
	@echo "  help          - Show this help message"

# Full build and setup process
build-release: clean-all
	@echo "🔨 Building api-pass in release mode..."
	cargo build --release
	@echo "📦 Installing to cargo bin..."
	cargo install --path .
	@echo "🧹 Cleaning up old data..."
	security delete-generic-password -a master -s api-pass 2>/dev/null || echo "No existing keychain item found (this is fine)"
	rm -rf ~/.api-pass/database.enc ~/.api-pass/master.salt 2>/dev/null || echo "No existing database files found (this is fine)"
	@echo "🔑 Initializing api-pass..."
	api-pass init
	@echo "✅ Build complete! api-pass is ready to use."

# Clean all data and keychain entries
clean-all:
	@echo "🧹 Cleaning all api-pass data..."
	security delete-generic-password -a master -s api-pass 2>/dev/null || echo "No keychain item to delete"
	rm -rf ~/.api-pass/ 2>/dev/null || echo "No data directory to remove"
	rm -f /tmp/api_pass_auth* 2>/dev/null || echo "No temp files to clean"
	@echo "✅ All data cleaned"

# Just install the binary
install:
	@echo "📦 Installing api-pass..."
	cargo install --path .
	@echo "✅ Installation complete"

# Test the installation
test:
	@echo "🧪 Testing api-pass installation..."
	@echo "Adding test API key..."
	api-pass set test-service --key "test-api-key-12345"
	@echo "Testing normal show:"
	api-pass show test-service
	@echo "Testing --key flag:"
	api-pass show test-service --key
	@echo "Testing environment variable capture:"
	@export TEST_KEY=$$(api-pass show test-service --key) && echo "Captured: $$TEST_KEY"
	@echo "Cleaning up test data..."
	api-pass delete test-service
	@echo "✅ Test complete"

# Development workflow
dev: build-release test
