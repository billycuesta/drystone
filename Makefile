.PHONY: build test clean run fmt install-deps verify help

help:
	@echo "Drystone - AWS Security Audit CLI"
	@echo ""
	@echo "Available targets:"
	@echo "  make build          - Build the drystone CLI binary"
	@echo "  make test           - Run tests"
	@echo "  make fmt            - Format code"
	@echo "  make clean          - Remove build artifacts and audit-logs"
	@echo "  make install-deps   - Download and verify Go dependencies"
	@echo "  make verify         - Verify module integrity"
	@echo "  make run-iam        - Build and run IAM audit (requires AWS_PROFILE)"

build:
	@echo "🔨 Building drystone..."
	@mkdir -p bin
	@go build -o bin/drystone cmd/main.go
	@echo "✅ Built: bin/drystone"

test:
	@echo "🧪 Running tests..."
	@go test -v ./...

fmt:
	@echo "📝 Formatting code..."
	@go fmt ./...
	@echo "✅ Formatted"

clean:
	@echo "🧹 Cleaning..."
	@rm -rf bin/
	@rm -rf audit-logs/
	@echo "✅ Cleaned"

install-deps:
	@echo "📥 Installing dependencies..."
	@go mod download
	@go mod tidy
	@echo "✅ Dependencies installed"

verify:
	@echo "✔️  Verifying modules..."
	@go mod verify
	@echo "✅ All modules verified"

run-iam: build
	@echo "🚀 Running IAM audit..."
	@./bin/drystone audit --skill iam

.DEFAULT_GOAL := help
