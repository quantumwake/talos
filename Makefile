# Talos — build / install / run
#
#   make build      → produce a standalone binary at dist/talos
#   make install    → install that binary to $(PREFIX)/bin (default /usr/local/bin)
#   make run        → scan the running processes
#   make serve      → launch the backend API
#   make portal     → run the React portal (dev server)
#   make test       → run the test suite

PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
BIN    := dist/talos

.DEFAULT_GOAL := help
.PHONY: help setup deps frontend-deps build build-frontend install uninstall run serve portal dev test clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: deps frontend-deps ## Install all Python + JS dependencies

deps: ## Sync Python dependencies (uv)
	uv sync

frontend-deps: ## Install React portal dependencies
	cd frontend && npm install

build: deps ## Build the standalone CLI binary -> dist/talos
	uv run pyinstaller --onefile --clean --name talos \
		--add-data "talos/data:talos/data" \
		--collect-submodules talos \
		talos.py
	@echo "Built $(BIN)"
	@./$(BIN) --help >/dev/null && echo "Binary runs OK."

build-frontend: frontend-deps ## Build the React portal for production -> frontend/dist
	cd frontend && npm run build

install: build ## Install the binary to $(BINDIR)
	@mkdir -p "$(BINDIR)"
	install -m 0755 "$(BIN)" "$(BINDIR)/talos"
	@echo "Installed -> $(BINDIR)/talos"
	@echo "Run:  talos scan"

uninstall: ## Remove the installed binary
	rm -f "$(BINDIR)/talos"

run: deps ## Scan running processes (rich report)
	uv run talos scan

dev: deps ## Run API + portal together and open the browser (single command)
	uv run talos dev

serve: deps ## Launch the backend API on :58789
	uv run talos serve

portal: frontend-deps ## Run the React portal dev server on :58790
	cd frontend && npm run dev

test: deps ## Run the test suite
	uv run pytest -q

clean: ## Remove build artifacts
	rm -rf build dist *.spec frontend/dist
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
