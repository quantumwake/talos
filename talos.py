"""PyInstaller entry point — `make build` bundles this into a standalone binary."""

from talos.cli import app

if __name__ == "__main__":
    app()
