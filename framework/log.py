"""Unified logging entry point. pytest.ini already configures log_cli; this only provides a getter."""
import logging


def get(name: str) -> logging.Logger:
    return logging.getLogger(f"dut.{name}")
