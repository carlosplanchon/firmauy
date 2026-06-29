# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

import getpass
import os
import sys
from enum import Enum
from typing import Optional

import typer


class PinSource(str, Enum):
    prompt = "prompt"
    env = "env"
    stdin = "stdin"
    fd = "fd"


def get_pin(source: PinSource, env_var: Optional[str], fd: Optional[int]) -> str:
    if source == PinSource.prompt:
        typer.secho(
            "Note: an incorrect PIN counts toward the card's retry limit and can block the cédula.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        pin = getpass.getpass("PIN PKCS#11: ")
    elif source == PinSource.env:
        if not env_var:
            raise typer.BadParameter("--pin-source env requires --pin-env-var")
        val = os.environ.get(env_var)
        if not val:
            raise RuntimeError(f"Environment variable '{env_var}' is not defined or empty.")
        pin = val
    elif source == PinSource.stdin:
        typer.echo("Reading PIN from stdin...", err=True)
        pin = sys.stdin.readline().rstrip("\r\n")
    elif source == PinSource.fd:
        if fd is None:
            raise typer.BadParameter("--pin-source fd requires --pin-fd")
        with os.fdopen(fd, closefd=False) as f:
            pin = f.readline().rstrip("\r\n")
    else:
        raise AssertionError(f"Unhandled PinSource: {source}")

    # An empty PIN is always a mistake (no input / EOF); refuse it before opening the token,
    # since attempting it would still count toward the card's retry limit.
    if not pin:
        raise RuntimeError(
            "Empty PIN received; aborting before contacting the card "
            "(an empty PIN would still count toward its retry limit)."
        )
    return pin
