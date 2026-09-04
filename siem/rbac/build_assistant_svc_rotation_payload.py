#!/usr/bin/env python3
"""Emit one assistant-svc replacement payload without persisting a password."""

import getpass
import json
import os
import stat
import sys
import warnings


def require_pipe_output() -> None:
    try:
        output_mode = os.fstat(sys.stdout.fileno()).st_mode
    except (AttributeError, OSError, ValueError) as exc:
        raise SystemExit("STOP: stdout must be a pipe to the reviewed curl command") from exc
    if not stat.S_ISFIFO(output_mode):
        raise SystemExit("STOP: stdout must be a pipe, not a terminal or file")


def main() -> int:
    require_pipe_output()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            current_password = getpass.getpass(
                "Current assistant-svc password (comparison only): "
            )
            replacement_password = getpass.getpass(
                "New assistant-svc password: "
            )
            confirmation = getpass.getpass(
                "Confirm new assistant-svc password: "
            )
    except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
        raise SystemExit("STOP: a private terminal prompt is required") from None

    if not current_password:
        raise SystemExit("STOP: current password must not be empty")
    if not replacement_password:
        raise SystemExit("STOP: replacement password must not be empty")
    if replacement_password != confirmation:
        raise SystemExit("STOP: replacement password confirmation differs")
    if replacement_password == current_password:
        raise SystemExit("STOP: replacement password must differ from current password")

    json.dump(
        {
            "password": replacement_password,
            "backend_roles": [],
            "opendistro_security_roles": [],
            "attributes": {},
        },
        sys.stdout,
        separators=(",", ":"),
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
