# SPDX-License-Identifier: MIT
"""Allow ``python -m voltage_verify ...``, which is what the VM instructions use under sudo."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
