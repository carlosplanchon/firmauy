# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Which operating system firmauy is on, asked in one place.

Code that behaves differently on Windows reads :data:`WINDOWS` from this module at call time,
rather than testing ``sys.platform`` where the difference shows up. One seam is easier to audit
than a dozen, and a test can flip it to exercise the Windows messages on any machine.

Only Windows has a branch. Everything else takes the POSIX path, unchanged.
"""

import sys

WINDOWS = sys.platform == "win32"
