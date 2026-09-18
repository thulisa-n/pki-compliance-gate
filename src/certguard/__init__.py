"""CertGuard package."""

from __future__ import annotations

__all__ = ["__version__", "REPORT_SCHEMA_VERSION"]

#: Engine version. Recorded in every compliance report and evidence manifest so
#: a finding can be reproduced against the exact code that produced it.
__version__ = "0.2.3"

#: Version of the compliance report JSON structure. Bumped on any breaking
#: change to the report shape so downstream consumers can fail loudly rather
#: than silently misread a field.
REPORT_SCHEMA_VERSION = "2.0"
