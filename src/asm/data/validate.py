"""Pandera schemas. Reject malformed feeds at the boundary."""

import pandera.pandas as pa
from pandera.typing import Series


class EPSSRecord(pa.DataFrameModel):
    """EPSS daily feed schema. Columns match upstream: cve, epss, percentile."""

    cve: Series[str] = pa.Field(str_matches=r"^CVE-\d{4}-\d{4,7}$")
    epss: Series[float] = pa.Field(ge=0.0, le=1.0)
    percentile: Series[float] = pa.Field(ge=0.0, le=1.0)


class CVERecord(pa.DataFrameModel):
    """NVD CVE schema. Used Monday when we add NVD ingestion."""

    cve_id: Series[str] = pa.Field(str_matches=r"^CVE-\d{4}-\d{4,7}$")
    cvss: Series[float] = pa.Field(ge=0.0, le=10.0, nullable=True)
    published: Series[pa.DateTime]
