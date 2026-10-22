# -*- coding: utf-8 -*-

"""Local CVE records for the PHP request-memory demo.

Vectors are the NVD CVSS 3.1 primary scores. CME attenuation reads the 3.1
metrics (AV, AC, PR, UI, S, C, I, A). CWE IDs are the CNA problem types
published in the CVE.org record on 21 October 2026.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DEMO_CVE_DATA = {
    "CVE-2026-109618": {
        "cve_id": "CVE-2026-109618",
        "description": (
            "PHP uses longjmp() for out-of-memory (OOM) errors to exit the "
            "current context and abort handling of the request. Some contexts "
            "may not properly account for this scenario and leave request "
            "memory in an uninitialized state before performing an allocation. "
            "The subsequent request cleanup procedure may read or branch on "
            "this memory. Multiple OOM strategies can consistently trigger "
            "this condition and lead to remote code execution (RCE)."
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_score": 9.8,
        "severity": "CRITICAL",
        "cwe_ids": ["CWE-416", "CWE-755", "CWE-824", "CWE-1325", "CWE-1419"],
    },
    "CVE-2026-109619": {
        "cve_id": "CVE-2026-109619",
        "description": (
            "PHP has various global state that temporarily points into request "
            "memory. In some scenarios, global state may not be correctly "
            "reset, or may be repopulated after being reset. The global state "
            "may then refer to request memory even after it has been freed. "
            "Subsequent requests may read or branch on this stale state before "
            "it is fully initialized. Multiple strategies can trigger this "
            "condition and produce remote code execution (RCE)."
        ),
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "base_score": 9.8,
        "severity": "CRITICAL",
        "cwe_ids": ["CWE-416", "CWE-755", "CWE-824", "CWE-1325", "CWE-1419"],
    },
}


def get_demo_cve(cve_id: str):
    """Return a copy of the demo record for cve_id, or None when it is absent."""
    record = DEMO_CVE_DATA.get(cve_id)
    if record is None:
        return None
    return {
        "cve_id": record["cve_id"],
        "description": record["description"],
        "cvss_vector": record["cvss_vector"],
        "base_score": record["base_score"],
        "severity": record["severity"],
        "cwe_ids": list(record["cwe_ids"]),
        "source": "demo",
    }
