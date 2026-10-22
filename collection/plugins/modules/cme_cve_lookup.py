#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Ansible module to look up CVE CVSS vector and CWE IDs."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: cme_cve_lookup
short_description: Look up CVSS vector and CWE IDs for a CVE
version_added: "1.0.0"
description:
  - Resolves CVE metadata for a CME control query.
  - Checks shipped demo data first, then NVD, then the Red Hat CSAF VEX feed,
    then the CVE.org CVE Services API.
  - Stops at the first source that returns a CVSS vector or at least one CWE ID.
  - Prefers a CVSS 3.1 vector when a source publishes more than one version,
    because CME attenuation uses the 3.1 metrics.
  - Returns the CVSS vector, base score, severity, CWE IDs, and description.
options:
  cve_id:
    description:
      - CVE identifier (e.g. CVE-2026-109618).
    type: str
    required: true
  nvd_endpoint:
    description:
      - NVD CVE API 2.0 base URL.
    type: str
    required: true
  nvd_api_key:
    description:
      - Optional NVD API key. Sent only to C(nvd_endpoint).
      - Never written to reports.
    type: str
    no_log: true
    required: true
  rhsa_endpoint:
    description:
      - Red Hat CSAF VEX base URL.
      - The module requests C(/{year}/{cve_id}.json) under this base.
    type: str
    required: true
  cve_org_endpoint:
    description:
      - CVE.org CVE Services API base URL (CVE JSON 5 records).
      - The module requests C(/{cve_id}) under this base.
    type: str
    required: true
  timeout_seconds:
    description:
      - HTTP timeout in seconds for each remote request.
    type: int
    required: true
  retries:
    description:
      - Number of HTTP attempts per remote source before that source is skipped.
    type: int
    required: true
author:
  - CME Project
"""

EXAMPLES = r"""
- name: Look up CVE metadata
  cme.controls.cme_cve_lookup:
    cve_id: CVE-2026-109618
    nvd_endpoint: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    nvd_api_key: ""
    rhsa_endpoint: "https://security.access.redhat.com/data/csaf/v2/vex"
    cve_org_endpoint: "https://cveawg.mitre.org/api/cve"
    timeout_seconds: 30
    retries: 3
  register: cve_meta
"""

RETURN = r"""
cve_id:
  description: Normalized CVE identifier.
  type: str
  returned: always
description:
  description: English CVE description from the source that answered.
  type: str
  returned: always
cvss_vector:
  description: CVSS vector string. CVSS 3.1 is preferred when several versions exist.
  type: str
  returned: always
base_score:
  description: CVSS base score, or null if unavailable.
  type: float
  returned: always
severity:
  description: CVSS base severity (CRITICAL, HIGH, MEDIUM, LOW).
  type: str
  returned: always
cwe_ids:
  description: CWE identifiers associated with the CVE.
  type: list
  elements: str
  returned: always
source:
  description: Metadata source that answered (demo, nvd, rhsa, or cve.org).
  type: str
  returned: always
"""

import json
import time
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cme.controls.plugins.module_utils.cve_demo_data import (
    get_demo_cve,
)

try:
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


class CveLookupMiss(Exception):
    """A source did not return a usable CVSS vector or CWE list."""


_RHSA_CVSS_KEYS = ("cvss_v3", "cvss_v4", "cvss_v2")
_CVE_ORG_CVSS_KEYS = (
    "cvssV3_1",
    "cvssV31",
    "cvssV3_0",
    "cvssV30",
    "cvssV4_0",
    "cvssV40",
    "cvssV2_0",
)


def _public_headers() -> dict:
    return {
        "Accept": "application/json",
        "User-Agent": "cme.controls/1.0 (https://github.com/nmartins0611/cme)",
    }


def _nvd_headers(api_key: str) -> dict:
    headers = _public_headers()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _vector_rank(vector: str) -> int:
    if vector.startswith("CVSS:3.1"):
        return 0
    if vector.startswith("CVSS:3.0"):
        return 1
    if vector.startswith("CVSS:3."):
        return 2
    if vector.startswith("CVSS:4."):
        return 3
    return 4


def _read_json(url: str, headers: dict, timeout_seconds: int) -> dict:
    request = Request(url, headers=headers)
    try:
        response = urlopen(request, timeout=timeout_seconds)
    except HTTPError as exc:
        if exc.code == 404:
            raise CveLookupMiss("HTTP 404")
        raise
    raw = response.read().decode("utf-8")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CveLookupMiss("response was not JSON ({0})".format(exc))
    if not isinstance(payload, dict):
        raise CveLookupMiss("response JSON was not an object")
    return payload


def _get_json_with_retries(
    url: str,
    headers: dict,
    timeout_seconds: int,
    retries: int,
    source_label: str,
    module: AnsibleModule,
) -> dict:
    last_error = None
    attempt = 0
    while attempt < retries:
        try:
            return _read_json(url, headers, timeout_seconds)
        except CveLookupMiss:
            raise
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            last_error = exc
            attempt += 1
            if attempt < retries:
                module.warn(
                    "{0} lookup attempt {1}/{2} failed: {3}".format(
                        source_label, attempt, retries, exc
                    )
                )
                time.sleep(2 * attempt)
    raise CveLookupMiss(
        "{0} request failed after {1} attempts: {2}".format(
            source_label, retries, last_error
        )
    )


def _cve_record(
    cve_id: str,
    description: str,
    vector: str,
    score,
    severity: str,
    cwe_ids: list,
    source: str,
) -> dict:
    if not vector and not cwe_ids:
        raise CveLookupMiss(
            "{0} returned no CVSS vector or CWE IDs".format(source)
        )
    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_vector": vector,
        "base_score": score,
        "severity": severity,
        "cwe_ids": cwe_ids,
        "source": source,
    }


def _pick_cvss(metrics: dict) -> dict:
    chosen = None
    chosen_rank = 99
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            vector = data.get("vectorString") or ""
            if not vector:
                continue
            rank = _vector_rank(vector)
            if entry.get("type") == "Primary":
                rank -= 1
            if rank < chosen_rank:
                chosen_rank = rank
                chosen = data
    if chosen is None:
        return {"vector": "", "score": None, "severity": ""}
    return {
        "vector": chosen.get("vectorString") or "",
        "score": chosen.get("baseScore"),
        "severity": (chosen.get("baseSeverity") or "").upper(),
    }


def _extract_cwes(weaknesses: list) -> list:
    cwes = []
    for weakness in weaknesses:
        for desc in weakness.get("description") or []:
            value = desc.get("value") or ""
            if not value.startswith("CWE-"):
                continue
            suffix = value[4:]
            if suffix.isdigit() and value not in cwes:
                cwes.append(value)
    return cwes


def _extract_description(descriptions: list) -> str:
    for desc in descriptions:
        if desc.get("lang") == "en" and desc.get("value"):
            return desc["value"]
    if descriptions:
        return descriptions[0].get("value") or ""
    return ""


def _cwe_id_from_text(value: str) -> str:
    token = (value or "").split(" ", 1)[0]
    if token.startswith("CWE-") and token[4:].isdigit():
        return token
    return ""


def _cwes_from_problem_types(problem_types: list, cwes: list) -> list:
    found = list(cwes)
    for problem in problem_types or []:
        for desc in problem.get("descriptions") or []:
            cwe_id = desc.get("cweId") or _cwe_id_from_text(desc.get("description") or "")
            if cwe_id.startswith("CWE-") and cwe_id[4:].isdigit() and cwe_id not in found:
                found.append(cwe_id)
    return found


def _best_named_cvss(metric_groups: list, keys: tuple) -> dict:
    chosen = None
    chosen_rank = 99
    for metric in metric_groups:
        if not isinstance(metric, dict):
            continue
        for key in keys:
            data = metric.get(key)
            if not isinstance(data, dict):
                continue
            vector = data.get("vectorString") or ""
            if not vector:
                continue
            rank = _vector_rank(vector)
            if rank < chosen_rank:
                chosen_rank = rank
                chosen = data
    if chosen is None:
        return {"vector": "", "score": None, "severity": ""}
    return {
        "vector": chosen.get("vectorString") or "",
        "score": chosen.get("baseScore"),
        "severity": (chosen.get("baseSeverity") or "").upper(),
    }


def lookup_cve_from_nvd(
    cve_id: str,
    nvd_endpoint: str,
    api_key: str,
    timeout_seconds: int,
    retries: int,
    module: AnsibleModule,
) -> dict:
    url = "{0}?cveId={1}".format(nvd_endpoint.rstrip("/"), cve_id)
    payload = _get_json_with_retries(
        url,
        _nvd_headers(api_key),
        timeout_seconds,
        retries,
        "NVD",
        module,
    )
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        raise CveLookupMiss("CVE not found in NVD")

    cve = vulnerabilities[0].get("cve") or {}
    cvss = _pick_cvss(cve.get("metrics") or {})
    return _cve_record(
        cve_id,
        _extract_description(cve.get("descriptions") or []),
        cvss["vector"],
        cvss["score"],
        cvss["severity"],
        _extract_cwes(cve.get("weaknesses") or []),
        "nvd",
    )


def _rhsa_url(rhsa_endpoint: str, cve_id: str) -> str:
    parts = cve_id.split("-")
    if len(parts) < 3 or not parts[1].isdigit():
        raise CveLookupMiss("cannot derive a Red Hat VEX year from {0}".format(cve_id))
    return "{0}/{1}/{2}.json".format(
        rhsa_endpoint.rstrip("/"),
        parts[1],
        cve_id.lower(),
    )


def _rhsa_vulnerability(payload: dict, cve_id: str) -> dict:
    for vuln in payload.get("vulnerabilities") or []:
        if (vuln.get("cve") or "").upper() == cve_id:
            return vuln
    raise CveLookupMiss("Red Hat VEX document has no entry for this CVE")


def _rhsa_description(vuln: dict) -> str:
    for note in vuln.get("notes") or []:
        if note.get("category") == "description" and note.get("text"):
            return note["text"]
    return vuln.get("title") or ""


def _rhsa_cwes(vuln: dict) -> list:
    raw = vuln.get("cwe")
    if isinstance(raw, list):
        items = raw
    elif raw:
        items = [raw]
    else:
        items = []
    cwes = []
    for item in items:
        if isinstance(item, dict):
            cwe_id = item.get("id") or ""
        elif isinstance(item, str):
            cwe_id = item
        else:
            cwe_id = ""
        cwe_id = _cwe_id_from_text(cwe_id) or cwe_id
        if cwe_id.startswith("CWE-") and cwe_id[4:].isdigit() and cwe_id not in cwes:
            cwes.append(cwe_id)
    return cwes


def _pick_rhsa_cvss(scores: list) -> dict:
    groups = []
    for entry in scores or []:
        if isinstance(entry, dict):
            groups.append(entry)
    return _best_named_cvss(groups, _RHSA_CVSS_KEYS)


def lookup_cve_from_rhsa(
    cve_id: str,
    rhsa_endpoint: str,
    timeout_seconds: int,
    retries: int,
    module: AnsibleModule,
) -> dict:
    url = _rhsa_url(rhsa_endpoint, cve_id)
    payload = _get_json_with_retries(
        url,
        _public_headers(),
        timeout_seconds,
        retries,
        "RHSA",
        module,
    )
    vuln = _rhsa_vulnerability(payload, cve_id)
    cvss = _pick_rhsa_cvss(vuln.get("scores") or [])
    return _cve_record(
        cve_id,
        _rhsa_description(vuln),
        cvss["vector"],
        cvss["score"],
        cvss["severity"],
        _rhsa_cwes(vuln),
        "rhsa",
    )


def _cve_org_description(record: dict) -> str:
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    text = _extract_description(cna.get("descriptions") or [])
    if text:
        return text
    for adp in containers.get("adp") or []:
        text = _extract_description(adp.get("descriptions") or [])
        if text:
            return text
    return ""


def _cve_org_cwes(record: dict) -> list:
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    cwes = _cwes_from_problem_types(cna.get("problemTypes") or [], [])
    for adp in containers.get("adp") or []:
        cwes = _cwes_from_problem_types(adp.get("problemTypes") or [], cwes)
    return cwes


def _pick_cve_org_cvss(record: dict) -> dict:
    containers = record.get("containers") or {}
    groups = []
    cna = containers.get("cna") or {}
    groups.extend(cna.get("metrics") or [])
    for adp in containers.get("adp") or []:
        groups.extend(adp.get("metrics") or [])
    return _best_named_cvss(groups, _CVE_ORG_CVSS_KEYS)


def lookup_cve_from_cve_org(
    cve_id: str,
    cve_org_endpoint: str,
    timeout_seconds: int,
    retries: int,
    module: AnsibleModule,
) -> dict:
    url = "{0}/{1}".format(cve_org_endpoint.rstrip("/"), cve_id)
    payload = _get_json_with_retries(
        url,
        _public_headers(),
        timeout_seconds,
        retries,
        "CVE.org",
        module,
    )
    state = ((payload.get("cveMetadata") or {}).get("state") or "").upper()
    if state and state != "PUBLISHED":
        raise CveLookupMiss("CVE.org record state is {0}".format(state))
    cvss = _pick_cve_org_cvss(payload)
    return _cve_record(
        cve_id,
        _cve_org_description(payload),
        cvss["vector"],
        cvss["score"],
        cvss["severity"],
        _cve_org_cwes(payload),
        "cve.org",
    )


def _warn_miss(module: AnsibleModule, source_label: str, exc: CveLookupMiss) -> None:
    module.warn(
        "{0} lookup did not return CVSS or CWE data: {1}".format(source_label, exc)
    )


def lookup_cve(
    cve_id: str,
    nvd_endpoint: str,
    api_key: str,
    rhsa_endpoint: str,
    cve_org_endpoint: str,
    timeout_seconds: int,
    retries: int,
    module: AnsibleModule,
) -> dict:
    demo = get_demo_cve(cve_id)
    if demo is not None:
        return demo

    misses = []
    try:
        return lookup_cve_from_nvd(
            cve_id, nvd_endpoint, api_key, timeout_seconds, retries, module
        )
    except CveLookupMiss as exc:
        misses.append("NVD: {0}".format(exc))
        _warn_miss(module, "NVD", exc)

    try:
        return lookup_cve_from_rhsa(
            cve_id, rhsa_endpoint, timeout_seconds, retries, module
        )
    except CveLookupMiss as exc:
        misses.append("RHSA: {0}".format(exc))
        _warn_miss(module, "RHSA", exc)

    try:
        return lookup_cve_from_cve_org(
            cve_id, cve_org_endpoint, timeout_seconds, retries, module
        )
    except CveLookupMiss as exc:
        misses.append("CVE.org: {0}".format(exc))
        _warn_miss(module, "CVE.org", exc)

    raise CveLookupMiss(
        "No CVSS vector or CWE IDs for {0} in demo data, NVD, RHSA, or CVE.org ({1})".format(
            cve_id, "; ".join(misses)
        )
    )


def run_module():
    module_args = dict(
        cve_id=dict(type="str", required=True),
        nvd_endpoint=dict(type="str", required=True),
        nvd_api_key=dict(type="str", required=True, no_log=True),
        rhsa_endpoint=dict(type="str", required=True),
        cve_org_endpoint=dict(type="str", required=True),
        timeout_seconds=dict(type="int", required=True),
        retries=dict(type="int", required=True),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    if not HAS_URLLIB:
        module.fail_json(msg="urllib is required for CVE lookup")

    if module.params["retries"] < 1:
        module.fail_json(msg="retries must be at least 1")
    if module.params["timeout_seconds"] < 1:
        module.fail_json(msg="timeout_seconds must be at least 1")

    cve_id = module.params["cve_id"].strip().upper()
    if not cve_id.startswith("CVE-"):
        module.fail_json(msg="cve_id must look like CVE-YYYY-NNNNN, got: {0}".format(cve_id))

    try:
        result = lookup_cve(
            cve_id,
            module.params["nvd_endpoint"],
            module.params["nvd_api_key"],
            module.params["rhsa_endpoint"],
            module.params["cve_org_endpoint"],
            module.params["timeout_seconds"],
            module.params["retries"],
            module,
        )
        module.exit_json(changed=False, **result)
    except Exception as exc:
        module.fail_json(
            msg="Failed to look up CVE metadata: {0}".format(str(exc)),
            exception=traceback.format_exc(),
        )


def main():
    run_module()


if __name__ == "__main__":
    main()
