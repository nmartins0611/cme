#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Ansible module to query CME MCP for controls that mitigate a given CVE."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: cme_query
short_description: Query CME MCP for controls that mitigate a CVE
version_added: "1.0.0"
description:
  - Given a CVE's CVSS vector string and/or CWE IDs, queries the CME MCP
    server to find which defensive controls are relevant.
  - Returns a list of CME-IDs suitable for building a dynamic Ansible profile.
  - This is the intelligence step — CME tells you what to verify and remediate.
options:
  cvss_vector:
    description:
      - CVSS vector string from the CVE advisory.
      - CME finds controls whose CVSS impacts match the vector's metrics.
    type: str
  cwe_ids:
    description:
      - List of CWE IDs associated with the CVE.
      - CME finds controls that mitigate these weakness classes.
    type: list
    elements: str
  mcp_endpoint:
    description:
      - URL of the CME MCP server HTTP endpoint.
    type: str
    required: true
  include_verification:
    description:
      - Whether to include verification command details in the output.
    type: bool
    default: false
author:
  - CME Project
"""

EXAMPLES = r"""
- name: Find controls for a CVE by CVSS vector
  cme.controls.cme_query:
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    mcp_endpoint: "http://cme-server:8000"
  register: cve_controls

- name: Find controls by CWE weakness
  cme.controls.cme_query:
    cwe_ids:
      - CWE-119
      - CWE-787
    mcp_endpoint: "http://cme-server:8000"
  register: cwe_controls

- name: Query with both vector and CWE for maximum coverage
  cme.controls.cme_query:
    cvss_vector: "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cwe_ids:
      - CWE-416
    mcp_endpoint: "http://cme-server:8000"
  register: combined_controls

- name: Build a dynamic profile from query results
  ansible.builtin.copy:
    content: |
      ---
      controls:
      {% for cid in combined_controls.cme_ids %}
        - {{ cid | lower | replace('-', '_') }}
      {% endfor %}
    dest: /tmp/cve_profile.yml
"""

RETURN = r"""
cme_ids:
  description: List of CME-IDs that mitigate the given CVE characteristics.
  type: list
  elements: str
  returned: always
controls:
  description: Full control details for each matched CME-ID.
  type: list
  elements: dict
  returned: always
  contains:
    cme_id:
      description: CME identifier.
      type: str
    control_name:
      description: Human-readable control name.
      type: str
    tactic:
      description: D3FEND-aligned tactic.
      type: str
    category:
      description: CME sub-category.
      type: str
    category_id:
      description: CME category slug.
      type: str
    control_layer:
      description: Technology layer.
      type: str
    description:
      description: Control description from the CME entry.
      type: str
    confidence:
      description: CME confidence rating.
      type: str
    matched_via:
      description: How this control was matched (cvss_vector, cwe, or both).
      type: str
query_summary:
  description: Summary of what was queried and how many results returned.
  type: dict
  returned: always
"""

import json
import traceback

from ansible.module_utils.basic import AnsibleModule

try:
    from urllib.request import urlopen, Request
    from urllib.error import URLError
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


def _mcp_post(url: str, payload: dict, session_id: str = "") -> tuple:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id

    data = json.dumps(payload).encode("utf-8")
    req = Request(url, data=data, headers=headers)
    response = urlopen(req, timeout=30)

    resp_session_id = response.headers.get("Mcp-Session-Id", session_id)
    raw = response.read().decode("utf-8")
    content_type = response.headers.get("Content-Type", "")

    if "text/event-stream" in content_type:
        result = _parse_sse(raw)
    else:
        result = json.loads(raw)

    if "error" in result:
        raise Exception("MCP error: {0}".format(result["error"]))

    return result, resp_session_id


def _parse_sse(raw: str) -> dict:
    for line in raw.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    raise Exception("No data line found in SSE response: {0}".format(raw[:200]))


def _mcp_init_session(url: str) -> str:
    payload = {
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "cme-ansible-query", "version": "1.0.0"},
        },
    }
    _, session_id = _mcp_post(url, payload)
    return session_id


def _extract_tool_result(result: dict) -> dict:
    content = result.get("result", {}).get("content", [])
    if content and content[0].get("type") == "text":
        return json.loads(content[0]["text"])
    return result.get("result", {})


def _call_tool(url: str, session_id: str, tool_name: str, arguments: dict, call_id: int) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments,
        },
    }
    result, _ = _mcp_post(url, payload, session_id)
    return _extract_tool_result(result)


def query_mitigations(endpoint: str, cvss_vector: str, cwe_ids: list, include_verification: bool) -> dict:
    url = endpoint.rstrip("/")
    if not url.endswith("/mcp"):
        url += "/mcp"

    session_id = _mcp_init_session(url)

    controls_by_id = {}
    call_id = 1

    if cvss_vector:
        vector_result = _call_tool(url, session_id, "get_mitigations_for_cvss_vector",
                                   {"cvss_vector": cvss_vector}, call_id)
        call_id += 1

        mitigations = vector_result.get("mitigations_by_metric", {})
        for metric, entries in mitigations.items():
            for entry in entries:
                cme_id = entry["cme_id"]
                if cme_id not in controls_by_id:
                    controls_by_id[cme_id] = {
                        "cme_id": cme_id,
                        "control_name": entry.get("control_name", ""),
                        "matched_via": "cvss_vector",
                        "matched_metrics": [metric],
                        "rationale": entry.get("rationale", ""),
                    }
                else:
                    if metric not in controls_by_id[cme_id].get("matched_metrics", []):
                        controls_by_id[cme_id]["matched_metrics"].append(metric)

    for cwe_id in (cwe_ids or []):
        cwe_result = _call_tool(url, session_id, "get_mitigations_for_weakness",
                                {"cwe_id": cwe_id}, call_id)
        call_id += 1

        if isinstance(cwe_result, list):
            cwe_entries = cwe_result
        else:
            cwe_entries = cwe_result.get("entries", cwe_result.get("mitigations", []))
            if not cwe_entries and "cme_id" in cwe_result:
                cwe_entries = [cwe_result]

        for entry in cwe_entries:
            cme_id = entry.get("cme_id", "")
            if not cme_id:
                continue
            if cme_id in controls_by_id:
                controls_by_id[cme_id]["matched_via"] = "both"
                controls_by_id[cme_id]["matched_cwe"] = controls_by_id[cme_id].get("matched_cwe", [])
                if cwe_id not in controls_by_id[cme_id]["matched_cwe"]:
                    controls_by_id[cme_id]["matched_cwe"].append(cwe_id)
            else:
                controls_by_id[cme_id] = {
                    "cme_id": cme_id,
                    "control_name": entry.get("control_name", ""),
                    "tactic": entry.get("tactic", ""),
                    "category": entry.get("category", ""),
                    "control_layer": entry.get("control_layer", ""),
                    "matched_via": "cwe",
                    "matched_cwe": [cwe_id],
                }

    # Enrich with full details if needed
    for cme_id, ctrl in controls_by_id.items():
        if not ctrl.get("tactic") or include_verification:
            detail = _call_tool(url, session_id, "get_cme_entry", {"cme_id": cme_id}, call_id)
            call_id += 1
            if "error" not in detail:
                ctrl["tactic"] = detail.get("tactic", ctrl.get("tactic", ""))
                ctrl["category"] = detail.get("category", ctrl.get("category", ""))
                ctrl["category_id"] = detail.get("category_id", ctrl.get("category_id", ""))
                ctrl["control_layer"] = detail.get("control_layer", ctrl.get("control_layer", ""))
                ctrl["confidence"] = detail.get("confidence", "Medium")
                ctrl["description"] = detail.get("description", ctrl.get("description", ""))
                if include_verification:
                    ctrl["verification"] = detail.get("verification", {})

    controls = sorted(controls_by_id.values(), key=lambda c: c["cme_id"])
    cme_ids = [c["cme_id"] for c in controls]

    return {
        "cme_ids": cme_ids,
        "controls": controls,
        "query_summary": {
            "cvss_vector": cvss_vector or "(not provided)",
            "cwe_ids": cwe_ids or [],
            "total_controls_found": len(cme_ids),
            "matched_by_vector": len([c for c in controls if c["matched_via"] in ("cvss_vector", "both")]),
            "matched_by_cwe": len([c for c in controls if c["matched_via"] in ("cwe", "both")]),
        },
    }


def run_module():
    module_args = dict(
        cvss_vector=dict(type="str", required=False, default=""),
        cwe_ids=dict(type="list", elements="str", required=False, default=[]),
        mcp_endpoint=dict(type="str", required=True),
        include_verification=dict(type="bool", required=False, default=False),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        required_one_of=[["cvss_vector", "cwe_ids"]],
        supports_check_mode=True,
    )

    cvss_vector = module.params["cvss_vector"]
    cwe_ids = module.params["cwe_ids"]
    mcp_endpoint = module.params["mcp_endpoint"]
    include_verification = module.params["include_verification"]

    try:
        if not HAS_URLLIB:
            module.fail_json(msg="urllib is required for MCP communication")

        result = query_mitigations(mcp_endpoint, cvss_vector, cwe_ids, include_verification)
        module.exit_json(changed=False, **result)

    except Exception as e:
        module.fail_json(
            msg="Failed to query CME MCP: {0}".format(str(e)),
            exception=traceback.format_exc(),
        )


def main():
    run_module()


if __name__ == "__main__":
    main()
