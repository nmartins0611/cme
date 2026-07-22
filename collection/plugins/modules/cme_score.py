#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Ansible module to calculate CVSS attenuation from active CME controls."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: cme_score
short_description: Calculate CVSS risk attenuation from active CME controls
version_added: "1.0.0"
description:
  - Given a list of active CME control IDs verified on a target host,
    queries the CME MCP server to calculate aggregated CVSS vector attenuation.
  - Returns the modified metrics showing how each CVSS base metric is shifted
    by the active defenses.
  - Can operate against a remote HTTP endpoint or a local SQLite database.
options:
  active_controls:
    description:
      - List of CME-IDs that are verified active on the target system.
    type: list
    elements: str
    required: true
  mcp_endpoint:
    description:
      - URL of the CME MCP server HTTP endpoint.
      - Mutually exclusive with C(database_path).
    type: str
  database_path:
    description:
      - Path to the local CME SQLite database file.
      - Used for offline scoring without a running MCP server.
      - Mutually exclusive with C(mcp_endpoint).
    type: path
  base_score:
    description:
      - Optional CVSS base score for simulation mode.
      - When provided along with C(base_vector), enables full risk simulation.
    type: float
  base_vector:
    description:
      - Optional CVSS base vector string for simulation mode.
      - When provided along with C(base_score), enables full risk simulation.
    type: str
author:
  - CME Project
"""

EXAMPLES = r"""
- name: Calculate attenuation for active controls
  cme.controls.cme_score:
    active_controls:
      - CME-101
      - CME-301
      - CME-601
    mcp_endpoint: "http://cme-server:8000"
  register: posture

- name: Display attenuated metrics
  ansible.builtin.debug:
    var: posture.attenuation

- name: Simulate CVE risk with active controls
  cme.controls.cme_score:
    active_controls:
      - CME-101
      - CME-301
    mcp_endpoint: "http://cme-server:8000"
    base_score: 9.8
    base_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
  register: simulation

- name: Score using local database
  cme.controls.cme_score:
    active_controls:
      - CME-101
      - CME-401
    database_path: "/opt/cme/data/cme.db"
  register: local_score
"""

RETURN = r"""
active_controls:
  description: Number of active CME controls provided.
  type: int
  returned: always
attenuation:
  description: Aggregated CVSS metric modifications from active controls.
  type: list
  elements: dict
  returned: success
  contains:
    metric:
      description: CVSS metric name (AV, AC, PR, UI, S, C, I, A).
      type: str
    modified_to:
      description: Value the metric is attenuated to.
      type: str
    contributing_controls:
      description: CME-IDs contributing to this metric modification.
      type: list
detail:
  description: Per-control impact detail.
  type: list
  returned: success
simulation:
  description: Full risk simulation results (only when base_score and base_vector provided).
  type: dict
  returned: when base_score and base_vector are provided
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

try:
    import sqlite3
    HAS_SQLITE = True
except ImportError:
    HAS_SQLITE = False


def query_http_attenuation(endpoint: str, active_ids: list) -> dict:
    url = endpoint.rstrip("/") + "/mcp"
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "calculate_attenuation",
            "arguments": {"active_cme_ids": active_ids},
        },
    }).encode("utf-8")

    req = Request(url, data=payload, headers={"Content-Type": "application/json"})
    response = urlopen(req, timeout=30)
    result = json.loads(response.read().decode("utf-8"))

    if "error" in result:
        raise Exception(f"MCP error: {result['error']}")

    content = result.get("result", {}).get("content", [])
    if content and content[0].get("type") == "text":
        return json.loads(content[0]["text"])
    return result.get("result", {})


def query_http_simulation(endpoint: str, active_ids: list, base_score: float, base_vector: str) -> dict:
    url = endpoint.rstrip("/") + "/mcp"
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "simulate_cve_risk",
            "arguments": {
                "base_score": base_score,
                "base_vector": base_vector,
                "active_cme_ids": active_ids,
            },
        },
    }).encode("utf-8")

    req = Request(url, data=payload, headers={"Content-Type": "application/json"})
    response = urlopen(req, timeout=30)
    result = json.loads(response.read().decode("utf-8"))

    if "error" in result:
        raise Exception(f"MCP error: {result['error']}")

    content = result.get("result", {}).get("content", [])
    if content and content[0].get("type") == "text":
        return json.loads(content[0]["text"])
    return result.get("result", {})


def query_sqlite_attenuation(db_path: str, active_ids: list) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    placeholders = ",".join("?" for _ in active_ids)
    rows = conn.execute(
        f"""SELECT v.cme_id, e.control_name, v.metric, v.from_value, v.to_value, v.rationale
            FROM cvss_vector_impacts v
            JOIN cme_entries e ON e.cme_id = v.cme_id
            WHERE v.cme_id IN ({placeholders})""",
        active_ids,
    ).fetchall()
    conn.close()

    if not rows:
        return {"active_controls": len(active_ids), "aggregated_attenuation": [], "detail": []}

    severity_order = {"N": 0, "L": 1, "A": 2, "P": 3, "U": 4, "H": 5, "C": 6}
    aggregated = {}
    details = []

    for row in rows:
        impact = {
            "cme_id": row["cme_id"],
            "control_name": row["control_name"],
            "metric": row["metric"],
            "from_value": row["from_value"],
            "to_value": row["to_value"],
            "rationale": row["rationale"],
        }
        details.append(impact)

        metric = row["metric"]
        if metric not in aggregated:
            aggregated[metric] = {
                "metric": metric,
                "modified_to": row["to_value"],
                "contributing_controls": [row["cme_id"]],
            }
        else:
            aggregated[metric]["contributing_controls"].append(row["cme_id"])
            current = severity_order.get(aggregated[metric]["modified_to"], 99)
            new = severity_order.get(row["to_value"], 99)
            if new < current:
                aggregated[metric]["modified_to"] = row["to_value"]

    return {
        "active_controls": len(active_ids),
        "aggregated_attenuation": list(aggregated.values()),
        "detail": details,
    }


def run_module():
    module_args = dict(
        active_controls=dict(type="list", elements="str", required=True),
        mcp_endpoint=dict(type="str", required=False, default=None),
        database_path=dict(type="path", required=False, default=None),
        base_score=dict(type="float", required=False, default=None),
        base_vector=dict(type="str", required=False, default=None),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        mutually_exclusive=[["mcp_endpoint", "database_path"]],
        required_one_of=[["mcp_endpoint", "database_path"]],
        supports_check_mode=True,
    )

    active_controls = [cid.upper() for cid in module.params["active_controls"]]
    mcp_endpoint = module.params["mcp_endpoint"]
    database_path = module.params["database_path"]
    base_score = module.params["base_score"]
    base_vector = module.params["base_vector"]

    result = dict(changed=False, active_controls=len(active_controls))

    try:
        if mcp_endpoint:
            if not HAS_URLLIB:
                module.fail_json(msg="urllib is required for HTTP mode")
            attenuation = query_http_attenuation(mcp_endpoint, active_controls)

            if base_score is not None and base_vector is not None:
                simulation = query_http_simulation(mcp_endpoint, active_controls, base_score, base_vector)
                result["simulation"] = simulation
        else:
            if not HAS_SQLITE:
                module.fail_json(msg="sqlite3 is required for local database mode")
            attenuation = query_sqlite_attenuation(database_path, active_controls)

        result["attenuation"] = attenuation.get("aggregated_attenuation", [])
        result["detail"] = attenuation.get("detail", [])

    except Exception as e:
        module.fail_json(msg=f"Failed to calculate CME attenuation: {str(e)}", exception=traceback.format_exc())

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
