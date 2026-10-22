"""Filter plugins for the CME Ansible Collection."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
name: cme_filters
author: CME Project
version_added: "1.0.0"
short_description: Filter plugins for CME control data
description:
  - Collection of Jinja2 filters for working with CME control verification
    results and platform matching across inventory hosts.
"""


class FilterModule(object):
    """CME filter plugins for Ansible."""

    def filters(self):
        return {
            "cme_active_controls": self.active_controls,
            "cme_failed_controls": self.failed_controls,
            "cme_platform_match": self.platform_match,
            "cme_attenuation_summary": self.attenuation_summary,
            "cme_controls_by_tactic": self.controls_by_tactic,
            "cme_controls_by_category": self.controls_by_category,
            "cme_recommend_enrich": self.recommend_enrich,
        }

    @staticmethod
    def active_controls(hostvars: dict, host: str = "") -> list:
        """Extract list of CME-IDs that passed verification on a host.

        Usage:
          {{ hostvars | cme_active_controls(inventory_hostname) }}
          {{ hostvars | cme_active_controls }}  (returns dict of host -> controls)
        """
        if host:
            host_vars = hostvars.get(host, {})
            return _extract_active_from_host(host_vars)

        result = {}
        for hostname, hvars in hostvars.items():
            active = _extract_active_from_host(hvars)
            if active:
                result[hostname] = active
        return result

    @staticmethod
    def failed_controls(hostvars: dict, host: str = "") -> list:
        """Extract list of CME-IDs that failed verification on a host.

        Usage:
          {{ hostvars | cme_failed_controls(inventory_hostname) }}
        """
        if host:
            host_vars = hostvars.get(host, {})
            return _extract_failed_from_host(host_vars)

        result = {}
        for hostname, hvars in hostvars.items():
            failed = _extract_failed_from_host(hvars)
            if failed:
                result[hostname] = failed
        return result

    @staticmethod
    def platform_match(entry_platforms: list, ansible_os_family: str, ansible_distribution: str = "") -> bool:
        """Check if a CME entry's platforms list matches the current host.

        Usage:
          {{ cme_platforms | cme_platform_match(ansible_os_family, ansible_distribution) }}
        """
        if not entry_platforms:
            return True

        os_family_lower = ansible_os_family.lower()
        distro_lower = ansible_distribution.lower()

        for platform in entry_platforms:
            p = platform.lower()
            if p == "any":
                return True
            if "rhel" in p and os_family_lower == "redhat":
                return True
            if "fedora" in p and distro_lower == "fedora":
                return True
            if "ubuntu" in p and distro_lower == "ubuntu":
                return True
            if "sles" in p and os_family_lower == "suse":
                return True
            if "windows" in p and os_family_lower == "windows":
                return True
            if "centos" in p and distro_lower == "centos":
                return True
            if "debian" in p and os_family_lower == "debian":
                return True
            if "kubernetes" in p:
                return True

        return False

    @staticmethod
    def attenuation_summary(attenuation_results: list) -> dict:
        """Summarize attenuation results into a compact report.

        Usage:
          {{ score_result.attenuation | cme_attenuation_summary }}
        """
        if not attenuation_results:
            return {"metrics_attenuated": 0, "summary": "No attenuation data"}

        metrics = []
        for item in attenuation_results:
            metric = item.get("metric", "?")
            modified_to = item.get("modified_to", "?")
            controls = item.get("contributing_controls", [])
            metrics.append(f"{metric}→{modified_to} (by {len(controls)} control(s))")

        return {
            "metrics_attenuated": len(attenuation_results),
            "modifications": metrics,
            "summary": "; ".join(metrics),
        }

    @staticmethod
    def recommend_enrich(controls: list) -> list:
        """Add role_id and remediability to CME query results.

        Usage:
          {{ cme_query_result.controls | cme_recommend_enrich }}
        """
        verify_only_categories = frozenset([
            "network isolation",
            "container isolation",
            "application input validation",
            "application controls",
            "network-isolation",
            "container-isolation",
            "application-input-validation",
            "application-controls",
        ])
        enriched = []
        for ctrl in controls:
            item = dict(ctrl)
            cme_id = ctrl.get("cme_id", "")
            category = (ctrl.get("category") or "").lower()
            category_id = (ctrl.get("category_id") or "").lower()
            auto_remediable = (
                category not in verify_only_categories
                and category_id not in verify_only_categories
            )
            item["tactic"] = ctrl.get("tactic") or "Unspecified"
            item["role_id"] = cme_id.lower().replace("-", "_")
            item["auto_remediable"] = auto_remediable
            item["remediation_mode"] = "ansible" if auto_remediable else "manual"
            matched_via = ctrl.get("matched_via", "")
            matched_labels = {
                "cvss_vector": "CVSS",
                "cwe": "CWE",
                "both": "CVSS + CWE",
            }
            item["matched_via_label"] = matched_labels.get(matched_via, matched_via)
            enriched.append(item)
        return enriched

    @staticmethod
    def controls_by_tactic(controls_vars: list) -> dict:
        """Group a list of CME control var dicts by tactic.

        Usage:
          {{ all_control_vars | cme_controls_by_tactic }}
        """
        result = {}
        for ctrl in controls_vars:
            tactic = ctrl.get("cme_tactic", "Unknown")
            result.setdefault(tactic, []).append(ctrl.get("cme_id", ""))
        return result

    @staticmethod
    def controls_by_category(controls_vars: list) -> dict:
        """Group a list of CME control var dicts by category.

        Usage:
          {{ all_control_vars | cme_controls_by_category }}
        """
        result = {}
        for ctrl in controls_vars:
            category = ctrl.get("cme_category", "Unknown")
            result.setdefault(category, []).append(ctrl.get("cme_id", ""))
        return result


def _extract_active_from_host(host_vars: dict) -> list:
    active = []
    for key, value in host_vars.items():
        if key.startswith("cme_") and key.endswith("_verify_0") and isinstance(value, dict):
            if value.get("rc", 1) == 0:
                cme_id = key.replace("_verify_0", "").replace("cme_", "CME-")
                active.append(cme_id)
    return sorted(active)


def _extract_failed_from_host(host_vars: dict) -> list:
    failed = []
    for key, value in host_vars.items():
        if key.startswith("cme_") and key.endswith("_verify_0") and isinstance(value, dict):
            if value.get("rc", 1) != 0 or value.get("failed", False):
                cme_id = key.replace("_verify_0", "").replace("cme_", "CME-")
                failed.append(cme_id)
    return sorted(failed)
