"""Generate Ansible Collection roles from CME entry data.

Reads all data/entries/*.json files and produces a complete Ansible Collection
under collection/roles/ with verify and remediate tasks for each CME control.
"""

import json
import re
import textwrap
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
ENTRIES_DIR = PROJECT_ROOT / "data" / "entries"
CATEGORIES_PATH = PROJECT_ROOT / "data" / "categories.json"
COLLECTION_DIR = PROJECT_ROOT / "collection"
ROLES_DIR = COLLECTION_DIR / "roles"

VERIFY_ONLY_CATEGORIES = frozenset([
    "network-isolation",
    "container-isolation",
    "application-input-validation",
    "application-controls",
])

SYSCTL_PATTERN = re.compile(
    r"(?:cat\s+/proc/sys/|sysctl\s+)([a-z_./]+)"
)

PLATFORM_MAP = {
    "linux": "ansible_os_family != 'Windows'",
    "rhel": "ansible_os_family == 'RedHat'",
    "windows": "ansible_os_family == 'Windows'",
    "any": "true",
    "kubernetes": "cme_kubernetes_host | default(false)",
}


def load_entries() -> list[dict]:
    entries = []
    for path in sorted(ENTRIES_DIR.glob("CME-*.json")):
        with open(path) as f:
            entries.append(json.load(f))
    return entries


def load_categories() -> dict:
    with open(CATEGORIES_PATH) as f:
        return json.load(f)


def role_name(cme_id: str) -> str:
    return cme_id.lower().replace("-", "_")


def sanitize_yaml_string(s: str) -> str:
    if any(c in s for c in ":{}'\"\\#|>&!%@`"):
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return f'"{s}"'


def generate_verify_tasks(entry: dict) -> str:
    verification = entry.get("verification", {})
    commands = verification.get("commands", [])
    method = verification.get("method", "")
    rname = role_name(entry["cme_id"])

    if not commands:
        no_cmd_lines = [
            f"---",
            f"# {entry['cme_id']}: {entry['control_name']}",
            f"# Verification method: {method}",
            f"# No machine-executable verification commands defined.",
            f"",
            f'- name: "{entry["cme_id"]} | No automated verification available"',
            f"  ansible.builtin.debug:",
            f'    msg: "Manual verification required: {method}"',
            f"  changed_when: false",
            f"",
        ]
        no_cmd_lines.append(_record_result_task(entry, "'skipped'", "'No automated verification'"))
        return "\n".join(no_cmd_lines)

    lines = [f"---\n# {entry['cme_id']}: {entry['control_name']}"]
    if method:
        lines.append(f"# Verification: {method}")
    lines.append("")

    for i, cmd in enumerate(commands):
        platform = cmd.get("platform", "linux")
        condition = PLATFORM_MAP.get(platform, f"ansible_system == '{platform}'")
        command_str = cmd["command"]
        expected = cmd["expected"]
        task_suffix = f" ({platform})" if len(commands) > 1 else ""

        lines.append(f'- name: "{entry["cme_id"]} | Run verification command{task_suffix}"')
        lines.append(f"  ansible.builtin.shell:")
        lines.append(f"    cmd: {sanitize_yaml_string(command_str)}")
        lines.append(f"  register: {rname}_verify_{i}")
        lines.append(f"  changed_when: false")
        lines.append(f"  failed_when: false")
        if condition != "true":
            lines.append(f"  when: {condition}")
        lines.append("")

        lines.append(f'- name: "{entry["cme_id"]} | Assert control is active{task_suffix}"')
        lines.append(f"  ansible.builtin.assert:")
        lines.append(f"    that:")
        lines.append(f"      - \"{rname}_verify_{i}.stdout is search('{_escape_regex(expected)}')\"")
        lines.append(f"    fail_msg: \"{entry['cme_id']} FAILED — expected '{_escape_yaml(expected)}'\"")
        lines.append(f"    success_msg: \"{entry['cme_id']} PASSED — {_escape_yaml(entry['control_name'])}\"")
        lines.append(f"  ignore_errors: true")
        lines.append(f"  register: {rname}_assert_{i}")
        if condition != "true":
            lines.append(f"  when: {condition} and {rname}_verify_{i} is not skipped")
        else:
            lines.append(f"  when: {rname}_verify_{i} is not skipped")
        lines.append("")

    status_expr = f"(({rname}_assert_0 is defined and {rname}_assert_0 is not failed) | ternary('passed', 'failed'))"
    detail_expr = f"(({rname}_assert_0 is defined) | ternary({rname}_assert_0.msg | default(''), 'not checked'))"
    lines.append(_record_result_task(entry, status_expr, detail_expr))

    return "\n".join(lines)


def _escape_regex(s: str) -> str:
    s = s.replace("\\", "\\\\")
    s = s.replace("'", "\\'")
    s = s.replace("(", "[(]")
    s = s.replace(")", "[)]")
    return s


def _escape_yaml(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _record_result_task(entry: dict, status_expr: str, detail_expr: str) -> str:
    """Generate a YAML task that appends a result dict to cme_results."""
    rname = role_name(entry["cme_id"])
    cme_id = entry["cme_id"]
    control = _escape_yaml(entry["control_name"]).replace("'", "\\'")
    tactic = entry["tactic"]
    category = entry["category"].replace("'", "\\'")
    layer = entry["control_layer"]
    confidence = entry.get("confidence", "Medium")

    result_dict = (
        f"{{'cme_id': '{cme_id}', "
        f"'control_name': '{control}', "
        f"'tactic': '{tactic}', "
        f"'category': '{category}', "
        f"'control_layer': '{layer}', "
        f"'confidence': '{confidence}', "
        f"'status': {status_expr}, "
        f"'detail': {detail_expr}}}"
    )

    return (
        f'- name: "{cme_id} | Record result"\n'
        f'  ansible.builtin.set_fact:\n'
        f'    cme_results: "{{{{ (cme_results | default([])) + [{result_dict}] }}}}"\n'
    )


def _extract_sysctl_key(command: str) -> str | None:
    match = SYSCTL_PATTERN.search(command)
    if match:
        key = match.group(1)
        return key.replace("/", ".")
    if "/proc/sys/" in command:
        proc_match = re.search(r"/proc/sys/(.+)", command)
        if proc_match:
            return proc_match.group(1).replace("/", ".")
    return None


def generate_remediate_tasks(entry: dict, categories: dict) -> str:
    category_id = entry.get("category_id", "")
    rname = role_name(entry["cme_id"])
    verification = entry.get("verification", {})
    commands = verification.get("commands", [])

    if category_id in VERIFY_ONLY_CATEGORIES:
        return _generate_verify_only_remediate(entry)

    if category_id == "kernel-hardening":
        return _generate_sysctl_remediate(entry, commands)

    if category_id == "syscall-bpf-controls":
        return _generate_sysctl_remediate(entry, commands)

    if category_id == "mandatory-access-control":
        return _generate_mac_remediate(entry, commands)

    if category_id == "cryptographic-controls":
        return _generate_crypto_remediate(entry, commands)

    if category_id == "filesystem-hardening":
        return _generate_filesystem_remediate(entry, commands)

    if category_id == "protocol-hardening":
        return _generate_service_remediate(entry, commands)

    if category_id == "credential-hardening":
        return _generate_service_remediate(entry, commands)

    if category_id in ("runtime-detection", "integrity-detection"):
        return _generate_service_remediate(entry, commands)

    if category_id == "patch-management":
        return _generate_patch_remediate(entry, commands)

    if category_id == "recovery-controls":
        return _generate_service_remediate(entry, commands)

    if category_id == "privilege-isolation":
        return _generate_sysctl_remediate(entry, commands)

    return _generate_generic_remediate(entry, commands)


def _generate_verify_only_remediate(entry: dict) -> str:
    rname = role_name(entry["cme_id"])
    return textwrap.dedent(f"""\
        ---
        # {entry['cme_id']}: {entry['control_name']}
        # This control requires manual/context-specific remediation.
        # Running verification only.

        - name: "{entry['cme_id']} | Set manual remediation required"
          ansible.builtin.set_fact:
            {rname}_manual_remediation_required: true

        - name: "{entry['cme_id']} | Run verification"
          ansible.builtin.include_tasks: verify.yml
    """)


def _generate_sysctl_remediate(entry: dict, commands: list[dict]) -> str:
    rname = role_name(entry["cme_id"])
    lines = [f"---\n# {entry['cme_id']}: {entry['control_name']}"]
    lines.append("")

    sysctl_applied = False
    seen_keys: set[str] = set()
    for cmd in commands:
        platform = cmd.get("platform", "linux")
        if platform == "windows":
            continue
        sysctl_key = _extract_sysctl_key(cmd.get("command", ""))
        if sysctl_key and sysctl_key not in seen_keys:
            seen_keys.add(sysctl_key)
            expected = cmd.get("expected", "").strip()
            value = _extract_sysctl_value(expected, sysctl_key)
            default_var = f"{rname}_{sysctl_key.replace('.', '_')}"
            lines.append(f'- name: "{entry["cme_id"]} | Set {sysctl_key}"')
            lines.append(f"  ansible.posix.sysctl:")
            lines.append(f"    name: {sysctl_key}")
            lines.append(f"    value: \"{{{{ {default_var} | default('{value}') }}}}\"")
            lines.append(f"    state: present")
            lines.append(f"    sysctl_set: true")
            lines.append(f"    reload: true")
            lines.append(f"  when: ansible_os_family != 'Windows'")
            lines.append("")
            sysctl_applied = True

    if not sysctl_applied:
        return _generate_generic_remediate(entry, commands)

    lines.append(f'- name: "{entry["cme_id"]} | Verify after remediation"')
    lines.append(f"  ansible.builtin.include_tasks: verify.yml")
    lines.append("")
    return "\n".join(lines)


def _extract_sysctl_value(expected: str, key: str) -> str:
    if "=" in expected:
        return expected.split("=", 1)[1].strip()
    return expected.strip()


def _generate_mac_remediate(entry: dict, commands: list[dict]) -> str:
    rname = role_name(entry["cme_id"])
    cme_id = entry["cme_id"]
    control = entry["control_name"].lower()

    lines = [f"---\n# {cme_id}: {entry['control_name']}"]
    lines.append("")

    if "selinux" in control:
        lines.append(f'- name: "{cme_id} | Ensure SELinux packages are installed"')
        lines.append(f"  ansible.builtin.package:")
        lines.append(f"    name:")
        lines.append(f"      - libselinux")
        lines.append(f"      - policycoreutils")
        lines.append(f"      - selinux-policy-targeted")
        lines.append(f"    state: present")
        lines.append(f"  when: ansible_os_family == 'RedHat'")
        lines.append("")
        lines.append(f'- name: "{cme_id} | Set SELinux to enforcing"')
        lines.append(f"  ansible.posix.selinux:")
        lines.append(f"    policy: targeted")
        lines.append(f"    state: enforcing")
        lines.append(f"  when: ansible_os_family == 'RedHat'")
        lines.append("")
    elif "apparmor" in control:
        lines.append(f'- name: "{cme_id} | Ensure AppArmor is installed and enabled"')
        lines.append(f"  ansible.builtin.package:")
        lines.append(f"    name:")
        lines.append(f"      - apparmor")
        lines.append(f"      - apparmor-utils")
        lines.append(f"    state: present")
        lines.append(f"  when: ansible_os_family == 'Debian'")
        lines.append("")
        lines.append(f'- name: "{cme_id} | Enable AppArmor service"')
        lines.append(f"  ansible.builtin.systemd:")
        lines.append(f"    name: apparmor")
        lines.append(f"    state: started")
        lines.append(f"    enabled: true")
        lines.append(f"  when: ansible_os_family == 'Debian'")
        lines.append("")
    else:
        return _generate_generic_remediate(entry, commands)

    lines.append(f'- name: "{cme_id} | Verify after remediation"')
    lines.append(f"  ansible.builtin.include_tasks: verify.yml")
    lines.append("")
    return "\n".join(lines)


def _generate_crypto_remediate(entry: dict, commands: list[dict]) -> str:
    cme_id = entry["cme_id"]
    rname = role_name(cme_id)
    lines = [f"---\n# {cme_id}: {entry['control_name']}"]
    lines.append("")

    has_crypto_policy = any("crypto-policies" in c.get("command", "") for c in commands)
    if has_crypto_policy:
        policy_var = f"{rname}_crypto_policy"
        expected = "FUTURE"
        for cmd in commands:
            if "crypto-policies" in cmd.get("command", ""):
                expected = cmd.get("expected", "FUTURE").strip()
                break
        lines.append(f'- name: "{cme_id} | Set system crypto policy"')
        lines.append(f"  ansible.builtin.command:")
        lines.append(f"    cmd: \"update-crypto-policies --set {{{{ {policy_var} | default('{expected}') }}}}\"")
        lines.append(f"  changed_when: true")
        lines.append(f"  when: ansible_os_family == 'RedHat'")
        lines.append("")
    else:
        return _generate_generic_remediate(entry, commands)

    lines.append(f'- name: "{cme_id} | Verify after remediation"')
    lines.append(f"  ansible.builtin.include_tasks: verify.yml")
    lines.append("")
    return "\n".join(lines)


def _generate_filesystem_remediate(entry: dict, commands: list[dict]) -> str:
    cme_id = entry["cme_id"]
    lines = [f"---\n# {cme_id}: {entry['control_name']}"]
    lines.append("")

    has_mount = any("mount" in c.get("command", "") or "findmnt" in c.get("command", "") for c in commands)
    has_chmod = any("stat" in c.get("command", "") or "chmod" in c.get("command", "") for c in commands)

    if has_mount or has_chmod:
        return _generate_generic_remediate(entry, commands)

    return _generate_generic_remediate(entry, commands)


def _generate_service_remediate(entry: dict, commands: list[dict]) -> str:
    cme_id = entry["cme_id"]
    lines = [f"---\n# {cme_id}: {entry['control_name']}"]
    lines.append("")

    service_found = False
    for cmd in commands:
        command_str = cmd.get("command", "")
        if "systemctl" in command_str:
            service_match = re.search(r"systemctl\s+\w+\s+(\S+)", command_str)
            if service_match:
                service_name = service_match.group(1).replace(".service", "")
                platform = cmd.get("platform", "linux")
                condition = PLATFORM_MAP.get(platform, "ansible_os_family != 'Windows'")
                lines.append(f'- name: "{cme_id} | Ensure {service_name} is running and enabled"')
                lines.append(f"  ansible.builtin.systemd:")
                lines.append(f"    name: {service_name}")
                lines.append(f"    state: started")
                lines.append(f"    enabled: true")
                if condition != "true":
                    lines.append(f"  when: {condition}")
                lines.append("")
                service_found = True

    if not service_found:
        return _generate_generic_remediate(entry, commands)

    lines.append(f'- name: "{cme_id} | Verify after remediation"')
    lines.append(f"  ansible.builtin.include_tasks: verify.yml")
    lines.append("")
    return "\n".join(lines)


def _generate_patch_remediate(entry: dict, commands: list[dict]) -> str:
    cme_id = entry["cme_id"]
    rname = role_name(cme_id)
    lines = [f"---\n# {cme_id}: {entry['control_name']}"]
    lines.append("")
    lines.append(f'- name: "{cme_id} | Ensure security updates are applied (RedHat)"')
    lines.append(f"  ansible.builtin.dnf:")
    lines.append(f"    name: \"*\"")
    lines.append(f"    security: true")
    lines.append(f"    state: latest")
    lines.append(f"  when: ansible_os_family == 'RedHat'")
    lines.append("")
    lines.append(f'- name: "{cme_id} | Ensure security updates are applied (Debian)"')
    lines.append(f"  ansible.builtin.apt:")
    lines.append(f"    upgrade: safe")
    lines.append(f"    update_cache: true")
    lines.append(f"  when: ansible_os_family == 'Debian'")
    lines.append("")
    lines.append(f'- name: "{cme_id} | Verify after remediation"')
    lines.append(f"  ansible.builtin.include_tasks: verify.yml")
    lines.append("")
    return "\n".join(lines)


def _generate_generic_remediate(entry: dict, commands: list[dict]) -> str:
    cme_id = entry["cme_id"]
    rname = role_name(cme_id)
    verification = entry.get("verification", {})
    method = verification.get("method", "")

    lines = [f"---\n# {cme_id}: {entry['control_name']}"]
    lines.append(f"# Remediation strategy: generic (review and customize for your environment)")
    if method:
        lines.append(f"# Verification method: {method}")
    lines.append("")
    lines.append(f'- name: "{cme_id} | Remediation requires environment-specific configuration"')
    lines.append(f"  ansible.builtin.debug:")
    lines.append(f"    msg: >-")
    lines.append(f"      {cme_id} ({entry['control_name']}) remediation depends on your")
    lines.append(f"      environment configuration. Override this role's tasks/main.yml")
    lines.append(f"      with site-specific remediation steps.")
    lines.append(f"  when: not ({rname}_custom_remediation | default(false))")
    lines.append("")
    lines.append(f'- name: "{cme_id} | Verify current state"')
    lines.append(f"  ansible.builtin.include_tasks: verify.yml")
    lines.append("")
    return "\n".join(lines)


def generate_vars(entry: dict) -> str:
    data = {
        "cme_id": entry["cme_id"],
        "cme_control_name": entry["control_name"],
        "cme_tactic": entry["tactic"],
        "cme_category": entry["category"],
        "cme_category_id": entry.get("category_id", ""),
        "cme_control_layer": entry["control_layer"],
        "cme_confidence": entry.get("confidence", "Medium"),
        "cme_cvss_vector_impacts": entry.get("cvss_vector_impacts", []),
        "cme_cwe_relationships": entry.get("cwe_relationships", []),
        "cme_platforms": entry.get("platforms", []),
    }

    lines = ["---"]
    for key, value in data.items():
        if isinstance(value, (list, dict)):
            lines.append(f"{key}: {json.dumps(value)}")
        else:
            lines.append(f"{key}: {sanitize_yaml_string(str(value))}")

    return "\n".join(lines) + "\n"


def generate_defaults(entry: dict) -> str:
    rname = role_name(entry["cme_id"])
    lines = ["---", f"# Tunable defaults for {entry['cme_id']}: {entry['control_name']}"]
    lines.append("")
    lines.append(f"# Set to true to skip this control")
    lines.append(f"{rname}_skip: false")
    lines.append("")
    lines.append(f"# Set to true if you have custom remediation tasks")
    lines.append(f"{rname}_custom_remediation: false")
    lines.append("")

    verification = entry.get("verification", {})
    commands = verification.get("commands", [])
    category_id = entry.get("category_id", "")

    if category_id in ("kernel-hardening", "syscall-bpf-controls", "privilege-isolation"):
        seen_defaults: set[str] = set()
        for cmd in commands:
            sysctl_key = _extract_sysctl_key(cmd.get("command", ""))
            if sysctl_key and sysctl_key not in seen_defaults:
                seen_defaults.add(sysctl_key)
                expected = cmd.get("expected", "").strip()
                value = _extract_sysctl_value(expected, sysctl_key)
                var_name = f"{rname}_{sysctl_key.replace('.', '_')}"
                lines.append(f"# Desired value for {sysctl_key}")
                lines.append(f"{var_name}: \"{value}\"")
                lines.append("")

    if category_id == "cryptographic-controls":
        for cmd in commands:
            if "crypto-policies" in cmd.get("command", ""):
                expected = cmd.get("expected", "FUTURE").strip()
                lines.append(f"# Crypto policy level")
                lines.append(f"{rname}_crypto_policy: \"{expected}\"")
                lines.append("")

    return "\n".join(lines) + "\n"


def generate_meta(entry: dict) -> str:
    platforms_list = entry.get("platforms", [])
    galaxy_platforms = []
    for p in platforms_list:
        p_lower = p.lower()
        if "rhel" in p_lower or "red hat" in p_lower:
            galaxy_platforms.append({"name": "EL", "versions": ["8", "9"]})
        elif "ubuntu" in p_lower:
            galaxy_platforms.append({"name": "Ubuntu", "versions": ["22.04", "24.04"]})
        elif "fedora" in p_lower:
            galaxy_platforms.append({"name": "Fedora", "versions": ["all"]})
        elif "sles" in p_lower or "suse" in p_lower:
            galaxy_platforms.append({"name": "SLES", "versions": ["15"]})
        elif "windows" in p_lower:
            galaxy_platforms.append({"name": "Windows", "versions": ["all"]})

    seen = set()
    unique_platforms = []
    for p in galaxy_platforms:
        key = p["name"]
        if key not in seen:
            seen.add(key)
            unique_platforms.append(p)

    lines = ["---", "galaxy_info:", f"  role_name: {role_name(entry['cme_id'])}"]
    lines.append(f"  author: CME Project")
    lines.append(f"  description: \"{entry['cme_id']}: {entry['control_name']}\"")
    lines.append(f"  license: Apache-2.0")
    lines.append(f"  min_ansible_version: \"2.15\"")

    if unique_platforms:
        lines.append(f"  platforms:")
        for p in unique_platforms:
            lines.append(f"    - name: {p['name']}")
            lines.append(f"      versions:")
            for v in p["versions"]:
                lines.append(f"        - \"{v}\"")

    lines.append("")
    lines.append("dependencies: []")
    lines.append("")

    return "\n".join(lines)


def generate_handlers(entry: dict) -> str:
    return "---\n# Handlers for " + entry["cme_id"] + "\n"


def generate_role(entry: dict, categories: dict) -> None:
    rname = role_name(entry["cme_id"])
    role_dir = ROLES_DIR / rname
    tasks_dir = role_dir / "tasks"
    defaults_dir = role_dir / "defaults"
    vars_dir = role_dir / "vars"
    handlers_dir = role_dir / "handlers"
    meta_dir = role_dir / "meta"

    for d in [tasks_dir, defaults_dir, vars_dir, handlers_dir, meta_dir]:
        d.mkdir(parents=True, exist_ok=True)

    (tasks_dir / "verify.yml").write_text(generate_verify_tasks(entry))
    (tasks_dir / "main.yml").write_text(generate_remediate_tasks(entry, categories))
    (defaults_dir / "main.yml").write_text(generate_defaults(entry))
    (vars_dir / "main.yml").write_text(generate_vars(entry))
    (handlers_dir / "main.yml").write_text(generate_handlers(entry))
    (meta_dir / "main.yml").write_text(generate_meta(entry))


def generate_profiles(entries: list[dict], categories: dict) -> None:
    profiles_dir = COLLECTION_DIR / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)

    all_ids = sorted([role_name(e["cme_id"]) for e in entries])
    _write_profile(profiles_dir / "full.yml", "Full profile — all CME controls", all_ids)

    rhel_ids = [
        role_name(e["cme_id"]) for e in entries
        if any("rhel" in p.lower() or "red hat" in p.lower() or "fedora" in p.lower()
               or "centos" in p.lower() for p in e.get("platforms", []))
        and e.get("category_id") not in VERIFY_ONLY_CATEGORIES
    ]
    _write_profile(profiles_dir / "rhel9_baseline.yml", "RHEL 9 baseline — remediable controls for Red Hat systems", sorted(rhel_ids))

    container_ids = [
        role_name(e["cme_id"]) for e in entries
        if e.get("category_id") in ("container-isolation", "syscall-bpf-controls")
        or any("kubernetes" in p.lower() or "container" in p.lower() for p in e.get("platforms", []))
    ]
    _write_profile(profiles_dir / "container_host.yml", "Container host profile — container and syscall controls", sorted(container_ids))

    minimal_categories = ("kernel-hardening", "mandatory-access-control", "cryptographic-controls")
    minimal_ids = [
        role_name(e["cme_id"]) for e in entries
        if e.get("category_id") in minimal_categories
        and e.get("confidence") == "High"
    ]
    _write_profile(profiles_dir / "minimal.yml", "Minimal profile — high-confidence kernel, MAC, and crypto controls", sorted(minimal_ids))


def _write_profile(path: Path, description: str, control_ids: list[str]) -> None:
    lines = [f"---", f"# {description}", f"controls:"]
    for cid in control_ids:
        lines.append(f"  - {cid}")
    lines.append("")
    path.write_text("\n".join(lines))


def main() -> None:
    entries = load_entries()
    categories = load_categories()

    print(f"Loaded {len(entries)} CME entries and {len(categories)} categories")

    if ROLES_DIR.exists():
        import shutil
        shutil.rmtree(ROLES_DIR)
    ROLES_DIR.mkdir(parents=True)

    for entry in entries:
        generate_role(entry, categories)
        print(f"  Generated role: {role_name(entry['cme_id'])}")

    generate_profiles(entries, categories)
    print(f"\nGenerated profiles in {COLLECTION_DIR / 'profiles'}")
    print(f"\nDone. {len(entries)} roles generated in {ROLES_DIR}")


if __name__ == "__main__":
    main()
