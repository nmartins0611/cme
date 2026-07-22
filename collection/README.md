# CME Controls — Ansible Collection

Compliance-as-code Ansible Collection for the **Common Mitigation Enumeration (CME)** taxonomy. Provides roles to verify and remediate 118 defensive security controls with deterministic CVSS vector attenuation scoring.

## Installation

```bash
# From the repository (development)
ansible-galaxy collection install ./collection

# From Galaxy (when published)
ansible-galaxy collection install cme.controls
```

### Dependencies

The collection requires:

- `ansible.posix` >= 1.5.0
- `community.general` >= 7.0.0

## Quick Start

### Verify your posture

```bash
ansible-playbook cme.controls.verify -i inventory.yml -e cme_profile=rhel9_baseline
```

### Remediate gaps

```bash
ansible-playbook cme.controls.remediate -i inventory.yml -e cme_profile=rhel9_baseline
```

### Generate a scored posture report

```bash
ansible-playbook cme.controls.report -i inventory.yml \
  -e cme_profile=rhel9_baseline \
  -e cme_mcp_endpoint=http://cme-server:8000
```

### Detect drift from baseline

```bash
# Save baseline
ansible-playbook cme.controls.drift_check -i inventory.yml \
  -e cme_profile=rhel9_baseline -e cme_save_baseline=true

# Check for drift later
ansible-playbook cme.controls.drift_check -i inventory.yml \
  -e cme_profile=rhel9_baseline
```

## Profiles

Profiles define which CME controls to apply. Located in `profiles/`:

| Profile | Description |
|---------|-------------|
| `minimal` | High-confidence kernel, MAC, and crypto controls (25 controls) |
| `rhel9_baseline` | Full remediable baseline for Red Hat systems |
| `container_host` | Container runtime and syscall controls |
| `full` | All 118 CME controls (includes verify-only) |

### Custom profiles

Create a YAML file with a list of control IDs:

```yaml
---
controls:
  - cme_101   # ASLR
  - cme_301   # SELinux
  - cme_401   # Crypto Policy
  - cme_601   # seccomp
```

Use with: `-e cme_profile_path=/path/to/my_profile.yml`

## Roles

Each CME entry has a corresponding role (`cme_101`, `cme_301`, etc.) with:

| File | Purpose |
|------|---------|
| `tasks/main.yml` | Remediate — converge host to desired state |
| `tasks/verify.yml` | Verify — check-only, no changes |
| `defaults/main.yml` | Tunable parameters |
| `vars/main.yml` | CME metadata (tactic, CVSS impacts, CWE mappings) |
| `meta/main.yml` | Platform support and dependencies |

### Using roles directly

```yaml
- hosts: servers
  roles:
    - cme.controls.cme_101   # Enable ASLR
    - cme.controls.cme_301   # Set SELinux enforcing
    - cme.controls.cme_401   # Set crypto policy FUTURE

- hosts: servers
  tasks:
    - name: Verify ASLR only
      ansible.builtin.include_role:
        name: cme.controls.cme_101
        tasks_from: verify.yml
```

### Skipping controls

```yaml
# In host_vars or group_vars
cme_101_skip: true
cme_301_skip: true
```

### Tuning control parameters

```yaml
# Override the sysctl value for ASLR
cme_101_kernel_randomize_va_space: "2"

# Override crypto policy level
cme_401_crypto_policy: "FIPS"
```

## Verify-Only Controls

Some controls cannot be auto-remediated because they require context-specific configuration:

- **Network Isolation** (CME-201 through CME-208) — firewall rules are org-specific
- **Container Isolation** (CME-701 through CME-710) — depends on orchestrator
- **Application Input Validation** (CME-1301 through CME-1317) — requires code changes
- **Application Controls** (CME-904 through CME-919) — depends on app stack

These roles run verification and set `cme_XXXX_manual_remediation_required: true` as a fact.

## Scoring Module

The `cme.controls.cme_score` module calculates CVSS attenuation from active controls:

```yaml
- name: Calculate risk attenuation
  cme.controls.cme_score:
    active_controls:
      - CME-101
      - CME-301
      - CME-601
    mcp_endpoint: "http://cme-server:8000"
  register: posture

- name: Show attenuation
  ansible.builtin.debug:
    msg: "{{ posture.attenuation | cme_attenuation_summary }}"
```

Supports two backends:
- `mcp_endpoint` — remote CME MCP server (HTTP)
- `database_path` — local SQLite database (offline)

## Filter Plugins

| Filter | Description |
|--------|-------------|
| `cme_active_controls` | Extract passed CME-IDs from hostvars |
| `cme_failed_controls` | Extract failed CME-IDs from hostvars |
| `cme_platform_match` | Check if a control applies to the current host |
| `cme_attenuation_summary` | Format attenuation results as compact summary |
| `cme_controls_by_tactic` | Group controls by D3FEND tactic |
| `cme_controls_by_category` | Group controls by CME category |

## Regenerating Roles

When new CME entries are added to `data/entries/`, regenerate the collection:

```bash
python scripts/generate_collection.py
```

This reads all JSON entries and produces updated roles, preserving the collection structure.

## Integration with CME MCP Server

The collection is designed to work alongside the CME MCP server:

1. **Verify** — Ansible runs verification commands from CME entries across the fleet
2. **Remediate** — Ansible converges hosts to desired state
3. **Score** — Ansible calls `calculate_attenuation` via MCP to get environmental CVSS scores
4. **Report** — Per-host and fleet-wide posture reports with quantified risk reduction

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│   Ansible   │────>│  Target Hosts    │     │  CME MCP    │
│  Playbook   │     │  (verify/fix)    │     │  Server     │
│             │────────────────────────────>│  (score)    │
└─────────────┘     └──────────────────┘     └─────────────┘
```

## License

Apache-2.0
