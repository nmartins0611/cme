{% raw %}
# Automated CVE Response and Compliance Verification with CME - Implementation Guide <!-- omit in toc -->

<!--
content_type: implementation-guide
product: Ansible Automation Platform
collections: cme.controls, ansible.posix, community.general, ansible.controller
companion: README-CME-Compliance.md
-->

This guide is the practitioner companion to [README-CME-Compliance.md](README-CME-Compliance.md). It gives the exact commands, variables, credentials, and Automation Controller fields required to deploy the CME MCP server, build the execution environment, load `cme.controls`, and run verify, remediate, report, CVE recommendation, and CVE response.

- [1. Prerequisites and Environment Setup](#1-prerequisites-and-environment-setup)
- [2. Configuration and Variables](#2-configuration-and-variables)
- [3. Step-by-Step Deployment](#3-step-by-step-deployment)
- [4. Execution](#4-execution)
- [5. Verification](#5-verification)
- [6. Troubleshooting](#6-troubleshooting)

<h2 id="1-prerequisites-and-environment-setup"></h2>

## 1. Prerequisites and Environment Setup

### Platform

| Component | Requirement |
|-----------|-------------|
| Ansible Automation Platform | 2.5 or newer. Workflow approval nodes and the `ansible.controller` collection are used by `collection/playbooks/configure_controller.yml`. |
| ansible-core | 2.15 or newer. Every role `meta/main.yml` sets `min_ansible_version: "2.15"`. |
| Control node (CLI) | A machine that can SSH to the target hosts and reach the controller API. |
| Target hosts | RHEL 8/9, Fedora, Ubuntu 22.04/24.04, or SLES 15 for the Linux roles. Windows is declared on role metadata; most verify tasks run only when `ansible_os_family != 'Windows'` or `ansible_os_family == 'RedHat'`. |
| CME MCP server | Self-hosted from this repo, or the public endpoint `https://cmetaxonomy.org`. |
| Container runtime | Docker Compose for the MCP stack. Podman or Docker plus `ansible-builder` 3 for the execution environment. |

### Ansible collections

`collection/galaxy.yml` declares:

| Collection | Constraint | Used for |
|------------|------------|----------|
| `cme.controls` | this repo, version 1.0.0 | 118 roles, `cme_query`, `cme_score`, `cme_cve_lookup`, profiles, playbooks |
| `ansible.posix` | `>=1.5.0` | `sysctl`, `selinux` |
| `community.general` | `>=7.0.0` | general modules used by generated roles |
| `ansible.controller` | ships with AAP 2.5 | `configure_controller.yml` only |
| `ansible.windows` | `>=3.0.0` in `ee/requirements.yml` | included in the EE build; absent from `galaxy.yml` |

`cme_query`, `cme_score`, and `cme_cve_lookup` use the Python standard library. `ee/requirements.txt` installs no extra Python packages.

### Execution environment

The definition is `ee/execution-environment.yml`:

- Base image: `registry.redhat.io/ansible-automation-platform-25/ee-minimal-rhel9:latest`
- Galaxy requirements: `ee/requirements.yml`
- `ee/requirements.yml` installs `cme.controls` from `https://github.com/nmartins0611/cme.git#collection/`
- Build argument `AH_TOKEN` is exported as `ANSIBLE_GALAXY_SERVER_AUTOMATION_HUB_TOKEN` so `ansible.posix` and `community.general` can be pulled from Automation Hub (`ee/ansible.cfg`)

The controller object created by `configure_controller.yml` defaults to image `quay.io/cme/cme-ee:latest`. That name is a placeholder. Build and push your own image, then pass it as `cme_ee_image`.

### CME MCP server

`docker-compose.yml` starts three services:

| Service | Role |
|---------|------|
| `postgres` | PostgreSQL 17. Database `cme`, user `cme`. |
| `seed` | Runs `uv run python -m src.seed`, then exits. |
| `server` | FastMCP streamable HTTP on container port 8000. |

The published port is `127.0.0.1:8000:8000`. An Automation Controller execution node cannot reach that bind address. Use one of these endpoints from jobs:

- Public: `https://cmetaxonomy.org` (modules append `/mcp` when it is missing)
- A self-hosted URL that execution nodes can route to, for example `http://cme-mcp.internal:8000`

Python for a non-container MCP process is `>=3.11` (`pyproject.toml`), installed with `uv`.

> **Warning:** Default database credentials.
>
> `docker-compose.yml` and the `Dockerfile` set `POSTGRES_PASSWORD` and `CME_PG_PASSWORD` to `cme`. The MCP HTTP service has no authentication of its own. Keep the compose publish address on `127.0.0.1` for a laptop, and change both passwords before any shared deployment. Store the replacement password outside git.

### Credentials

Create these before the first Controller run. Keep tokens and keys in Ansible Vault or a file outside the repository. Do not commit them.

| Credential | Where it is consumed | What to store |
|------------|----------------------|---------------|
| Automation Controller OAuth token | `configure_controller.yml` extra vars `controller_host` and `controller_oauthtoken` | Token for a user with organization admin (or system admin) on the target controller. The play asserts both variables are non-empty. |
| Machine SSH | Controller credential `CME Machine Credential`, type Machine | `cme_ssh_key` or `cme_ssh_password`. The playbook sets `username: root` and marks the task `no_log: true`. Pass exactly one of the two secrets. |
| CME MCP endpoint | Custom credential type `CME MCP Endpoint`, and job-template extra vars | URL only. The CaC play writes `cme_mcp_endpoint` into template extra vars. It creates credential `CME MCP Server` and does not attach that credential to the job templates. |
| Automation Hub token | `ansible-builder` build arg `AH_TOKEN` | Offline token from <a target="_blank" href="https://console.redhat.com/ansible/automation-hub/token">Automation Hub</a>. |
| `registry.redhat.io` | Pull of the EE base image | Red Hat registry credentials on the build host. |
| Container registry | Execution nodes pull `cme_ee_image` | A registry credential in Controller when the EE image is private. |
| NVD API key | `cve_recommend.yml` extra var `nvd_api_key` | Optional. The module marks it `no_log`. The CVE Response survey does not have a field for it. |
| SCM credential | Only if `cme_scm_url` is a private Git remote | `configure_controller.yml` sets `scm_type: git` and does not set `scm_credential`. The default URL `https://github.com/nmartins0611/cme.git` is public. |

`controller_validate_certs` is `false` in the play `vars`. Override it with `-e controller_validate_certs=true` when the controller certificate is in the trust store.

<h2 id="2-configuration-and-variables"></h2>

## 2. Configuration and Variables

### Playbook variables

Set these as extra vars, survey answers, or group vars. Defaults below are the values in the playbooks.

| Variable | Default | Playbooks | Purpose |
|----------|---------|-----------|---------|
| `cme_profile` | `minimal` | `verify.yml`, `remediate.yml`, `report.yml`, `verify_report.yml`, `full_cycle.yml`, `drift_check.yml` | Profile file name without `.yml` under `collection/profiles/`. |
| `cme_profile_path` | empty | same as `cme_profile` | Absolute or relative path to a custom profile. When non-empty, this path is loaded and `cme_profile` is ignored for control selection. |
| `cme_profiles_dir` | `{{ playbook_dir }}/../profiles` | same | Directory of shipped profiles. Leave it at the default when the playbook runs from the collection. |
| `cme_mcp_endpoint` | empty, except configure play default `http://cme-mcp:8000` | `report.yml`, `full_cycle.yml`, `cve_recommend.yml`, `cve_response.yml`, `configure_controller.yml` | MCP base URL. `cme_query` and `cme_score` append `/mcp` when the URL does not already end with `/mcp`. |
| `cme_database_path` | empty | `report.yml`, `full_cycle.yml`, `cme_score` | Path to a local `cme.db` for offline scoring. Mutually exclusive with `cme_mcp_endpoint` inside `cme_score`. |
| `cme_report_dir` | `.` on `report.yml`; `./reports` on `full_cycle.yml`; `{{ playbook_dir }}/../../reports` on `cve_recommend.yml`, `cve_response.yml`, `verify_report.yml` | report playbooks | Directory for HTML, Markdown, and JSON output. Set an explicit directory on Controller jobs. Files are written on the execution node and are removed when the job container exits. |
| `cme_stop_on_failure` | `false` | `remediate.yml` | Declared on the play. Remediation continues per control through `_apply_control.yml` rescue blocks. |
| `cve_id` | `CVE-UNKNOWN` | `cve_recommend.yml`, `cve_response.yml` | CVE identifier. `cve_recommend.yml` accepts `CVE-YYYY-NNNN`. |
| `cvss_vector` | empty | `cve_recommend.yml`, `cve_response.yml` | Full vector, for example `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. The MCP parser keeps metrics `AV`, `AC`, `PR`, `UI`, `S`, `C`, `I`, `A`. |
| `cwe_ids` | `[]` | `cve_recommend.yml`, `cve_response.yml` | List of CWE IDs. `cve_response.yml` reads this list. |
| `cwe_ids_csv` | empty | `cve_recommend.yml` and both surveys | Comma-separated CWE IDs. `cve_recommend.yml` merges this into the query. `cve_response.yml` does not read `cwe_ids_csv`. |
| `nvd_endpoint` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | `cve_recommend.yml` | NVD CVE API 2.0. Second lookup source, after shipped demo data. |
| `nvd_api_key` | empty | `cve_recommend.yml` | Optional NVD rate-limit key. Sent only to NVD. |
| `rhsa_endpoint` | `https://security.access.redhat.com/data/csaf/v2/vex` | `cve_recommend.yml` | Red Hat CSAF VEX base. Third source. Requests `/{year}/{cve_id}.json`. |
| `cve_org_endpoint` | `https://cveawg.mitre.org/api/cve` | `cve_recommend.yml` | CVE.org CVE Services API. Fourth source. Requests `/{cve_id}`. |
| `nvd_timeout_seconds` | `30` | `cve_recommend.yml` | Per-request timeout for NVD, Red Hat, and CVE.org. |
| `nvd_retries` | `3` | `cve_recommend.yml` | Attempts per remote source before that source is skipped. |
| `cme_save_baseline` | `false` | `drift_check.yml` | `true` writes the baseline and skips comparison. |
| `cme_baseline_path` | `./cme_baseline.json` | `drift_check.yml` | Baseline JSON path on the control node. |
| `controller_host` | empty | `configure_controller.yml` | Controller base URL, including `https://`. Required. |
| `controller_oauthtoken` | empty | `configure_controller.yml` | OAuth token. Required. |
| `controller_validate_certs` | `false` | `configure_controller.yml` | TLS verification for the controller API. |
| `cme_org_name` | `CME Security` | `configure_controller.yml` | Organization to create. |
| `cme_project_name` | `CME Compliance Collection` | `configure_controller.yml` | Project name. |
| `cme_scm_url` | `https://github.com/nmartins0611/cme.git` | `configure_controller.yml` | Git remote for the project. |
| `cme_scm_branch` | `main` | `configure_controller.yml` | Git branch. |
| `cme_inventory_name` | `CME Target Hosts` | `configure_controller.yml` | Inventory name. |
| `cme_ee_name` | `CME Execution Environment` | `configure_controller.yml` | EE object name. |
| `cme_ee_image` | `quay.io/cme/cme-ee:latest` | `configure_controller.yml` | Image execution nodes pull. Replace this. |
| `cme_credential_name` | `CME Machine Credential` | `configure_controller.yml` | Machine credential name. |
| `cme_target_host` | empty | `configure_controller.yml` | When non-empty, one host is added to the inventory. |
| `cme_ssh_key` | omitted | `configure_controller.yml` | Private key data for the machine credential. |
| `cme_ssh_password` | omitted | `configure_controller.yml` | Password for the machine credential. |
| `cme_webhook_url` | undefined | `configure_controller.yml` | When defined, creates notification template `CME Compliance Webhook`. |

### Shipped profiles

| `cme_profile` | File | Controls |
|---------------|------|----------|
| `minimal` | `collection/profiles/minimal.yml` | 25 |
| `rhel9_baseline` | `collection/profiles/rhel9_baseline.yml` | 55 |
| `container_host` | `collection/profiles/container_host.yml` | 16 |
| `full` | `collection/profiles/full.yml` | 118 |

Controller job templates for Verify, Remediate, Report, and the workflow set `cme_profile: rhel9_baseline` in template extra vars. Launch-time extra vars and survey variables replace that value.

### Per-control variables

Every role defaults file defines:

- `cme_<id>_skip` (boolean, default `false`). `verify.yml`, `remediate.yml`, and `full_cycle.yml` skip the role when this is true. `cve_response.yml` does not consult the skip flag.
- `cme_<id>_custom_remediation` (boolean, default `false`). On roles whose `tasks/main.yml` prints "Remediation requires environment-specific configuration", `true` suppresses that debug task. It does not load another task file. Site-specific steps belong in that role's `tasks/main.yml`.

Roles with an additional tunable, and the value their verify task asserts:

| Variable | Default | Verify expects |
|----------|---------|----------------|
| `cme_101_kernel_randomize_va_space` | `"2"` | `/proc/sys/kernel/randomize_va_space` equals `2` |
| `cme_107_kernel_modules_disabled` | `"1"` | the role's sysctl check for `1` |
| `cme_108_kernel_kptr_restrict` | `"1"` | the role's sysctl check for `1` |
| `cme_110_kernel_kexec_load_disabled` | `"1"` | the role's sysctl check for `1` |
| `cme_118_fs_protected_symlinks` | `"1"` | protected symlinks `1` |
| `cme_118_fs_protected_hardlinks` | `"1"` | protected hardlinks `1` |
| `cme_118_fs_protected_regular` | `"2"` | protected regular `2` |
| `cme_118_fs_protected_fifos` | `"2"` | protected fifos `2` |
| `cme_401_crypto_policy` | `"FUTURE"` | `update-crypto-policies --show` contains `FUTURE` |
| `cme_603_kernel_unprivileged_bpf_disabled` | `"1"` | unprivileged BPF disabled `1` |
| `cme_604_user_max_user_namespaces` | `"0"` | user namespaces `0` |
| `cme_604_kernel_unprivileged_userns_clone` | `"0"` | userns clone `0` |

Quote these values. The verify tasks compare strings.

`cme_401` remediation runs `update-crypto-policies --set` with `cme_401_crypto_policy`, then `tasks/verify.yml` searches for the literal `FUTURE`. A value such as `FIPS` changes the host and the control is still recorded as failed.

### Valid and invalid configuration

Valid custom profile (`/etc/ansible/cme-lab.yml`):

```yaml
---
controls:
  - cme_101
  - cme_301
  - cme_401
```

Valid group vars:

```yaml
---
cme_profile: rhel9_baseline
cme_301_skip: true
cme_101_kernel_randomize_va_space: "2"
cme_401_crypto_policy: "FUTURE"
```

Valid vault file for Controller configuration (`controller_credentials.yml`, encrypt this file):

```yaml
---
controller_host: https://controller.example.com
controller_oauthtoken: REPLACE_WITH_TOKEN
controller_validate_certs: true
cme_scm_url: https://github.com/nmartins0611/cme.git
cme_scm_branch: main
cme_ee_image: quay.io/example/cme-ee:1.0.0
cme_mcp_endpoint: https://cmetaxonomy.org
cme_target_host: 192.0.2.10
cme_ssh_key: |
  -----BEGIN OPENSSH PRIVATE KEY-----
  REPLACE
  -----END OPENSSH PRIVATE KEY-----
```

Invalid profile entries are rejected by role lookup or load the wrong object:

```yaml
---
controls:
  - CME-101                 # role names are lowercase with underscores
  - cme.controls.cme_301    # profiles store the short role name
  - cme_999                 # no such role
```

Invalid extra vars:

```yaml
cme_profile: rhel9-baseline          # file name is rhel9_baseline.yml
cme_profile_path: ""                 # empty is fine; a missing file path fails include_vars
cme_mcp_endpoint: http://127.0.0.1:8000   # valid on the laptop CLI; refused from an EE pod
```

Passing both `cme_mcp_endpoint` and `cme_database_path` to `cme_score` fails the module argument spec (`mutually_exclusive`).

<h2 id="3-step-by-step-deployment"></h2>

## 3. Step-by-Step Deployment

### Step 1. Start the MCP server

From the repository root:

```bash
docker compose up -d
docker compose ps
```

`postgres` is healthy, `seed` has exited 0, and `server` is listening. Confirm the session handshake the modules use:

```bash
curl -sS -D /tmp/cme-mcp.headers -o /tmp/cme-mcp.body \
  -X POST http://127.0.0.1:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cme-check","version":"1.0.0"}}}'
grep -i '^Mcp-Session-Id:' /tmp/cme-mcp.headers
grep -E 'serverInfo|"result"' /tmp/cme-mcp.body
```

A session id header and a JSON-RPC `result` mean the endpoint the collection calls is up. To reset the database: `docker compose down -v && docker compose up -d`.

For a single-user SQLite server on the same machine as the CLI:

```bash
uv sync
uv run python -m src.seed
uv run python -m src.validate
```

Offline scoring then uses `cme_database_path` pointed at `data/cme.db`. That path is on the control node, which is the execution node only for `connection: local` plays.

### Step 2. Install the collection on a control node

```bash
mkdir -p ./collections
ansible-galaxy collection install -p ./collections ./collection
ansible-galaxy collection install -p ./collections 'ansible.posix:>=1.5.0' 'community.general:>=7.0.0'
ansible-galaxy collection install -p ./collections ansible.controller
export ANSIBLE_COLLECTIONS_PATH="$PWD/collections${ANSIBLE_COLLECTIONS_PATH:+:$ANSIBLE_COLLECTIONS_PATH}"
ansible-galaxy collection list | grep -E 'cme.controls|ansible.posix|community.general|ansible.controller'
```

Invoke playbooks by FQCN (`cme.controls.verify`). That sets collection context so profile entries such as `cme_101` resolve to `cme.controls.cme_101`. Running `ansible-playbook collection/playbooks/verify.yml` from a git checkout does not set that context, and Ansible looks for a standalone role named `cme_101`.

### Step 3. Build and push the execution environment

Log in to `registry.redhat.io`, then from the repository:

```bash
ansible-builder build \
  -f ee/execution-environment.yml \
  -c ee \
  -t quay.io/example/cme-ee:1.0.0 \
  --build-arg AH_TOKEN="$AH_TOKEN"
podman push quay.io/example/cme-ee:1.0.0
```

Use the same tag as `cme_ee_image`. Execution nodes must be able to pull it. Add a registry credential in Controller when the repository is private, and associate it with the EE after the CaC run if `configure_controller.yml` did not set one (the play does not set a pull credential).

### Step 4. Write the CLI inventory

`inventory.yml` at the repository root (this file is yours; it is not shipped):

```yaml
---
all:
  hosts:
    rhel-vm:
      ansible_host: 192.0.2.10
      ansible_user: root
```

`remediate.yml` and phase 3 of `full_cycle.yml` set `become: true`. `cve_response.yml` phase 3 does not. On the Controller, the CVE Response template sets `become_enabled: true`, which covers that gap. On the CLI, add `-b` when you run `cme.controls.cve_response`.

### Step 5. Import the project and create Controller objects

`collection/playbooks/configure_controller.yml` creates the organization, credential type, credentials, EE, project, inventory, job templates, workflow, and optional webhook. Run it once from the control node:

```bash
ansible-playbook cme.controls.configure_controller \
  -e @controller_credentials.yml --ask-vault-pass
```

Equivalent explicit form:

```bash
ansible-playbook cme.controls.configure_controller \
  -e controller_host=https://controller.example.com \
  -e controller_oauthtoken="$CONTROLLER_TOKEN" \
  -e controller_validate_certs=true \
  -e cme_scm_url=https://github.com/nmartins0611/cme.git \
  -e cme_scm_branch=main \
  -e cme_ee_image=quay.io/example/cme-ee:1.0.0 \
  -e cme_mcp_endpoint=https://cmetaxonomy.org \
  -e cme_target_host=192.0.2.10 \
  -e @cme_ssh_secret.yml
```

`cme_ssh_secret.yml` contains only `cme_ssh_key` or `cme_ssh_password`.

In the Controller UI, open **Projects**, select `CME Compliance Collection`, and run **Sync**. `scm_update_on_launch` is true, so later jobs also update. Wait until the first sync succeeds before launching a template. Playbook paths are relative to the repository root.

#### Project

| Field | Value |
|-------|-------|
| Name | `CME Compliance Collection` |
| Organization | `CME Security` |
| SCM Type | Git |
| SCM URL | `cme_scm_url` (default `https://github.com/nmartins0611/cme.git`) |
| SCM Branch | `cme_scm_branch` (default `main`) |
| Update Revision on Launch | Enabled |
| SCM Credential | None, unless you add one for a private remote |

#### Inventory

| Field | Value |
|-------|-------|
| Name | `CME Target Hosts` |
| Organization | `CME Security` |
| Host | `cme_target_host` when that variable is non-empty |

Add the rest of the fleet in the UI or with `ansible.controller.host`. The CaC play adds at most one host.

#### Execution environment

| Field | Value |
|-------|-------|
| Name | `CME Execution Environment` |
| Image | `cme_ee_image` |
| Pull | Missing |

#### Credential type `CME MCP Endpoint`

| Field | Value |
|-------|-------|
| Kind | Cloud |
| Input | `cme_mcp_endpoint` (string, required) |
| Injector | extra var `cme_mcp_endpoint` |

#### Credentials

| Name | Type | Inputs |
|------|------|--------|
| `CME Machine Credential` | Machine | username `root`, `ssh_key_data` from `cme_ssh_key`, `password` from `cme_ssh_password` |
| `CME MCP Server` | CME MCP Endpoint | `cme_mcp_endpoint` |

#### Job templates

| Field | CME — Verify Posture | CME — Remediate | CME — Posture Report | CME — CVE Recommended Controls | CME — CVE Response |
|-------|----------------------|------------------|----------------------|--------------------------------|---------------------|
| Organization | CME Security | CME Security | CME Security | CME Security | CME Security |
| Project | CME Compliance Collection | CME Compliance Collection | CME Compliance Collection | CME Compliance Collection | CME Compliance Collection |
| Playbook | `collection/playbooks/verify.yml` | `collection/playbooks/remediate.yml` | `collection/playbooks/report.yml` | `collection/playbooks/cve_recommend.yml` | `collection/playbooks/cve_response.yml` |
| Inventory | CME Target Hosts | CME Target Hosts | CME Target Hosts | CME Target Hosts | CME Target Hosts |
| Execution environment | CME Execution Environment | CME Execution Environment | CME Execution Environment | CME Execution Environment | CME Execution Environment |
| Credential | CME Machine Credential | CME Machine Credential | CME Machine Credential | none | CME Machine Credential |
| Privilege escalation | disabled | enabled | disabled | disabled | enabled |
| Prompt on launch | variables | variables | variables | variables | variables |
| Extra vars | `cme_profile: rhel9_baseline` | `cme_profile: rhel9_baseline` | `cme_profile: rhel9_baseline` and `cme_mcp_endpoint` | `cme_mcp_endpoint`, empty `cvss_vector`, empty `cwe_ids`, `cve_id: CVE-UNKNOWN` | same CVE extra vars as the recommend template |
| Survey | none | none | none | CVE Details (below) | CVE Details (below) |

CVE Recommended Controls survey:

| Question | Variable | Type | Required | Default |
|----------|----------|------|----------|---------|
| CVE ID | `cve_id` | text | yes | empty |
| CVSS Vector | `cvss_vector` | text | no | empty |
| CWE IDs | `cwe_ids_csv` | text | no | empty |

Leave vector and CWE empty to look them up. Order is shipped demo data (`CVE-2026-109618`, `CVE-2026-109619`), then NVD, then Red Hat VEX, then CVE.org. The first source with a CVSS vector or a CWE ID wins. CVSS 3.1 is preferred when a source publishes more than one version. The playbook accepts a CVE id matching `CVE-[0-9]{4}-[0-9]+`.

CVE Response survey:

| Question | Variable | Type | Required | Default |
|----------|----------|------|----------|---------|
| CVE ID | `cve_id` | text | yes | empty |
| CVSS Vector | `cvss_vector` | text | yes | empty |
| CWE IDs | `cwe_ids_csv` | text | no | empty |

`cve_response.yml` requires `cvss_vector` or a non-empty `cwe_ids` list. The survey CWE box sets `cwe_ids_csv`, which this playbook ignores. Pass CWE IDs as a JSON list in extra vars when you need them on this template (see Execution).

#### Workflow template `CME — Full Compliance Cycle`

| Field | Value |
|-------|-------|
| Organization | CME Security |
| Inventory | CME Target Hosts |
| Prompt on launch | variables |
| Extra vars | `cme_profile: rhel9_baseline` |
| Description | Verify, then approval, then remediate, then report |

Nodes, in order:

| Identifier | Node | Success nodes |
|------------|------|---------------|
| `pre_verify` | Job template `CME — Verify Posture` | `approval_gate` |
| `approval_gate` | Approval `Approve Remediation`, timeout 3600 seconds | `remediate` |
| `remediate` | Job template `CME — Remediate` | `post_report` |
| `post_report` | Job template `CME — Posture Report` | none |

This workflow does not run `collection/playbooks/full_cycle.yml`. That file is the single-playbook CLI equivalent (PRE score, remediate, POST score, reports).

The approval node needs a user or team with the Approve role on the workflow. The playbook does not assign that role.

#### Notification

Notification template `CME Compliance Webhook` (type webhook, HTTP POST, `Content-Type: application/json`) is created only when `cme_webhook_url` is defined. The playbook does not attach the notification to a job template. Attach it in the UI to the templates that should emit events.

> **Tip:** Limit who can run CaC.
>
> `configure_controller.yml` stays a CLI play. The CaC run does not create a job template for itself. Restrict the vault file and the OAuth token to the automation team, because the play creates an organization, a root machine credential, and job templates with privilege escalation.

### Step 6. RBAC after the CaC run

| Template | Suggested execute access | Why |
|----------|--------------------------|-----|
| CME — Verify Posture | Security operations, auditors | Read-only SSH checks |
| CME — Posture Report | Security operations, auditors | Read-only checks plus MCP scoring |
| CME — CVE Recommended Controls | Security operations | Localhost MCP and NVD calls, no host changes |
| CME — Remediate | A small change-approved group | Changes sysctl, SELinux, packages, crypto policy |
| CME — CVE Response | The same change-approved group | Includes remediation |
| CME — Full Compliance Cycle | Operators who may request a change; approvers are separate | Stops on the approval node |

<h2 id="4-execution"></h2>

## 4. Execution

Run Verify before any remediate job. Remediation changes host state. Verification and CVE recommendation do not.

Duration scales with control count and SSH latency. The `minimal` profile runs 25 controls, `rhel9_baseline` runs 55, and `full` runs 118. Each control is one or more commands. A single lab host on `minimal` is typically a few minutes. `rhel9_baseline` remediation is longer when packages are installed or SELinux must relabel. Plan a maintenance window for Remediate, CVE Response, and the workflow's remediate node. Some controls (FIPS, dm-verity, Secure Boot, LUKS) only print a site-specific message and then verify; they do not finish configuration by themselves.

### CLI

Read-only posture (`minimal`):

```bash
ansible-playbook cme.controls.verify \
  -i inventory.yml \
  -e cme_profile=minimal
```

RHEL baseline verify, then remediate:

```bash
ansible-playbook cme.controls.verify \
  -i inventory.yml \
  -e cme_profile=rhel9_baseline

ansible-playbook cme.controls.remediate \
  -i inventory.yml \
  -e cme_profile=rhel9_baseline
```

`remediate.yml` already sets `become: true`. A check-mode preview:

```bash
ansible-playbook cme.controls.remediate \
  -i inventory.yml \
  -e cme_profile=minimal \
  --check
```

Posture report with scoring. Pick one backend:

```bash
ansible-playbook cme.controls.report \
  -i inventory.yml \
  -e cme_profile=rhel9_baseline \
  -e cme_mcp_endpoint=https://cmetaxonomy.org \
  -e cme_report_dir=./reports
```

```bash
ansible-playbook cme.controls.report \
  -i inventory.yml \
  -e cme_profile=rhel9_baseline \
  -e cme_database_path="$PWD/data/cme.db" \
  -e cme_report_dir=./reports
```

HTML per host, no MCP call:

```bash
ansible-playbook cme.controls.verify_report \
  -i inventory.yml \
  -e cme_profile=minimal \
  -e cme_report_dir=./reports
```

Single-playbook PRE/POST cycle:

```bash
ansible-playbook cme.controls.full_cycle \
  -i inventory.yml \
  -e cme_profile=minimal \
  -e cme_mcp_endpoint=https://cmetaxonomy.org \
  -e cme_report_dir=./reports
```

Drift baseline, then a later comparison:

```bash
ansible-playbook cme.controls.drift_check \
  -i inventory.yml \
  -e cme_profile=rhel9_baseline \
  -e cme_save_baseline=true \
  -e cme_baseline_path=./cme_baseline.json

ansible-playbook cme.controls.drift_check \
  -i inventory.yml \
  -e cme_profile=rhel9_baseline \
  -e cme_baseline_path=./cme_baseline.json
```

CVE recommendation (demo data for the PHP CVEs, otherwise NVD then Red Hat then CVE.org; no host changes):

```bash
ansible-playbook cme.controls.cve_recommend \
  -e cve_id=CVE-2024-38476 \
  -e cme_mcp_endpoint=https://cmetaxonomy.org \
  -e cme_report_dir=./reports
```

Air-gapped recommendation (NVD is skipped when both vector and CWE list are provided):

```bash
ansible-playbook cme.controls.cve_recommend \
  -e cve_id=CVE-2024-38476 \
  -e cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
  -e '{"cwe_ids": ["CWE-829"]}' \
  -e cme_mcp_endpoint=https://cmetaxonomy.org \
  -e cme_report_dir=./reports
```

Apply the generated profile:

```bash
ansible-playbook cme.controls.remediate \
  -i inventory.yml \
  -e cme_profile_path="$PWD/reports/cve_profile_CVE_2024_38476.yml"
```

Full CVE response. This play changes hosts. `-b` is required on the CLI:

```bash
ansible-playbook cme.controls.cve_response \
  -i inventory.yml \
  -b \
  -e cme_mcp_endpoint=https://cmetaxonomy.org \
  -e cve_id=CVE-2024-38476 \
  -e cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" \
  -e '{"cwe_ids": ["CWE-829"]}' \
  -e cme_report_dir=./reports
```

Phase 5 of `cve_response.yml` sends `base_score: 9.8` with whatever `cvss_vector` you passed. The modified vector is meaningful; the numeric score in that phase stays on the hardcoded 9.8 input. `cve_recommend.yml` passes the looked-up base score through when a source returned one.

### Controller UI

1. Sync project `CME Compliance Collection` if the last sync failed.
2. Launch `CME — Verify Posture`. Set `cme_profile` to `minimal` for the first run.
3. Read the job log. Each control prints `CME-XXX PASSED` or `CME-XXX FAILED`.
4. Launch `CME — Full Compliance Cycle` when the verify log is acceptable. Approve `Approve Remediation` within 3600 seconds.
5. Launch `CME — CVE Recommended Controls` and enter `CVE-2026-109618` or `CVE-2026-109619`. Leave the vector and CWE fields empty. Those two IDs resolve from demo data on the execution node. Any other CVE needs a path to NVD, Red Hat, or CVE.org.
6. Launch `CME — CVE Response` only with a vector. To include CWE IDs, launch from the API below so `cwe_ids` is a list.

### Controller API

Verify:

```bash
curl -sk -X POST \
  "https://controller.example.com/api/v2/job_templates/CME%20%E2%80%94%20Verify%20Posture/launch/" \
  -H "Authorization: Bearer $CONTROLLER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"extra_vars": {"cme_profile": "minimal"}}'
```

The template name uses an em dash (`CME — Verify Posture`), which is why the path contains `%E2%80%94`. List templates if you need the numeric id:

```bash
curl -sk \
  -H "Authorization: Bearer $CONTROLLER_TOKEN" \
  "https://controller.example.com/api/v2/job_templates/?name=CME%20%E2%80%94%20Verify%20Posture" \
  | jq '.results[].id'
```

CVE recommendation:

```bash
curl -sk -X POST \
  "https://controller.example.com/api/v2/job_templates/CME%20%E2%80%94%20CVE%20Recommended%20Controls/launch/" \
  -H "Authorization: Bearer $CONTROLLER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"extra_vars": {"cve_id": "CVE-2024-38476", "cme_mcp_endpoint": "https://cmetaxonomy.org", "cme_report_dir": "/tmp/cme-reports"}}'
```

CVE response with a CWE list:

```bash
curl -sk -X POST \
  "https://controller.example.com/api/v2/job_templates/CME%20%E2%80%94%20CVE%20Response/launch/" \
  -H "Authorization: Bearer $CONTROLLER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"extra_vars": {"cve_id": "CVE-2024-38476", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "cwe_ids": ["CWE-829"], "cme_mcp_endpoint": "https://cmetaxonomy.org", "cme_report_dir": "/tmp/cme-reports"}}'
```

Workflow:

```bash
curl -sk -X POST \
  "https://controller.example.com/api/v2/workflow_job_templates/CME%20%E2%80%94%20Full%20Compliance%20Cycle/launch/" \
  -H "Authorization: Bearer $CONTROLLER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"extra_vars": {"cme_profile": "rhel9_baseline"}}'
```

Poll a job you just launched (`jq -r .id` from the launch response):

```bash
curl -sk \
  -H "Authorization: Bearer $CONTROLLER_TOKEN" \
  "https://controller.example.com/api/v2/jobs/JOB_ID/" \
  | jq '{status, failed}'
```

<h2 id="5-verification"></h2>

## 5. Verification

### On the target host

After a successful `rhel9_baseline` or `minimal` remediate, these commands match the role assertions:

```bash
sysctl kernel.randomize_va_space
```

Expected: `kernel.randomize_va_space = 2` (CME-101).

```bash
getenforce
```

Expected: `Enforcing` (CME-301, Red Hat family).

```bash
update-crypto-policies --show
```

Expected: `FUTURE` (CME-401, Red Hat family).

```bash
sysctl kernel.kptr_restrict kernel.kexec_load_disabled kernel.unprivileged_bpf_disabled
```

Expected values when those roles ran and the host is Linux: `kernel.kptr_restrict = 1`, `kernel.kexec_load_disabled = 1`, `kernel.unprivileged_bpf_disabled = 1`.

### CLI recap

`cme.controls.verify` ends with:

```text
TASK [Display verification summary]
ok: [rhel-vm] => {
    "msg": "Verification complete: 25 controls checked on rhel-vm"
}
```

The count is `cme_loaded_profile.controls | length` (25 for `minimal`, 55 for `rhel9_baseline`). The play recap shows `failed=0`. Individual control asserts use `ignore_errors: true`, so a failed control still leaves the play recap green. Scroll for `CME-XXX FAILED` lines. The report playbooks record those as `status: failed`.

`cme.controls.report` prints:

```text
JSON report: ./reports/cme_posture_report.json
Markdown report: ./reports/cme_posture_report.md
```

and a block headed `CME POSTURE SCORE`.

`cme.controls.cve_recommend` writes:

- `reports/cve_CVE_2024_38476_recommended_controls.html`
- `reports/cve_CVE_2024_38476_recommended_controls.md`
- `reports/cve_CVE_2024_38476_recommended_controls.json`
- `reports/cve_profile_CVE_2024_38476.yml`

`cme.controls.cve_response` prints `CVE RESPONSE SUMMARY`, including PRE and POST active counts, and writes:

- `reports/cve_CVE-2024-38476_<hostname>_PRE.html`
- `reports/cve_CVE-2024-38476_<hostname>_POST.html`
- `reports/cve_profile_CVE_2024_38476.yml`

The response HTML names keep the hyphen in `cve_id`. The recommend report names replace hyphens with underscores. Both behaviors come from the playbooks.

`cme.controls.full_cycle` writes `cme_report_PRE.html`, `cme_report_POST.html`, and `cme_posture_report.md` under `cme_report_dir`. The final debug task also mentions `cme_posture_PRE.json` and `cme_posture_POST.json`; the play writes the HTML files and the Markdown file.

### Controller job output

Open the job and search the stdout for:

- `CME-101 PASSED` after ASLR is on
- `CME-301 PASSED` after SELinux enforcing
- `Verification complete:` on the verify template
- `Remediation complete:` on the remediate template
- `CME POSTURE SCORE` on the report template
- `CVE RESPONSE SUMMARY` on the CVE response template

A workflow that is waiting shows the approval node pending. Approving it starts `CME — Remediate`. Denying it stops the workflow before remediation.

Confirm a sample of the JSON report when you ran from the CLI:

```bash
jq '.summary' reports/cme_posture_report.json
```

`passed` plus `failed` is the number of control results collected. `mcp_attenuation` is present when `cme_mcp_endpoint` or `cme_database_path` was set and at least one control passed.

<h2 id="6-troubleshooting"></h2>

## 6. Troubleshooting

| Symptom | Where to look | Fix |
|---------|---------------|-----|
| `controller_host and controller_oauthtoken are required` | `configure_controller.yml` pre_tasks | Pass both extra vars. A vault file must decrypt (`--ask-vault-pass` or a vault password file). |
| `401` or `403` from the controller API | CaC task that calls `ansible.controller` | The token is missing admin or org-admin rights, or it was revoked. Create a new personal token and rerun. |
| Certificate verify failed talking to the controller | First `ansible.controller` task | Pass `-e controller_validate_certs=true` only after the controller CA is trusted. The play default is `false`. |
| `ERROR! the role 'cme_101' was not found` | First `include_role` in verify or remediate | Run `ansible-playbook cme.controls.verify` with `ANSIBLE_COLLECTIONS_PATH` pointing at the install path from Step 2. A filesystem path to `collection/playbooks/verify.yml` does not select the collection. |
| `include_vars` failed to find `.../profiles/<name>.yml` | Play pre_tasks | `cme_profile` must be `minimal`, `rhel9_baseline`, `container_host`, or `full`, or set `cme_profile_path` to a real file. |
| `cme_mcp_endpoint is required` | Phase 1 of `cve_response.yml` or `cve_recommend.yml` | Pass the URL. Template extra vars from CaC already set it when configure was given `cme_mcp_endpoint`. |
| `Provide cvss_vector, cwe_ids, or both` | `cve_response.yml` | The survey CWE field is `cwe_ids_csv` and is ignored here. Pass `cvss_vector`, or pass `cwe_ids` as a list via the API. |
| `Could not resolve a CVSS vector or CWE IDs` | `cve_recommend.yml` | Demo data, NVD, Red Hat, and CVE.org all missed. Pass `cvss_vector` and/or `cwe_ids`. |
| NVD HTTP 403 or 429 | `cme_cve_lookup` task | The module warns and continues to Red Hat, then CVE.org. Set `nvd_api_key` from Vault when you need the NVD record specifically. Raise `nvd_retries` only after the key is present. |
| `CME found no controls for this CVE` | `cve_response.yml` after `cme_query` | The vector contained none of `AV AC PR UI S C I A`, or the MCP data set has no matching impacts. Confirm with the curl handshake, then query with a known vector from the Execution section. |
| `urlopen` error, connection refused, or timed out on `cme_query` / `cme_score` | Module traceback in the job log | From an EE, `127.0.0.1:8000` is the pod, not your laptop. Point `cme_mcp_endpoint` at `https://cmetaxonomy.org` or a routed host. Modules POST to `<endpoint>/mcp`. |
| MCP HTTP 406 or empty SSE body | Module exception `No data line found in SSE response` | The server must answer `Accept: application/json, text/event-stream`. Confirm you are hitting `/mcp` on this project's server, not a different HTTP service on port 8000. |
| `mutually exclusive: mcp_endpoint\| database_path` | `cme_score` | Set one backend. |
| `No route to host` or `UNREACHABLE` | Play recap for the target | The inventory `ansible_host`, security groups, and the machine credential key must match. The CaC credential username is `root`. |
| `Permission denied` on `sysctl`, `getenforce`, or `dnf` | Failed task inside a role | Enable privilege escalation. It is already on for `CME — Remediate` and `CME — CVE Response`. Add `-b` for CLI `cve_response`. Enable it on the Verify template when read-only checks need root. |
| Package install failed, `no package` / `nothing provides` | `ansible.builtin.package` or `dnf` task | The host needs entitled RHEL repositories or an equivalent local repo before remediation. |
| `CME-301 FAILED — expected 'Enforcing'` after remediate | Role assert in the job log | `getenforce` still returns `Disabled` or `Permissive`. A switch from `Disabled` to `Enforcing` applies on the next boot. Reboot in a maintenance window, then rerun verify. A switch from `Permissive` applies immediately; if the assert still fails, read the `ansible.posix.selinux` task above the assert for the module error. |
| `CME-401 FAILED — expected 'FUTURE'` after you set another policy | `cme_401` verify | `tasks/verify.yml` searches for `FUTURE`. Keep `cme_401_crypto_policy: "FUTURE"` when you need a pass result. |
| Control still failed and the log says `manual remediation required` or `environment-specific configuration` | Role `tasks/main.yml` for CME-201 through CME-208, CME-701 through CME-706, CME-904 through CME-919, and CME-1301 through CME-1317 (`manual_remediation_required`). CME-402, CME-504, and CME-707 through CME-710 print the environment-specific debug line and then verify. | Those roles do not converge the host. Edit `tasks/main.yml` for that role when you have a local standard. `cme_<id>_custom_remediation: true` only suppresses the debug line. |
| Remediate job is green and the same controls still fail | `ignore_errors` on verify asserts, and `_apply_control.yml` rescue | The play is designed to continue. Search stdout for `remediation failed` and for `FAILED`. The JSON report `summary.failed` is the count that matters. |
| `cme_score` task skipped and the report attenuation table is empty | Report or full_cycle when condition | Scoring runs when a backend is set and at least one control passed. A profile that fails every check produces no attenuation block. |
| POST score shows modifications but the numeric score is still 9.8 | `cve_response.yml` phase 5 | That play hardcodes `base_score: 9.8`. Use `cve_recommend.yml` when you need the NVD base score in the simulation. |
| Workflow sits on approval, then fails | Workflow node `approval_gate`, timeout 3600 | Assign Approve on `CME — Full Compliance Cycle` to a team and approve the node. A denied or expired approval does not start remediation. |
| Job fails pulling `quay.io/cme/cme-ee:latest` | EE pull event on the job | Rebuild with your registry tag and rerun configure with that `cme_ee_image`, or edit the EE image in the UI. Attach a registry credential when the repo is private. |
| Galaxy build of the EE fails on Automation Hub | `ansible-builder` log | Export a current `AH_TOKEN` and pass `--build-arg AH_TOKEN=...`. `ee/ansible.cfg` expects that token for the certified collections. |
| Reports missing in the Controller UI | Job stdout shows paths under `/tmp` or `playbook_dir/../../reports` | Those files live on the execution node and disappear with the container. The durable record in Controller is the job stdout. For files, run the same playbook from the CLI with `cme_report_dir=./reports`. |
| Webhook never fires | `configure_controller.yml` notification task | Pass `-e cme_webhook_url=https://your-sink.example/cme` and rerun CaC. Then attach `CME Compliance Webhook` to the job template success/failure notifications in the UI. |
| Inventory has no hosts | Jobs fail immediately with no hosts matched | `cme_target_host` was empty during CaC. Add hosts to `CME Target Hosts`. |
| Project sync fails | Project detail in the UI | Default URL and branch are public `main`. A fork needs `cme_scm_url` and `cme_scm_branch` on the next CaC run. A private repo needs an SCM credential added in the UI. |
| Duplicate CME ids or schema errors after regenerating roles | `python scripts/generate_collection.py` then `uv run python -m src.validate` | Fix the JSON entry under `data/entries/` and regenerate. The collection roles are generated from those files. |

> **Tip:** Read control results in the report, then the recap.
>
> Verify asserts are marked `ignore_errors: true`, so a play recap of `failed=0` can still mean controls failed. Use `jq '.summary' reports/cme_posture_report.json` or the `CME-XXX FAILED` lines in the job log.

{% endraw %}
