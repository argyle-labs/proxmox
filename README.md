<p align="center">
  <img src="assets/icon-256.png" width="120" alt="proxmox" />
</p>

# proxmox

[Proxmox VE](https://www.proxmox.com/) is a virtualization platform for KVM VMs and LXC containers. This first-party [orca](https://github.com/argyle-labs/orca) plugin **connects orca to existing Proxmox nodes over their REST API** (`https://<node>:8006`) — it deploys nothing itself.

It works two ways, both documented:

- **With orca** — register nodes, then drive guests + inspect the cluster through orca's generic surfaces plus a few proxmox-specific tools.
- **Without orca (standalone)** — stand up Proxmox itself (bare-metal or nested VM) and generate an API token by hand. See the guides below.

---

## Run it without orca

- **Install Proxmox VE** — bare-metal *or* nested in a VM: [docs/setup.md](docs/setup.md).
- **Generate an API token** for the plugin to authenticate with: [docs/tokens.md](docs/tokens.md).

Proxmox listens on `:8006` (self-signed cert by default). Nothing else is deployed — the plugin is a client of that endpoint.

---

## With orca

### 1. Register nodes — the endpoint registry

`proxmox.*` is the registry of Proxmox **endpoints**. The token secret is stored via orca's **secrets domain** (`#[secret]`), never plaintext in the row.

| command | what it does |
| --- | --- |
| `proxmox.create` | register an endpoint (one or more `--address kind=url`, `token_id`, `token_secret`, `insecure`, `enabled`) |
| `proxmox.list` | list registered endpoints (secret excluded) |
| `proxmox.detail` | show one endpoint (secret excluded) |
| `proxmox.update` | edit an endpoint's address / token / flags |
| `proxmox.delete` | unregister an endpoint |

Each endpoint carries an ordered **address fallback list** rather than a single URL. Register one or more paths — `--address fqdn=https://pve.example.com --address lan=http://<ip>:8006 --address tailscale=https://<ts-name>:8006` — and orca tries each enabled entry in order, caching the last-known-good path and falling through on a connect error. The free-form `kind` label doubles as the locality class the fewest-hop router uses to prefer the cheapest reachable path.

### 2. Manage guests — the generic unit surface

Every VM and LXC across every enabled endpoint is a **unit** (`kind = vm` or `lxc`). Drive them through orca's five-verb `unit` surface — no proxmox-specific verbs:

| verb | action(s) | what it does |
| --- | --- | --- |
| `list` | — | enumerate guests across the cluster (`/cluster/resources`) |
| `detail` | — | inspect one guest (typed, proxmox-rich payload); for a running LXC on this node, also probes the guest standard and reports it in `guard_violations` |
| `update` | `start` | start the guest |
| `update` | `stop` | hard-stop the guest |
| `update` | `shutdown` | ACPI shutdown |
| `update` | `reboot` | reboot the guest |
| `update` | `backup` | vzdump the guest to backup storage, waited on; returns a `BackupRef` |
| `update` | `restore` | restore the guest in place from a `BackupRef` |
| `update` | `update` | LXC only: back up, then run the in-container updater; a plan unless the payload sets `"execute": true` (see [docs/guest-standard.md](docs/guest-standard.md)) |
| `create` | `provision` | provision a new VM/LXC (needs a typed payload; LXC needs `ostemplate`) |
| `delete` | — | destroy the guest |

### 3. Inspect the cluster + manage access — proxmox tools

| command | what it does |
| --- | --- |
| `proxmox.nodes` | list cluster member nodes for an endpoint |
| `proxmox.node_detail` | list the VMs + LXCs on one node |
| `proxmox.cluster_status` | cluster name, quorum, and node membership for an endpoint |
| `proxmox.cluster_list` | cluster status across all enabled endpoints |
| `proxmox.action` | lifecycle action (`start`/`stop`/`shutdown`/`reboot`) on a VM or LXC *(role: admin)* |
| `proxmox.host_logs` | fetch a node's systemd journal over HTTPS (mirrors `journalctl`) |
| `proxmox.access_bootstrap` | mint/rotate a least-privilege `orca@pve!orca` token via the PVE `/access` API + store it in the secrets domain (see [docs/tokens.md](docs/tokens.md)) |
| `proxmox.thin.audit` | per guest disk on LVM-thin storage: discard active / staged for next start / missing (with the exact value the fix writes), and thin allocation vs in-guest usage for running LXC root filesystems |
| `proxmox.thin.enable_discard` | set `mountoptions=discard` (LXC) / `discard=on` (VM disk) on a guest's thin disks *(role: admin; dry-run unless `execute: true`; staged until the guest's next start)* |
| `proxmox.backup_job.list` | scheduled vzdump jobs (`/cluster/backup`): schedule, storage, guest selection, mode, compress, notes template, retention |
| `proxmox.backup_job.upsert` | create or update a vzdump job; `prune_backups` defaults to `keep-last=10` *(role: admin; returns the diff against the current job unless `execute: true`)* |
| `proxmox.backup_job.delete` | delete a vzdump job *(role: admin; dry-run unless `execute: true`)* |
| `proxmox.guest.pxarexclude` | replace an LXC's `/.pxarexclude` through orca's lxc-push seam; the CT must run on this plugin's node *(role: admin; dry-run unless `execute: true`)* |
| `proxmox.guest.standard.audit` | an LXC's guest standard: OS, root console autologin, the orca `update` gate, the app's own updater, and a leftover forced-command backup key ([docs/guest-standard.md](docs/guest-standard.md)) |
| `proxmox.guest.standard.apply` | install root console autologin and the `update` gate in an LXC; idempotent *(role: admin; dry-run unless `execute: true`)* |
| `proxmox.guest.update` | back an LXC up through the PVE API, then run its updater *(role: admin; dry-run unless `execute: true`)* |
| `proxmox.lxc_data.plan` | per LXC on this node: its mounts, the app's data paths (per-app table), where each lives (rootfs / volume / bind) and how it is backed up (vzdump / `lxc-bind` host capture / uncovered) |

> `proxmox.action` overlaps with the unit `update` verb — both power-manage a guest. Use the unit surface for orca-managed fleet lifecycle; `proxmox.action` is the direct tool form.

Under the hood the plugin also contributes three **domain backends** over the plugin-toolkit capability seams — `cluster_roster` (fleet grouping), `topology` (parent-host nesting), and `unit` (the surface above) — registered automatically when orca spawns the plugin subprocess.

## Credentials

The plugin authenticates with a PVE API token. [docs/tokens.md](docs/tokens.md) covers both paths: generate one **by hand** (network-first / remote), or have the plugin **self-provision** a least-privilege token via `proxmox.access_bootstrap`. The secret is held in orca's secrets domain and never written in plaintext.

## Layout

- `src/lib.rs` — config, error types, PVE fetch helpers.
- `src/tools.rs` — endpoint registry (`endpoint_resource!`) + node/cluster inspection + `proxmox.action` + `host_logs`.
- `src/access.rs` — `proxmox.access_bootstrap`: least-privilege identity via the `/access` REST API.
- `src/thin_discard.rs` — `proxmox.thin.{audit,enable_discard}`: LVM-thin discard drift + allocation divergence.
- `src/unit_provider.rs` — the five-verb `vm` + `lxc` surface.
- `src/guest_standard.rs` — `proxmox.guest.standard.{audit,apply}` + `proxmox.guest.update`: console autologin and the backup-gated `update`.
- `src/lxc_guest.rs` — in-container reads/writes through orca's `lxc-exec` / `lxc-push` seams, and the allowlist mirror.
- `src/registration.rs`, `src/cluster_roster_impl.rs`, `src/topology.rs` — the three domain-backend registrations + impls.
- `specs/`, `spec-tools/`, `examples/pve_to_openapi.rs` — convert Proxmox's `apidoc.js` into the vendored OpenAPI spec (`build.rs` codegens the typed client).
- `docs/` — [setup.md](docs/setup.md) (install Proxmox), [tokens.md](docs/tokens.md) (API tokens), [guest-standard.md](docs/guest-standard.md) (console autologin + `update` gate).
- `assets/` — plugin icon.
