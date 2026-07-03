<p align="center">
  <img src="assets/icon-256.png" width="120" alt="proxmox" />
</p>

# proxmox

Proxmox VE is a bare-metal virtualization platform for KVM VMs and LXC containers.

A first-party [orca](https://github.com/argyle-labs/orca) plugin (appliance integration).

This plugin **connects orca to an existing proxmox install** — there's nothing to deploy here. Stand up proxmox from the upstream project, then point orca at it.

---

## Run it without orca

Install proxmox per the upstream project: <https://www.proxmox.com/>. It listens on port `8006` by default; this plugin talks to that endpoint (host, credentials/token) — no container is deployed.


## With orca

orca drives this plugin through its generic **five-verb unit surface** — no
proxmox-specific tools. The plugin registers two kinds, `vm` (KVM/qemu) and `lxc`,
and maps the verbs onto the PVE REST API:

- **List** / **Detail** — enumerate guests across the cluster (`/cluster/resources`)
  and inspect one.
- **Update** — power actions (`start` / `stop` / `shutdown` / `reboot`) via the
  `action` field.
- **Create** / **Delete** — provision and destroy guests.

Rich, proxmox-specific data comes back in the typed unit payload.

## Credentials

The plugin authenticates to `https://<node>:8006` with a PVE API token. See
[docs/tokens.md](docs/tokens.md) for how to generate one — manually for
network-first / remote use, or self-provisioned by the plugin when orca runs on
the node. The token secret is held in orca's encrypted store and never written
in plaintext.

## Layout

- `src/` — the plugin (pure Rust): the `UnitProvider` (`vm` + `lxc` kinds, five
  verbs) and the `endpoint_resource!` config surface (host + API token).
- `spec-tools/`, `examples/pve_to_openapi.rs` — convert Proxmox's `apidoc.js` into
  an OpenAPI spec (the proxmox-only spec-refresh step).
- `assets/` — plugin icon.
