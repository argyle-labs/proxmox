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

orca drives this plugin through its generic surface — rich, proxmox-specific data comes back in the typed `service.status` payload, never bespoke tools.

## Layout

- `src/` — the plugin (pure Rust): the `ServiceBackend` descriptor + `configure` / `status`.
- `assets/` — plugin icon.
