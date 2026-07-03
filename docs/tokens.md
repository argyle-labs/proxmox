# Proxmox API tokens

This plugin talks to Proxmox VE over its REST API (`https://<node>:8006/api2/json`).
Every call authenticates with an **API token** — an `USER@REALM!TOKENID` id paired
with a secret UUID. Tokens are preferred over a password login: they can be scoped,
revoked independently, and never expire a session.

There are two ways to get one:

- **Manual** — you generate the token by hand on the node (console or root SSH) and
  hand orca the id + secret. Use this to bootstrap, or when you want to mint the
  credential yourself.
- **Self-provisioned (`proxmox.access_bootstrap`)** — give the plugin a root/admin
  token once, and it mints a dedicated least-privilege `orca@pve!orca` token for
  itself over the PVE **REST `/access` API** and stores it through orca's secrets
  domain. This is network-first: it runs from your laptop against a live node — no
  SSH or on-node shell required.

Either way the secret is held in orca's encrypted store (SQLCipher-backed) and marked
`#[secret]` on the endpoint — it is never written to disk in plaintext and never logged.

---

## 1. Manual token (remote / network-first)

Run on the node (console or SSH). The simplest form gives the token the full
privileges of the user it belongs to:

```sh
# root@pam token named "orca", inheriting root's privileges (privsep 0)
pveum user token add root@pam orca --privsep 0 --output-format json
```

Output — **the `value` is shown exactly once**:

```json
{
  "full-tokenid": "root@pam!orca",
  "info": { "privsep": "0" },
  "value": "db67dc0e-eaae-4503-9604-f2f2fdb0004a"
}
```

Give orca:

| field          | value                                            |
| -------------- | ------------------------------------------------ |
| `name`         | a label for this endpoint in the registry (e.g. `pve-node1`) |
| `address`      | one or more `--address kind=url` (e.g. `--address lan=https://192.0.2.10:8006`); repeat for fallback paths, tried in registered order |
| `token_id`     | the `full-tokenid`, e.g. `root@pam!orca`         |
| `token_secret` | the `value` UUID (secret — stored in the secrets domain) |
| `insecure`     | `true` for the default self-signed certificate   |
| `enabled`      | `true` to use the endpoint; `false` to soft-disable without deleting |

Verify the token directly:

```sh
curl -sk https://<node>:8006/api2/json/version \
  -H "Authorization: PVEAPIToken=root@pam!orca=<value>"
# {"data":{"version":"9.1.9",...}}
```

### Least-privilege variant (recommended for standing use)

`--privsep 0` is convenient for a quick validation but grants root. For a token orca
keeps, create a dedicated user + role with only the privileges the plugin needs and
leave privilege separation on (`--privsep 1`, the default):

This is the **exact identity `proxmox.access_bootstrap` mints** (role name,
privilege set, privsep, and ACL) — do it by hand when you'd rather not hand the
plugin a root token first. The `OrcaOps` privilege set below is verbatim from
`ORCA_OPS_PRIVS` in `src/access.rs`; keep the two in sync.

```sh
# OrcaOps: full guest lifecycle (audit, power, console, config, allocate/clone/
# backup, datastore space) but NO User.Modify / Permissions.Modify / Realm.* —
# a leaked runtime token cannot create users or escalate.
pveum role add OrcaOps -privs "VM.Audit VM.PowerMgmt VM.Console \
  VM.Config.Disk VM.Config.CPU VM.Config.Memory VM.Config.Network \
  VM.Config.Options VM.Config.Cloudinit VM.Allocate VM.Clone VM.Backup \
  Datastore.Audit Datastore.AllocateSpace Datastore.AllocateTemplate \
  Sys.Audit Sys.Console Pool.Audit"

# a token-only user in the PVE realm
pveum user add orca@pve

# grant the role at the root path (or scope to a pool/node for tighter blast radius)
pveum acl modify / --users orca@pve --roles OrcaOps

# the token, privilege-separated: its ACL is intersected with the user's
pveum user token add orca@pve orca --privsep 1 --comment 'orca runtime' --output-format json

# privsep tokens start with NO privileges of their own — grant the role to the token id too
pveum acl modify / --tokens 'orca@pve!orca' --roles OrcaOps
```

On a **cluster**, users / roles / ACLs / tokens live in the shared config
(`/etc/pve`), so run this once on any member node and it applies fleet-wide.
`role add` / `acl modify` are idempotent; re-running only rotates the token.

### Store the secret in 1Password

The one-time `value` is the durable credential — put it in 1Password (or your
secrets manager) as the source of truth, then hand it to orca. The token secret
never needs to be typed again; rotation re-mints it.

```sh
# personal 1Password, "orca" vault (any vault name works — orca is the convention)
op item create --vault orca --category "API Credential" \
  --title "orca@pve — <cluster> PVE runtime token" \
  "credential=<value>" "token id[text]=orca@pve!orca" "cluster[text]=<name>"
```

### Register the cluster in orca

A PVE cluster answers the same API on every member node, so register it as **one
endpoint with one `--address` per node** — orca tries them in registered order and
falls through on a dead node. The secret lands in orca's secrets domain, never a
plaintext column.

```sh
proxmox.create --name <cluster> \
  --address lan=https://<node-a>:8006 \
  --address lan=https://<node-b>:8006 \
  --address lan=https://<node-c>:8006 \
  --token-id 'orca@pve!orca' --token-secret <value> --insecure true

proxmox.nodes --endpoint <cluster>   # verify: lists every cluster member online
unit.list --kind lxc                  # verify: enumerates the cluster's guests
```

### Managing tokens

```sh
pveum user token list root@pam --output-format json   # list
pveum user token remove root@pam orca                  # revoke
```

---

## 2. Self-provisioning via `proxmox.access_bootstrap`

Instead of crafting the least-privilege identity above by hand, register an endpoint
with a **root/admin** token once and call `proxmox.access_bootstrap`. The plugin then
builds the whole least-privilege identity for itself over the PVE **REST `/access`
API** — no `pveum` shell, no SSH, works from your laptop against a live node:

1. **Ensure the role** — creates/updates an `OrcaOps` role with the audit +
   power-management privileges the plugin needs (`ensure_role`).
2. **Ensure the user** — creates the token-only `orca@pve` user (`ensure_user`).
3. **Grant the ACL** — binds the role to the user (and the token id) at `/`
   (`grant_acl`).
4. **Generate the token** — mints a privilege-separated `orca@pve!orca` token and
   returns the one-time secret (`generate_token`).
5. **Store + repoint** — the secret is saved through orca's **secrets domain** (the
   plugin never learns which backend — 1Password / native / … — holds it), and the
   endpoint is repointed from the bootstrap root token to `orca@pve!orca`.

Rotation re-runs the mint with a fresh token and deletes the old one (`delete_token`),
so a leaked token has a bounded lifetime. The plugin owns its Proxmox credential
end-to-end; orca just provides the encrypted place to keep it. Because it is pure REST,
this is the same path whether orca runs remotely or on the node itself.

---

## Notes

- Proxmox ships a self-signed cert on `:8006`. Set `insecure = true`, or install the
  node's CA and leave it `false`.
- Token ids are permanent once issued; to "rotate" you add a new token and remove the
  old one (there is no in-place secret reset) — `proxmox.access_bootstrap` automates this.
- A PVE cluster exposes the same API on every member node's `:8006`; register one
  `--address` per node you can reach and orca falls through them in order, so the
  endpoint stays live even when one node is down.
