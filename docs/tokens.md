# Proxmox API tokens

This plugin talks to Proxmox VE over its REST API (`https://<node>:8006/api2/json`).
Every call authenticates with an **API token** — an `USER@REALM!TOKENID` id paired
with a secret UUID. Tokens are preferred over a password login: they can be scoped,
revoked independently, and never expire a session.

There are two ways to get one, matching orca's [network-first, then on-system](https://github.com/argyle-labs/orca)
model:

- **Remote / network-first** — you generate the token by hand on the node (or via
  root SSH) and hand orca the id + secret. Use this to drive a Proxmox node from
  another machine across the mesh.
- **On-system self-provisioning** — when orca runs *on* the Proxmox node, the plugin
  generates and rotates its **own** token via `pveum` and stores it through orca's
  secrets domain. Nothing to paste by hand.

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
| `base_url`     | `https://<node>:8006` (e.g. `https://10.10.10.8:8006`) |
| `token_id`     | the `full-tokenid`, e.g. `root@pam!orca`         |
| `token_secret` | the `value` UUID (secret)                        |
| `insecure`     | `true` for the default self-signed certificate   |

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

```sh
# a role that can see and power-manage guests, and read cluster/node status
pveum role add OrcaOps -privs "VM.Audit VM.PowerMgmt VM.Console \
  Datastore.Audit Sys.Audit Sys.Console"

# a token-only user in the PVE realm
pveum user add orca@pve

# grant the role at the root path (or scope to a pool/node for tighter blast radius)
pveum acl modify / --users orca@pve --roles OrcaOps

# the token, privilege-separated: its ACL is intersected with the user's
pveum user token add orca@pve orca --privsep 1 --output-format json

# privsep tokens start with NO privileges of their own — grant the role to the token id too
pveum acl modify / --tokens 'orca@pve!orca' --roles OrcaOps
```

Then feed orca `token_id = orca@pve!orca` and its `value`. Add `VM.Allocate` /
`Datastore.AllocateSpace` only if you want orca to **create** or **destroy** guests
(the five-verb `Create` / `Delete` verbs); omit them for a read/power-only token.

### Managing tokens

```sh
pveum user token list root@pam --output-format json   # list
pveum user token remove root@pam orca                  # revoke
```

---

## 2. On-system self-provisioning (orca on the node)

When orca is installed **on** the Proxmox node, the plugin does the above for you.
Token creation via `pveum` is a host-local, API-less operation, so it belongs in the
on-system half of the plugin rather than requiring a human to paste a secret:

1. On first configure with no token, the plugin shells `pveum user token add` for a
   dedicated `orca@pve!orca` token (privsep + `OrcaOps` role as above), reading the
   one-time `value` from the command output.
2. It stores the secret through orca's **secrets domain** — the plugin never learns
   which backend (1Password / native / …) holds it; it only asks the domain to keep
   and return the secret by handle.
3. Rotation re-runs `token add` with a new id, updates the stored secret, then
   `token remove`s the old id — so a leaked token has a bounded lifetime.

The plugin owns its Proxmox credential end-to-end; orca just provides the encrypted
place to keep it.

---

## Notes

- Proxmox ships a self-signed cert on `:8006`. Set `insecure = true`, or install the
  node's CA and leave it `false`.
- Token ids are permanent once issued; to "rotate" you add a new token and remove the
  old one (there is no in-place secret reset).
- Fleet reference: nodes `thor` / `loki` / `frigg`, PVE 9.1.x, API on `:8006`.
