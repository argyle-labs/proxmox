# Guest standard: root console autologin and a backup-gated `update`

Every LXC is held to two things beyond its resource floor:

- **Root console autologin.** The PVE console logs straight in as root.
- **A one-word `update`.** It runs the container's updater only after orca has
  backed the container up.

`unit.detail` probes a running LXC on the plugin's own node and fills the guard's
`has_root_console` / `has_update_command` facts. A probed LXC is then held to
`require_root_console` and `require_update_command`, and a missing piece shows
in `guard_violations`. An unprobed guest (a VM, a stopped or remote LXC, or a
`list` row) is held to the resource floor only, so facts nobody read never fail
closed.

## Verbs

| verb | role | what it does |
| --- | --- | --- |
| `proxmox.guest.standard.audit` | read | probe one LXC and report its facts, guard violations and drift |
| `proxmox.guest.standard.apply` | admin | install autologin and the `update` gate; dry-run unless `execute: true` |
| `proxmox.guest.update` | admin | back up through the PVE API, then run the updater; dry-run unless `execute: true` |
| `unit.update action=update` (lxc) | admin | the same backup-then-update, as a unit action |

All of them run in-container work through `pct` on the node that runs the
container, so they run on the orca instance on that node.

## Probe (read-only)

The probe only uses `cat` and `ls -d`, both already on the allowlist. `test -e`
would need its own allowlist entry, and `ls -d` gives the same answer.

| fact | read |
| --- | --- |
| OS | `cat /etc/os-release` (`ID` / `ID_LIKE`: debian, ubuntu, alpine) |
| root console, Debian | `cat /etc/systemd/system/container-getty@.service.d/autologin.conf` contains `--autologin root` |
| root console, Alpine | a live `getty` line in `/etc/inittab` uses `-l /usr/local/sbin/autologin`, and that wrapper contains `login -f root` |
| `update` gate | `cat /usr/local/bin/update` carries the `# orca-update-gate v1` marker |
| app updater | `ls -d /usr/bin/update` |
| legacy backup key | `ls -d /root/.orca/host_backup_key` (reported as drift) |

## Apply

Apply is idempotent: it writes a file only when its trimmed contents differ, and
it reloads only after a write. The dry run lists each file (`create` or
`overwrite`, with its mode) and each command.

Debian / Ubuntu:

1. Write `/etc/systemd/system/container-getty@.service.d/autologin.conf`
   (`ExecStart=-/sbin/agetty --autologin root --noclear --keep-baud tty%I ...`).
2. Run `systemctl daemon-reload`.
3. Run `systemctl try-restart container-getty@1.service container-getty@2.service`.
   This ends an open console session on those ttys.

Alpine:

1. Write `/usr/local/sbin/autologin` (`exec login -f root`, mode 0755).
2. Rewrite every live `/sbin/getty` line in `/etc/inittab` to
   `/sbin/getty -n -l /usr/local/sbin/autologin ...`. Commented lines are left
   alone.
3. Run `kill -HUP 1`, because busybox init re-reads inittab only on SIGHUP. Until
   orca allowlists `kill`, this step is **deferred**: the plan and the result
   mark it `deferred`, and autologin takes effect at the container's next start.

Both:

- Write the gate to `/usr/local/bin/update` (mode 0755). It shadows
  `/usr/bin/update` on `PATH`, and community-scripts regenerates that file after
  every successful update, so the gate does not live there. The gate runs the
  updater only while `/run/orca-update-backup.json` is less than an hour old.
  Otherwise it refuses and tells the operator to run `proxmox.guest.update`.
  `/run` is tmpfs, so a reboot closes the gate.

## Update

1. Probe, and resolve the updater. With `auto`, that is the app's own
   `/usr/bin/update` when present, otherwise `apk` on Alpine and `apt-get`
   otherwise.
2. Refuse **before the backup** if any updater step is outside the allowlist.
3. Back up through the unit `backup` action: vzdump through the PVE API, waited
   on. A failed backup aborts the update. When the caller passes a `backup`
   (`BackupRef`) in the payload, that one is used instead.
4. Write the backup reference to `/run/orca-update-backup.json`, which opens the
   in-guest gate for an hour.
5. Run the updater. A failing step stops the run and names what already ran.

This replaces the hand-rolled gate, which reached the host over ssh with a
forced-command key (`/root/.orca/host_backup_key` →
`command="/usr/local/bin/orca-guest-backup <vmid>"` in
`/etc/pve/priv/authorized_keys`). The container no longer holds a credential to
its host. The audit reports a leftover key as drift. Removing it, and its host
line, is not yet an orca step.

## lxc-exec allowlist additions

orca's root-side `lxc-exec` allowlist (`system::lxc_exec::ALLOWED_COMMANDS`,
tracked in orca#769) does not yet carry these. The plugin mirrors the current
list (`lxc_guest::EXEC_ALLOWLIST`) and the needed additions
(`lxc_guest::PROPOSED_ALLOWLIST`). A step that needs one is named in the plan as
`needs allowlist: <cmd>`.

| entry | used for | why it is needed |
| --- | --- | --- |
| `kill` | `kill -HUP 1` | makes the Alpine inittab change live without a container restart |
| `apk` | `apk update`, `apk upgrade` | the Alpine package updater, the counterpart of the allowed `apt-get` |
| `update` | `/usr/bin/update` | the app's own updater (community-scripts, or a Gitea or Caddy updater that validates and rolls back), run only after orca's backup |

`sh` is not requested. Every step execs its program directly, and allowing
`sh -c` would turn the seam into arbitrary root exec in the container.
