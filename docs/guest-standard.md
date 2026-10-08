# Guest standard: root console autologin and a backup-gated `update`

Every LXC is held to two things beyond its resource floor:

- **Root console autologin.** The PVE console logs straight in as root.
- **A one-word `update`.** It runs the container's updater only after orca has
  backed the container up.

`unit.detail` probes a running LXC on the plugin's own node and fills the guard's
`has_root_console` / `has_update_command` facts. A probed LXC is then held to
`require_root_console` and `require_update_command`, and a missing piece shows
in `guard_violations`. If the probe itself fails or times out, that shows as a
`guest standard probe failed: …` violation, never as a pass. An unprobed guest
(a VM, a stopped or remote LXC, or a `list` row) is held to the resource floor
only, so facts nobody read never fail closed.

## Security notes

- With autologin, PVE's `VM.Console` privilege on a container **equals root in
  that container**. Grant console access accordingly.
- The `update` gate is a **safety interlock**, not a security control. It stops
  an operator from updating without a fresh restore point. Root in the
  container can always run the updater directly.

## Verbs

| verb | role | what it does |
| --- | --- | --- |
| `proxmox.guest.standard.audit` | read | probe one LXC and report its facts, guard violations and drift |
| `proxmox.guest.standard.apply` | admin | install autologin and the `update` gate; dry-run unless `execute: true` |
| `proxmox.guest.update` | admin | back up through the PVE API, then run the updater; dry-run unless `execute: true` |
| `unit.update action=update` (lxc) | admin | the same backup-then-update; returns a plan unless the payload sets `"execute": true` |

The unit action's dry run touches nothing, not even a read in the container, so
it names how the updater is chosen rather than the exact commands.
`proxmox.guest.update`'s dry run probes first and lists the exact steps.

All of them run in-container work through `pct` on the node that runs the
container. Before any exec they check that the node name matches and that
`/etc/pve/lxc/<vmid>.conf` exists locally, because pmxcfs lists only this node's
containers there.

## Probe (read-only)

The probe uses only `stat`, `head`, `ls -d` and `systemctl show`, all already on
the allowlist. It is bounded to 10 s.

Every file read first runs `stat -L -c '%F|%s' --`, then `head -c 65536 --`. The
paths are inside the container, and a guest could point one at `/dev/zero` or a
FIFO. A read is refused when the file is:

- not a regular file;
- larger than 64 KiB on disk (the seam trims output, so the size comes from
  `stat`, not from what was read);
- not valid UTF-8.

`systemctl` output larger than 64 KiB is refused too. `test -e` would need its
own allowlist entry, and `ls -d` gives the same answer.

| fact | read |
| --- | --- |
| OS | `/etc/os-release` (`ID` / `ID_LIKE`: debian, ubuntu, alpine) |
| root console, Debian | two reads of `container-getty@1.service` must both show `--autologin root` (or `-a root`, `--autologin=root`, `-aroot`) in the effective `ExecStart`. `systemctl show -p ExecStart --value` gives the command after every drop-in and `ExecStart=` reset. `systemctl cat` gives the literal last `[Service]` `ExecStart=` line after the last reset, with `\` continuation lines joined, so a quoted `"--autologin root"` (a single argument) is not counted. This covers orca's `container-getty@.service.d/autologin.conf` and community-scripts' `container-getty@1.service.d/*.conf`. |
| root console, Alpine | the live `tty1` line in `/etc/inittab` uses `-l /usr/local/sbin/autologin`, that wrapper contains `login -f root`, and `/etc/.pve-ignore.inittab` exists |
| `update` gate | `/usr/local/bin/update` carries the `# orca-update-gate v1` marker |
| foreign gate | `/usr/local/bin/update` exists without the marker (reported as drift) |
| app updater | `ls -d /usr/bin/update` |
| legacy backup key | `ls -d /root/.orca/host_backup_key` (reported as drift) |

## Apply

Every file orca writes goes through orca's `lxc-push` seam, which runs
`pct push`. `pct push` enters the container's mount namespace before creating
the file, and also its user namespace (as uid 0) for an unprivileged
container. Paths, symlinks included, therefore resolve inside the container,
with the access of the container's root; pve-container's `pct.pm` says so in
its comment on `push`.

Before each write, orca also checks the target and its existing parents with
`stat -c '%n|%F' --`, as a guard against accidents. It refuses unless:

- the target is a regular file or absent;
- every existing parent is a real directory;
- `stat` answered every path, either on stdout or with a "No such file" line.
  A `stat` that failed for any other reason is never read as "absent".

Apply is idempotent. It writes a file only when its trimmed contents differ, and
it skips the console steps when autologin is already in effect. The dry run
lists each file (`create`, or `overwrite` with a line diff) and each command.

Debian / Ubuntu:

1. Write `/etc/systemd/system/container-getty@.service.d/autologin.conf`
   (`ExecStart=-/sbin/agetty --autologin root --noclear --keep-baud tty%I ...`).
2. Run `systemctl daemon-reload`.
3. Run `systemctl try-restart container-getty@1.service container-getty@2.service`.
   This ends an open console session on those ttys.

Alpine:

1. Write an empty `/etc/.pve-ignore.inittab`. On every container start, PVE's
   Alpine setup drops each inittab line matching `^\s*tty\d+:\d*:[^:]*:.*getty`
   and writes fresh `ttyN::respawn:/sbin/getty 38400 ttyN` lines, unless this
   file exists. Without it, the autologin would be wiped before init read it.
2. Write `/usr/local/sbin/autologin` (`exec login -f root`, mode 0755).
3. Rewrite the live `ttyN` and `console` getty lines in `/etc/inittab` to
   `/sbin/getty -n -l /usr/local/sbin/autologin ...`. Other ids (such as
   `ttyS0`) and commented lines are left alone. A line that already passes
   `-l <program>` is also left alone and reported as drift.
4. Run `kill -HUP 1`, because busybox init re-reads inittab only on SIGHUP. Until
   orca allowlists `kill`, this step is **deferred**: the plan and the result
   mark it `deferred`, and autologin takes effect at the container's next start.

The `update` gate:

- **The gate is refused if its updater cannot run.** That is the case when the
  updater `auto` resolves to (`/usr/bin/update` or `apk`) is not allowlisted, or
  the OS has no updater. A gate nothing could open would only break `update`.
- **An existing `/usr/local/bin/update` without the orca marker** (such as the
  hand-rolled ssh gate) is refused unless `replace_gate: true` is passed. With
  it, the old script is kept as `/usr/local/bin/update.orca-replaced`, and the
  plan shows the diff.
  - The copy goes through orca, because the seam has no `cp`. The exec seam
    trims both ends of its output, so the copy is refused unless the read
    length equals the on-disk size. A gate ending in a newline is refused
    until core returns raw bytes or allowlists `cp`.
  - If `.orca-replaced` already holds a different script, the replacement is
    refused, so neither script is lost.
- **What gets written.** Otherwise the gate is written to
  `/usr/local/bin/update` (mode 0755). It shadows `/usr/bin/update` on `PATH`;
  community-scripts regenerates that file after every successful update, so the
  gate does not live there.
- **When it opens.** The gate runs the updater only while
  `/run/orca-update-backup.json` is less than an hour old. Otherwise it refuses
  and names the exact `proxmox.guest.update --endpoint … --ctid …` call. The
  endpoint name is written into the script, so it must match `[A-Za-z0-9._-]`.
  `/run` is tmpfs, so a reboot closes the gate.

## Update

Everything that can refuse does so before the backup:

1. Probe, and resolve the updater. With `auto`, that is `/usr/bin/update` when
   present, otherwise `apk` on Alpine and `apt-get` on Debian/Ubuntu.
   - An explicit updater that does not fit the OS is refused, for example `apt`
     on Alpine, or `community` without `/usr/bin/update`.
   - So is an OS with no updater.
2. Refuse if any updater command is outside the allowlist.
3. Refuse if another update of the same CT is in progress in this plugin
   process. This per-CT lock is held from the probe until the update finishes.
   A caller that drops the request releases the lock while the unit keeps
   running in the container. The unit's own running check (below) is the
   backstop for that case, and for another orca instance.
4. On systemd guests, refuse if `orca-guest-update.service` is running, if it
   loads from any file other than orca's `/run/systemd/system` one, or if it
   has drop-ins. The check reads `systemctl show -p FragmentPath -p DropInPaths`.

Then:

5. Back up through the unit `backup` action: vzdump through the PVE API, waited
   on. A failed backup aborts the update.
6. Write the backup reference to `/run/orca-update-backup.json`, which opens the
   in-guest gate for an hour.
7. Run the updater.
   - **On Debian/Ubuntu** it runs as a oneshot systemd unit, so the 5-minute
     lxc-exec timeout cannot kill dpkg mid-upgrade.
     1. Orca writes `/run/systemd/system/orca-guest-update.service` with
        `RemainAfterExit=yes`, `DEBIAN_FRONTEND=noninteractive`, output to the
        journal, and one `ExecStart=` per command.
     2. It runs `systemctl daemon-reload`, and checks again that the unit loads
        from that file alone.
     3. It refuses if the unit is `activating` (or otherwise running) at any
        check. It never uses `restart`, which would kill a run someone else
        started.
        - An earlier finished run, held `active` by `RemainAfterExit`, is
          stopped with `systemctl stop --job-mode=fail` first. Its commands
          have exited by then. With the default `KillMode=control-group`, the
          stop does kill any process an update command left behind in the
          unit's cgroup.
        - It then notes the `InvocationID` and runs
          `systemctl start --no-block --job-mode=fail`.
        - Per systemctl(1), `fail` makes a request fail if it would reverse a
          pending start job into a stop, or the reverse. It does not refuse a
          start that merges into another caller's pending start. The
          `ActiveState` check just before only narrows that window: another
          root caller's start can still merge with orca's, and orca then
          reports that run.
     4. A new `InvocationID` must appear within 60 s, or the update fails
        rather than reading a previous run's result. Orca then reads the unit
        again. If the `InvocationID` has changed, the run is orca's and polling
        continues. Otherwise only the queued start job is cancelled
        (`systemctl show -p Job`, then `systemctl cancel <job>`). The unit is
        never stopped, which could kill a run that began after the last poll,
        mid-upgrade. If the cancel fails, the start stays queued and the error
        says "queued, not started". A run that starts late is still covered by
        the backup and the gate marker.
     5. It polls `systemctl show` every 5 s, for up to 2 h, and requires
        `ActiveState=active` and `Result=success`. `RemainAfterExit` keeps
        those values after the run, so systemd cannot reset them before orca
        reads them.
     6. The output is `systemctl status --lines=40`, capped at 64 KiB.
       `journalctl` would need its own allowlist entry.
   - **On Alpine** the commands run directly through the seam, still under its
     5-minute timeout.

Any failure after the backup names the restore point and the exact
`unit.update action=restore` payload.

The update takes its own backup. The payload has no field for a backup taken
elsewhere: a caller-supplied `BackupRef` cannot be trusted until core's
pre-mutation guard (orca#767) hands one over on a trusted channel.

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
| `/usr/bin/update` | the app's own updater | community-scripts, or a Gitea or Caddy updater that validates and rolls back, run only after orca's backup. Proposed as an absolute path, because the allowlist matches basenames today and a bare `update` would admit any program of that name. |

`sh` is not requested. Every step execs its program directly, and `sh -c` would
let the exec seam run any command line it is handed.

The allowlist bounds what the exec seam runs. It is not a complete boundary for
the container, because `lxc-push` already writes files as the container's root,
including the update unit above. The plugin only ever puts commands that are
themselves allowlisted into that unit.
