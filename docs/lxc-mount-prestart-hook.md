# LXC pre-start mount-guard hook

Field note on the LXC pre-start hook that media containers use to guard their
storage mount, why it stopped guarding anything after the storage backend
changed, and what the guard has to check to be correct.

Media LXC guests that serve off network storage — Plex on `CT110 mimir` (thor),
`CT115 njord` (frigg) — declare a hook in their config:

```
hookscript: local:snippets/pool-mount-hook.sh
```

The hook runs on the host in the guest's `pre-start` phase. Its job is to
**refuse to start the container unless its network storage mount is a live, real
mount.** `/mnt/data` on the host is bind-mounted into the guest; if that host
mount is missing or stale when the guest starts, the guest comes up against a
dead directory and silently serves nothing. A guard that fails the mount check
must abort the start. Proxmox surfaces a failing pre-start hook as:

```
run_buffer: ... Script exited with status 2
lxc_init: Failed to run lxc.hook.pre-start
```

A nonzero exit from the hook is the whole mechanism — that is the only thing
that keeps a guest from starting against bad storage.

---

## The bug: the guard validates a mechanism that no longer exists

The hook decides whether `/mnt/data` is mounted by reading an **autofs** map at
`/etc/auto.orca` (`ORCA_AUTOFS_MAP`). That was correct when the fleet mounted
network storage through autofs/NFS.

The fleet has since migrated off autofs. Network storage is now mounted by a
systemd unit — `orca-smb-mounts.service` → `/usr/local/sbin/orca-smb-mount` —
serving CIFS mounts. `/etc/auto.orca` no longer exists on these hosts.

So the hook falls into its "no autofs map present" branch and `exit 0`. It is a
**no-op.** It validates nothing, blocks nothing, and lets every guest start
regardless of the state of `/mnt/data` — which is exactly the failure it was
written to prevent. A guest will happily come up against a stale or dead
`/mnt/data` and serve an empty library.

This is a dead guard: it still runs, still exits cleanly, still looks like it is
doing its job. During the storage incident it is why containers eventually
started even though a bad mount was supposed to hold them back — the guard was
answering a question about a backend that was gone.

---

## Correct behavior

The guard has to validate the mount mechanism actually in use, not a retired
one.

1. **Verify each required host mountpoint is a live network mount.** Check the
   filesystem type with `findmnt -t cifs,nfs4 <mp>` — the mount must be present
   *and* of the expected type.

2. **Probe liveness, not just presence.** Mount-table presence is not the same
   as a working mount: a stale CIFS mount still appears in `findmnt`. Follow the
   `findmnt` check with a short-timeout `stat` against the mountpoint so a hung
   or stale mount fails the guard instead of passing it.

3. **Attempt a repair before refusing.** If a mountpoint is absent or stale,
   remount it — `systemctl restart orca-smb-mounts.service` — and re-check.

4. **Refuse start if still dead.** Only allow the guest to start once every
   required mountpoint passes both the type check and the liveness probe. If a
   mount cannot be brought back, exit nonzero and let the start abort.

### A running guest's bind mount does not refresh

Even after the host mount is repaired, a *running* container's bind mount does
not pick up the fix. The bind was established from the host mount at container
start; repairing the host mount later does not re-plumb it into a live guest.
Fixing storage under a running guest therefore requires restarting the guest for
the corrected mount to take effect. The pre-start guard only protects the start
transition — it cannot heal a guest that is already up.

---

## Where this belongs

The guard-and-remount logic is host-level today: a hand-maintained snippet plus
a systemd unit sitting outside anything that manages them. It should live in the
managed orca proxmox/SMB tooling, which already owns the mount mechanism the
guard is meant to check, rather than in a hook script that drifts out of sync
with the backend the moment the backend changes — which is exactly how it became
a dead guard.
