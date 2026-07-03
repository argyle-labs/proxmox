# Install Proxmox VE

This plugin is a **client** of an existing Proxmox VE node — it deploys nothing. Stand up Proxmox one of two ways, then generate an API token ([tokens.md](tokens.md)) and register the endpoint with orca.

Two paths, both supported:

- **[Bare-metal](#bare-metal)** — the production path; dedicate a physical host.
- **[Nested VM](#nested-vm)** — run Proxmox *inside* another hypervisor for a lab/test node.

Either way Proxmox serves its API + web UI on **`https://<node>:8006`** (self-signed cert by default).

---

## Bare-metal

The supported production install: Proxmox owns the hardware.

1. **Download the ISO** — the *Proxmox VE* installer image from <https://www.proxmox.com/en/downloads>.
2. **Write it to USB** — e.g. `dd if=proxmox-ve_*.iso of=/dev/sdX bs=4M status=progress` (Linux), or [balenaEtcher] cross-platform. **Verify the target device** — `dd` overwrites it wholesale.
3. **Boot the installer** and follow the prompts: target disk (ZFS/ext4/LVM), locale, a strong `root` password + admin email, and the management NIC's static IP / gateway / DNS.
4. **First boot** — browse to `https://<node-ip>:8006`, log in as `root@pam`. Accept the self-signed cert (or install the node CA).
5. **(Optional) drop the enterprise repo** if you have no subscription, so `apt update` succeeds:

   ```sh
   # on the node, as root
   sed -i 's/^deb/#deb/' /etc/apt/sources.list.d/pve-enterprise.list
   echo 'deb http://download.proxmox.com/debian/pve bookworm pve-no-subscription' \
     > /etc/apt/sources.list.d/pve-no-subscription.list
   apt update && apt -y dist-upgrade
   ```

[balenaEtcher]: https://etcher.balena.io/

---

## Nested VM

Run Proxmox inside an existing hypervisor — handy for a throwaway lab node or to test this plugin without dedicated hardware. It needs **nested virtualization** enabled on the host so the guest can itself run KVM VMs (LXC works without it).

### On a Linux/KVM host

1. **Enable nested KVM** on the host (once):

   ```sh
   # Intel
   echo 'options kvm_intel nested=1' | sudo tee /etc/modprobe.d/kvm-nested.conf
   sudo modprobe -r kvm_intel && sudo modprobe kvm_intel
   cat /sys/module/kvm_intel/parameters/nested   # expect Y

   # AMD: swap kvm_intel → kvm_amd above
   ```

2. **Create the VM** (virt-manager or `virt-install`): ≥ 2 vCPU, ≥ 4 GB RAM, ≥ 32 GB disk, and set the **CPU model to `host-passthrough`** so VMX/SVM is exposed to the guest. Attach the Proxmox ISO.
3. **Install** exactly as in [Bare-metal](#bare-metal) steps 3–5 — the installer is identical inside the VM.
4. **Reach it** — give the VM a bridged NIC (or forward `:8006`) so orca can reach `https://<vm-ip>:8006`.

### On Proxmox itself (Proxmox-in-Proxmox)

Same idea on an existing PVE host: enable nested virtualization on the parent, create a VM with **CPU type `host`**, and install the ISO. See the upstream guide: <https://pve.proxmox.com/wiki/Nested_Virtualization>.

> Nested VMs run guests slowly and are unsupported for production — use them for labs/tests only. The real fleet runs Proxmox bare-metal.

---

## Next steps

1. Generate an API token — [tokens.md](tokens.md).
2. Register the endpoint: `proxmox.create` with at least one `--address kind=url` (e.g. `--address lan=https://<node>:8006`; add `--address fqdn=…` / `--address tailscale=…` for fallback paths), the token id/secret, and `insecure = true` for the self-signed cert.
3. Verify: `proxmox.nodes` (list cluster members) and `unit.list` (enumerate guests).
