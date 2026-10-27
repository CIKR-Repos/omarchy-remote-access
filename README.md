# Remote Access for Omarchy

Use your Omarchy computer from anywhere: your Mac, a Windows PC, a phone or
another Omarchy machine. One bar widget turns on **Remote Desktop (RDP)**,
**screen sharing (VNC)** and **SSH**, only on the networks you choose
(Tailscale by default). It also keeps a list of computers to connect *out* to:
Windows PCs, Macs, servers and Raspberry Pis.

## Install

```sh
omarchy plugin add https://github.com/CIKR-Repos/omarchy-remote-access.git --enable
```

Open **Remote Access** in the bar and click **Set up**. Setup asks for your
password **once** and:

- installs what's needed: `hypr-rdp` 0.1.7 (built from the AUR at a pinned,
  reviewed commit), `wayvnc`, `openssh`, `ufw`, `freerdp`, and the remote
  unlock tools;
- installs a small root-owned helper with a polkit rule, so after setup the
  firewall and SSH server follow your switches **without asking again**.

Setup is safe to run again. Anything already installed is skipped.

## This computer

| | How | Notes |
|---|---|---|
| **Remote Desktop (RDP)** | [hypr-rdp](https://github.com/MuNeNICK/hypr-rdp) | A password is created the first time you switch it on and shown in the panel (Show / Copy / New) |
| **Screen sharing (VNC)** | [wayvnc](https://github.com/any1/wayvnc) | Password and encryption always on |
| **Terminal (SSH)** | OpenSSH | Key-only logins for your user; paste your other computer's public key in Settings |

The switch at the top pauses or resumes everything at once without forgetting
your choices.

**Networks.** Tailscale is on by default. Home Wi-Fi/Ethernet, WireGuard,
ZeroTier and NetBird can be added in Settings. The firewall (ufw) opens the
RDP/VNC/SSH ports **only on those networks**. **Client VPN tunnels such as
Cisco AnyConnect, OpenVPN or vpnc are always blocked**, because they're usually
an employer's network.

### When you connect over RDP

- **Your whole desktop comes with you.** Every workspace and window moves to
  the RDP screen, which is sized to your client's window and follows it when
  you resize. When you leave, they go back to the monitors they came from.
- **This computer locks itself** (Settings, on by default). Its screens stay
  off and its keyboard, touchpad, mouse and touchscreen are disabled while
  you're connected. When the session ends, Omarchy locks, and the screens come
  back showing the lock screen. USB keyboards you plug in and the power button
  always work.
- **Nothing cuts the session off.** Closing the lid, idling and sleep are held
  off until you disconnect.
- **One session at a time.** A new login replaces the current one.
- The Omarchy bar and menus are on the RDP screen too, so you can change
  settings, restart or shut down from the client.

If a session drops without a clean disconnect, a watchdog undoes all of this
and locks the computer within about 15 seconds.

**Choose your Super key.** Omarchy's shortcuts use Super. Pick which key on
your client acts as Super, for the remote keyboard only (your local keyboard
never changes):

| Setting | Effect |
|---|---|
| ⌘ Command | ⌘ / Windows key is Super. On a Mac, Windows App quits on ⌘Q and turns ⌘W/C/V into Ctrl shortcuts. |
| **⌥ Option** (best on a Mac) | Option acts as Super and ⌘ acts as Alt, so macOS keeps its shortcuts |
| Control | Control acts as Super |
| Caps Lock | Caps Lock acts as Super |

**Screen.** *Fit my window* (default) uses a virtual screen sized to your
client. *Mirror* shows the laptop screen or an external monitor as it is.

### Connect from another device

- **Mac, iPhone, iPad:** Microsoft **Windows App** → Add PC → the address shown
  in the panel, with the RDP user and password.
- **Windows:** Remote Desktop Connection (`mstsc`) with the same address.
- **VNC:** a viewer with encrypted VNC, such as TigerVNC or RealVNC.
  macOS's built-in Screen Sharing doesn't support it; use RDP instead.
- **SSH:** `ssh <user>@<address>`

Compare the certificate fingerprint in Settings the first time you connect.

## Computers

Save Windows PCs or other Omarchy machines (RDP), Macs, Linux and Raspberry
Pis (VNC), or servers (SSH), and connect in one click.

- **RDP** opens FreeRDP in a window that resizes the remote desktop as you
  resize it. Options: domain, RD Gateway, **use all my monitors** (spans
  external monitors), and **send Super shortcuts to the PC**. Off by default,
  so Omarchy's shortcuts still move and resize the window.
- **Passwords** are optional and kept in your **desktop keyring**, never in
  the plugin's files. FreeRDP hides them from the process list. Leave the
  field empty and FreeRDP asks when you connect.
- If a connection fails, a notification says why: wrong password (on Windows
  with a Microsoft account, use the account password, not the PIN), Remote
  Desktop off, unreachable, and so on.

## Unlock the disk remotely after a restart (advanced)

On an encrypted Omarchy install, a restart stops at the disk password. Turn on
**Settings → After a restart → Unlock the disk remotely**. The plugin then:

1. shows a **Tailscale sign-in link** for a boot-time device named
   `<hostname>-initrd` (no Tailscale settings to edit);
2. builds a separate boot image with Wi-Fi, Tailscale and an SSH unlock prompt
   ([mkinitcpio-tailscale](https://github.com/dangra/mkinitcpio-tailscale),
   `encryptssh`), and adds it to the Limine menu as **Omarchy (remote unlock)**;
3. rebuilds it automatically after kernel updates.

After a restart, run `ssh root@<hostname>-initrd` and type the disk password.
Typing it at the computer still works.

Trade-offs: the boot partition isn't encrypted, so it holds your Wi-Fi key
and the boot device's Tailscale key. That device is an ordinary device of
yours, so disable its key expiry in the Tailscale admin console (Machines →
`<hostname>-initrd` → Disable key expiry) or sign it in again before it
expires. Your disk password is never stored.

## Where things are stored

| What | Where |
|---|---|
| Settings and saved computers | `~/.local/state/omarchy/plugins/cikr-repos.remote-access/` (readable only by you) |
| RDP/VNC passwords, certificate, server configs | same folder |
| Saved computer passwords | desktop keyring (`secret-tool`) |
| Services | `~/.config/systemd/user/omarchy-remote-access-{rdp,vnc}.service` |
| Helper and its polkit rule | `/usr/local/lib/omarchy-remote-access/`, `/etc/polkit-1/rules.d/49-omarchy-remote-access.rules` |
| SSH settings | `/etc/ssh/sshd_config.d/30-omarchy-remote-access.conf` |
| Firewall rules | ufw rules commented `omarchy-remote-access` |
| Remote unlock | `/etc/mkinitcpio-remote-unlock.conf`, `/etc/initcpio/tailscale/`, `/boot/EFI/Linux/omarchy-remote-unlock.efi` |

## Known issues

- hypr-rdp 0.1.7 sometimes logs *"Capture thread died with a live session"*
  right after a client connects or resizes. Clients such as Windows App
  reconnect on their own, but you may see a brief drop.
- RDP shows one screen at a time. A client can't span this desktop across
  several of its own monitors.
- Remote access works only while you're logged in. Keep auto-login on so a
  restart brings it back.
- Suspend has no remote wake-up.
- The remote-unlock boot entry is added next to your normal entries, not as
  the default. Pick it in the boot menu, or set it as the default in Limine
  once you've tested it.

## Remove

```sh
~/.config/omarchy/plugins/cikr-repos.remote-access/backend.py uninstall --dry-run   # see what will be removed
~/.config/omarchy/plugins/cikr-repos.remote-access/backend.py uninstall
omarchy plugin remove cikr-repos.remote-access
```

`uninstall` stops the services and removes the firewall rules, SSH settings,
helper, polkit rule, remote-unlock boot entry, saved passwords and settings.
It asks for nothing; installed packages stay.

## License

MIT
