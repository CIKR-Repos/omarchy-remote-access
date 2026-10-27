#!/usr/bin/python3 -I
"""Privileged helper for the Remote Access plugin.

Setup copies this file to /usr/local/lib/omarchy-remote-access/helper.py (root
owned) and adds a polkit rule that lets the desktop user run *that copy*
through pkexec without a password. Everything it does is limited to the
commands below, and every argument is checked.

  helper.py setup --user NAME --source PATH   install packages, this helper and the polkit rule
  helper.py firewall [--rule IFACE:PORT]... [--close-open PORT]...
  helper.py ssh on|off --user NAME
  helper.py unlock register|install|rebuild|remove|status
  helper.py uninstall                         remove everything setup and the plugin added
  helper.py version

Progress lines: "STEP <text>", "LINK <url>", "OK <text>", "ERROR <text>".
"""
import grp
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile

VERSION = "1"
INSTALL_DIR = "/usr/local/lib/omarchy-remote-access"
INSTALLED = os.path.join(INSTALL_DIR, "helper.py")
POLKIT_RULE = "/etc/polkit-1/rules.d/49-omarchy-remote-access.rules"
FIREWALL_TAG = "omarchy-remote-access"
SSHD_DROPIN = "/etc/ssh/sshd_config.d/30-omarchy-remote-access.conf"
UFW_RULES = ("/etc/ufw/user.rules", "/etc/ufw/user6.rules")

REPO_PACKAGES = ["wayvnc", "openssh", "ufw", "freerdp", "wpa_supplicant", "tailscale",
                 "mkinitcpio-utils", "mkinitcpio-netconf", "jq",
                 # hypr-rdp's dependencies and build tools
                 "pam", "fuse3", "libpulse", "libva", "libxkbcommon", "mesa", "pipewire", "wayland",
                 "cargo", "clang", "cmake", "git", "base-devel"]
# AUR packages, pinned to a reviewed commit and PKGBUILD.
AUR_PACKAGES = [
    {"name": "hypr-rdp", "version": "0.1.7", "commit": "25a9457285b37bb859bc6939c7731bf020d531e8",
     "pkgbuild_sha256": "3e218e06f1a469cb5d8886a0544fb4dba567e447887b30c9e045c45842ff8c1d",
     "replaces": ["omarchy-remote-desktop-backend"]},
    {"name": "mkinitcpio-tailscale", "version": "2.10.1", "commit": "cc287ad1bda2622e850f71abe38b1addc6563acb",
     "pkgbuild_sha256": "714ada455460301630ab9b6ad8e625eed44e8fb829e261f3937ec117d120dcfd",
     "replaces": []},
]

# Remote disk unlock: a separate boot entry whose image adds Wi-Fi, DHCP and Tailscale
# before encryptssh, which takes the passphrase from the console or over SSH.
UNLOCK_NAME = "omarchy-remote-unlock"
UNLOCK_CONF = "/etc/mkinitcpio-remote-unlock.conf"
UNLOCK_CMDLINE = "/etc/kernel/remote-unlock.cmdline"
UNLOCK_UKI = "/boot/EFI/Linux/%s.efi" % UNLOCK_NAME
UNLOCK_STATE = "/etc/omarchy-remote-unlock.json"
UNLOCK_PACMAN_HOOK = "/etc/pacman.d/hooks/90-omarchy-remote-unlock.hook"
WIFI_CONF = "/etc/wpa_supplicant/initcpio.conf"
TS_STATEDIR = "/etc/initcpio/tailscale"

UNLOCK_HOOKS = ("base udev keyboard autodetect microcode modconf kms keymap consolefont block "
                "wifi-unlock netconf tailscale encryptssh filesystems fsck btrfs-overlayfs resume")

WIFI_INSTALL_HOOK = r'''#!/bin/bash
# Installed by the Omarchy Remote Access plugin: Wi-Fi in early boot.
build() {
    [[ -r /etc/wpa_supplicant/initcpio.conf ]] || { error "wifi-unlock: no /etc/wpa_supplicant/initcpio.conf"; return 1; }
    add_checked_modules '/drivers/net/wireless/'
    add_module ccm
    add_module gcm
    add_module cmac
    add_file /usr/lib/firmware/regulatory.db
    add_file /usr/lib/firmware/regulatory.db.p7s
    add_binary wpa_supplicant
    add_binary ip
    add_file /etc/wpa_supplicant/initcpio.conf /etc/wpa_supplicant/initcpio.conf 0600
    add_runscript
}
help() { echo "Connects the first Wi-Fi card (renamed wlan0) for remote disk unlocking."; }
'''

WIFI_RUN_HOOK = r'''#!/usr/bin/ash
# Installed by the Omarchy Remote Access plugin.
run_hook() {
    local dev="" i=0
    while [ -z "$dev" ] && [ "$i" -lt 20 ]; do
        for d in /sys/class/net/*; do
            [ -d "$d/wireless" ] && dev="${d##*/}" && break
        done
        [ -z "$dev" ] && sleep 1 && i=$((i + 1))
    done
    [ -z "$dev" ] && { msg ":: wifi-unlock: no Wi-Fi device"; return 0; }
    [ "$dev" != wlan0 ] && ip link set "$dev" name wlan0
    ip link set wlan0 up
    msg ":: wifi-unlock: connecting to Wi-Fi"
    wpa_supplicant -B -i wlan0 -c /etc/wpa_supplicant/initcpio.conf -f /tmp/wifi-unlock.log
    i=0
    while ! grep -q CTRL-EVENT-CONNECTED /tmp/wifi-unlock.log 2>/dev/null && [ "$i" -lt 30 ]; do
        sleep 1
        i=$((i + 1))
    done
}
run_cleanuphook() {
    killall wpa_supplicant 2>/dev/null
    ip addr flush dev wlan0 2>/dev/null
    ip link set wlan0 down 2>/dev/null
}
'''

IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
# Client VPN tunnels (Cisco, OpenVPN, vpnc, PPP) are usually an employer's network.
CLIENT_VPN_PREFIXES = ("tun", "tap", "cscotun", "vpn", "ppp")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def say(kind, text):
    print(kind, text, flush=True)


def run(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def stream(cmd, **kw):
    """Run a command, relaying its output as STEP lines. Returns the exit code."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, **kw)
    for line in proc.stdout:
        line = line.rstrip()
        if line:
            say("LOG", line[:300])
    return proc.wait()


def checked_user(name):
    if not name or not USER_RE.match(name):
        raise SystemExit(say("ERROR", "bad user name") or 1)
    try:
        user = pwd.getpwnam(name)
    except KeyError:
        raise SystemExit(say("ERROR", "no such user") or 1)
    # Through pkexec, only the user who called it.
    caller = os.environ.get("PKEXEC_UID")
    if caller is not None and str(user.pw_uid) != caller:
        raise SystemExit(say("ERROR", "user does not match the caller") or 1)
    return user


def allowed_port(port):
    """SSH, or an unprivileged port: never a port of another root-owned service."""
    return port == 22 or 1024 <= port < 65536


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ---- setup ----------------------------------------------------------------------

def build_aur(pkg, user):
    """Build a pinned AUR package as the desktop user and install it."""
    have = run("pacman", "-Q", pkg["name"]).stdout.split()
    if len(have) == 2 and have[1].startswith(pkg["version"] + "-"):
        say("STEP", "%s %s already installed" % (pkg["name"], pkg["version"]))
        return True
    say("STEP", "Building %s %s (this can take several minutes)…" % (pkg["name"], pkg["version"]))
    work = tempfile.mkdtemp(prefix="omarchy-remote-access-")
    os.chown(work, user.pw_uid, user.pw_gid)
    as_user = ["runuser", "-u", user.pw_name, "--"]
    src = os.path.join(work, pkg["name"])
    try:
        if run(*as_user, "git", "clone", "-q", "https://aur.archlinux.org/%s.git" % pkg["name"], src).returncode \
                or run(*as_user, "git", "-C", src, "checkout", "-q", pkg["commit"]).returncode:
            say("ERROR", "could not download %s from the AUR" % pkg["name"])
            return False
        if sha256(os.path.join(src, "PKGBUILD")) != pkg["pkgbuild_sha256"]:
            say("ERROR", "%s build script does not match the reviewed version; not building it" % pkg["name"])
            return False
        env = {"HOME": user.pw_dir, "PATH": "/usr/bin", "LANG": "C.UTF-8", "PKGDEST": work}
        if stream(as_user + ["env", *("%s=%s" % kv for kv in env.items()), "makepkg", "--noconfirm"], cwd=src):
            say("ERROR", "building %s failed" % pkg["name"])
            return False
        built = sorted(f for f in os.listdir(work) if f.startswith(pkg["name"] + "-") and ".pkg.tar" in f)
        if not built:
            say("ERROR", "no package was produced for %s" % pkg["name"])
            return False
        for old in pkg["replaces"]:
            if run("pacman", "-Q", old).returncode == 0:
                run("pacman", "-Rdd", "--noconfirm", old)
        if stream(["pacman", "-U", "--noconfirm", "--needed", os.path.join(work, built[-1])]):
            say("ERROR", "installing %s failed" % pkg["name"])
            return False
        return True
    finally:
        shutil.rmtree(work, ignore_errors=True)


def cmd_setup(args):
    user = checked_user(args.get("--user"))
    source = args.get("--source", "")
    if not source.endswith("/helper.py") or not os.path.isfile(source):
        say("ERROR", "bad --source")
        return 1
    say("STEP", "Installing packages…")
    if stream(["pacman", "-S", "--noconfirm", "--needed", *REPO_PACKAGES]):
        say("ERROR", "installing packages failed")
        return 1
    for pkg in AUR_PACKAGES:
        if not build_aur(pkg, user):
            return 1
    say("STEP", "Installing the helper…")
    os.makedirs(INSTALL_DIR, mode=0o755, exist_ok=True)
    shutil.copyfile(source, INSTALLED)
    os.chown(INSTALLED, 0, 0)
    os.chmod(INSTALLED, 0o755)
    with open(POLKIT_RULE, "w") as f:
        f.write('''// Installed by the Omarchy Remote Access plugin: lets %(user)s run its helper
// (and only that file) from the desktop session without a password.
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" &&
        action.lookup("program") == "%(helper)s" &&
        subject.user == "%(user)s" && subject.local && subject.active) {
        return polkit.Result.YES;
    }
});
''' % {"user": user.pw_name, "helper": INSTALLED})
    os.chmod(POLKIT_RULE, 0o644)
    if run("systemctl", "is-enabled", "ufw").stdout.strip() != "enabled":
        run("systemctl", "enable", "--now", "ufw")
        run("ufw", "--force", "enable")
    say("OK", "Setup complete")
    return 0


# ---- firewall + ssh ----------------------------------------------------------------

def ufw_tuples():
    rules = []
    for f in UFW_RULES:
        try:
            lines = open(f).read().splitlines()
        except OSError:
            continue
        for line in lines:
            m = re.match(r"### tuple ### allow (\S+) (\S+) (\S+) (\S+) (\S+) in(?:_(\S+))?(?: comment=(\S+))?", line)
            if not m:
                continue
            proto, port, _dst, _sport, _src, iface, comment = m.groups()
            try:
                comment = bytes.fromhex(comment).decode() if comment else ""
            except ValueError:
                comment = ""
            rules.append({"proto": proto, "port": port, "iface": iface or "", "comment": comment})
    return rules


def cmd_firewall(argv):
    rules, close_open = [], []
    it = iter(argv)
    for a in it:
        value = next(it, "")
        if a == "--rule":
            iface, _, port = value.partition(":")
            if not IFACE_RE.match(iface) or iface.startswith(CLIENT_VPN_PREFIXES) \
                    or not port.isdigit() or not allowed_port(int(port)):
                say("ERROR", "bad rule %r" % value)
                return 1
            rules.append((iface, int(port)))
        elif a == "--close-open" and value.isdigit() and allowed_port(int(value)):
            close_open.append(int(value))
        else:
            say("ERROR", "bad argument %r" % a)
            return 1
    if not shutil.which("ufw"):
        say("ERROR", "ufw is not installed")
        return 1
    have = {(r["iface"], r["port"], r["proto"]) for r in ufw_tuples() if r["comment"] == FIREWALL_TAG and r["iface"]}
    want = {(i, str(p), "tcp") for i, p in rules}
    for iface, port, proto in have - want:
        run("ufw", "delete", "allow", "in", "on", iface, "to", "any", "port", port, "proto", proto)
    for port in close_open:
        for spec in ("%d/tcp" % port, "%d" % port):
            run("ufw", "delete", "allow", spec)
    for iface, port, _ in sorted(want - have):
        res = run("ufw", "allow", "in", "on", iface, "to", "any", "port", port, "proto", "tcp", "comment", FIREWALL_TAG)
        if res.returncode != 0:
            say("ERROR", "firewall: " + (res.stderr or res.stdout).strip())
            return 1
    say("OK", "Firewall updated")
    return 0


def cmd_ssh(argv):
    if len(argv) < 3 or argv[0] not in ("on", "off") or argv[1] != "--user":
        say("ERROR", "usage: ssh on|off --user NAME")
        return 1
    user = checked_user(argv[2])
    if argv[0] == "on":
        with open(SSHD_DROPIN, "w") as f:
            f.write("# Managed by the Omarchy Remote Access plugin. Key-only logins for %s.\n"
                    "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
                    "PermitRootLogin no\nAllowUsers %s\n" % (user.pw_name, user.pw_name))
        check = run("sshd", "-t")
        if check.returncode != 0:
            os.remove(SSHD_DROPIN)
            say("ERROR", "SSH config check failed: " + check.stderr.strip())
            return 1
        run("systemctl", "enable", "sshd")
        run("systemctl", "restart", "sshd")
        say("OK", "SSH on")
    else:
        if os.path.exists(SSHD_DROPIN):
            os.remove(SSHD_DROPIN)
            run("systemctl", "disable", "--now", "sshd")
        say("OK", "SSH off")
    return 0


# ---- remote disk unlock ------------------------------------------------------------

def unlock_state():
    try:
        with open(UNLOCK_STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def kernel_dir(pkgbase):
    """Newest installed module directory of the given kernel package."""
    best = None
    for d in sorted(os.listdir("/usr/lib/modules")):
        base = os.path.join("/usr/lib/modules", d)
        try:
            if open(os.path.join(base, "pkgbase")).read().strip() == pkgbase and os.path.exists(os.path.join(base, "vmlinuz")):
                best = d
        except OSError:
            continue
    return best


def wifi_config():
    res = run("nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active")
    conn = next((l.rsplit(":", 1)[0] for l in res.stdout.splitlines() if l.endswith(":802-11-wireless")), "")
    if not conn:
        return "Connect to the Wi-Fi network to use at boot first"
    ssid = run("nmcli", "-g", "802-11-wireless.ssid", "connection", "show", conn).stdout.strip()
    psk = run("nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", conn).stdout.strip()
    if not psk:
        return "Only WPA password networks are supported at boot"
    # The passphrase goes on stdin: on the command line other users could read it.
    derived = run("wpa_passphrase", ssid, input=psk + "\n")
    if derived.returncode != 0:
        return "Could not prepare the Wi-Fi settings"
    body = "\n".join(l for l in derived.stdout.splitlines() if not l.strip().startswith("#"))
    os.makedirs("/etc/wpa_supplicant", exist_ok=True)
    fd = os.open(WIFI_CONF, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("ctrl_interface=/run/wpa_supplicant\n" + body + "\n")
    return ""


def write_cmdline():
    line = open("/proc/cmdline").read().split()
    drop = re.compile(r"^(BOOT_IMAGE|initrd|ip|loglevel|systemd\.show_status|rd\.udev\.log_level|vt\.global_cursor_default)=|^(quiet|splash)$")
    keep = [w for w in line if not drop.match(w)]
    if not any(w.startswith("cryptdevice=") for w in keep):
        return "This boot has no cryptdevice= setting; remote unlock needs Omarchy's encrypted setup"
    os.makedirs("/etc/kernel", exist_ok=True)
    with open(UNLOCK_CMDLINE, "w") as f:
        f.write(" ".join(keep + ["ip=:::::wlan0:dhcp"]) + "\n")
    return ""


def build_unlock_image(state):
    kver = kernel_dir(state["pkgbase"])
    if not kver:
        say("ERROR", "kernel %s not found" % state["pkgbase"])
        return 1
    say("STEP", "Building the remote-unlock boot image for %s…" % kver)
    if stream(["mkinitcpio", "-c", UNLOCK_CONF, "-k", kver, "-U", UNLOCK_UKI, "--cmdline", UNLOCK_CMDLINE]):
        say("ERROR", "building the boot image failed")
        return 1
    return 0


def cmd_unlock(argv):
    action = argv[0] if argv else ""
    if action == "status":
        state = unlock_state()
        print(json.dumps({
            "registered": os.path.isfile(os.path.join(TS_STATEDIR, "tailscaled.state")),
            "installed": bool(state) and os.path.exists(UNLOCK_UKI),
            "hostname": "%s-initrd" % os.uname().nodename,
            "bootedRemote": "ip=:::::wlan0:dhcp" in open("/proc/cmdline").read(),
        }))
        return 0
    if action == "register":
        if not shutil.which("setup-initcpio-tailscale"):
            say("ERROR", "mkinitcpio-tailscale is not installed; run setup again")
            return 1
        say("STEP", "Waiting for you to sign in to Tailscale…")
        proc = subprocess.Popen(["setup-initcpio-tailscale"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            m = re.search(r"https://login\.tailscale\.com/\S+", line)
            if m:
                say("LINK", m.group(0))
        if proc.wait() != 0 or not os.path.isfile(os.path.join(TS_STATEDIR, "tailscaled.state")):
            say("ERROR", "Tailscale sign-in did not finish")
            return 1
        say("OK", "Signed in")
        return 0
    if action == "install":
        if not os.path.isfile(os.path.join(TS_STATEDIR, "tailscaled.state")):
            say("ERROR", "Sign in to Tailscale for the boot device first")
            return 1
        uname = os.uname().release
        try:
            pkgbase = open("/usr/lib/modules/%s/pkgbase" % uname).read().strip()
        except OSError:
            say("ERROR", "cannot tell which kernel package is running")
            return 1
        for err in (wifi_config(), write_cmdline()):
            if err:
                say("ERROR", err)
                return 1
        for path, text in (("/etc/initcpio/install/wifi-unlock", WIFI_INSTALL_HOOK),
                           ("/etc/initcpio/hooks/wifi-unlock", WIFI_RUN_HOOK)):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(text)
        with open(UNLOCK_CONF, "w") as f:
            f.write("# Managed by the Omarchy Remote Access plugin (remote disk unlock image).\n"
                    "MODULES=()\nBINARIES=()\nFILES=()\nHOOKS=(%s)\n" % UNLOCK_HOOKS)
        state = {"pkgbase": pkgbase}
        with open(UNLOCK_STATE, "w") as f:
            json.dump(state, f)
        if build_unlock_image(state):
            return 1
        say("STEP", "Adding the boot entry…")
        res = run("limine-entry-tool", "--add-uki", UNLOCK_NAME, UNLOCK_UKI, "--comment", "Omarchy (remote unlock)")
        if res.returncode != 0:
            say("ERROR", "adding the boot entry failed: " + (res.stderr or res.stdout).strip()[-300:])
            return 1
        os.makedirs(os.path.dirname(UNLOCK_PACMAN_HOOK), exist_ok=True)
        with open(UNLOCK_PACMAN_HOOK, "w") as f:
            f.write("# Installed by the Omarchy Remote Access plugin: keep the remote-unlock image current.\n"
                    "[Trigger]\nOperation = Install\nOperation = Upgrade\nType = Package\n"
                    "Target = %s\nTarget = mkinitcpio*\nTarget = tailscale\nTarget = wpa_supplicant\n"
                    "Target = intel-ucode\nTarget = amd-ucode\nTarget = linux-firmware*\n\n"
                    "[Action]\nDescription = Rebuilding the remote-unlock boot image...\nWhen = PostTransaction\n"
                    "Exec = %s unlock rebuild\n" % (pkgbase, INSTALLED))
        say("OK", "Remote unlock is ready")
        return 0
    if action == "rebuild":
        state = unlock_state()
        if not state:
            return 0
        if build_unlock_image(state):
            return 1
        run("limine-entry-tool", "--add-uki", UNLOCK_NAME, UNLOCK_UKI, "--comment", "Omarchy (remote unlock)", "--overwrite")
        say("OK", "Rebuilt")
        return 0
    if action == "remove":
        run("limine-entry-tool", "--remove-kernel", UNLOCK_NAME)
        for path in (UNLOCK_UKI, UNLOCK_CONF, UNLOCK_CMDLINE, UNLOCK_STATE, UNLOCK_PACMAN_HOOK, WIFI_CONF,
                     "/etc/initcpio/install/wifi-unlock", "/etc/initcpio/hooks/wifi-unlock"):
            if os.path.exists(path):
                os.remove(path)
        shutil.rmtree(TS_STATEDIR, ignore_errors=True)
        say("OK", "Remote unlock removed")
        return 0
    say("ERROR", "usage: unlock register|install|rebuild|remove|status")
    return 1


def cmd_uninstall():
    cmd_unlock(["remove"])
    cmd_firewall([])
    cmd_ssh_off = os.path.exists(SSHD_DROPIN)
    if cmd_ssh_off:
        os.remove(SSHD_DROPIN)
        run("systemctl", "disable", "--now", "sshd")
    for path in (POLKIT_RULE, INSTALLED):
        if os.path.exists(path):
            os.remove(path)
    shutil.rmtree(INSTALL_DIR, ignore_errors=True)
    say("OK", "Removed")
    return 0


def main(argv):
    if os.geteuid() != 0:
        say("ERROR", "run through pkexec")
        return 1
    cmd = argv[0] if argv else ""
    if cmd == "version":
        print(VERSION)
        return 0
    if cmd == "setup":
        # The installed copy runs without a password, so it must never replace itself.
        if os.path.realpath(__file__) == INSTALLED:
            say("ERROR", "run setup from the plugin (it asks for your password)")
            return 1
        args = dict(zip(argv[1::2], argv[2::2]))
        return cmd_setup(args)
    if cmd == "firewall":
        return cmd_firewall(argv[1:])
    if cmd == "ssh":
        return cmd_ssh(argv[1:])
    if cmd == "unlock":
        return cmd_unlock(argv[1:])
    if cmd == "uninstall":
        return cmd_uninstall()
    say("ERROR", "unknown command")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
