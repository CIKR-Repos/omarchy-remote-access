#!/usr/bin/env python3
"""Backend for the Remote Access widget.

Lets other devices reach this desktop over RDP (hypr-rdp), VNC (wayvnc) and SSH,
only on the networks the user picks (Tailscale by default), and keeps a list of
Windows PCs to connect out to with FreeRDP.

  backend.py status                       JSON for the panel
  backend.py allow <on|off>               master switch: pause or resume everything
  backend.py service <rdp|vnc|ssh> <on|off>
  backend.py settings                     merge JSON settings from stdin
  backend.py password <rdp|vnc>           set a password from stdin
  backend.py generate-password <rdp|vnc>  set and print a random password
  backend.py add-key                      append an SSH public key from stdin
  backend.py setup                        one-time setup: packages, helper, firewall (one password prompt)
  backend.py get-password <rdp|vnc>       print the saved password (for the panel's password box)
  backend.py unlock <register|install|remove>  remote disk unlock after a restart
  backend.py host-save                    add/update a saved computer from stdin JSON
  backend.py host-remove <id>
  backend.py host-connect <id>
  backend.py uninstall                    stop everything and remove what setup installed
  backend.py event <rdp-start|rdp-end|rdp-stopped>  hypr-rdp session hooks
  backend.py watchdog                     undo the privacy lock if a session dies uncleanly

Actions print lines for the panel: "STEP <text>", "LINK <url>", "OK <text>" or "ERROR <text>".
Privileged work (firewall, SSH server, packages, boot entry) goes through helper.py,
which setup installs root-owned with a polkit rule, so it never asks again.

Safety rules:
  * a service never starts without a password (RDP, VNC) or a key (SSH);
  * services listen on all addresses only while the firewall (ufw) is active and
    then only the chosen network interfaces are opened; without ufw they bind to
    the first chosen network's address;
  * client VPN tunnels (OpenConnect/AnyConnect, OpenVPN, vpnc, …) are usually an
    employer's network and can never be opened for incoming connections.
"""
import getpass
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import uuid

PLUGIN_ID = "cikr-repos.remote-access"
STATE_DIR = os.path.join(os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")),
                         "omarchy", "plugins", PLUGIN_ID)
CONFIG = os.path.join(STATE_DIR, "config.json")
UNIT_DIR = os.path.expanduser("~/.config/systemd/user")
UNITS = {"rdp": "omarchy-remote-access-rdp.service", "vnc": "omarchy-remote-access-vnc.service"}
FIREWALL_TAG = "omarchy-remote-access"
SSHD_DROPIN = "/etc/ssh/sshd_config.d/30-omarchy-remote-access.conf"
HELPER = "/usr/local/lib/omarchy-remote-access/helper.py"
PLUGIN_HELPER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "helper.py")
UFW_RULES = ("/etc/ufw/user.rules", "/etc/ufw/user6.rules")
HEADLESS_OUTPUT = "hypr-rdp"
# Which client key acts as Super (Omarchy's main modifier) in an RDP session. hypr-rdp
# builds the remote keyboard's keymap without XKB options, so libxkbcommon takes them
# from XKB_DEFAULT_OPTIONS: only the remote keyboard changes, never the local one.
SUPER_KEYS = {
    "command": "",                      # Mac ⌘ / Windows key, as sent by the client
    "option": "altwin:swap_alt_win",    # Mac ⌥ Option / Alt acts as Super (and ⌘ as Alt)
    "control": "ctrl:swap_lwin_lctl",   # Control acts as Super
    "capslock": "caps:super",           # Caps Lock acts as Super
}
SESSION = "session.json"  # what an RDP session changed, so it can be undone
# Hyprland device and output names that may be put into Lua code (they come from
# USB descriptors, so anything else is skipped rather than quoted).
LUA_NAME_RE = re.compile(r"^[A-Za-z0-9:._-]{1,96}$")
# Input devices that must keep working during a session: the RDP client's own
# virtual keyboard/pointer, other virtual input, and power/lid buttons.
KEEP_INPUT = ("hl-virtual", "unknown-device", "power-button", "sleep-button", "lid-switch", "video-bus")
SSH_PORT = 22

DEFAULTS = {
    "rdp": {"enabled": False, "port": 3389, "mode": "fit", "output": "", "username": getpass.getuser(),
            "lock": True, "move_workspaces": True, "super_key": "command"},
    "vnc": {"enabled": False, "port": 5900, "output": "", "username": getpass.getuser()},
    "ssh": {"enabled": False},
    "allow": True,
    "networks": ["tailscale0"],
    "hosts": [],
    "unlock": {"enabled": False, "registered": False},
}

IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


def say(kind, text):
    print(kind, text, flush=True)


def run(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def path(name):
    return os.path.join(STATE_DIR, name)


def write_private(name, text):
    p = path(name)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(p, 0o600)
    return p


def read(p, default=""):
    try:
        with open(p) as f:
            return f.read()
    except OSError:
        return default


def load_config():
    try:
        with open(CONFIG) as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    for key, value in DEFAULTS.items():
        if isinstance(value, dict):
            cfg[key] = {**value, **cfg.get(key, {})}
        else:
            cfg.setdefault(key, value)
    return cfg


def on(cfg, service):
    """A service runs when it's switched on and the master switch allows it."""
    return cfg.get("allow", True) and cfg[service]["enabled"]


def save_config(cfg):
    write_private("config.json", json.dumps(cfg, indent=2))


# ---- environment ---------------------------------------------------------------

def rdp_server_current():
    """hypr-rdp 0.1.7 or newer (older versions crash when a client resizes)."""
    res = run("hypr-rdp", "--version") if shutil.which("hypr-rdp") else None
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", res.stdout if res else "")
    return bool(m) and tuple(int(x) for x in m.groups()) >= (0, 1, 7)


def missing_packages():
    needed = {"hypr-rdp": "hypr-rdp", "wayvnc": "wayvnc", "sshd": "openssh",
              "ufw": "ufw", "sdl-freerdp3": "freerdp", "openssl": "openssl"}
    return sorted({pkg for binary, pkg in needed.items() if not shutil.which(binary)})


def monitors():
    res = run("hyprctl", "monitors", "-j")
    try:
        return [{"name": m["name"], "width": m["width"], "height": m["height"]}
                for m in json.loads(res.stdout) if m["name"] != HEADLESS_OUTPUT]
    except ValueError:
        return []


def nm_device_types():
    res = run("nmcli", "-t", "-f", "DEVICE,TYPE", "device")
    types = {}
    for line in res.stdout.splitlines():
        dev, _, kind = line.partition(":")
        types[dev] = kind
    return types


def classify(name, nm_type):
    """(kind, label, allowed) for a network interface, or None to hide it."""
    if name == "lo" or name.startswith(("docker", "br-", "veth", "virbr", "vnet", "podman", "cni")):
        return None
    if name == "tailscale0":
        return "tailscale", "Tailscale", True
    if name.startswith("zt"):
        return "vpn", "ZeroTier", True
    if name.startswith(("wt", "nb-")):
        return "vpn", "NetBird", True
    if name.startswith("wg") or nm_type == "wireguard":
        return "vpn", "WireGuard", True
    if nm_type in ("wifi", "ethernet"):
        return "lan", "Local network (Wi-Fi)" if nm_type == "wifi" else "Local network (Ethernet)", True
    if nm_type in ("tun", "tap") or name.startswith(("tun", "tap", "vpn", "cscotun", "ppp")):
        return "client-vpn", "Client VPN (work network)", False
    return None


def networks(cfg):
    res = run("ip", "-j", "-4", "addr", "show", "up")
    try:
        links = json.loads(res.stdout)
    except ValueError:
        links = []
    types = nm_device_types()
    out = []
    for link in links:
        name = link.get("ifname", "")
        info = classify(name, types.get(name, ""))
        if not info:
            continue
        addrs = [a["local"] for a in link.get("addr_info", []) if a.get("family") == "inet"]
        if not addrs:
            continue
        kind, label, allowed = info
        out.append({"iface": name, "kind": kind, "label": label, "address": addrs[0],
                    "allowed": allowed, "selected": allowed and name in cfg["networks"]})
    out.sort(key=lambda n: ({"tailscale": 0, "vpn": 1, "lan": 2}.get(n["kind"], 3), n["iface"]))
    return out


def firewall_active():
    # ufw's own state file is readable without root.
    return "ENABLED=yes" in read("/etc/ufw/ufw.conf") and run("systemctl", "is-active", "ufw").stdout.strip() == "active"


def ufw_tuples():
    """Allow rules from ufw's rule files: (port, proto, iface or '', comment)."""
    rules = []
    for f in UFW_RULES:
        for line in read(f).splitlines():
            # "### tuple ### allow <proto> <dport> <dst> <sport> <src> in[_<iface>] [comment=<hex>]"
            m = re.match(r"### tuple ### allow (\S+) (\S+) (\S+) (\S+) (\S+) in(?:_(\S+))?(?: comment=(\S+))?", line)
            if not m:
                continue
            proto, port, _dst, _sport, src, iface, comment = m.groups()
            try:
                comment = bytes.fromhex(comment).decode() if comment else ""
            except ValueError:
                comment = ""
            rules.append({"proto": proto, "port": port, "iface": iface or "", "src": src, "comment": comment})
    return rules


def wanted_rules(cfg, nets):
    ports = []
    if on(cfg, "rdp"):
        ports.append(int(cfg["rdp"]["port"]))
    if on(cfg, "vnc"):
        ports.append(int(cfg["vnc"]["port"]))
    if on(cfg, "ssh"):
        ports.append(SSH_PORT)
    ifaces = [n["iface"] for n in nets if n["selected"]]
    return sorted({(iface, port) for iface in ifaces for port in ports})


def open_rules(cfg):
    """Existing rules that open one of our ports to every network."""
    ports = {str(cfg["rdp"]["port"]), str(cfg["vnc"]["port"]), str(SSH_PORT)}
    return sorted({r["port"] for r in ufw_tuples()
                   if r["port"] in ports and not r["iface"] and r["comment"] != FIREWALL_TAG})


def sshd_state():
    return {"active": run("systemctl", "is-active", "sshd").stdout.strip() == "active",
            "managed": os.path.exists(SSHD_DROPIN)}


def bind_address(cfg, nets):
    if firewall_active():
        return "0.0.0.0"
    chosen = [n for n in nets if n["selected"]]
    return chosen[0]["address"] if chosen else ""


def peers(port):
    """(local address, remote address) of established connections to a local port."""
    res = run("ss", "-tnH", "state", "established", "( sport = :%d )" % port)
    out = set()
    for line in res.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4:
            out.add((fields[2].rsplit(":", 1)[0].strip("[]"), fields[3].rsplit(":", 1)[0].strip("[]")))
    return sorted(out)


def unit_active(service):
    return run("systemctl", "--user", "is-active", UNITS[service]).stdout.strip() in ("active", "activating")


# ---- certificate + config files --------------------------------------------------

def ensure_certificate():
    cert, key = path("cert.pem"), path("key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        res = run("openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "3650",
                  "-subj", "/CN=%s" % os.uname().nodename, "-keyout", key, "-out", cert)
        if res.returncode != 0:
            raise RuntimeError("could not create a certificate: " + res.stderr.strip())
        os.chmod(key, 0o600)
    return cert, key


def fingerprint():
    if not os.path.exists(path("cert.pem")):
        return ""
    res = run("openssl", "x509", "-in", path("cert.pem"), "-noout", "-fingerprint", "-sha256")
    return res.stdout.strip().split("=", 1)[-1]


def toml_str(value):
    return json.dumps(str(value))


def write_rdp_config(cfg, address):
    cert, key = ensure_certificate()
    rdp = cfg["rdp"]
    hook = "%s %s event" % (sys.executable, os.path.abspath(__file__))
    lines = [
        "bind = %s" % toml_str("%s:%d" % (address, int(rdp["port"]))),
        "username = %s" % toml_str(rdp["username"]),
        "password_file = %s" % toml_str(path("rdp.password")),
        "cert = %s" % toml_str(cert),
        "key = %s" % toml_str(key),
        "on_session_start = %s" % toml_str(hook + " rdp-start"),
        "on_session_end = %s" % toml_str(hook + " rdp-end"),
    ]
    if rdp["mode"] == "mirror" and rdp["output"]:
        lines.append("output = %s" % toml_str(rdp["output"]))
    write_private("hypr-rdp.toml", "\n".join(lines) + "\n")


def write_vnc_config(cfg, address):
    cert, key = ensure_certificate()
    vnc = cfg["vnc"]
    write_private("wayvnc.config", "\n".join([
        "address=%s" % address,
        "port=%d" % int(vnc["port"]),
        "enable_auth=true",
        "username=%s" % vnc["username"],
        "password=%s" % read(path("vnc.password")).strip(),
        "certificate_file=%s" % cert,
        "private_key_file=%s" % key,
    ]) + "\n")


def write_units(cfg):
    os.makedirs(UNIT_DIR, exist_ok=True)
    base = ("[Unit]\nDescription=%s (Omarchy Remote Access)\nPartOf=graphical-session.target\n"
            "After=graphical-session.target\n\n[Service]\n%s\nRestart=on-failure\nRestartSec=3\n\n"
            "[Install]\nWantedBy=graphical-session.target\n")
    me = "%s %s" % (sys.executable, os.path.abspath(__file__))
    # Workspaces go home before the virtual screen is removed; on start, any that
    # Hyprland parked on the new virtual screen are sent back.
    xkb = SUPER_KEYS.get(cfg["rdp"].get("super_key", "command"), "")
    rdp = base % ("RDP server", ("Environment=XKB_DEFAULT_OPTIONS=%s\n" % xkb if xkb else "") +
                  "ExecStart=/usr/bin/hypr-rdp --config %s\n"
                  "ExecStartPost=-/bin/sh -c 'sleep 2; exec %s event rdp-ready'\n"
                  "ExecStopPost=-%s event rdp-stopped\n"
                  "ExecStopPost=-/usr/bin/hyprctl output remove %s" % (path("hypr-rdp.toml"), me, me, HEADLESS_OUTPUT))
    vnc = base % ("VNC server", "ExecStart=/usr/bin/wayvnc --config=%s%s" % (path("wayvnc.config"), vnc_output_arg(cfg)))
    for service, text in (("rdp", rdp), ("vnc", vnc)):
        with open(os.path.join(UNIT_DIR, UNITS[service]), "w") as f:
            f.write(text)
    run("systemctl", "--user", "daemon-reload")


def vnc_output_arg(cfg):
    # Without a choice wayvnc takes the first output, which can be RDP's virtual screen.
    output = cfg["vnc"]["output"] or next((m["name"] for m in monitors()), "")
    return " --output=%s" % output if output and IFACE_RE.match(output) else ""


# ---- applying ---------------------------------------------------------------------

def apply_services(cfg, only=("rdp", "vnc")):
    """Rewrite configs and (re)start or stop the given user services, so a change to
    one never drops the other's sessions. Returns error text or ''."""
    nets = networks(cfg)
    address = bind_address(cfg, nets)
    errors = []
    for service in only:
        unit = UNITS[service]
        if not on(cfg, service):
            run("systemctl", "--user", "disable", "--now", unit)
            continue
        if not address:
            errors.append("%s: choose a network first" % service.upper())
            continue
        if not read(path("%s.password" % service)).strip():
            errors.append("%s: set a password first" % service.upper())
            run("systemctl", "--user", "disable", "--now", unit)
            continue
        try:
            if service == "rdp":
                write_rdp_config(cfg, address)
            else:
                write_vnc_config(cfg, address)
        except RuntimeError as e:
            errors.append("%s: %s" % (service.upper(), e))
            continue
        write_units(cfg)
        run("systemctl", "--user", "enable", unit)
        res = run("systemctl", "--user", "restart", unit)
        if res.returncode != 0:
            errors.append("%s did not start (journalctl --user -u %s)" % (service.upper(), unit))
    return "; ".join(errors)


def system_in_sync(cfg, nets):
    """Whether the firewall and SSH server match the settings (no root needed to check)."""
    if open_rules(cfg):
        return False
    if firewall_active():
        have = {(r["iface"], int(r["port"])) for r in ufw_tuples()
                if r["comment"] == FIREWALL_TAG and r["iface"] and r["port"].isdigit()}
        if have != set(wanted_rules(cfg, nets)):
            return False
    ssh = sshd_state()
    return ssh["active"] == ssh["managed"] == on(cfg, "ssh")


# ---- privileged helper -------------------------------------------------------------

def helper_state():
    """ready: installed and current; outdated: plugin updated, setup needed again; missing."""
    if not os.path.isfile(HELPER):
        return "missing"
    try:
        with open(HELPER, "rb") as a, open(PLUGIN_HELPER, "rb") as b:
            return "ready" if a.read() == b.read() else "outdated"
    except OSError:
        return "missing"


def helper(*args, relay=False):
    """Run the installed helper through pkexec (no password after setup).
    relay=True passes its progress lines through to the panel. Returns (ok, last line)."""
    if helper_state() == "missing":
        return False, "ERROR Finish setup first"
    proc = subprocess.Popen(["pkexec", HELPER, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    last = ""
    for line in proc.stdout:
        line = line.rstrip()
        if not line:
            continue
        if relay and line.split(" ", 1)[0] in ("STEP", "LINK", "LOG"):
            print(line, flush=True)
        if line.startswith(("OK", "ERROR")):
            last = line
    ok = proc.wait() == 0
    return ok, last or ("OK" if ok else "ERROR Cancelled")


def sync_system(cfg, nets=None):
    """Bring the firewall and SSH server in line with the settings. Returns error text or ''."""
    nets = nets or networks(cfg)
    if system_in_sync(cfg, nets):
        return ""
    if helper_state() != "ready":
        return "Run setup to let the firewall follow your settings"
    args = ["firewall"]
    for iface, port in wanted_rules(cfg, nets):
        args += ["--rule", "%s:%d" % (iface, port)]
    for port in open_rules(cfg):
        args += ["--close-open", port]
    ok, line = helper(*args)
    if not ok:
        return line.partition(" ")[2] or "Firewall update failed"
    ssh = sshd_state()
    if ssh["managed"] != on(cfg, "ssh") or ssh["active"] != on(cfg, "ssh"):
        ok, line = helper("ssh", "on" if on(cfg, "ssh") else "off", "--user", getpass.getuser())
        if not ok:
            return line.partition(" ")[2] or "SSH update failed"
    return ""


def cmd_setup():
    """One-time setup: the only step that asks for the admin password."""
    print("STEP Waiting for your password…", flush=True)
    proc = subprocess.Popen(["pkexec", "/usr/bin/python3", "-I", PLUGIN_HELPER, "setup",
                             "--user", getpass.getuser(), "--source", PLUGIN_HELPER],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    last = ""
    for line in proc.stdout:
        line = line.rstrip()
        if line.startswith(("STEP", "LOG")):
            print(line, flush=True)
        elif line.startswith(("OK", "ERROR")):
            last = line
    code = proc.wait()
    if code in (126, 127):
        say("ERROR", "Setup needs your password once. Try again when you're ready.")
        return 1
    if code != 0:
        print(last or "ERROR Setup failed", flush=True)
        return 1
    cfg = load_config()
    error = sync_system(cfg)
    say("ERROR" if error else "OK", error or "All set")
    return 1 if error else 0


def cmd_unlock(action):
    cfg = load_config()
    if action == "register":
        ok, line = helper("unlock", "register", relay=True)
        cfg["unlock"]["registered"] = ok
    elif action == "install":
        ok, line = helper("unlock", "install", relay=True)
        cfg["unlock"]["enabled"] = ok
    elif action == "remove":
        ok, line = helper("unlock", "remove", relay=True)
        if ok:
            cfg["unlock"] = {"enabled": False, "registered": False}
    else:
        say("ERROR", "usage: unlock register|install|remove")
        return 2
    save_config(cfg)
    print(line, flush=True)
    return 0 if ok else 1


# ---- commands ---------------------------------------------------------------------

def cmd_status():
    cfg = load_config()
    nets = networks(cfg)
    label_by_addr = {n["address"]: n["label"] for n in nets}

    def peer_list(port):
        # Labelled by the local address the connection arrived on.
        return [{"address": remote, "network": label_by_addr.get(local, "")} for local, remote in peers(port)]

    services = {}
    for service in ("rdp", "vnc"):
        s = cfg[service]
        services[service] = {
            "enabled": s["enabled"], "running": unit_active(service), "port": s["port"],
            "username": s["username"], "hasPassword": bool(read(path("%s.password" % service)).strip()),
            "output": s["output"], "sessions": peer_list(int(s["port"])),
        }
    services["rdp"]["mode"] = cfg["rdp"]["mode"]
    services["rdp"]["lock"] = cfg["rdp"].get("lock", True)
    services["rdp"]["superKey"] = cfg["rdp"].get("super_key", "command")
    services["rdp"]["moveWorkspaces"] = cfg["rdp"].get("move_workspaces", True)
    services["rdp"]["locked"] = os.path.exists(path(SESSION))
    ssh = sshd_state()
    keys = [l for l in read(os.path.expanduser("~/.ssh/authorized_keys")).splitlines() if l.strip() and not l.startswith("#")]
    services["ssh"] = {"enabled": cfg["ssh"]["enabled"], "running": ssh["active"], "port": SSH_PORT,
                       "username": getpass.getuser(), "keys": len(keys), "sessions": peer_list(SSH_PORT)}
    print(json.dumps({
        "services": services,
        "networks": nets,
        "monitors": monitors(),
        "firewall": firewall_active(),
        "openRules": open_rules(cfg),
        "systemInSync": system_in_sync(cfg, nets),
        "setup": helper_state() if rdp_server_current() and not missing_packages() else "missing",
        "allow": cfg.get("allow", True),
        "unlock": {**cfg["unlock"], "hostname": "%s-initrd" % os.uname().nodename},
        "fingerprint": fingerprint(),
        "hosts": cfg["hosts"],
        "missing": missing_packages(),
    }))
    return 0


def cmd_service(service, state):
    cfg = load_config()
    if service not in ("rdp", "vnc", "ssh") or state not in ("on", "off"):
        say("ERROR", "usage: service <rdp|vnc|ssh> <on|off>")
        return 2
    on = state == "on"
    if on and service in ("rdp", "vnc") and not read(path("%s.password" % service)).strip():
        # First time on: make a password; the panel shows it in its box.
        write_private("%s.password" % service, secrets.token_urlsafe(12))
    if on and service == "ssh" and not read(os.path.expanduser("~/.ssh/authorized_keys")).strip():
        say("ERROR", "Add your other computer's SSH public key in Settings first")
        return 1
    cfg[service]["enabled"] = on
    save_config(cfg)
    error = "" if service == "ssh" else apply_services(cfg, only=(service,))
    error = error or sync_system(cfg)
    if error:
        say("ERROR", error)
        return 1
    say("OK", "%s %s" % (service.upper(), "on" if on else "off"))
    return 0


def cmd_allow(state):
    if state not in ("on", "off"):
        say("ERROR", "usage: allow on|off")
        return 2
    cfg = load_config()
    cfg["allow"] = state == "on"
    save_config(cfg)
    error = apply_services(cfg) or sync_system(cfg)
    if error:
        say("ERROR", error)
        return 1
    say("OK", "Remote access " + ("on" if cfg["allow"] else "paused"))
    return 0


def cmd_settings():
    cfg = load_config()
    try:
        update = json.loads(sys.stdin.readline() or "{}")
    except ValueError:
        say("ERROR", "bad settings")
        return 1
    touched = set()
    for service in ("rdp", "vnc"):
        for key, value in (update.get(service) or {}).items():
            if key not in ("lock", "move_workspaces"):  # read when a session starts; no restart needed
                touched.add(service)
            if key == "port" and str(value).isdigit() and 1024 <= int(value) < 65536:
                cfg[service]["port"] = int(value)
            elif key == "mode" and value in ("fit", "mirror"):
                cfg[service]["mode"] = value
            elif key == "output" and (value == "" or IFACE_RE.match(str(value))):
                cfg[service]["output"] = value
            elif key == "username" and re.match(r"^[A-Za-z0-9_.@-]{1,64}$", str(value)):
                cfg[service]["username"] = value
            elif key in ("lock", "move_workspaces") and service == "rdp" and isinstance(value, bool):
                cfg[service][key] = value
            elif key == "super_key" and service == "rdp" and value in SUPER_KEYS:
                cfg[service][key] = value
    if "networks" in update:
        allowed = {n["iface"] for n in networks(cfg) if n["allowed"]}
        cfg["networks"] = [i for i in update["networks"] if i in allowed]
    if "networks" in update:
        touched |= {"rdp", "vnc"}
    save_config(cfg)
    error = apply_services(cfg, only=tuple(sorted(touched)))
    if error:
        say("ERROR", error)
        return 1
    error = sync_system(cfg)
    if error:
        say("ERROR", error)
        return 1
    say("OK", "Saved")
    return 0


def cmd_password(service, generate=False):
    if service not in ("rdp", "vnc"):
        say("ERROR", "usage: password <rdp|vnc>")
        return 2
    password = secrets.token_urlsafe(12) if generate else sys.stdin.readline().strip()
    if len(password) < 8 or "\n" in password:
        say("ERROR", "Use at least 8 characters")
        return 1
    write_private("%s.password" % service, password)
    cfg = load_config()
    error = apply_services(cfg, only=(service,))  # restarts it so the new password takes effect
    if error and cfg[service]["enabled"]:
        say("ERROR", error)
        return 1
    say("OK", password if generate else "Password saved")
    return 0


def cmd_add_key():
    key = sys.stdin.readline().strip()
    if not re.match(r"^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) [A-Za-z0-9+/=]+( .*)?$", key) or "\n" in key:
        say("ERROR", "That doesn't look like an SSH public key (it starts with ssh-ed25519 or ssh-rsa)")
        return 1
    ssh_dir = os.path.expanduser("~/.ssh")
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    auth = os.path.join(ssh_dir, "authorized_keys")
    if key.split()[1] in read(auth):
        say("OK", "That key is already added")
        return 0
    with open(auth, "a") as f:
        f.write(key + "\n")
    os.chmod(auth, 0o600)
    say("OK", "Key added")
    return 0


# Saved computer passwords live in the desktop keyring, never in config.json.
def keyring_attrs(host_id):
    return ["app", "omarchy-remote-access", "computer", host_id]


def keyring_get(host_id):
    if not shutil.which("secret-tool"):
        return ""
    return run("secret-tool", "lookup", *keyring_attrs(host_id)).stdout.rstrip("\n")


def keyring_set(host_id, name, password):
    res = subprocess.run(["secret-tool", "store", "--label=Remote Access: %s" % name, *keyring_attrs(host_id)],
                         input=password, capture_output=True, text=True)
    return res.returncode == 0


def keyring_clear(host_id):
    if shutil.which("secret-tool"):
        run("secret-tool", "clear", *keyring_attrs(host_id))


def cmd_host_save():
    cfg = load_config()
    try:
        host = json.loads(sys.stdin.readline() or "{}")
    except ValueError:
        say("ERROR", "bad host")
        return 1
    address = str(host.get("host", "")).strip()
    if not re.match(r"^[A-Za-z0-9.:\[\]_-]{1,253}$", address):
        say("ERROR", "Enter the PC's name or address")
        return 1
    protocol = host.get("protocol", "rdp")
    if protocol not in ("rdp", "vnc", "ssh"):
        say("ERROR", "Pick RDP, VNC or SSH")
        return 1
    port = str(host.get("port", "")).strip()
    if port and not (port.isdigit() and 0 < int(port) < 65536):
        say("ERROR", "The port must be a number")
        return 1
    entry = {
        "id": host.get("id") or uuid.uuid4().hex[:8],
        "protocol": protocol,
        "port": port,
        "name": str(host.get("name", "")).strip()[:60] or address,
        "host": address,
        "username": str(host.get("username", "")).strip()[:64],
        "domain": str(host.get("domain", "")).strip()[:64],
        "gateway": str(host.get("gateway", "")).strip()[:253],
        "multimon": bool(host.get("multimon")),
        "grab_keys": bool(host.get("grab_keys")),
    }
    password = str(host.get("password", ""))
    if host.get("forgetPassword"):
        keyring_clear(entry["id"])
    elif password:
        if "\n" in password or not keyring_set(entry["id"], entry["name"], password):
            say("ERROR", "Couldn't save the password in the keyring")
            return 1
    entry["savedPassword"] = bool(keyring_get(entry["id"]))
    cfg["hosts"] = [h for h in cfg["hosts"] if h["id"] != entry["id"]] + [entry]
    cfg["hosts"].sort(key=lambda h: h["name"].lower())
    save_config(cfg)
    say("OK", "Saved %s" % entry["name"])
    return 0


def cmd_host_remove(host_id):
    keyring_clear(host_id)
    cfg = load_config()
    cfg["hosts"] = [h for h in cfg["hosts"] if h["id"] != host_id]
    save_config(cfg)
    say("OK", "Removed")
    return 0


def connect_command(host):
    """Client command for a saved computer, or (None, error)."""
    protocol, address, port = host.get("protocol", "rdp"), host["host"], host.get("port", "")
    if protocol == "rdp":
        # FreeRDP asks for the password and for unknown certificates in its own window.
        # Spanning monitors needs the X11 client: the Wayland (SDL) one misreads
        # Hyprland's outputs as 64x64 and refuses to connect. With one real screen
        # there is nothing to span, so a single resizable window is used.
        span = host["multimon"] and len(monitors()) > 1
        client = "xfreerdp3" if span else "sdl-freerdp3"
        if not shutil.which(client):
            return None, "FreeRDP is not installed (omarchy pkg add freerdp)"
        cmd = [client, "/v:%s" % (address + (":" + port if port else "")), "+clipboard", "/sound",
               "/title:%s" % host["name"]]
        cmd.append("/multimon" if span else "+dynamic-resolution")
        if not host.get("grab_keys"):
            # Keep Omarchy's Super shortcuts (move, resize, workspaces) working on
            # the session window; everything else still goes to the remote PC.
            cmd.append("-grab-keyboard")
        if host["username"]:
            cmd.append("/u:%s" % host["username"])
        password = keyring_get(host["id"])
        if password:
            # FreeRDP blanks this out of its process list as soon as it starts.
            cmd.append("/p:%s" % password)
        if host["domain"]:
            cmd.append("/d:%s" % host["domain"])
        else:
            # Home PCs aren't in a Windows domain; skip the Kerberos attempt.
            cmd.append("/auth-pkg-list:!kerberos")
        if host["gateway"]:
            cmd.append("/g:%s" % host["gateway"])
        return cmd, None
    if protocol == "vnc":
        if not shutil.which("vncviewer"):
            return None, "A VNC viewer is not installed (omarchy pkg add tigervnc)"
        return ["vncviewer", "%s::%s" % (address, port or "5900")], None
    target = ("%s@%s" % (host["username"], address)) if host["username"] else address
    ssh = ["ssh", target] + (["-p", port] if port else [])
    return ["xdg-terminal-exec", "--title=%s" % host["name"]] + ssh, None


def cmd_host_connect(host_id):
    cfg = load_config()
    host = next((h for h in cfg["hosts"] if h["id"] == host_id), None)
    if not host:
        say("ERROR", "Unknown computer")
        return 1
    cmd, error = connect_command(host)
    if error:
        say("ERROR", error)
        return 1
    if host.get("protocol", "rdp") == "rdp" and not host["username"]:
        say("ERROR", "Add the username for %s first (Computers → Edit)" % host["name"])
        return 1
    # Watched in the background, so a failure is reported instead of vanishing.
    subprocess.Popen([sys.executable, os.path.abspath(__file__), "watch-connection", host["id"]],
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     start_new_session=True)
    say("OK", "Connecting to %s…" % host["name"])
    return 0


CONNECT_ERRORS = [
    ("LOGON_FAILURE", "Wrong username or password. On a Windows PC that signs in with a Microsoft account, "
                      "use the account's email and its password, not the PIN."),
    ("ACCOUNT_RESTRICTION", "Windows refused that account for remote sign-in (blank password or not allowed)."),
    ("PASSWORD_EXPIRED", "That account's password has expired. Sign in on the PC once to change it."),
    ("CONNECT_TRANSPORT_FAILED", "Couldn't reach it. Is it on, and is Tailscale connected on both?"),
    ("DNS_NAME_NOT_FOUND", "That name can't be found. Check the address or Tailscale name."),
    ("CONNECT_FAILED", "Couldn't reach it. Is Remote Desktop turned on in Windows Settings → System → Remote Desktop?"),
    ("SECURITY_NEGO_CONNECT_FAILED", "The PC refused the security handshake. Check that Remote Desktop is on."),
    ("PRE_CONNECT_FAILED", "FreeRDP couldn't set up the screens. Try turning off \"Use all my monitors\" for this computer."),
    ("CONNECT_CANCELLED", ""),
]


def keep_dialogs_on_screen(proc, session_title, seconds=180):
    """FreeRDP's SDL dialogs (certificate, password) can open far outside every
    monitor under Hyprland, leaving the connection waiting on a window nobody can
    see. Float and center each of its windows that lands off its monitor."""
    import time
    fixed = set()
    deadline = time.time() + seconds
    while proc.poll() is None and time.time() < deadline:
        try:
            clients = json.loads(run("hyprctl", "clients", "-j").stdout)
            mons = {m["id"]: m for m in json.loads(run("hyprctl", "monitors", "-j").stdout)}
        except ValueError:
            clients, mons = [], {}
        for c in clients:
            # Only dialogs: the session window itself stays tiled and resizable.
            if c.get("pid") != proc.pid or c["address"] in fixed or c.get("title") == session_title:
                continue
            m = mons.get(c.get("monitor"))
            x, y = c["at"]
            if m and m["x"] <= x < m["x"] + m["width"] and m["y"] <= y < m["y"] + m["height"]:
                continue
            addr = c["address"]
            if re.match(r"^0x[0-9a-f]+$", addr):
                hypr_lua('hl.dispatch(hl.dsp.window.float({ action = "enable", window = "address:%s" }))' % addr)
                hypr_lua('hl.dispatch(hl.dsp.window.center({ window = "address:%s" }))' % addr)
                hypr_lua('hl.dispatch(hl.dsp.focus({ window = "address:%s" }))' % addr)
            fixed.add(addr)
        time.sleep(0.5)


def cmd_watch_connection(host_id):
    host = next((h for h in load_config()["hosts"] if h["id"] == host_id), None)
    cmd, error = connect_command(host) if host else (None, "unknown computer")
    if error:
        return 1
    log_file = path("connect-%s.log" % host_id)
    with open(log_file, "w") as log:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        keep_dialogs_on_screen(proc, host["name"])
        code = proc.wait()
    if code == 0:
        return 0
    text = read(log_file)
    reason = next((msg for key, msg in CONNECT_ERRORS if key in text), None)
    if reason is None:
        errors = [l for l in text.splitlines() if "ERRCONNECT_" in l or "[ERROR]" in l]
        reason = re.sub(r"^.*\]: ", "", errors[-1])[-160:] if errors else "The connection ended with an error."
    if reason:
        run("notify-send", "-a", "Remote Access", "Couldn't connect to %s" % host["name"], reason)
    return code


# ---- privacy lock: this laptop is dark and ignores local input during an RDP session --

def hypr_lua(code):
    return run("hyprctl", "eval", code)


def physical_inputs():
    res = run("hyprctl", "devices", "-j")
    try:
        devices = json.loads(res.stdout)
    except ValueError:
        return []
    names = [d["name"] for d in devices.get("keyboards", []) + devices.get("mice", [])
             + devices.get("touch", []) + devices.get("tablets", [])]
    return sorted({n for n in names if LUA_NAME_RE.match(n) and not n.startswith(KEEP_INPUT)})


def workspaces():
    res = run("hyprctl", "workspaces", "-j")
    try:
        return [w for w in json.loads(res.stdout) if w["id"] > 0]
    except ValueError:
        return []


def active_workspaces():
    res = run("hyprctl", "monitors", "-j")
    try:
        return {m["name"]: m["activeWorkspace"]["id"] for m in json.loads(res.stdout)}
    except (ValueError, KeyError):
        return {}


def move_workspace(ws_id, monitor):
    if isinstance(ws_id, int) and LUA_NAME_RE.match(monitor):
        hypr_lua('hl.dispatch(hl.dsp.workspace.move({ workspace = "%d", monitor = "%s" }))' % (ws_id, monitor))


def session_start(cfg):
    """An RDP session began: bring the desktop to it and, if wanted, lock this laptop."""
    if os.path.exists(path(SESSION)):
        return
    rdp = cfg["rdp"]
    fit = rdp["mode"] != "mirror"
    lock = rdp.get("lock", True)
    # A mirrored monitor is what the remote side sees, so it has to stay on.
    keep = "" if fit else rdp["output"]
    state = {
        "lock": lock,
        "outputs": [m["name"] for m in monitors() if m["name"] != keep and LUA_NAME_RE.match(m["name"])] if lock else [],
        "devices": physical_inputs() if lock else [],
        "wake": {key: run("hyprctl", "repl", "return tostring(hl.get_config('misc.%s'))" % key).stdout.strip() != "false"
                 for key in ("key_press_enables_dpms", "mouse_move_enables_dpms")},
        "workspaces": [],
        "active": {},
    }
    if fit and rdp.get("move_workspaces", True):
        state["active"] = {k: v for k, v in active_workspaces().items() if k != HEADLESS_OUTPUT}
        state["workspaces"] = [{"id": w["id"], "monitor": w["monitor"]} for w in workspaces()
                               if w["monitor"] != HEADLESS_OUTPUT]
    # Written first, so every undo path knows what to restore even if this is interrupted.
    write_private(SESSION, json.dumps(state))

    for w in state["workspaces"]:
        move_workspace(w["id"], HEADLESS_OUTPUT)
    focused = next(iter(state["active"].values()), None)
    if isinstance(focused, int):
        hypr_lua('hl.dispatch(hl.dsp.focus({ workspace = "%d" }))' % focused)
    if lock:
        hypr_lua("hl.config({ misc = { key_press_enables_dpms = false, mouse_move_enables_dpms = false } })")
        for name in state["devices"]:
            hypr_lua('hl.device({ name = "%s", enabled = false })' % name)
        for name in state["outputs"]:
            hypr_lua('hl.dispatch(hl.dsp.dpms({ action = "off", monitor = "%s" }))' % name)
    subprocess.Popen([sys.executable, os.path.abspath(__file__), "watchdog"], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def session_end():
    """Undo session_start: workspaces home, input and screens back, then lock if it was locked."""
    try:
        with open(path(SESSION)) as f:
            state = json.load(f)
    except (OSError, ValueError):
        return False
    present = {m["name"] for m in monitors()}
    for w in state.get("workspaces", []):
        if w.get("monitor") in present:
            move_workspace(w.get("id"), w["monitor"])
    for monitor, ws_id in state.get("active", {}).items():
        if monitor in present and isinstance(ws_id, int):
            hypr_lua('hl.dispatch(hl.dsp.focus({ workspace = "%d" }))' % ws_id)
    for name in state.get("devices", []):
        if LUA_NAME_RE.match(name):
            hypr_lua('hl.device({ name = "%s", enabled = true })' % name)
    wake = state.get("wake", {})
    hypr_lua("hl.config({ misc = { key_press_enables_dpms = %s, mouse_move_enables_dpms = %s } })" % (
        "true" if wake.get("key_press_enables_dpms", True) else "false",
        "true" if wake.get("mouse_move_enables_dpms", True) else "false"))
    if state.get("lock"):
        # Lock before the screens come back, so the lock screen is the first thing shown.
        run("omarchy-shell", "lock", "lock")
    for name in state.get("outputs", []):
        if LUA_NAME_RE.match(name):
            hypr_lua('hl.dispatch(hl.dsp.dpms({ action = "on", monitor = "%s" }))' % name)
    os.remove(path(SESSION))
    return bool(state.get("lock"))


def cmd_watchdog():
    """Runs for the length of an RDP session. Keeps the lid, idle and sleep from
    cutting it off, and undoes the session changes if it ends without hypr-rdp's
    end hook (crash, killed service, dropped network)."""
    import time
    cfg = load_config()
    inhibitor = None
    if shutil.which("systemd-inhibit"):
        inhibitor = subprocess.Popen(
            ["systemd-inhibit", "--what=handle-lid-switch:sleep:idle", "--who=Remote Access",
             "--why=Remote desktop session in progress", "--mode=block", "sleep", "infinity"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    misses = 0
    try:
        while os.path.exists(path(SESSION)):
            time.sleep(5)
            # Unlocking the lock screen from the client turns every screen on;
            # keep this computer's screens dark for the rest of the session.
            try:
                with open(path(SESSION)) as f:
                    blank = set(json.load(f).get("outputs", []))
                lit = [m["name"] for m in json.loads(run("hyprctl", "monitors", "-j").stdout)
                       if m["name"] in blank and m.get("dpmsStatus")]
            except (OSError, ValueError):
                lit = []
            for name in lit:
                if LUA_NAME_RE.match(name):
                    hypr_lua('hl.dispatch(hl.dsp.dpms({ action = "off", monitor = "%s" }))' % name)
            alive = unit_active("rdp") and peers(int(cfg["rdp"]["port"]))
            misses = 0 if alive else misses + 1
            if misses >= 3:
                if session_end():
                    run("notify-send", "-a", "Remote Access", "Remote desktop ended",
                        "The RDP connection dropped, so this computer was locked.")
    finally:
        if inhibitor:
            inhibitor.terminate()
    return 0


def cmd_uninstall():
    session_end()
    for unit in UNITS.values():
        run("systemctl", "--user", "disable", "--now", unit)
        unit_file = os.path.join(UNIT_DIR, unit)
        if os.path.exists(unit_file):
            os.remove(unit_file)
    run("systemctl", "--user", "daemon-reload")
    if helper_state() != "missing":
        ok, line = helper("uninstall", relay=True)
        if not ok:
            print(line, flush=True)
            return 1
    for host in load_config().get("hosts", []):
        keyring_clear(host["id"])
    shutil.rmtree(STATE_DIR, ignore_errors=True)
    say("OK", "Removed. Packages stay installed; remove them with pacman if you like.")
    return 0


def cmd_event(event):
    cfg = load_config()
    if event == "rdp-start":
        session_start(cfg)
        run("notify-send", "-a", "Remote Access", "Remote desktop connected",
            "Someone signed in to this desktop over RDP." + (" This screen is locked until they leave." if cfg["rdp"].get("lock", True) else ""))
    elif event == "rdp-ready":
        if not os.path.exists(path(SESSION)):
            home = next((m["name"] for m in monitors()), "")
            for w in workspaces():
                if w["monitor"] == HEADLESS_OUTPUT and w["windows"] and home:
                    move_workspace(w["id"], home)
    elif event in ("rdp-end", "rdp-stopped"):
        locked = session_end()
        if event == "rdp-end":
            run("notify-send", "-a", "Remote Access", "Remote desktop disconnected",
                "The RDP session ended." + (" This computer is locked." if locked else ""))
    return 0


def main(argv):
    cmd, args = (argv[0] if argv else ""), argv[1:]
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    if cmd == "status":
        return cmd_status()
    if cmd == "allow" and len(args) == 1:
        return cmd_allow(args[0])
    if cmd == "service" and len(args) == 2:
        return cmd_service(*args)
    if cmd == "settings":
        return cmd_settings()
    if cmd in ("password", "generate-password") and len(args) == 1:
        return cmd_password(args[0], generate=cmd == "generate-password")
    if cmd == "add-key":
        return cmd_add_key()
    if cmd == "setup":
        return cmd_setup()
    if cmd == "get-password" and len(args) == 1 and args[0] in ("rdp", "vnc"):
        print(read(path("%s.password" % args[0])).strip())
        return 0
    if cmd == "unlock" and len(args) == 1:
        return cmd_unlock(args[0])
    if cmd == "host-save":
        return cmd_host_save()
    if cmd == "host-remove" and len(args) == 1:
        return cmd_host_remove(args[0])
    if cmd == "watch-connection" and len(args) == 1:
        return cmd_watch_connection(args[0])
    if cmd == "host-connect" and len(args) == 1:
        return cmd_host_connect(args[0])
    if cmd == "event" and len(args) == 1:
        return cmd_event(args[0])
    if cmd == "watchdog":
        return cmd_watchdog()
    if cmd == "uninstall":
        return cmd_uninstall()
    print(__doc__.split("\n\n")[2], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
