import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Remote Access: reach this desktop over RDP, VNC and SSH on chosen networks,
// connect out to saved computers, and unlock the disk remotely after a restart.
// backend.py does the work; this widget shows its status and edits settings.
Panel {
  id: root
  moduleName: "cikr-repos.remote-access"
  ipcTarget: "remote-access"
  manageIpc: false

  // Last `backend.py status` result.
  property var st: ({ services: { rdp: {}, vnc: {}, ssh: {} }, networks: [], monitors: [], hosts: [], missing: [], openRules: [], firewall: true, fingerprint: "", setup: "ready", allow: true, unlock: {} })
  // this | computers | settings
  property string tab: "this"
  property bool editingHost: false
  property var editHost: null
  property string message: ""
  property bool failed: false
  property string progress: ""
  property string loginLink: ""
  property bool showRdpPassword: false
  property bool showVncPassword: false
  // What's saved, so the Save buttons know when a box has been edited.
  property string rdpSaved: ""
  property string vncSaved: ""

  readonly property string backend: Qt.resolvedUrl("backend.py").toString().replace("file://", "")
  readonly property bool busy: actionProc.running
  readonly property var services: st && st.services ? st.services : ({ rdp: {}, vnc: {}, ssh: {} })
  readonly property bool ready: st.setup === "ready"
  readonly property var selectedNetworks: (st.networks || []).filter(function(n) { return n.selected })
  readonly property int sessionCount: ((services.rdp || {}).sessions || []).length + ((services.vnc || {}).sessions || []).length + ((services.ssh || {}).sessions || []).length
  readonly property bool anyOn: !!(st.allow && ((services.rdp || {}).enabled || (services.vnc || {}).enabled || (services.ssh || {}).enabled))
  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property string metaText: {
    if (busy) return progress !== "" ? progress : "Working…"
    if (!ready) return "Setup needed"
    if (!st.allow) return "Paused"
    if (sessionCount > 0) return sessionCount === 1 ? "1 person connected" : sessionCount + " connections"
    var on = []
    if (services.rdp.enabled) on.push("RDP")
    if (services.vnc.enabled) on.push("VNC")
    if (services.ssh.enabled) on.push("SSH")
    return on.length ? "Ready · " + on.join(", ") : "Nothing switched on"
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function refresh() {
    if (!statusProc.running) statusProc.running = true
  }

  // Runs a backend action; `input` (optional) goes over stdin, never argv.
  function run(args, input) {
    if (actionProc.running) return
    failed = false
    message = ""
    progress = ""
    actionProc.input = input === undefined ? "" : input
    actionProc.command = [backend].concat(args)
    actionProc.running = true
  }

  function loadPasswords() {
    rdpPasswordProc.running = true
    vncPasswordProc.running = true
  }

  function copy(text) {
    // Through stdin: a password in wl-copy's arguments would be readable by other users.
    if (copyProc.running) return
    copyProc.text = text
    copyProc.stdinEnabled = true
    copyProc.running = true
    message = "Copied"
    failed = false
  }

  function savePassword(service, text) {
    if (text.length < 8) {
      message = "Use at least 8 characters"
      failed = true
      return
    }
    run(["password", service], text)
    // Hand the keys back to the panel (Esc, Tab), which typing in the box had paused.
    keyCatcher.forceActiveFocus()
  }

  function serviceDescription(key) {
    var s = services[key] || {}
    var sessions = s.sessions || []
    if (sessions.length > 0) {
      var who = sessions.map(function(p) { return p.address + (p.network ? " (" + p.network + ")" : "") })
      return "Connected from " + who.join(", ") + (key === "rdp" && s.locked ? " · this laptop is locked" : "")
    }
    if (key === "ssh") return s.keys ? "Key-only login as " + s.username : "Add your other computer's key in Settings"
    if (!s.hasPassword) return "Set a password first"
    if (key === "rdp") return s.mode === "mirror" && s.output ? "Shows " + s.output : "Fits your window · brings your workspaces"
    return s.output ? "Shows " + s.output : "Shows the main screen"
  }

  function toggleService(key) {
    var s = services[key]
    // Switching RDP/VNC on the first time also creates its password (shown in its box).
    if (!s.enabled && key !== "ssh" && !s.hasPassword) showRdpPassword = key === "rdp"
    if (!s.enabled && key === "ssh" && !s.keys) {
      tab = "settings"
      message = "Paste your other computer's SSH public key, then switch SSH on."
      Qt.callLater(function() { sshKey.forceActiveFocus() })
      return
    }
    run(["service", key, s.enabled ? "off" : "on"])
  }

  function openHost(host) {
    editHost = host ? JSON.parse(JSON.stringify(host)) : { id: "", name: "", host: "", protocol: "rdp", port: "", username: "", domain: "", gateway: "", multimon: false }
    hostName.text = editHost.name
    hostAddress.text = editHost.host
    hostProtocol.value = editHost.protocol || "rdp"
    hostPort.text = editHost.port || ""
    hostUser.text = editHost.username
    hostDomain.text = editHost.domain
    hostGateway.text = editHost.gateway
    hostMultimon.checked = editHost.multimon === true
    hostGrab.checked = editHost.grab_keys === true
    hostPassword.text = ""
    tab = "computers"
    editingHost = true
  }

  function saveHost() {
    run(["host-save"], JSON.stringify({
      id: editHost.id, name: hostName.text, host: hostAddress.text, protocol: hostProtocol.value,
      port: hostPort.text, username: hostUser.text, domain: hostDomain.text, gateway: hostGateway.text,
      multimon: hostMultimon.checked, grab_keys: hostGrab.checked, password: hostProtocol.value === "rdp" ? hostPassword.text : ""
    }))
    hostPassword.text = ""
    editingHost = false
  }

  function toggleNetwork(iface) {
    var chosen = selectedNetworks.map(function(n) { return n.iface })
    var i = chosen.indexOf(iface)
    if (i >= 0) chosen.splice(i, 1)
    else chosen.push(iface)
    run(["settings"], JSON.stringify({ networks: chosen }))
  }

  function screenOptions(forRdp) {
    var options = forRdp ? [{ value: "fit", label: "Fit my window (recommended)" }] : [{ value: "", label: "Main screen" }]
    for (var i = 0; i < (st.monitors || []).length; i++) {
      var m = st.monitors[i]
      options.push({ value: (forRdp ? "mirror:" : "") + m.name, label: (forRdp ? "Mirror " : "") + m.name + " · " + m.width + "×" + m.height })
    }
    return options
  }

  onOpenedChanged: {
    if (opened) {
      refresh()
      loadPasswords()
      Qt.callLater(function() { keyCatcher.forceActiveFocus() })
    } else {
      editingHost = false
      showRdpPassword = false
      showVncPassword = false
    }
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function status(): string { return root.metaText }
    function showTab(name: string): void { root.open(); root.tab = name }
  }

  Process {
    id: statusProc
    command: [root.backend, "status"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: { try { root.st = JSON.parse(text) } catch (e) {} }
    }
  }

  Process {
    id: rdpPasswordProc
    command: [root.backend, "get-password", "rdp"]
    // Keeps a password you're still typing; only an unedited box follows the saved one.
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: { if (rdpPassword.text === root.rdpSaved) rdpPassword.text = text.trim(); root.rdpSaved = text.trim() } }
  }

  Process {
    id: vncPasswordProc
    command: [root.backend, "get-password", "vnc"]
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: { if (vncPassword.text === root.vncSaved) vncPassword.text = text.trim(); root.vncSaved = text.trim() } }
  }

  Process {
    id: copyProc
    property string text: ""
    command: ["wl-copy"]
    onStarted: {
      write(text)
      text = ""
      stdinEnabled = false  // closes stdin, so wl-copy takes what was written
    }
  }

  Process {
    id: actionProc
    property string input: ""
    stdinEnabled: true
    onStarted: {
      write(input + "\n")
      input = ""
    }
    stdout: SplitParser {
      onRead: function(line) {
        var space = line.indexOf(" ")
        var kind = space > 0 ? line.slice(0, space) : line
        var text = space > 0 ? line.slice(space + 1) : ""
        if (kind === "STEP") root.progress = text
        else if (kind === "LINK") root.loginLink = text
        else if (kind === "OK" || kind === "ERROR") {
          root.failed = kind === "ERROR"
          // A generated password lands in its box, not in the message line.
          if (!root.failed && actionProc.command[1] === "generate-password") root.message = "New password set. It's in the box below."
          else root.message = text
        }
      }
    }
    onExited: {
      root.progress = ""
      root.loginLink = ""
      root.refresh()
      root.loadPasswords()
    }
  }

  Timer {
    interval: 5000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "󰢹"
    foreground: root.anyOn ? root.barForeground : Qt.darker(root.barForeground, 1.55)
    tooltipText: "Remote Access: " + root.metaText
    onPressed: function(buttonCode) { root.toggle() }
  }

  // A labelled value with optional copy, used for address/user/password lines.
  component InfoRow: Row {
    property string label: ""
    property string value: ""
    property bool copyable: true
    width: parent ? parent.width : 0
    spacing: Style.space(8)
    Text {
      width: Style.space(96)
      anchors.verticalCenter: parent.verticalCenter
      text: parent.label
      color: root.dim
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
    }
    Text {
      width: parent.width - Style.space(96) - copyBtn.width - Style.space(16)
      anchors.verticalCenter: parent.verticalCenter
      text: parent.value
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: Style.font.bodySmall
      elide: Text.ElideRight
    }
    Button {
      id: copyBtn
      visible: parent.copyable
      text: "Copy"
      foreground: root.foreground
      fontFamily: root.fontFamily
      onClicked: root.copy(parent.value)
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(440))
    contentHeight: panel.fittedContentHeight(column.implicitHeight, Style.space(820))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      // Off while typing a password, or it would take Enter, Space and h/j/k/l/x.
      blocked: root.tab !== "this" || root.editingHost || rdpPassword.activeFocus
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Flickable {
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: column
          width: parent.width
          spacing: Style.space(10)

          PanelHero {
            id: hero
            width: parent.width
            title: "Remote Access"
            meta: root.metaText
            foreground: root.foreground
            fontFamily: root.fontFamily
            iconOpacity: root.anyOn ? 1.0 : 0.5
            iconComponent: Component {
              Text { text: "󰢹"; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.display }
            }
            trailingControl: Component {
              ToggleSwitch {
                visible: root.ready
                checked: root.st.allow === true
                busy: root.busy
                foreground: hero.foreground
                onToggled: root.run(["allow", root.st.allow ? "off" : "on"])
              }
            }
          }

          ButtonGroup {
            width: parent.width
            visible: root.ready
            options: [
              { value: "this", label: "This computer" },
              { value: "computers", label: "Computers" },
              { value: "settings", label: "Settings" }
            ]
            value: root.tab
            fontFamily: root.fontFamily
            foreground: root.foreground
            onChanged: function(v) { root.tab = v; root.editingHost = false; root.message = "" }
          }

          Text {
            visible: text !== ""
            width: parent.width
            text: root.message
            textFormat: Text.PlainText
            color: root.failed ? root.urgent : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // ---- first run ------------------------------------------------------------
          Column {
            width: parent.width
            spacing: Style.space(10)
            visible: !root.ready

            Text {
              width: parent.width
              text: root.st.setup === "outdated"
                ? "Remote Access was updated and needs to finish setting up."
                : "Set up once and you're done: this installs the remote desktop, screen sharing and SSH tools, and lets the firewall follow your switches. It asks for your password one time."
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.WordWrap
            }
            Text {
              visible: root.busy
              width: parent.width
              text: root.progress !== "" ? root.progress : "Starting…"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
            Button {
              text: root.busy ? "Setting up…" : "Set up"
              enabled: !root.busy
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.run(["setup"])
            }
          }

          // ---- this computer ----------------------------------------------------------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.ready && root.tab === "this"

            Repeater {
              model: [
                { key: "rdp", label: "Remote Desktop (RDP)" },
                { key: "vnc", label: "Screen sharing (VNC)" },
                { key: "ssh", label: "Terminal (SSH)" }
              ]
              delegate: Toggle {
                required property var modelData
                width: column.width
                enabled: root.st.allow === true
                opacity: root.st.allow ? 1.0 : 0.5
                label: modelData.label
                description: root.serviceDescription(modelData.key)
                checked: root.services[modelData.key].enabled === true
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.toggleService(modelData.key)
              }
            }

            PanelSeparator { width: parent.width; visible: root.anyOn }

            Repeater {
              model: root.anyOn ? root.selectedNetworks : []
              delegate: InfoRow {
                required property var modelData
                label: modelData.label.replace(/ \(.*\)/, "")
                value: modelData.address
              }
            }
            InfoRow {
              visible: root.anyOn && root.services.rdp.enabled === true
              label: "User"
              value: root.services.rdp.username || ""
            }

            // RDP password: shown in its own box, with show / copy / new.
            Row {
              visible: root.anyOn && root.services.rdp.enabled === true
              width: parent.width
              spacing: Style.space(8)
              Text {
                width: Style.space(96)
                anchors.verticalCenter: parent.verticalCenter
                text: "Password"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }
              TextField {
                id: rdpPassword
                width: parent.width - Style.space(96) - rdpSave.width - rdpEye.width - rdpCopy.width - rdpNew.width - Style.space(40)
                password: !root.showRdpPassword
                foreground: root.foreground
                font.family: root.fontFamily
                placeholderText: "Type your own, or press New"
                onAccepted: root.savePassword("rdp", text)
              }
              // "Saved" while the box matches the stored password; "Save" once you type your own.
              Button {
                id: rdpSave
                text: rdpPassword.text === root.rdpSaved && root.rdpSaved !== "" ? "Saved" : "Save"
                enabled: rdpPassword.text !== root.rdpSaved
                opacity: enabled ? 1 : 0.5
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.savePassword("rdp", rdpPassword.text)
              }
              Button { id: rdpEye; text: root.showRdpPassword ? "Hide" : "Show"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: root.showRdpPassword = !root.showRdpPassword }
              Button { id: rdpCopy; text: "Copy"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: root.copy(rdpPassword.text) }
              Button { id: rdpNew; text: "New"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: { root.showRdpPassword = true; root.run(["generate-password", "rdp"]) } }
            }

            Text {
              visible: root.anyOn && root.selectedNetworks.length === 0
              width: parent.width
              text: "Pick a network in Settings so other devices can reach this computer."
              color: root.urgent
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
            Text {
              visible: !root.st.allow
              width: parent.width
              text: "Paused: nothing can connect. Your choices are kept; switch on to resume."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }

          // ---- computers ---------------------------------------------------------------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.ready && root.tab === "computers" && !root.editingHost

            Text {
              visible: (root.st.hosts || []).length === 0
              width: parent.width
              text: "Save Windows PCs, Macs, servers or other Omarchy machines and connect in one click."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
            Repeater {
              model: root.st.hosts || []
              delegate: Row {
                required property var modelData
                width: column.width
                spacing: Style.space(8)
                Button {
                  width: parent.width - editButton.width - Style.space(8)
                  text: modelData.name + "  ·  " + (modelData.protocol || "rdp").toUpperCase()
                  bordered: true
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  onClicked: root.run(["host-connect", modelData.id])
                }
                Button {
                  id: editButton
                  text: "Edit"
                  foreground: root.foreground
                  fontFamily: root.fontFamily
                  onClicked: root.openHost(modelData)
                }
              }
            }
            Button {
              text: "Add a computer"
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.openHost(null)
            }
          }

          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.ready && root.tab === "computers" && root.editingHost

            ButtonGroup {
              id: hostProtocol
              width: parent.width
              options: [{ value: "rdp", label: "RDP" }, { value: "vnc", label: "VNC" }, { value: "ssh", label: "SSH" }]
              value: "rdp"
              fontFamily: root.fontFamily
              foreground: root.foreground
              onChanged: function(v) { hostProtocol.value = v }
            }
            Text {
              width: parent.width
              text: hostProtocol.value === "rdp" ? "Windows PCs and other Omarchy machines" : (hostProtocol.value === "vnc" ? "Macs, Linux desktops, Raspberry Pi" : "Any server, in a terminal")
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
            TextField { id: hostName; width: parent.width; placeholderText: "Name, e.g. Office PC"; foreground: root.foreground; font.family: root.fontFamily }
            TextField { id: hostAddress; width: parent.width; placeholderText: "Address or Tailscale name"; foreground: root.foreground; font.family: root.fontFamily }
            TextField { id: hostUser; width: parent.width; visible: hostProtocol.value !== "vnc"; placeholderText: "Username (optional)"; foreground: root.foreground; font.family: root.fontFamily }
            Row {
              width: parent.width
              spacing: Style.space(8)
              visible: hostProtocol.value === "rdp"
              TextField {
                id: hostPassword
                width: parent.width - (forgetButton.visible ? forgetButton.width + Style.space(8) : 0)
                password: true
                placeholderText: root.editHost && root.editHost.savedPassword ? "Password saved. Type to change it" : "Password (optional, kept in your keyring)"
                foreground: root.foreground
                font.family: root.fontFamily
              }
              Button {
                id: forgetButton
                visible: !!(root.editHost && root.editHost.savedPassword)
                text: "Forget"
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: {
                  root.run(["host-save"], JSON.stringify({ id: root.editHost.id, name: root.editHost.name, host: root.editHost.host,
                    protocol: root.editHost.protocol, port: root.editHost.port, username: root.editHost.username,
                    domain: root.editHost.domain, gateway: root.editHost.gateway, multimon: root.editHost.multimon, forgetPassword: true }))
                  root.editingHost = false
                }
              }
            }
            TextField { id: hostPort; width: parent.width; placeholderText: "Port (optional)"; foreground: root.foreground; font.family: root.fontFamily }
            TextField { id: hostDomain; width: parent.width; visible: hostProtocol.value === "rdp"; placeholderText: "Domain (optional)"; foreground: root.foreground; font.family: root.fontFamily }
            TextField { id: hostGateway; width: parent.width; visible: hostProtocol.value === "rdp"; placeholderText: "RD Gateway (optional)"; foreground: root.foreground; font.family: root.fontFamily }
            Toggle {
              id: hostMultimon
              width: parent.width
              visible: hostProtocol.value === "rdp"
              label: "Use all my monitors"
              description: "Spread the remote desktop across every screen, external monitors included"
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: checked = !checked
            }
            Toggle {
              id: hostGrab
              width: parent.width
              visible: hostProtocol.value === "rdp"
              label: "Send Super shortcuts to the PC"
              description: checked ? "The Windows key goes to the PC; Omarchy's shortcuts don't work on this window"
                                   : "Omarchy's Super shortcuts keep working (move, resize, workspaces)"
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: checked = !checked
            }
            Row {
              spacing: Style.space(8)
              Button { text: "Save"; enabled: hostAddress.text.trim() !== ""; bordered: true; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: root.saveHost() }
              Button {
                visible: root.editHost !== null && root.editHost.id !== ""
                text: "Delete"
                foreground: root.urgent
                fontFamily: root.fontFamily
                onClicked: { root.run(["host-remove", root.editHost.id]); root.editingHost = false }
              }
              Button { text: "Cancel"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: root.editingHost = false }
            }
          }

          // ---- settings -------------------------------------------------------------------
          Column {
            width: parent.width
            spacing: Style.space(8)
            visible: root.ready && root.tab === "settings"

            PanelSectionHeader { text: "ACCEPT CONNECTIONS FROM"; foreground: root.foreground; fontFamily: root.fontFamily }
            Repeater {
              model: root.st.networks || []
              delegate: Toggle {
                required property var modelData
                width: column.width
                enabled: modelData.allowed
                opacity: modelData.allowed ? 1.0 : 0.5
                label: modelData.label
                description: modelData.allowed ? modelData.address : "Blocked: work VPNs never accept incoming connections"
                checked: modelData.selected
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: if (modelData.allowed) root.toggleNetwork(modelData.iface)
              }
            }

            PanelSectionHeader { text: "REMOTE DESKTOP"; foreground: root.foreground; fontFamily: root.fontFamily }
            Dropdown {
              width: parent.width
              label: "Screen"
              options: root.screenOptions(true)
              value: root.services.rdp.mode === "mirror" && root.services.rdp.output ? "mirror:" + root.services.rdp.output : "fit"
              fontFamily: root.fontFamily
              onChanged: function(value) {
                if (value === "fit") root.run(["settings"], JSON.stringify({ rdp: { mode: "fit" } }))
                else root.run(["settings"], JSON.stringify({ rdp: { mode: "mirror", output: value.slice(7) } }))
              }
            }
            Text {
              width: parent.width
              text: "Super key on your remote keyboard"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
            }
            ButtonGroup {
              width: parent.width
              options: [
                { value: "command", label: "⌘ Command" },
                { value: "option", label: "⌥ Option" },
                { value: "control", label: "Control" },
                { value: "capslock", label: "Caps Lock" }
              ]
              value: root.services.rdp.superKey || "command"
              fontFamily: root.fontFamily
              foreground: root.foreground
              onChanged: function(v) { root.run(["settings"], JSON.stringify({ rdp: { super_key: v } })) }
            }
            Text {
              width: parent.width
              text: ({
                command: "⌘ is sent as Super, but on a Mac ⌘Q quits Windows App and ⌘W/C/V are turned into Ctrl shortcuts.",
                option: "Recommended on a Mac: ⌥ Option acts as Super and ⌘ acts as Alt, so macOS keeps its shortcuts.",
                control: "Control acts as Super; the Windows/⌘ key acts as Control.",
                capslock: "Caps Lock acts as Super; every other key works as usual."
              })[root.services.rdp.superKey || "command"]
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WordWrap
            }
            Toggle {
              width: parent.width
              visible: root.services.rdp.mode !== "mirror"
              label: "Bring my workspaces"
              description: "All your workspaces move to the remote screen while you're connected"
              checked: root.services.rdp.moveWorkspaces !== false
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.run(["settings"], JSON.stringify({ rdp: { move_workspaces: !(root.services.rdp.moveWorkspaces !== false) } }))
            }
            Toggle {
              width: parent.width
              label: "Lock this laptop while connected"
              description: "Screens off and keyboard/touchpad disabled during a session; locked when you leave"
              checked: root.services.rdp.lock !== false
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.run(["settings"], JSON.stringify({ rdp: { lock: !(root.services.rdp.lock !== false) } }))
            }

            PanelSectionHeader { text: "SCREEN SHARING (VNC)"; foreground: root.foreground; fontFamily: root.fontFamily }
            Dropdown {
              width: parent.width
              label: "Screen"
              options: root.screenOptions(false)
              value: root.services.vnc.output || ""
              fontFamily: root.fontFamily
              onChanged: function(value) { root.run(["settings"], JSON.stringify({ vnc: { output: value } })) }
            }
            Row {
              width: parent.width
              spacing: Style.space(8)
              TextField {
                id: vncPassword
                width: parent.width - vncSave.width - vncEye.width - vncNew.width - Style.space(24)
                password: !root.showVncPassword
                placeholderText: "VNC password: type your own, or press New"
                foreground: root.foreground
                font.family: root.fontFamily
                onAccepted: root.savePassword("vnc", text)
              }
              Button {
                id: vncSave
                text: vncPassword.text === root.vncSaved && root.vncSaved !== "" ? "Saved" : "Save"
                enabled: vncPassword.text !== root.vncSaved
                opacity: enabled ? 1 : 0.5
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: root.savePassword("vnc", vncPassword.text)
              }
              Button { id: vncEye; text: root.showVncPassword ? "Hide" : "Show"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: root.showVncPassword = !root.showVncPassword }
              Button { id: vncNew; text: "New"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: { root.showVncPassword = true; root.run(["generate-password", "vnc"]) } }
            }

            PanelSectionHeader { text: "TERMINAL (SSH)"; foreground: root.foreground; fontFamily: root.fontFamily }
            Text {
              width: parent.width
              text: (root.services.ssh.keys || 0) === 0 ? "Paste your other computer's public key (on a Mac: cat ~/.ssh/id_ed25519.pub)." : root.services.ssh.keys + " key(s) allowed. Paste another to add it."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
            Row {
              width: parent.width
              spacing: Style.space(8)
              TextField {
                id: sshKey
                width: parent.width - addKey.width - Style.space(8)
                placeholderText: "ssh-ed25519 AAAA… you@mac"
                foreground: root.foreground
                font.family: root.fontFamily
              }
              Button {
                id: addKey
                text: "Add"
                enabled: sshKey.text.trim() !== ""
                bordered: true
                foreground: root.foreground
                fontFamily: root.fontFamily
                onClicked: { root.run(["add-key"], sshKey.text.trim()); sshKey.text = "" }
              }
            }

            PanelSectionHeader { text: "AFTER A RESTART"; foreground: root.foreground; fontFamily: root.fontFamily }
            Toggle {
              width: parent.width
              label: "Unlock the disk remotely"
              description: root.st.unlock && root.st.unlock.enabled
                ? "After a restart, run: ssh root@" + root.st.unlock.hostname + " and type your disk password. Typing it here still works too."
                : "Advanced. Lets you type the disk password over Tailscale after a restart, so the computer comes back without anyone at it. Stores your Wi-Fi key and a Tailscale key on the unencrypted boot partition."
              checked: !!(root.st.unlock && root.st.unlock.enabled)
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: {
                if (root.st.unlock && root.st.unlock.enabled) root.run(["unlock", "remove"])
                else if (root.st.unlock && root.st.unlock.registered) root.run(["unlock", "install"])
                else root.run(["unlock", "register"])
              }
            }
            Button {
              visible: root.loginLink !== ""
              text: "Sign in to Tailscale for the boot device"
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: Quickshell.execDetached(["xdg-open", root.loginLink])
            }
            Button {
              visible: !!(root.st.unlock && root.st.unlock.registered && !root.st.unlock.enabled) && !root.busy
              text: "Finish: build the boot entry"
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.run(["unlock", "install"])
            }
            Text {
              visible: root.busy && root.progress !== ""
              width: parent.width
              text: root.progress
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }

            Text {
              visible: (root.st.fingerprint || "") !== ""
              width: parent.width
              text: "Certificate fingerprint: " + root.st.fingerprint
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WrapAnywhere
            }
          }
        }
      }
    }
  }
}
