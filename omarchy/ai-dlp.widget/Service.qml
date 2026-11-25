import QtQuick
import Quickshell
import Quickshell.Io

// State and actions for the AI DLP widget. The dlpwatch helper beside this
// file tails the proxy's event log and reports the systemd units; switching
// routing on or off goes through the ai-dlp command (pkexec asks for
// authentication). No shell command line is ever built from data.
Item {
  id: root

  property var settings: ({})
  property var strings: null
  property bool panelOpen: false

  readonly property string helperPath: decodeURIComponent(String(Qt.resolvedUrl("dlpwatch")).replace(/^file:\/\//, ""))
  readonly property string controlPath: "/usr/local/bin/ai-dlp"
  readonly property bool showAllowedSetting: setting("showAllowed", true) !== false
  readonly property bool notifyRedacted: setting("notifyRedacted", true) !== false
  readonly property bool notifyAttachments: setting("notifyAttachments", true) !== false

  property bool installed: true
  property string proxy: "unknown"
  property string firewall: "unknown"
  property var counts: ({ allowed: 0, redacted: 0, attachments: 0 })
  // Newest first: { time, action, host, method, path, bytes, rules, reason, test,
  //                 attachments: [{ kind, media, bytes, name, source }] }.
  property var recent: []
  property string feedError: ""
  property string lastError: ""
  property bool received: false

  // "missing", "unknown", "on", "off" or "proxyDown".
  readonly property string status: {
    if (!installed) return "missing"
    if (!received) return "unknown"
    if (firewall === "active") return proxy === "active" ? "on" : "proxyDown"
    return "off"
  }
  readonly property bool routingOn: firewall === "active"
  readonly property bool busy: toggleProcess.running
  // "redacted" or "attachment" for a few seconds after one happens, for the bar icon.
  property string flash: ""

  // The request opened in the detail view: { method, host, path, stored, changes:
  // [{ rule, before, after, count }], total, distinct, file, error }, or null.
  property var detail: null
  readonly property bool detailLoading: detailProcess.running

  function loadDetail(id) {
    if (!/^\d{13}-[0-9a-f]{8}$/.test(String(id || ""))) {
      detail = { error: t("detail.notStored"), changes: [], stored: false }
      return
    }
    detail = null
    detailProcess.command = [helperPath, "detail", id]
    detailProcess.running = true
  }

  function applyDetail(raw) {
    var d
    try { d = JSON.parse(String(raw || "")) } catch (e) { d = { error: t("detail.readFailed") } }
    var changes = Array.isArray(d.changes) ? d.changes.slice(0, 30).map(function(c) {
      var rule = /^[A-Za-z0-9_.\-]{1,64}$/.test(String(c.rule || "")) ? String(c.rule) : "secret"
      return { rule: rule, before: bounded(c.before, 400), after: bounded(c.after, 400),
               count: Math.max(1, parseInt(c.count, 10) || 1) }
    }) : []
    detail = {
      method: bounded(d.method, 10), host: bounded(d.host, 253), path: bounded(d.path, 2000),
      stored: d.stored === true, changes: changes,
      total: Math.max(0, parseInt(d.total, 10) || 0), distinct: Math.max(0, parseInt(d.distinct, 10) || 0),
      file: bounded(d.file, 300), error: bounded(d.error, 200)
    }
  }

  function openFile(path) {
    var p = String(path || "")
    if (/^\/var\/log\/ai-dlp\/requests\/\d{13}-[0-9a-f]{8}\.json$/.test(p))
      Quickshell.execDetached(["xdg-open", p])
  }

  property double _lastSeen: 0
  property double _lastRedactNotify: 0

  function setting(name, fallback) {
    var value = settings ? settings[name] : undefined
    return value === undefined || value === null ? fallback : value
  }

  function t(key) {
    return strings ? strings.t(key) : key
  }

  function bounded(value, max) {
    return String(value === undefined || value === null ? "" : value).substring(0, max)
  }

  // The helper already bounds fields; keep only known ones here too.
  function sanitize(e) {
    var rules = {}
    if (e && typeof e.rules === "object" && e.rules !== null) {
      var keys = Object.keys(e.rules).slice(0, 20)
      for (var i = 0; i < keys.length; i++) rules[bounded(keys[i], 64)] = Math.max(0, parseInt(e.rules[keys[i]], 10) || 0)
    }
    var action = ["allowed", "redacted"].indexOf(e.action) >= 0 ? e.action : "allowed"
    var attachments = Array.isArray(e.attachments) ? e.attachments.slice(0, 20).map(function(a) {
      var kind = ["image", "pdf", "document", "file"].indexOf(a.kind) >= 0 ? a.kind : "file"
      return { kind: kind, media: bounded(a.media, 80), bytes: Math.max(0, Number(a.bytes) || 0),
               name: bounded(a.name, 120), source: bounded(a.source, 20) }
    }) : []
    return {
      time: Number(e.time) || 0,
      action: action,
      host: bounded(e.host, 253),
      method: bounded(e.method, 10),
      path: bounded(e.path, 200),
      bytes: Math.max(0, Number(e.bytes) || 0),
      rules: rules,
      reason: bounded(e.reason, 200),
      test: e.test === true,
      id: /^\d{13}-[0-9a-f]{8}$/.test(String(e.id || "")) ? String(e.id) : "",
      notes: Array.isArray(e.notes) ? e.notes.slice(0, 20).map(function(n) { return bounded(n, 200) }) : [],
      attachments: attachments
    }
  }

  function rulesText(rules) {
    var keys = Object.keys(rules || {})
    return keys.map(function(k) { return rules[k] > 1 ? k + " ×" + rules[k] : k }).join(", ")
  }

  function apply(line) {
    var parsed
    try { parsed = JSON.parse(String(line || "")) } catch (e) { return }
    received = true
    installed = parsed.installed !== false
    proxy = bounded(parsed.proxy, 16)
    firewall = bounded(parsed.firewall, 16)
    var c = parsed.counts || {}
    counts = {
      allowed: Math.max(0, parseInt(c.allowed, 10) || 0),
      redacted: Math.max(0, parseInt(c.redacted, 10) || 0),
      attachments: Math.max(0, parseInt(c.attachments, 10) || 0)
    }
    var list = Array.isArray(parsed.recent) ? parsed.recent.slice(0, 40).map(sanitize) : []
    feedError = bounded(parsed.error, 200)
    announce(list)
    recent = list
  }

  // Flash the bar icon and notify for redactions and attachments that are new since
  // the last update. The first update only sets the baseline.
  function announce(list) {
    var newest = list.length > 0 ? list[0].time : 0
    if (_lastSeen === 0) { _lastSeen = newest || 1; return }
    var fresh = list.filter(function(e) { return e.time > root._lastSeen })
    if (newest > _lastSeen) _lastSeen = newest
    var redacted = fresh.filter(function(e) { return e.action === "redacted" && !e.test })
    var files = []
    fresh.forEach(function(e) { if (!e.test) files = files.concat(e.attachments) })
    if (files.length > 0 && notifyAttachments && !panelOpen)
      notify("normal", t("notify.attachments"), attachmentsSummary(files))
    if (redacted.length > 0 || files.length > 0) {
      flash = redacted.length > 0 ? "redacted" : "attachment"
      flashTimer.restart()
      var now = Date.now()
      if (redacted.length > 0 && notifyRedacted && !panelOpen && now - _lastRedactNotify > 60000) {
        _lastRedactNotify = now
        notify("normal", t("notify.redacted"), t("notify.redactedBody").arg(rulesText(redacted[0].rules)).arg(redacted[0].host))
      }
    }
  }

  // "2 images, 1 PDF (contract.pdf)"
  function attachmentsSummary(files) {
    var byKind = {}
    var names = []
    files.forEach(function(a) {
      byKind[a.kind] = (byKind[a.kind] || 0) + 1
      if (a.name !== "" && names.length < 3) names.push(a.name)
    })
    var parts = Object.keys(byKind).map(function(k) {
      return strings ? strings.tn("kind." + k, byKind[k]).arg(byKind[k]) : byKind[k] + " " + k
    })
    return parts.join(", ") + (names.length > 0 ? " (" + names.join(", ") + ")" : "")
  }

  function notify(urgency, title, body) {
    Quickshell.execDetached(["notify-send", "-a", "AI DLP", "-u", urgency, "-i", "security-high", "--", title, body])
  }

  function toggle() {
    if (busy || !installed) return
    lastError = ""
    toggleProcess.command = [controlPath, routingOn ? "off" : "on"]
    toggleProcess.running = true
  }

  function refresh() {
    if (!statusProcess.running) statusProcess.running = true
  }

  Timer {
    id: flashTimer
    interval: 4000
    onTriggered: root.flash = ""
  }

  Process {
    id: watchProcess
    command: [root.helperPath, "watch"]
    running: true
    stdout: SplitParser { onRead: function(line) { root.apply(line) } }
    // The watcher only stops if something kills it; bring it back.
    onExited: watchRestart.restart()
  }

  Timer {
    id: watchRestart
    interval: 5000
    onTriggered: watchProcess.running = true
  }

  Process {
    id: statusProcess
    command: [root.helperPath, "status"]
    stdout: StdioCollector { id: statusOut; waitForEnd: true }
    onExited: function(exitCode) { if (exitCode === 0) root.apply(statusOut.text) }
  }

  Process {
    id: detailProcess
    command: []
    stdout: StdioCollector { id: detailOut; waitForEnd: true }
    onExited: function(exitCode) { root.applyDetail(detailOut.text) }
  }

  Process {
    id: toggleProcess
    command: []
    onExited: function(exitCode) {
      if (exitCode !== 0) root.lastError = root.t("error.toggleFailed")
      root.refresh()
    }
  }
}
