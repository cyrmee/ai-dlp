import QtQuick
import QtQuick.Layouts
import Quickshell
import qs.Commons
import qs.Commons as Commons
import qs.Ui

// Bar widget for the ai-dlp proxy. The shield shows whether traffic to
// AI services is being inspected and lights up for a moment (accent) whenever
// secrets are redacted or an image/PDF is sent; it turns urgent if the proxy is down.
// Left click opens the live request list, right click switches inspection on
// or off, middle click re-reads the state.
Panel {
  id: root
  moduleName: "ai-dlp.widget"
  ipcTarget: "ai-dlp.widget"
  manageIpc: false

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color accent: Commons.Color.accent
  readonly property color dim: Qt.darker(foreground, 1.4)
  readonly property color faint: Qt.darker(foreground, 1.9)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  property bool cursorActive: false
  // "all", "flagged", or one category: "allowed", "redacted", "attachments".
  property string filter: dlp.showAllowedSetting ? "all" : "flagged"
  // The request shown in the detail view (an event), or null for the lists.
  property var detailEntry: null
  property double now: Date.now()

  function escapeMarkup(text) {
    return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;")
  }

  // Plain text with every [REDACTED:rule] marker in bold accent; the rest is escaped.
  function highlight(text) {
    var colour = String(accent)
    return escapeMarkup(text).replace(/\[REDACTED:[A-Za-z0-9_.\-]{1,64}\]/g, function(m) {
      return "<b><font color=\"" + colour + "\">" + m + "</font></b>"
    })
  }

  function setFilter(category) {
    filter = filter === category ? "all" : category
  }

  function showDetail(entry) {
    detailEntry = entry
    dlp.loadDetail(entry.id)
    scroller.contentY = 0
  }

  readonly property string glyph: {
    if (dlp.status === "proxyDown") return "󰻌"   // shield-alert
    if (dlp.status === "on") return "󰕥"          // shield-check
    return "󰦞"                                   // shield-off
  }

  readonly property string stateText: dlp.busy ? strings.t("state.switching") : strings.t("state." + dlp.status)
  readonly property string detailText: ({
    on: strings.t("detail.on"), off: strings.t("detail.off"),
    proxyDown: strings.t("detail.proxyDown"), missing: strings.t("detail.missing")
  })[dlp.status] || ""

  readonly property var visibleRecent: dlp.recent.filter(function(e) {
    if (filter === "all") return true
    if (filter === "flagged") return e.action !== "allowed" || e.attachments.length > 0
    if (filter === "attachments") return e.attachments.length > 0
    return e.action === filter
  }).slice(0, 25)

  function agoText(time) {
    var seconds = Math.max(0, Math.round((now - time) / 1000))
    if (seconds < 5) return strings.t("ago.now")
    if (seconds < 60) return strings.t("ago.s").arg(Commons.I18n.formatNumber(seconds))
    var minutes = Math.floor(seconds / 60)
    if (minutes < 60) return strings.t("ago.m").arg(Commons.I18n.formatNumber(minutes))
    var hours = Math.floor(minutes / 60)
    if (hours < 48) return strings.t("ago.h").arg(Commons.I18n.formatNumber(hours))
    return strings.t("ago.d").arg(Commons.I18n.formatNumber(Math.floor(hours / 24)))
  }

  function sizeText(bytes) {
    if (bytes >= 1048576) return strings.t("size.mb").arg(Commons.I18n.formatNumber(bytes / 1048576, 1))
    return strings.t("size.kb").arg(Commons.I18n.formatNumber(Math.max(1, Math.round(bytes / 1024))))
  }

  function toneFor(action) {
    if (action === "redacted" || action === "attachments") return root.accent
    return root.dim
  }

  function actionGlyph(action) {
    if (action === "redacted") return "󰈉"  // eye-off
    return "󰄬"                             // check
  }

  function attachmentText(a) {
    var parts = [strings.t("kind." + a.kind + ".label")]
    if (a.media !== "" && a.media.indexOf("*") < 0) parts.push(a.media.replace(/^[a-z]+\//, "").toUpperCase())
    if (a.bytes > 0) parts.push(sizeText(a.bytes))
    if (a.name !== "") parts.push(a.name)
    return parts.join(" · ")
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: if (opened) {
    cursorActive = false
    detailEntry = null
    now = Date.now()
    dlp.refresh()
    Qt.callLater(function() { if (panel.loadedContent) panel.loadedContent.forceActiveFocus() })
  }

  Commons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  Service {
    id: dlp
    settings: root.settings
    strings: strings
    panelOpen: root.opened
  }

  // Keeps the "ago" times current while the panel is open.
  Timer {
    interval: 5000
    repeat: true
    running: root.opened
    onTriggered: root.now = Date.now()
  }

  ShellIpc {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { dlp.refresh(); return "ok" }
    function status(): string { return dlp.status }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    slotSize: Style.bar.statusSlot
    text: root.glyph
    tooltipText: strings.t("title") + " · " + root.stateText
    active: dlp.flash !== "" || dlp.status === "proxyDown"
    activeColor: dlp.flash !== "" ? root.accent : root.urgent
    opacity: dlp.busy ? pulse.value : (dlp.status === "on" || dlp.status === "proxyDown" ? 1.0 : 0.45)
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) dlp.toggle()
      else if (buttonCode === Qt.MiddleButton) dlp.refresh()
      else root.toggle()
    }
  }

  QtObject {
    id: pulse
    property real value: 1.0
  }

  SequentialAnimation {
    running: dlp.busy
    loops: Animation.Infinite
    onStopped: pulse.value = 1.0
    NumberAnimation { target: pulse; property: "value"; from: 1.0; to: 0.35; duration: Style.duration(700); easing.type: Easing.InOutSine }
    NumberAnimation { target: pulse; property: "value"; from: 0.35; to: 1.0; duration: Style.duration(700); easing.type: Easing.InOutSine }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(400))
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(640))

    content: PanelKeyCatcher {
      implicitHeight: column.implicitHeight
      anchors.fill: parent
      onMoveRequested: function(dx, dy) { root.cursorActive = true }
      // A stray Enter as the panel takes focus only shows the cursor on the
      // switch; a second one flips it, so inspection is never dropped by accident.
      onActivateRequested: {
        if (root.cursorActive) dlp.toggle()
        else root.cursorActive = true
      }
      onCloseRequested: {
        if (root.detailEntry !== null) root.detailEntry = null
        else root.close()
      }
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "r" || t === "R") dlp.refresh()
        else if (t === "a" || t === "A") root.filter = root.filter === "all" ? "flagged" : "all"
      }

      Flickable {
        id: scroller
        anchors.fill: parent
        contentWidth: width
        contentHeight: column.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        interactive: contentHeight > height

        Column {
          id: column
          width: scroller.width
          spacing: Style.space(14)

          // ---------- Hero: shield · title/state · switch ----------
          Item {
            id: header
            width: parent.width
            implicitHeight: hero.implicitHeight
            readonly property bool ringVisible: root.cursorActive
            readonly property string hint: dlp.routingOn ? strings.t("hint.off") : strings.t("hint.on")
            function focusSwitch() { root.cursorActive = true }

            PanelHero {
              id: hero
              width: parent.width
              title: strings.t("title")
              meta: root.stateText
              foreground: root.foreground
              fontFamily: root.fontFamily
              iconOpacity: dlp.status === "on" || dlp.status === "proxyDown" ? 1.0 : 0.5
              iconComponent: Component {
                Text {
                  textFormat: Text.PlainText
                  text: root.glyph
                  color: dlp.status === "proxyDown" ? root.urgent : root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.display
                }
              }

              trailingControl: Component {
                ToggleSwitch {
                  id: routingSwitch
                  visible: dlp.installed
                  checked: dlp.busy ? !dlp.routingOn : dlp.routingOn
                  busy: dlp.busy
                  hasCursor: header.ringVisible
                  foreground: hero.foreground
                  onHovered: function(on) { if (on) header.focusSwitch() }
                  onToggled: dlp.toggle()

                  PanelToolTip {
                    visible: routingSwitch.containsMouse
                    text: header.hint
                    fontFamily: hero.fontFamily
                  }
                }
              }
            }
          }

          Caption {
            visible: text !== ""
            text: dlp.lastError !== "" ? dlp.lastError : (dlp.feedError !== "" ? dlp.feedError : root.detailText)
            color: dlp.lastError !== "" || dlp.feedError !== "" ? root.urgent : root.dim
          }

          PanelSeparator { foreground: root.foreground }

          // ---------- Detail view of one request ----------
          DetailView {
            visible: root.detailEntry !== null
            width: parent.width
          }

          // ---------- Today ----------
          Column {
            visible: root.detailEntry === null
            width: parent.width
            spacing: Style.space(8)

            PanelSectionHeader {
              text: strings.t("counts.title")
              foreground: root.foreground
              fontFamily: root.fontFamily
            }

            Grid {
              id: stats
              width: parent.width
              columns: 3
              spacing: Style.spacing.xs
              readonly property real cellWidth: (width - spacing * (columns - 1)) / columns

              StatTile { width: stats.cellWidth; action: "allowed"; value: dlp.counts.allowed }
              StatTile { width: stats.cellWidth; action: "redacted"; value: dlp.counts.redacted }
              StatTile { width: stats.cellWidth; action: "attachments"; value: dlp.counts.attachments }
            }
          }

          PanelSeparator { visible: root.detailEntry === null; foreground: root.foreground }

          // ---------- Recent requests ----------
          Column {
            visible: root.detailEntry === null
            width: parent.width
            spacing: Style.space(4)

            Item {
              width: parent.width
              implicitHeight: Math.max(recentHeader.implicitHeight, filterToggle.implicitHeight)

              PanelSectionHeader {
                id: recentHeader
                anchors.left: parent.left
                anchors.verticalCenter: parent.verticalCenter
                text: strings.t("recent.title")
                foreground: root.foreground
                fontFamily: root.fontFamily
              }

              // "All" / "Flagged", switched with a click or the A key.
              Text {
                id: filterToggle
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                textFormat: Text.PlainText
                text: strings.t("filter." + root.filter)
                color: filterMouse.containsMouse ? root.foreground : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                font.letterSpacing: 1.2

                MouseArea {
                  id: filterMouse
                  anchors.fill: parent
                  anchors.margins: -Style.space(4)
                  hoverEnabled: true
                  cursorShape: Qt.PointingHandCursor
                  onClicked: root.filter = root.filter === "all" ? "flagged" : "all"
                }

                PanelToolTip {
                  visible: filterMouse.containsMouse
                  text: root.filter === "all" || root.filter === "flagged" ? strings.t("filter.hint") : strings.t("filter.clear")
                  fontFamily: root.fontFamily
                }
              }
            }

            Item { width: 1; height: Style.space(4) }

            Caption {
              visible: root.visibleRecent.length === 0
              text: root.filter === "all" ? strings.t("recent.empty")
                : (root.filter === "flagged" ? strings.t("recent.emptyFlagged") : strings.t("recent.emptyFiltered"))
              color: root.dim
            }

            Repeater {
              model: root.visibleRecent
              EventRow {
                required property var modelData
                width: parent.width
                entry: modelData
              }
            }
          }
        }
      }
    }
  }

  // One request in full: what was sent (after redaction), its headers (login headers
  // hidden) and its payload as selectable text, with the full copy one click away.
  component DetailView: Column {
    id: dv
    readonly property var entry: root.detailEntry || ({})
    readonly property var d: dlp.detail
    spacing: Style.space(10)

    RowLayout {
      width: parent.width
      spacing: Style.space(8)

      PanelActionButton {
        iconText: "󰁍"
        tooltipText: strings.t("detail.back")
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: root.detailEntry = null
      }

      Text {
        Layout.fillWidth: true
        textFormat: Text.PlainText
        text: (dv.entry.method ? dv.entry.method + " " : "") + (dv.entry.path || "/")
        color: dv.entry.action === "allowed" ? root.foreground : root.toneFor(dv.entry.action)
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
        font.bold: true
        elide: Text.ElideMiddle
      }

      PanelActionButton {
        visible: dv.d !== null && !!dv.d.file && !dv.d.error
        iconText: "󰏌"
        tooltipText: strings.t("detail.open")
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: dlp.openFile(dv.d.file)
      }
    }

    Caption {
      text: [dv.entry.host, strings.t("action." + (dv.entry.action || "allowed")), root.agoText(dv.entry.time || 0)]
        .concat(dv.entry.action === "redacted" ? [dlp.rulesText(dv.entry.rules)] : []).join(" · ")
      color: root.dim
    }

    Caption {
      visible: dlp.detailLoading || (dv.d !== null && dv.d.error !== "")
      text: dlp.detailLoading ? strings.t("detail.loading") : (dv.d ? dv.d.error : "")
      color: dlp.detailLoading ? root.dim : root.urgent
    }

    // What was redacted: each change with a little of the text around it. The copy is
    // stored after redaction, so the secret itself never appears here.
    Column {
      visible: dv.d !== null && !dv.d.error
      width: parent.width
      spacing: Style.space(8)

      PanelSectionHeader {
        text: dv.d && dv.d.total > 0
          ? strings.tn("detail.changes", dv.d.total).arg(Commons.I18n.formatNumber(dv.d.total))
          : strings.t("detail.changesTitle")
        foreground: root.foreground
        fontFamily: root.fontFamily
      }

      Caption {
        visible: dv.d !== null && dv.d.changes.length === 0
        text: !dv.d ? "" : (!dv.d.stored ? strings.t("detail.bodyNotStored")
          : (dv.entry.action === "allowed" ? strings.t("detail.nothingRedacted") : strings.t("detail.noPreview")))
        color: root.dim
      }

      Repeater {
        model: dv.d ? dv.d.changes : []
        BorderSurface {
          required property var modelData
          width: parent.width
          implicitHeight: changeColumn.implicitHeight + Style.space(14)
          color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.04)
          radius: Style.cornerRadius
          borderSpec: Border.controlSpec("normal", root.foreground, Commons.Color.accent)

          Column {
            id: changeColumn
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.margins: Style.space(8)
            spacing: Style.space(3)

            Text {
              textFormat: Text.PlainText
              text: modelData.rule + (modelData.count > 1 ? "  ×" + Commons.I18n.formatNumber(modelData.count) : "")
              color: root.accent
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            // Escaped first, so only the [REDACTED:…] markers are styled and nothing in the
            // request can act as markup.
            Text {
              width: parent.width
              textFormat: Text.StyledText
              text: root.highlight(modelData.before + "[REDACTED:" + modelData.rule + "]" + modelData.after)
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              wrapMode: Text.WrapAnywhere
            }
          }
        }
      }

      Caption {
        visible: dv.d !== null && dv.d.distinct > dv.d.changes.length
        text: dv.d ? strings.t("detail.more").arg(Commons.I18n.formatNumber(dv.d.distinct - dv.d.changes.length)) : ""
        color: root.dim
      }
    }
  }

  component Caption: Text {
    textFormat: Text.PlainText
    width: parent ? parent.width : implicitWidth
    wrapMode: Text.WordWrap
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
  }

  // A bordered tile: the count large, its label small underneath. Clicking it shows only
  // that category in the Recent list (clicking again shows everything).
  component StatTile: BorderSurface {
    id: tile
    property string action: "allowed"
    property int value: 0
    readonly property bool lit: value > 0 && action !== "allowed"
    readonly property bool selected: root.filter === action

    implicitHeight: tileColumn.implicitHeight + Style.space(14)
    height: implicitHeight
    color: selected ? Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.14) : "transparent"
    radius: Style.cornerRadius
    borderSpec: Border.controlSpec(tileMouse.containsMouse ? "hover" : "normal",
                                   selected ? root.accent : (lit ? root.toneFor(action) : root.foreground),
                                   Commons.Color.accent)

    MouseArea {
      id: tileMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: root.setFilter(tile.action)
    }

    PanelToolTip {
      visible: tileMouse.containsMouse
      text: strings.t("tile.hint")
      fontFamily: root.fontFamily
    }

    Column {
      id: tileColumn
      anchors.centerIn: parent
      width: parent.width - Style.space(8)
      spacing: Style.space(1)

      Text {
        width: parent.width
        horizontalAlignment: Text.AlignHCenter
        textFormat: Text.PlainText
        text: Commons.I18n.formatNumber(tile.value)
        color: tile.value > 0 ? (tile.action === "allowed" ? root.foreground : root.toneFor(tile.action)) : root.faint
        font.family: root.fontFamily
        font.pixelSize: Style.font.title
        font.bold: true
      }

      Text {
        width: parent.width
        horizontalAlignment: Text.AlignHCenter
        textFormat: Text.PlainText
        text: strings.t("count." + tile.action)
        color: root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        elide: Text.ElideRight
      }
    }
  }

  // One request: a status glyph, the path with host/size underneath, any
  // rules, notes or attachments below that, and the time on the right.
  component EventRow: Item {
    id: row
    property var entry: ({})
    readonly property color tone: root.toneFor(entry.action)

    implicitHeight: rowLayout.implicitHeight + Style.space(8)

    Rectangle {
      anchors.fill: parent
      anchors.leftMargin: -Style.space(4)
      anchors.rightMargin: -Style.space(4)
      radius: Style.cornerRadius
      color: rowMouse.containsMouse ? Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.06) : "transparent"
    }

    MouseArea {
      id: rowMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: root.showDetail(row.entry)
    }

    PanelToolTip {
      visible: rowMouse.containsMouse
      text: strings.t("detail.rowHint")
      fontFamily: root.fontFamily
    }

    RowLayout {
      id: rowLayout
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(10)

      Text {
        Layout.alignment: Qt.AlignTop
        Layout.topMargin: Style.space(1)
        textFormat: Text.PlainText
        text: root.actionGlyph(row.entry.action)
        color: row.tone
        font.family: root.fontFamily
        font.pixelSize: Style.font.body
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: Style.space(2)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(8)

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            text: row.entry.path || "/"
            color: row.entry.action === "allowed" ? root.foreground : row.tone
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            font.bold: row.entry.action !== "allowed"
            elide: Text.ElideMiddle
          }

          Text {
            textFormat: Text.PlainText
            text: root.agoText(row.entry.time)
            color: root.faint
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          text: {
            var parts = [row.entry.host]
            if (row.entry.bytes > 0) parts.push(root.sizeText(row.entry.bytes))
            if (row.entry.test) parts.push(strings.t("action.test"))
            return parts.join(" · ")
          }
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          elide: Text.ElideRight
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          text: row.entry.action === "redacted" ? strings.t("detail.redacted").arg(dlp.rulesText(row.entry.rules)) : ""
          color: row.tone
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
          maximumLineCount: 2
          elide: Text.ElideRight
        }

        // What ai-dlp did beyond plain redaction: files removed, content sent unscanned, ...
        Repeater {
          model: row.entry.notes || []
          Text {
            required property var modelData
            Layout.fillWidth: true
            textFormat: Text.PlainText
            text: "󰋽  " + modelData
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
            maximumLineCount: 2
            elide: Text.ElideRight
          }
        }

        // Images and PDFs cannot be scanned for secrets, so each one is listed.
        Repeater {
          model: row.entry.attachments || []
          Text {
            required property var modelData
            Layout.fillWidth: true
            textFormat: Text.PlainText
            text: (modelData.kind === "image" ? "󰋩  " : "󰈦  ") + root.attachmentText(modelData)
            color: root.accent
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            elide: Text.ElideMiddle
          }
        }
      }
    }
  }
}
