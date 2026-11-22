import QtQuick
import QtQuick.Layouts
import Quickshell
import qs.Commons
import qs.Commons as Commons
import qs.Ui

// Bar widget for the ai-dlp proxy. The shield shows whether traffic to
// Anthropic is being inspected and lights up for a moment whenever secrets are
// redacted or an image/PDF is sent (accent) or a request is blocked (urgent).
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
  property bool showAllowed: dlp.showAllowedSetting
  property double now: Date.now()

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

  readonly property var visibleRecent: (showAllowed ? dlp.recent
    : dlp.recent.filter(function(e) { return e.action !== "allowed" || e.attachments.length > 0 })).slice(0, 25)

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
    if (action === "blocked") return root.urgent
    if (action === "redacted" || action === "attachments") return root.accent
    return root.dim
  }

  function actionGlyph(action) {
    if (action === "blocked") return "󰅙"   // close-circle
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
    activeColor: dlp.flash === "redacted" || dlp.flash === "attachment" ? root.accent : root.urgent
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
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "r" || t === "R") dlp.refresh()
        else if (t === "a" || t === "A") root.showAllowed = !root.showAllowed
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

          // ---------- Today ----------
          Column {
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
              columns: 4
              spacing: Style.spacing.xs
              readonly property real cellWidth: (width - spacing * (columns - 1)) / columns

              StatTile { width: stats.cellWidth; action: "allowed"; value: dlp.counts.allowed }
              StatTile { width: stats.cellWidth; action: "redacted"; value: dlp.counts.redacted }
              StatTile { width: stats.cellWidth; action: "blocked"; value: dlp.counts.blocked }
              StatTile { width: stats.cellWidth; action: "attachments"; value: dlp.counts.attachments }
            }
          }

          PanelSeparator { foreground: root.foreground }

          // ---------- Recent requests ----------
          Column {
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
                text: root.showAllowed ? strings.t("filter.all") : strings.t("filter.flagged")
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
                  onClicked: root.showAllowed = !root.showAllowed
                }

                PanelToolTip {
                  visible: filterMouse.containsMouse
                  text: strings.t("filter.hint")
                  fontFamily: root.fontFamily
                }
              }
            }

            Item { width: 1; height: Style.space(4) }

            Caption {
              visible: root.visibleRecent.length === 0
              text: root.showAllowed ? strings.t("recent.empty") : strings.t("recent.emptyFlagged")
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

  component Caption: Text {
    textFormat: Text.PlainText
    width: parent ? parent.width : implicitWidth
    wrapMode: Text.WordWrap
    font.family: root.fontFamily
    font.pixelSize: Style.font.caption
  }

  // A bordered tile: the count large, its label small underneath.
  component StatTile: BorderSurface {
    id: tile
    property string action: "allowed"
    property int value: 0
    readonly property bool lit: value > 0 && action !== "allowed"

    implicitHeight: tileColumn.implicitHeight + Style.space(14)
    height: implicitHeight
    color: "transparent"
    radius: Style.cornerRadius
    borderSpec: Border.controlSpec("normal", lit ? root.toneFor(action) : root.foreground, Commons.Color.accent)

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
  // rules, block reason or attachments below that, and the time on the right.
  component EventRow: Item {
    id: row
    property var entry: ({})
    readonly property color tone: root.toneFor(entry.action)

    implicitHeight: rowLayout.implicitHeight + Style.space(8)

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
          text: row.entry.action === "blocked" ? row.entry.reason
            : (row.entry.action === "redacted" ? strings.t("detail.redacted").arg(dlp.rulesText(row.entry.rules)) : "")
          color: row.tone
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
          maximumLineCount: 2
          elide: Text.ElideRight
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
