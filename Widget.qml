pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

// Bar icon for Based: a short horizontal line with one dot above it, drawn
// in the bar's own colour. The tooltip summarises
// the last scan, which the CLI writes after every run.
//   left click  : toggle the timeline window
//   right click : run a scan, then show the timeline
BarWidget {
  id: root
  moduleName: "io.github.bufuuu.based"

  readonly property string stateHome: Quickshell.env("XDG_STATE_HOME") || (Quickshell.env("HOME") + "/.local/state")
  readonly property string summaryPath: stateHome + "/based/summary.json"

  property var summary: null
  property int clock: 0 // bumped every minute so "ago" stays fresh

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function ago(iso) {
    clock
    var mins = Math.floor((Date.now() - Date.parse(iso)) / 60000)
    if (mins < 1) return "just now"
    if (mins < 60) return mins + "m ago"
    if (mins < 48 * 60) return Math.floor(mins / 60) + "h ago"
    return Math.floor(mins / 1440) + "d ago"
  }

  function tooltip() {
    if (!summary) return "Based: no scan yet\nRight click to scan (needs the based program: see the README)"
    var s = summary
    var head = s.high > 0 ? s.high + " very unusual item" + (s.high === 1 ? "" : "s") + " to look at"
      : s.med > 0 ? s.med + " unusual item" + (s.med === 1 ? "" : "s") + " worth a look"
      : "Nothing very unusual or unusual"
    return "Based: " + head
      + "\n" + s.high + " very unusual · " + s.med + " unusual · " + s.low + " a bit unusual · " + s.info + " normal"
      + "\nLast scan " + ago(s.scanned_at)
      + "\nLeft: timeline · Right: scan"
  }

  // `based open` toggles one floating window instead of stacking new ones.
  function openTimeline() {
    Util.execDetached("based open")
  }

  function runScan() {
    Util.execDetached("based open --scan")
  }

  FileView {
    id: summaryFile
    path: root.summaryPath
    watchChanges: true
    printErrors: false
    onFileChanged: reload()
    onLoaded: {
      try { root.summary = JSON.parse(text()) } catch (e) { root.summary = null }
    }
    onLoadFailed: root.summary = null
  }

  Timer {
    interval: 60000
    running: true
    repeat: true
    onTriggered: root.clock++
  }

  // The CLI replaces summary.json atomically (and it may not exist yet when
  // the shell starts), which a file watch can miss; re-read it cheaply.
  Timer {
    interval: 5000
    running: true
    repeat: true
    onTriggered: summaryFile.reload()
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    // a line with a dot above it, sized to the bar's icon canvas
    iconComponent: Component {
      Item {
        id: mark
        readonly property real u: Math.min(width, height)
        Rectangle {
          width: mark.u * 0.22
          height: width
          radius: width / 2
          color: button.foreground
          anchors.horizontalCenter: parent.horizontalCenter
          y: mark.height / 2 - mark.u * 0.30
        }
        Rectangle {
          width: mark.u * 0.70
          height: Math.max(1, Math.round(mark.u * 0.11))
          radius: height / 2
          color: button.foreground
          anchors.horizontalCenter: parent.horizontalCenter
          y: mark.height / 2 + mark.u * 0.12
        }
      }
    }
    tooltipText: { root.clock; return root.tooltip() }
    useActiveColor: false
    onPressed: function(b) {
      if (b === Qt.RightButton) root.runScan()
      else root.openTimeline()
    }
  }
}
