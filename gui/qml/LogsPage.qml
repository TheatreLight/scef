import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

Page {
    id: logsPageRoot
    padding: 24

    function currentPath() {
        if (!fileCombo.model || fileCombo.currentIndex < 0 ||
                fileCombo.currentIndex >= fileCombo.model.length)
            return ""
        return fileCombo.model[fileCombo.currentIndex].path
    }

    function reloadContent() {
        var path = currentPath()
        if (path === "") {
            logText.text = "No log files found in " + controller.logDirPath()
            return
        }

        logText.text = controller.readLogFile(path)
        Qt.callLater(function() {
            logText.cursorPosition = logText.length
            logFlick.contentY = Math.max(0, logFlick.contentHeight - logFlick.height)
        })
    }

    function populate() {
        var previousPath = currentPath()
        var files = controller.listLogFiles()
        var items = []
        var selectedIndex = 0

        for (var i = 0; i < files.length; i++) {
            var path = files[i]
            var normalized = path.replace(/\\/g, "/")
            items.push({
                "name": normalized.substring(normalized.lastIndexOf("/") + 1),
                "path": path
            })
            if (path === previousPath)
                selectedIndex = i
        }

        fileCombo.model = items
        fileCombo.currentIndex = items.length > 0 ? selectedIndex : -1
        reloadContent()
    }

    Component.onCompleted: populate()

    ColumnLayout {
        anchors.fill: parent
        spacing: 16

        Label {
            text: "Logs"
            font.pixelSize: 24
            font.bold: true
            color: Material.color(Material.Amber)
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            ComboBox {
                id: fileCombo
                textRole: "name"
                Layout.fillWidth: true
                onActivated: reloadContent()
            }

            Button {
                text: "Refresh files"
                onClicked: populate()
            }

            Button {
                text: "Reload content"
                enabled: fileCombo.currentIndex >= 0
                onClicked: reloadContent()
            }
        }

        Flickable {
            id: logFlick
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            contentWidth: Math.max(width, logText.implicitWidth)
            contentHeight: Math.max(height, logText.implicitHeight)

            TextArea {
                id: logText
                readOnly: true
                selectByMouse: true
                wrapMode: TextArea.NoWrap
                font.family: "Consolas"
                font.pixelSize: 12
                width: Math.max(logFlick.width, implicitWidth)
                height: Math.max(logFlick.height, implicitHeight)
                background: Rectangle {
                    color: Material.color(Material.Grey, Material.Shade900)
                    border.color: Material.color(Material.Grey)
                    border.width: 1
                    radius: 4
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true

            Item { Layout.fillWidth: true }

            Button {
                text: "Back"
                onClicked: stackView.pop()
            }
        }
    }
}
