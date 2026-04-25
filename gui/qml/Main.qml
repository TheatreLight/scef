import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

Window {
    id: window
    width: 900
    height: 600
    visible: true
    title: "SCEF - Encrypted Container Manager"

    Material.theme: Material.Dark
    Material.primary: Material.Red
    Material.accent: Material.LightGreen

    StackView {
        id: stackView
        anchors.fill: parent
        initialItem: startPage
    }

    Component {
        id: startPage
        StartPage {}
    }

    Component {
        id: createPage
        CreatePage {}
    }

    Component {
        id: fileListPage
        FileListPage {}
    }

    Component {
        id: logsPage
        LogsPage {}
    }
}
