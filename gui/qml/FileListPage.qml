import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import QtQuick.Dialogs
import "utils.js" as Utils

Page {
    padding: 24

    property var selectedIndices: ({})


    function getSelectedNames() {
        var names = []
        for (var idx in selectedIndices) {
            if (selectedIndices[idx]) {
                names.push(controller.fileListModel.nameAtRow(parseInt(idx)))
            }
        }
        return names
    }

    function getSelectedCount() {
        var count = 0
        for (var idx in selectedIndices) {
            if (selectedIndices[idx]) count++
        }
        return count
    }

    FileDialog {
        id: addFileDialog
        title: "Select files to add"
        fileMode: FileDialog.OpenFiles
        onAccepted: {
            var files = []
            for (var i = 0; i < selectedFiles.length; i++) {
                files.push(selectedFiles[i].toString())
            }
            errorLabel.visible = false
            successLabel.visible = false
            var error = controller.addFiles(files)
            if (error !== "") {
                errorLabel.text = error
                errorLabel.visible = true
            } else {
                selectedIndices = {}
                selectedIndicesChanged()
                successLabel.text = files.length + " file(s) added successfully"
                successLabel.visible = true
            }
        }
    }

    FolderDialog {
        id: extractDirDialog
        title: "Select output directory"
        onAccepted: {
            errorLabel.visible = false
            successLabel.visible = false
            var names = getSelectedNames()
            var error = controller.extractFiles(names, selectedFolder)
            if (error !== "") {
                errorLabel.text = error
                errorLabel.visible = true
            } else {
                successLabel.text = names.length > 0
                    ? names.length + " file(s) extracted successfully"
                    : "All files extracted successfully"
                successLabel.visible = true
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 16

        RowLayout {
            spacing: 16

            ColumnLayout {
                spacing: 2

                Label {
                    text: "Container Files"
                    font.pixelSize: 24
                    font.bold: true
                    color: Material.color(Material.Amber)
                }

                Label {
                    text: controller.currentContainerPath
                    font.pixelSize: 12
                    opacity: 0.5
                    visible: controller.currentContainerPath !== ""
                }
            }

            Item { Layout.fillWidth: true }

            Label {
                text: controller.fileListModel.count + " file(s)"
                opacity: 0.7
                font.pixelSize: 14
            }
        }

        // File list
        ListView {
            id: fileListView
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: controller.fileListModel
            clip: true

            headerPositioning: ListView.OverlayHeader
            header: Rectangle {
                width: fileListView.width
                height: 40
                color: Material.color(Material.Grey, Material.Shade900)
                z: 2

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 48
                    anchors.rightMargin: 16
                    spacing: 16

                    Label {
                        text: "Name"
                        font.bold: true
                        Layout.fillWidth: true
                        Layout.preferredWidth: 3
                    }
                    Label {
                        text: "Size"
                        font.bold: true
                        Layout.preferredWidth: 100
                        horizontalAlignment: Text.AlignRight
                    }
                    Label {
                        text: "SHA-256"
                        font.bold: true
                        Layout.preferredWidth: 200
                    }
                }
            }

            delegate: ItemDelegate {
                width: fileListView.width
                height: 44

                contentItem: RowLayout {
                    spacing: 16

                    CheckBox {
                        id: selectBox
                        checked: !!selectedIndices[index]
                        onToggled: {
                            var copy = selectedIndices
                            copy[index] = checked
                            selectedIndices = copy
                            selectedIndicesChanged()
                        }
                    }

                    Label {
                        text: model.name
                        elide: Text.ElideMiddle
                        Layout.fillWidth: true
                        Layout.preferredWidth: 3
                    }

                    Label {
                        text: Utils.formatSize(model.size)
                        Layout.preferredWidth: 100
                        horizontalAlignment: Text.AlignRight
                        opacity: 0.7
                    }

                    Label {
                        text: model.checksum ? model.checksum.substring(0, 16) + "..." : ""
                        Layout.preferredWidth: 200
                        font.family: "Consolas"
                        font.pixelSize: 12
                        opacity: 0.5
                    }
                }
            }

            Rectangle {
                anchors.fill: parent
                color: "transparent"
                border.color: Material.color(Material.Grey)
                border.width: 1
                radius: 4
                z: -1
            }
        }

        // Status messages
        Label {
            id: errorLabel
            color: "red"
            visible: false
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        Label {
            id: successLabel
            color: "lightgreen"
            visible: false
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        // Action buttons
        RowLayout {
            spacing: 16

            Button {
                text: "Add Files"
                onClicked: {
                    successLabel.visible = false
                    errorLabel.visible = false
                    addFileDialog.open()
                }
            }

            Button {
                text: getSelectedCount() > 0
                      ? "Extract Selected (" + getSelectedCount() + ")"
                      : "Extract All"
                onClicked: {
                    successLabel.visible = false
                    errorLabel.visible = false
                    extractDirDialog.open()
                }
            }

            Item { Layout.fillWidth: true }

            Button {
                text: "Back"
                onClicked: {
                    controller.closeContainer()
                    stackView.pop(null)
                }
            }
        }
    }
}
