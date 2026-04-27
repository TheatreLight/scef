import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import QtQuick.Dialogs
import "utils.js" as Utils

Page {
    id: startPageRoot
    padding: 32

    property int selectedDriveIndex: -1
    property int driveListRevision: 0
    property string progressStage: ""
    property real progressFraction: 0.0

    function progressText() {
        if (progressStage === "") {
            return "Opening container..."
        }
        if ((progressStage === "Encrypting data..." || progressStage === "Decrypting data...")
                && progressFraction > 0.0 && progressFraction < 1.0) {
            return progressStage + " " + Math.round(progressFraction * 100) + "%"
        }
        return progressStage
    }

    Component.onCompleted: controller.driveListModel.refresh()

    Connections {
        target: controller.driveListModel
        function onModelReset() {
            driveListRevision++
        }
    }

    // Track whether WE started the open operation (vs CreatePage or FileListPage).
    property bool waitingForOpen: false

    Connections {
        target: controller
        function onProgressChanged(stageLabel, fraction) {
            progressStage = stageLabel
            progressFraction = fraction
        }

        function onOperationFinished(error) {
            if (!waitingForOpen) return
            waitingForOpen = false
            busyDialog.close()
            if (error !== "") {
                errorLabel.text = error
                errorLabel.visible = true
            } else {
                stackView.push(fileListPage)
            }
        }
    }

    Dialog {
        id: busyDialog
        anchors.centerIn: parent
        modal: true
        closePolicy: Popup.NoAutoClose
        standardButtons: Dialog.NoButton
        title: "Opening container..."

        ColumnLayout {
            spacing: 16

            BusyIndicator {
                running: true
                Layout.alignment: Qt.AlignHCenter
            }

            Label {
                text: startPageRoot.progressText()
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
                Layout.maximumWidth: Math.min(startPageRoot.width - 96, 480)
            }
        }
    }

    Dialog {
        id: overwriteDialog
        anchors.centerIn: parent
        modal: true
        title: "Warning"
        standardButtons: Dialog.Yes | Dialog.No

        Label {
            text: "A container already exists on this drive.\nCreating a new one will destroy the existing container.\n\nContinue?"
            wrapMode: Text.WordWrap
        }

        onAccepted: {
            var drivePath = controller.driveListModel.pathAtRow(selectedDriveIndex)
            stackView.push(createPage, { "initialDestDir": drivePath })
        }
    }

    FolderDialog {
        id: customDirDialog
        title: "Select directory for container"
        onAccepted: {
            stackView.push(createPage, { "initialDestDir": selectedFolder.toString() })
        }
    }

    FileDialog {
        id: openFileDialog
        title: "Select container file"
        nameFilters: ["SCEF containers (*.scef)", "All files (*)"]
        onAccepted: {
            errorLabel.visible = false
            passwordDialog.containerPath = selectedFile
            passwordDialog.open()
        }
    }

    PasswordDialog {
        id: passwordDialog
        anchors.centerIn: parent

        property string containerPath: ""

        onAccepted: {
            errorLabel.visible = false
            progressStage = ""
            progressFraction = 0.0
            var pw = passwordDialog.password
            passwordDialog.password = ""
            var err = controller.openContainer(passwordDialog.containerPath, pw)
            if (err !== "") {
                errorLabel.text = err
                errorLabel.visible = true
                return
            }
            waitingForOpen = true
            busyDialog.open()
        }

        onRejected: {
            passwordDialog.containerPath = ""
            errorLabel.visible = false
        }
    }

    StackView.onStatusChanged: {
        if (StackView.status === StackView.Active) {
            errorLabel.visible = false
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 20

        // Title
        Label {
            text: "SCEF"
            font.pixelSize: 48
            font.bold: true
            color: Material.color(Material.Amber)
            Layout.alignment: Qt.AlignHCenter
        }

        Label {
            text: "Self-contained Encrypted Container Format"
            font.pixelSize: 14
            opacity: 0.7
            Layout.alignment: Qt.AlignHCenter
        }

        // Removable Drives section
        GroupBox {
            title: "Removable Drives"
            Layout.fillWidth: true
            Layout.fillHeight: true

            ColumnLayout {
                anchors.fill: parent
                spacing: 8

                ListView {
                    id: driveListView
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    model: controller.driveListModel
                    clip: true
                    currentIndex: selectedDriveIndex

                    delegate: ItemDelegate {
                        width: driveListView.width
                        highlighted: index === selectedDriveIndex
                        onClicked: selectedDriveIndex = index

                        contentItem: RowLayout {
                            spacing: 12

                            Label {
                                text: "\uD83D\uDD0C"
                                font.pixelSize: 20
                            }

                            ColumnLayout {
                                spacing: 2
                                Layout.fillWidth: true

                                Label {
                                    text: model.letter + " " + model.label
                                    font.pixelSize: 14
                                    font.bold: true
                                }

                                Label {
                                    text: Utils.formatSize(model.freeSpace) + " free of " + Utils.formatSize(model.totalSpace)
                                    font.pixelSize: 12
                                    opacity: 0.6
                                }
                            }

                            Label {
                                text: model.hasContainer ? "Container found" : "No container"
                                color: model.hasContainer ? Material.color(Material.LightGreen) : Material.color(Material.Grey)
                                font.pixelSize: 12
                            }
                        }
                    }

                    Label {
                        anchors.centerIn: parent
                        text: "No removable drives detected"
                        opacity: 0.4
                        font.pixelSize: 14
                        visible: driveListView.count === 0
                    }
                }

                Button {
                    text: "Refresh"
                    onClicked: {
                        selectedDriveIndex = -1
                        controller.driveListModel.refresh()
                    }
                }
            }
        }

        // Drive action buttons
        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: 16

            Button {
                text: "Create on Drive"
                font.pixelSize: 14
                enabled: selectedDriveIndex >= 0
                onClicked: {
                    if (controller.driveListModel.hasContainerAtRow(selectedDriveIndex)) {
                        overwriteDialog.open()
                    } else {
                        var drivePath = controller.driveListModel.pathAtRow(selectedDriveIndex)
                        stackView.push(createPage, { "initialDestDir": drivePath })
                    }
                }
            }

            Button {
                text: "Open from Drive"
                font.pixelSize: 14
                enabled: selectedDriveIndex >= 0 && driveListRevision >= 0
                         && controller.driveListModel.hasContainerAtRow(selectedDriveIndex)
                onClicked: {
                    errorLabel.visible = false
                    var drivePath = controller.driveListModel.pathAtRow(selectedDriveIndex)
                    passwordDialog.containerPath = "file:///" + drivePath + "container.scef"
                    passwordDialog.open()
                }
            }
        }

        // Collapsible manual options
        ColumnLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: 8

            Button {
                id: moreOptionsBtn
                text: moreOptions.visible ? "\u25B2 Less options" : "\u25BC More options"
                flat: true
                opacity: 0.6
                Layout.alignment: Qt.AlignHCenter
                onClicked: moreOptions.visible = !moreOptions.visible
            }

            RowLayout {
                id: moreOptions
                visible: false
                Layout.alignment: Qt.AlignHCenter
                spacing: 16

                Button {
                    text: "Create in Directory..."
                    onClicked: customDirDialog.open()
                }

                Button {
                    text: "Open File..."
                    onClicked: openFileDialog.open()
                }
            }
        }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            spacing: 12

            Switch {
                text: "Enable benchmarks"
                checked: controller.benchEnabled
                onToggled: controller.benchEnabled = checked
            }

            Button {
                text: "View logs"
                flat: true
                onClicked: stackView.push(logsPage)
            }
        }

        // Error label
        Label {
            id: errorLabel
            color: "red"
            visible: false
            wrapMode: Text.WordWrap
            Layout.maximumWidth: 400
            Layout.alignment: Qt.AlignHCenter
        }
    }
}
