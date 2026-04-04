import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import QtQuick.Dialogs

Page {
    id: createPageRoot
    padding: 24
    property bool sizeError: false
    property string initialDestDir: ""

    FileDialog {
        id: filePickerDialog
        title: "Select files to encrypt"
        fileMode: FileDialog.OpenFiles
        onAccepted: {
            for (var i = 0; i < selectedFiles.length; i++) {
                var path = selectedFiles[i].toString()
                if (path.toLowerCase().endsWith(".scef")) continue
                fileListModelLocal.append({"filePath": path})
            }
        }
    }

    ListModel {
        id: fileListModelLocal
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 16

        Label {
            text: "Create New Container"
            font.pixelSize: 24
            font.bold: true
            color: Material.color(Material.Amber)
        }

        // Destination path display
        Label {
            text: "Destination: " + decodeURIComponent(
                initialDestDir.replace(/^file:\/\/\//, "").replace(/^file:\/\//, ""))
            font.pixelSize: 12
            opacity: 0.6
            visible: initialDestDir !== ""
        }

        // Files to encrypt
        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 8

            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                color: "transparent"
                border.color: Material.color(Material.Grey)
                border.width: 1
                radius: 4

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 1
                    spacing: 0

                    RowLayout {
                        Layout.alignment: Qt.AlignRight
                        Layout.rightMargin: 8
                        Layout.topMargin: 4
                        spacing: 4

                        Label {
                            text: fileListModelLocal.count > 0
                                  ? fileListModelLocal.count + " file(s) selected"
                                  : "No files selected"
                            opacity: 0.5
                            font.pixelSize: 12
                        }

                        Label {
                            text: "\u2714"
                            color: Material.color(Material.LightGreen)
                            font.pixelSize: 14
                            visible: fileListModelLocal.count > 0
                        }
                    }

                    ListView {
                        id: fileListView
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        model: fileListModelLocal
                        clip: true
                        currentIndex: -1

                        delegate: ItemDelegate {
                            width: fileListView.width
                            highlighted: ListView.isCurrentItem
                            onClicked: fileListView.currentIndex = index

                            contentItem: Label {
                                text: model.filePath.toString().split('/').pop().split('\\').pop()
                                elide: Text.ElideMiddle
                            }
                        }
                    }
                }
            }

            ColumnLayout {
                Layout.alignment: Qt.AlignTop
                spacing: 8

                Button {
                    text: "Add Files"
                    onClicked: filePickerDialog.open()
                }

                Button {
                    text: "Remove"
                    enabled: fileListView.currentIndex >= 0
                    onClicked: {
                        if (fileListView.currentIndex >= 0)
                            fileListModelLocal.remove(fileListView.currentIndex)
                    }
                }
            }
        }

        // Password and size
        GroupBox {
            title: "Container Settings"
            Layout.fillWidth: true

            GridLayout {
                width: parent.width
                columns: 3
                columnSpacing: 16
                rowSpacing: 8

                Label { text: "Password:" }
                TextField {
                    id: passwordField
                    Layout.fillWidth: true
                    echoMode: TextInput.Password
                    placeholderText: "Enter password"
                }
                Label {
                    text: "\u2714"
                    color: Material.color(Material.LightGreen)
                    font.pixelSize: 18
                    Layout.preferredWidth: 18
                    opacity: passwordField.text !== "" ? 1 : 0
                }

                Label { text: "Confirm Password:" }
                TextField {
                    id: confirmPasswordField
                    Layout.fillWidth: true
                    echoMode: TextInput.Password
                    placeholderText: "Confirm password"
                }
                Label {
                    text: "\u2714"
                    color: passwordField.text === confirmPasswordField.text
                           ? Material.color(Material.LightGreen) : "red"
                    font.pixelSize: 18
                    Layout.preferredWidth: 18
                    opacity: confirmPasswordField.text !== "" ? 1 : 0
                }

                Label { text: "Container Size (MB):" }
                SpinBox {
                    id: sizeSpin
                    from: 1
                    to: 102400
                    value: 4
                    editable: true
                    Material.accent: sizeError ? "#FF0000" : Material.LightGreen
                    onValueModified: { sizeError = false; errorLabel.visible = false }
                }
                Label {
                    text: "\u2716"
                    color: "#FF0000"
                    font.pixelSize: 18
                    Layout.preferredWidth: 18
                    opacity: sizeError ? 1 : 0
                }
            }
        }

        // Validation errors
        Label {
            id: errorLabel
            color: "red"
            visible: false
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
        }

        // Action buttons
        RowLayout {
            spacing: 16

            Button {
                text: "Create"
                enabled: initialDestDir !== ""
                         && fileListModelLocal.count > 0
                         && passwordField.text !== ""
                         && passwordField.text === confirmPasswordField.text
                         && !controller.busy

                onClicked: {
                    errorLabel.visible = false
                    sizeError = false
                    var files = []
                    for (var i = 0; i < fileListModelLocal.count; i++) {
                        files.push(fileListModelLocal.get(i).filePath)
                    }

                    var error = controller.createContainer(
                        initialDestDir,
                        files,
                        passwordField.text,
                        sizeSpin.value
                    )

                    // Synchronous error (e.g. size validation)
                    if (error !== "") {
                        errorLabel.text = error
                        errorLabel.visible = true
                        if (error.indexOf("too large") !== -1) {
                            sizeError = true
                            sizeSpin.forceActiveFocus()
                        }
                    }
                    // else: async operation started, wait for operationFinished
                }
            }

            Button {
                text: "Back"
                onClicked: stackView.pop()
            }

            Item { Layout.fillWidth: true }

            Label {
                text: passwordField.text !== confirmPasswordField.text
                      && confirmPasswordField.text !== ""
                      ? "Passwords do not match" : ""
                color: "orange"
            }
        }
    }

    // Busy overlay
    Rectangle {
        anchors.fill: parent
        color: "#80000000"
        visible: controller.busy
        z: 10

        ColumnLayout {
            anchors.centerIn: parent
            spacing: 16

            BusyIndicator {
                running: controller.busy
                Layout.alignment: Qt.AlignHCenter
            }

            Label {
                text: "Creating container..."
                font.pixelSize: 16
                Layout.alignment: Qt.AlignHCenter
            }
        }
    }

    // Success overlay (shown after async create completes)
    Rectangle {
        id: successOverlay
        anchors.fill: parent
        color: "#CC000000"
        visible: false
        z: 11

        ColumnLayout {
            anchors.centerIn: parent
            spacing: 16

            Label {
                text: "\u2714"
                color: Material.color(Material.LightGreen)
                font.pixelSize: 64
                Layout.alignment: Qt.AlignHCenter
            }

            Label {
                text: "Container successfully created"
                color: Material.color(Material.LightGreen)
                font.pixelSize: 18
                Layout.alignment: Qt.AlignHCenter
            }
        }
    }

    // Handle async result (only when this page is active)
    Connections {
        target: controller
        enabled: createPageRoot.StackView.status === StackView.Active
        function onOperationFinished(error) {
            if (error !== "") {
                errorLabel.text = error
                errorLabel.visible = true
                if (error.indexOf("too large") !== -1) {
                    sizeError = true
                    sizeSpin.forceActiveFocus()
                }
            } else {
                controller.closeContainer()
                successOverlay.visible = true
                successTimer.start()
            }
        }
    }

    Timer {
        id: successTimer
        interval: 1500
        onTriggered: {
            successOverlay.visible = false
            controller.driveListModel.refresh()
            stackView.pop(null)
        }
    }
}
