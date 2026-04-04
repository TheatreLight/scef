import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

Dialog {
    id: root
    modal: true
    title: "Enter Password"
    closePolicy: Popup.NoAutoClose
    standardButtons: Dialog.Ok | Dialog.Cancel

    property alias password: passwordField.text

    contentItem: ColumnLayout {
        spacing: 8

        Label {
            text: "Password:"
        }

        TextField {
            id: passwordField
            echoMode: TextInput.Password
            Layout.preferredWidth: 300
            placeholderText: "Enter container password"
            Keys.onReturnPressed: root.accept()
        }
    }

    onOpened: {
        passwordField.text = ""
        passwordField.forceActiveFocus()
    }
}
