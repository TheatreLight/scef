find_package(Qt6 REQUIRED COMPONENTS Quick QuickControls2)
qt_standard_project_setup(REQUIRES 6.5)

qt_add_executable(scef-gui
    main.cpp
)

qt_add_qml_module(scef-gui
    URI scef
    VERSION 1.0
    SOURCES
        ScefController.h ScefController.cpp
        FileListModel.h FileListModel.cpp
        DriveListModel.h DriveListModel.cpp
    QML_FILES
        qml/Main.qml
        qml/StartPage.qml
        qml/CreatePage.qml
        qml/PasswordDialog.qml
        qml/FileListPage.qml
)

target_link_libraries(scef-gui PRIVATE
    scef_lib
    Qt6::Quick
    Qt6::QuickControls2
)

set_target_properties(scef-gui PROPERTIES
    WIN32_EXECUTABLE TRUE
)
