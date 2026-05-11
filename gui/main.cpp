#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QCoreApplication>
#include <QQuickStyle>
#include <QStandardPaths>
#include <QDir>

#include "ScefController.h"
#include "Logger.h"

int main(int argc, char* argv[])
{
    QCoreApplication::setOrganizationName("MEPhI");
    QCoreApplication::setApplicationName("SCEF");

    QGuiApplication app(argc, argv);

    // Per-user writable location: %LOCALAPPDATA%\MEPhI\SCEF\logs on Windows.
    // Program Files is read-only for non-admin users, so logs cannot live next
    // to the executable in a per-machine install.
    QString appDataDir =
        QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    QDir().mkpath(appDataDir);
    std::filesystem::path logDir = appDataDir.toStdString();
    logDir /= "logs";
    Logger::init(/*mirror_to_console=*/false, logDir);
#ifdef NDEBUG
    Logger::setLevel(LogLevel::INFO);
#else
    Logger::setLevel(LogLevel::DEBUG);
#endif
    QQuickStyle::setStyle("Material");

    ScefController controller;
    QQmlApplicationEngine engine;

    engine.rootContext()->setContextProperty("controller", &controller);

    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        []() { QCoreApplication::exit(-1); },
        Qt::QueuedConnection);

    engine.loadFromModule("scef", "Main");

    return app.exec();
}
