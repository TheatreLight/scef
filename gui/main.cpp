#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QCoreApplication>
#include <QQuickStyle>

#include "ScefController.h"
#include "Logger.h"

int main(int argc, char* argv[])
{
    QGuiApplication app(argc, argv);

    // Log directory: <executable_dir>/logs/
    std::filesystem::path logDir =
        QCoreApplication::applicationDirPath().toStdString();
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
