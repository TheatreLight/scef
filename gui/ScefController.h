#ifndef SCEF_CONTROLLER_H
#define SCEF_CONTROLLER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QThread>

#include <functional>
#include <memory>
#include <string>

#include "DriveListModel.h"
#include "FileListModel.h"

class FileManager;

class ScefController : public QObject {
    Q_OBJECT
    Q_PROPERTY(FileListModel* fileListModel READ fileListModel CONSTANT)
    Q_PROPERTY(DriveListModel* driveListModel READ driveListModel CONSTANT)
    Q_PROPERTY(bool containerOpen READ isContainerOpen NOTIFY containerOpenChanged)
    Q_PROPERTY(bool busy READ isBusy NOTIFY busyChanged)
    Q_PROPERTY(QString currentContainerPath READ currentContainerPath NOTIFY containerOpenChanged)
    Q_PROPERTY(bool benchEnabled READ benchEnabled WRITE setBenchEnabled NOTIFY benchEnabledChanged)

public:
    explicit ScefController(QObject* parent = nullptr);
    ~ScefController() override;

    Q_INVOKABLE QString createContainer(const QString& destDir,
                                         const QStringList& files,
                                         const QString& password,
                                         quint64 sizeMB,
                                         int kdfProfileIndex = 0,
                                         int kdfM_MiB = 64,
                                         int kdfT = 3,
                                         int kdfP = 4);

    Q_INVOKABLE QString openContainer(const QString& containerPath,
                                       const QString& password);

    Q_INVOKABLE QString addFiles(const QStringList& filePaths);

    Q_INVOKABLE QString extractFiles(const QStringList& fileNames,
                                      const QString& outputDir);

    Q_INVOKABLE void closeContainer();

    Q_INVOKABLE QString logDirPath() const;
    Q_INVOKABLE QStringList listLogFiles() const;
    Q_INVOKABLE QString readLogFile(const QString& path, qint64 maxBytes = 1048576) const;

    FileListModel* fileListModel() const;
    DriveListModel* driveListModel() const;
    bool isContainerOpen() const;
    bool isBusy() const;
    QString currentContainerPath() const;
    bool benchEnabled() const;
    void setBenchEnabled(bool enabled);

signals:
    void containerOpenChanged();
    void busyChanged();
    void benchEnabledChanged();
    void operationFinished(const QString& error);

private:
    // Run heavy FileManager work on a background thread.
    // workFn: called on worker thread with the FileManager pointer.
    // onSuccess: called on main thread if work succeeded (fm is alive).
    void runAsync(std::unique_ptr<FileManager> fm,
                  std::function<void(FileManager*)> workFn,
                  std::function<void()> onSuccess);
    void refreshFileList();
    void scrubPassword();

    std::unique_ptr<FileManager> fileManager_;
    FileListModel* fileListModel_;
    DriveListModel* driveListModel_;
    QString currentContainerDir_;
    std::string currentPassword_;
    bool containerOpen_ = false;
    bool busy_ = false;
};

#endif // SCEF_CONTROLLER_H
