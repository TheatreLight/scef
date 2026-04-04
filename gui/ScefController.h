#ifndef SCEF_CONTROLLER_H
#define SCEF_CONTROLLER_H

#include <QObject>
#include <QThread>

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

public:
    explicit ScefController(QObject* parent = nullptr);
    ~ScefController() override;

    Q_INVOKABLE QString createContainer(const QString& destDir,
                                         const QStringList& files,
                                         const QString& password,
                                         quint64 sizeMB);

    Q_INVOKABLE QString openContainer(const QString& containerPath,
                                       const QString& password);

    Q_INVOKABLE QString addFiles(const QStringList& filePaths);

    Q_INVOKABLE QString extractFiles(const QStringList& fileNames,
                                      const QString& outputDir);

    Q_INVOKABLE void closeContainer();

    FileListModel* fileListModel() const;
    DriveListModel* driveListModel() const;
    bool isContainerOpen() const;
    bool isBusy() const;
    QString currentContainerPath() const;

signals:
    void containerOpenChanged();
    void busyChanged();
    void operationFinished(const QString& error);

private:
    void runAsync(std::unique_ptr<FileManager> fm, QString dir, std::string pwd);
    void refreshFileList();
    void scrubPassword();

    std::unique_ptr<FileManager> fileManager_;
    FileListModel* fileListModel_;
    DriveListModel* driveListModel_;
    std::string currentPassword_;
    QString currentContainerDir_;
    bool containerOpen_ = false;
    bool busy_ = false;
};

#endif // SCEF_CONTROLLER_H
