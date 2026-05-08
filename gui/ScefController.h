#ifndef SCEF_CONTROLLER_H
#define SCEF_CONTROLLER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QThread>
#include <QVariantMap>

#include <functional>
#include <memory>

#include "DriveListModel.h"
#include "FileListModel.h"
// PasswordStrengthEstimator.h is included only in the .cpp (used only in method bodies).

class FileManager;

class ScefController : public QObject {
    Q_OBJECT
    Q_PROPERTY(FileListModel* fileListModel READ fileListModel CONSTANT)
    Q_PROPERTY(DriveListModel* driveListModel READ driveListModel CONSTANT)
    Q_PROPERTY(bool containerOpen READ isContainerOpen NOTIFY containerOpenChanged)
    Q_PROPERTY(bool busy READ isBusy NOTIFY busyChanged)
    // currentContainerPath has its own NOTIFY signal (not piggy-backed on containerOpenChanged).
    Q_PROPERTY(QString currentContainerPath READ currentContainerPath NOTIFY currentContainerPathChanged)
    Q_PROPERTY(bool benchEnabled READ benchEnabled WRITE setBenchEnabled NOTIFY benchEnabledChanged)

public:
    explicit ScefController(QObject* parent = nullptr);
    ~ScefController() override;

    // containerFilePath: full path to the new container file (e.g. "/mnt/usb/container.scef").
    // QML constructs this from the chosen directory + defaultContainerName(dir) or user input.
    Q_INVOKABLE QString createContainer(const QString& containerFilePath,
                                         const QStringList& files,
                                         const QString& password,
                                         quint64 sizeMB,
                                         int kdfProfileIndex = 0,
                                         int kdfM_MiB = 64,
                                         int kdfT = 3,
                                         int kdfP = 4,
                                         int cipherIndex = 0);

    Q_INVOKABLE QVariantMap estimatePasswordStrength(const QString& password,
                                                      int kdfProfileIndex) const;

    // containerPath: full path to an existing .scef file.
    Q_INVOKABLE QString openContainer(const QString& containerPath,
                                       const QString& password);

    Q_INVOKABLE QString addFiles(const QStringList& filePaths);

    Q_INVOKABLE QString extractFiles(const QStringList& fileNames,
                                      const QString& outputDir);

    Q_INVOKABLE void closeContainer();

    Q_INVOKABLE QString logDirPath() const;
    Q_INVOKABLE QStringList listLogFiles() const;
    Q_INVOKABLE QString readLogFile(const QString& path, qint64 maxBytes = 1048576) const;

    // Returns the filename portion (no directory) of the next non-colliding container path
    // inside dir. E.g. "container.scef" or "container_1.scef".
    Q_INVOKABLE QString defaultContainerName(const QString& dir) const;

    // Delegates to DriveListModel::containerFilesAtRow(row).
    // Returns a list of absolute paths to *.scef files in the drive root at the given row.
    Q_INVOKABLE QStringList containerFilesAtRow(int row) const;

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
    void currentContainerPathChanged();
    void operationFinished(const QString& error);
    // fraction: 0.0–1.0 when fractionMeaningful is true.
    // fraction: -1.0 signals "indeterminate" — QML should hide the progress percent.
    void progressChanged(const QString& stageLabel, double fraction);

private:
    void installProgressCallback(FileManager* fm);

    // Run heavy FileManager work on a background thread.
    //
    // fm:             FileManager to transfer to the worker (may be null — worker creates its own).
    // workFn:         Called on the worker thread with the FileManager pointer.
    // onSuccess:      Called on the main thread if workFn completed without exception;
    //                 self->fileManager_ has already been restored at that point.
    // restoreOnError: If true, fileManager_ is also restored on error (add/extract keep the
    //                 container open). If false, fileManager_ is left null on error
    //                 (create/open — container is not considered open after failure).
    void runAsync(std::unique_ptr<FileManager> fm,
                  std::function<void(FileManager*)> workFn,
                  std::function<void()> onSuccess,
                  bool restoreOnError = false);

    void refreshFileList();

    std::unique_ptr<FileManager> fileManager_;
    FileListModel* fileListModel_;
    DriveListModel* driveListModel_;
    QString currentContainerDir_;
    bool containerOpen_ = false;
    bool busy_ = false;
};

#endif // SCEF_CONTROLLER_H
