#include "ScefController.h"
#include "FileManager.h"

#include <QFileInfo>
#include <QUrl>

#include <botan/mem_ops.h>

#include <vector>

namespace {

std::string toLocalPath(const QString& urlOrPath)
{
    QUrl url(urlOrPath);
    if (url.isLocalFile())
        return url.toLocalFile().toStdString();
    return urlOrPath.toStdString();
}

std::vector<std::string> toStdPaths(const QStringList& list)
{
    std::vector<std::string> result;
    result.reserve(static_cast<size_t>(list.size()));
    for (const auto& item : list)
        result.push_back(toLocalPath(item));
    return result;
}

} // namespace

ScefController::ScefController(QObject* parent)
    : QObject(parent)
    , fileListModel_(new FileListModel(this))
    , driveListModel_(new DriveListModel(this))
{
}

ScefController::~ScefController()
{
    scrubPassword();
}

QString ScefController::createContainer(const QString& destDir,
                                         const QStringList& files,
                                         const QString& password,
                                         quint64 sizeMB)
{
    if (busy_) return QStringLiteral("Operation already in progress");

    auto paths = toStdPaths(files);
    auto dir = toLocalPath(destDir);
    auto pwd = password.toStdString();
    uint64_t sizeBytes = sizeMB * 1024ULL * 1024ULL;

    // Pre-validate synchronously (init checks size before creating file)
    try {
        fileManager_ = std::make_unique<FileManager>();
        fileManager_->init(paths, dir, sizeBytes, DEFAULT_MAX_TABLE_SIZE,
                           /*create_new=*/true, pwd);
    } catch (const std::exception& e) {
        fileManager_.reset();
        return QString::fromUtf8(e.what());
    }

    // Heavy work (write/encrypt) runs on a background thread
    runAsync([this]() {
        fileManager_->write();
    }, QString::fromStdString(dir), std::move(pwd));

    return {};
}

QString ScefController::openContainer(const QString& containerPath,
                                       const QString& password)
{
    if (busy_) return QStringLiteral("Operation already in progress");

    try {
        auto filePath = toLocalPath(containerPath);
        QFileInfo fi(QString::fromStdString(filePath));
        auto dir = fi.absolutePath().toStdString();
        auto pwd = password.toStdString();

        fileManager_ = std::make_unique<FileManager>();
        fileManager_->init({}, dir, 0, DEFAULT_MAX_TABLE_SIZE,
                           /*create_new=*/false, pwd);

        scrubPassword();
        currentPassword_ = std::move(pwd);
        currentContainerDir_ = fi.absolutePath();
        containerOpen_ = true;
        emit containerOpenChanged();

        refreshFileList();
        return {};
    } catch (const std::exception& e) {
        fileManager_.reset();
        return QString::fromUtf8(e.what());
    }
}

QString ScefController::addFiles(const QStringList& filePaths)
{
    if (busy_) return QStringLiteral("Operation already in progress");

    try {
        auto paths = toStdPaths(filePaths);
        auto dir = currentContainerDir_.toStdString();

        fileManager_ = std::make_unique<FileManager>();
        fileManager_->init(paths, dir, 0, DEFAULT_MAX_TABLE_SIZE,
                           /*create_new=*/false, currentPassword_);
        fileManager_->add();

        refreshFileList();
        return {};
    } catch (const std::exception& e) {
        return QString::fromUtf8(e.what());
    }
}

QString ScefController::extractFiles(const QStringList& fileNames,
                                      const QString& outputDir)
{
    if (busy_) return QStringLiteral("Operation already in progress");

    try {
        std::vector<std::string> names;
        names.reserve(static_cast<size_t>(fileNames.size()));
        for (const auto& n : fileNames)
            names.push_back(n.toStdString());

        auto dir = currentContainerDir_.toStdString();
        auto outDir = toLocalPath(outputDir);

        fileManager_ = std::make_unique<FileManager>();
        fileManager_->init(names, dir, 0, DEFAULT_MAX_TABLE_SIZE,
                           /*create_new=*/false, currentPassword_);
        fileManager_->extract(outDir);

        return {};
    } catch (const std::exception& e) {
        return QString::fromUtf8(e.what());
    }
}

void ScefController::closeContainer()
{
    fileManager_.reset();
    fileListModel_->clear();
    scrubPassword();
    currentContainerDir_.clear();
    containerOpen_ = false;
    emit containerOpenChanged();
}

FileListModel* ScefController::fileListModel() const
{
    return fileListModel_;
}

DriveListModel* ScefController::driveListModel() const
{
    return driveListModel_;
}

bool ScefController::isContainerOpen() const
{
    return containerOpen_;
}

bool ScefController::isBusy() const
{
    return busy_;
}

QString ScefController::currentContainerPath() const
{
    return currentContainerDir_;
}

void ScefController::runAsync(std::function<void()> work, const QString& dir, std::string pwd)
{
    busy_ = true;
    emit busyChanged();

    auto* thread = QThread::create([this, work = std::move(work), dir, pwd = std::move(pwd)]() {
        QString error;
        try {
            work();
        } catch (const std::exception& e) {
            error = QString::fromUtf8(e.what());
        }

        QMetaObject::invokeMethod(this, [this, error, dir, pwd = std::move(pwd)]() mutable {
            if (error.isEmpty()) {
                scrubPassword();
                currentPassword_ = std::move(pwd);
                currentContainerDir_ = dir;
                containerOpen_ = true;
                emit containerOpenChanged();
                refreshFileList();
            } else {
                fileManager_.reset();
            }

            busy_ = false;
            emit busyChanged();
            emit operationFinished(error);
        }, Qt::QueuedConnection);
    });

    thread->start();
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);
}

void ScefController::refreshFileList()
{
    if (fileManager_) {
        fileListModel_->setFiles(fileManager_->getFilesTable());
    } else {
        fileListModel_->clear();
    }
}

void ScefController::scrubPassword()
{
    if (!currentPassword_.empty()) {
        Botan::secure_scrub_memory(currentPassword_.data(), currentPassword_.size());
        currentPassword_.clear();
    }
}
