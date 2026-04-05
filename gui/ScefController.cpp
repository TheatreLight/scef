#include "ScefController.h"
#include "FileManager.h"
#include "KdfProfiles.h"

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
                                         quint64 sizeMB,
                                         int kdfProfileIndex,
                                         int kdfM_MiB,
                                         int kdfT,
                                         int kdfP)
{
    if (busy_) return QStringLiteral("Operation already in progress");

    auto paths = toStdPaths(files);
    auto dir = toLocalPath(destDir);
    auto pwd = password.toStdString();
    uint64_t sizeBytes = sizeMB * 1024ULL * 1024ULL;

    // Map profile index (0–3 = named profiles, 4 = custom) to EKDFProfile.
    EKDFProfile profile;
    switch (kdfProfileIndex) {
        case 1:  profile = EKDFProfile::FastAccess;   break;
        case 2:  profile = EKDFProfile::HighSecurity; break;
        case 3:  profile = EKDFProfile::Browser;      break;
        case 4:  profile = EKDFProfile::None;         break;
        default: profile = EKDFProfile::Standard;     break;  // index 0 = Standard
    }

    // Pre-validate synchronously (init checks size before creating file)
    try {
        fileManager_ = std::make_unique<FileManager>();
        fileManager_->init(paths, dir, sizeBytes, DEFAULT_MAX_TABLE_SIZE,
                           /*create_new=*/true, pwd);

        if (profile != EKDFProfile::None) {
            const KdfProfileParams* p = getProfileParams(profile);
            if (p)
                fileManager_->setKdfParams(profile, p->m_kib, p->t, p->p);
        } else {
            fileManager_->setKdfParams(EKDFProfile::None,
                                       static_cast<uint32_t>(kdfM_MiB) * 1024u,
                                       static_cast<uint32_t>(kdfT),
                                       static_cast<uint32_t>(kdfP));
        }
    } catch (const std::exception& e) {
        fileManager_.reset();
        return QString::fromUtf8(e.what());
    }

    // Heavy work runs on a background thread.
    auto dirQ = QString::fromStdString(dir);
    runAsync(std::move(fileManager_),
        [](FileManager* fm) { fm->write(); },
        [this, dirQ, pwd = std::move(pwd)]() mutable {
            scrubPassword();
            currentPassword_ = std::move(pwd);
            currentContainerDir_ = dirQ;
            containerOpen_ = true;
            emit containerOpenChanged();
            refreshFileList();
        });

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

    // Each operation creates a fresh FileManager that re-reads current container
    // state from disk, ensuring we always operate on the latest on-disk data.
    try {
        auto paths = toStdPaths(filePaths);
        auto dir = currentContainerDir_.toStdString();

        auto fm = std::make_unique<FileManager>();
        fm->init(paths, dir, 0, DEFAULT_MAX_TABLE_SIZE,
                 /*create_new=*/false, currentPassword_);

        runAsync(std::move(fm),
            [](FileManager* f) { f->add(); },
            [this]() { refreshFileList(); });

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

        auto fm = std::make_unique<FileManager>();
        fm->init(names, dir, 0, DEFAULT_MAX_TABLE_SIZE,
                 /*create_new=*/false, currentPassword_);

        runAsync(std::move(fm),
            [outDir](FileManager* f) { f->extract(outDir); },
            []() {});

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

void ScefController::runAsync(std::unique_ptr<FileManager> fm,
                              std::function<void(FileManager*)> workFn,
                              std::function<void()> onSuccess)
{
    busy_ = true;
    emit busyChanged();

    // Transfer FileManager ownership to the worker thread to avoid race conditions.
    auto* fmRaw = fm.get();
    auto* thread = QThread::create([this, fm = std::move(fm), fmRaw,
                                    workFn = std::move(workFn),
                                    onSuccess = std::move(onSuccess)]() mutable {
        QString error;
        try {
            workFn(fmRaw);
        } catch (const std::exception& e) {
            error = QString::fromUtf8(e.what());
        }

        QMetaObject::invokeMethod(this, [this, error, fm = std::move(fm),
                                         onSuccess = std::move(onSuccess)]() mutable {
            if (error.isEmpty()) {
                fileManager_ = std::move(fm);
                onSuccess();
            } else {
                fm.reset();
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
