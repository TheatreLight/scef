#include "ScefController.h"
#include "FileManager.h"
#include "KdfProfiles.h"
#include "Logger.h"
#include "enums/ECiphers.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileInfoList>
#include <QPointer>
#include <QStringList>
#include <QUrl>
#include <QVariantMap>

#include <botan/secmem.h>

#include <memory>
#include <utility>
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

Botan::secure_vector<char> securePasswordFromQString(const QString& password)
{
    const QByteArray utf8 = password.toUtf8();
    return Botan::secure_vector<char>(utf8.constData(), utf8.constData() + utf8.size());
}

EKDFProfile profileFromIndex(int kdfProfileIndex)
{
    switch (kdfProfileIndex) {
        case 0:  return EKDFProfile::Standard;
        case 1:  return EKDFProfile::Fast;
        case 2:  return EKDFProfile::High;
        case 3:  return EKDFProfile::Browser;
        case 4:  return EKDFProfile::None;
        default: return EKDFProfile::Standard;
    }
}

} // namespace

ScefController::ScefController(QObject* parent)
    : QObject(parent)
    , fileListModel_(new FileListModel(this))
    , driveListModel_(new DriveListModel(this))
{
}

ScefController::~ScefController() = default;

QString ScefController::createContainer(const QString& destDir,
                                         const QStringList& files,
                                         const QString& password,
                                         quint64 sizeMB,
                                         int kdfProfileIndex,
                                         int kdfM_MiB,
                                         int kdfT,
                                         int kdfP,
                                         int cipherIndex)
{
    if (busy_) return QStringLiteral("Operation already in progress");

    auto paths = toStdPaths(files);
    auto dir = toLocalPath(destDir);
    auto pwd = securePasswordFromQString(password);
    uint64_t sizeBytes = sizeMB * 1024ULL * 1024ULL;

    // Map profile index (0–3 = named profiles, 4 = custom) to EKDFProfile.
    EKDFProfile profile = profileFromIndex(kdfProfileIndex);

    // Map cipher index (0 = AES-256-GCM, 1 = Kuznechik-GCM) to ECipher.
    ECipher cipher;
    switch (cipherIndex) {
        case 0:  cipher = ECipher::AES_256_GCM;   break;
        case 1:  cipher = ECipher::Kuznechik_GCM; break;
        default: cipher = ECipher::AES_256_GCM;   break;
    }

    // Pre-validate synchronously (init checks size before creating file)
    try {
        fileManager_ = std::make_unique<FileManager>();
        fileManager_->init(paths, dir, sizeBytes, DEFAULT_MAX_TABLE_SIZE,
                           /*create_new=*/true, pwd);

        fileManager_->setCipher(cipher);

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
        [this, dirQ]() {
            currentContainerDir_ = dirQ;
            containerOpen_ = true;
            emit containerOpenChanged();
            refreshFileList();
        });

    return {};
}

QVariantMap ScefController::estimatePasswordStrength(const QString& password,
                                                      int kdfProfileIndex) const
{
    auto pwd = securePasswordFromQString(password);
    PasswordStrengthEstimator estimator;
    const auto result = estimator.estimate(pwd, profileFromIndex(kdfProfileIndex));

    QVariantMap map;
    map.insert(QStringLiteral("score"), result.score);
    map.insert(QStringLiteral("bits"), result.bits);
    map.insert(QStringLiteral("recommendedMin"), result.recommendedMin);
    map.insert(QStringLiteral("meetsRecommendation"), result.meetsRecommendation);
    map.insert(QStringLiteral("warning"), QString::fromStdString(result.warning));
    map.insert(QStringLiteral("crackTimeOffline"), QString::fromStdString(result.crackTimeOffline));
    return map;
}

QString ScefController::openContainer(const QString& containerPath,
                                       const QString& password)
{
    if (busy_) return QStringLiteral("Operation already in progress");

    auto filePath = toLocalPath(containerPath);
    QFileInfo fi(QString::fromStdString(filePath));
    auto dir = fi.absolutePath().toStdString();
    auto pwd = securePasswordFromQString(password);
    auto dirQ = fi.absolutePath();

    auto fm = std::make_unique<FileManager>();

    runAsync(std::move(fm),
        [dir, pwd = std::move(pwd)](FileManager* f) mutable {
            f->init({}, dir, 0, DEFAULT_MAX_TABLE_SIZE,
                    /*create_new=*/false, pwd);
        },
        [this, dirQ]() {
            currentContainerDir_ = dirQ;
            containerOpen_ = true;
            emit containerOpenChanged();
            refreshFileList();
        });

    return {};
}

QString ScefController::addFiles(const QStringList& filePaths)
{
    if (busy_) return QStringLiteral("Operation already in progress");
    if (!fileManager_) return QStringLiteral("No container is open");

    try {
        auto paths = toStdPaths(filePaths);
        fileManager_->setFilesList(paths);

        // Transfer ownership to the async worker; it returns via onSuccess.
        runAsync(std::move(fileManager_),
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
    if (!fileManager_) return QStringLiteral("No container is open");

    try {
        std::vector<std::string> names;
        names.reserve(static_cast<size_t>(fileNames.size()));
        for (const auto& n : fileNames)
            names.push_back(n.toStdString());

        auto outDir = toLocalPath(outputDir);
        fileManager_->setFilesList(names);

        runAsync(std::move(fileManager_),
            [outDir](FileManager* f) { f->extract(outDir); },
            []() {});

        return {};
    } catch (const std::exception& e) {
        return QString::fromUtf8(e.what());
    }
}

void ScefController::closeContainer()
{
    if (busy_) return;
    fileManager_.reset();
    fileListModel_->clear();
    currentContainerDir_.clear();
    containerOpen_ = false;
    emit containerOpenChanged();
}

QString ScefController::logDirPath() const
{
    return QCoreApplication::applicationDirPath() + QStringLiteral("/logs");
}

QStringList ScefController::listLogFiles() const
{
    QDir dir(logDirPath());
    const QFileInfoList entries = dir.entryInfoList(QStringList() << QStringLiteral("*.log"),
                                                    QDir::Files,
                                                    QDir::Time);
    QStringList files;
    files.reserve(entries.size());
    for (const QFileInfo& entry : entries)
        files.push_back(entry.absoluteFilePath());
    return files;
}

QString ScefController::readLogFile(const QString& path, qint64 maxBytes) const
{
    if (maxBytes <= 0) {
        return QStringLiteral("[invalid maxBytes]");
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return QString::fromUtf8("[cannot open: ") + path + QStringLiteral("]");

    QString prefix;
    const qint64 size = file.size();
    if (size > maxBytes) {
        if (!file.seek(size - maxBytes)) {
            return QStringLiteral("[cannot seek: ") + path + QStringLiteral("]");
        }
        prefix = QStringLiteral("... (truncated, showing last %1 KiB) ...\n")
            .arg(maxBytes / 1024);
    }

    const QByteArray bytes = file.read(maxBytes);
    return prefix + QString::fromUtf8(bytes);
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

bool ScefController::benchEnabled() const
{
    return Logger::benchEnabled();
}

void ScefController::setBenchEnabled(bool enabled)
{
    if (enabled == Logger::benchEnabled())
        return;

    Logger::setBenchEnabled(enabled);
    emit benchEnabledChanged();
}

void ScefController::runAsync(std::unique_ptr<FileManager> fm,
                              std::function<void(FileManager*)> workFn,
                              std::function<void()> onSuccess)
{
    busy_ = true;
    emit busyChanged();

    // Transfer FileManager ownership to the worker thread to avoid race conditions.
    auto* fmRaw = fm.get();
    QPointer<ScefController> guard(this);
    auto* thread = QThread::create([guard, fm = std::move(fm), fmRaw,
                                    workFn = std::move(workFn),
                                    onSuccess = std::move(onSuccess)]() mutable {
        QString error;
        try {
            workFn(fmRaw);
        } catch (const std::exception& e) {
            error = QString::fromUtf8(e.what());
        }

        QMetaObject::invokeMethod(qApp, [guard, error, fm = std::move(fm),
                                         onSuccess = std::move(onSuccess)]() mutable {
            if (!guard) {
                // Controller was destroyed while the worker was running.
                fm.reset();
                return;
            }
            auto* self = guard.data();
            if (error.isEmpty()) {
                self->fileManager_ = std::move(fm);
                onSuccess();
            } else {
                fm.reset();
            }

            self->busy_ = false;
            emit self->busyChanged();
            emit self->operationFinished(error);
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


