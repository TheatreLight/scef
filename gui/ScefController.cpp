#include "ScefController.h"
#include "BrowserViewer.h"
#include "ContainerName.h"
#include "FileManager.h"
#include "KdfProfiles.h"
#include "Logger.h"
#include "PasswordStrengthEstimator.h"
#include "enums/ECiphers.h"
#include "enums/EHash.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileInfoList>
#include <QMetaObject>
#include <QPointer>
#include <QStringList>
#include <QUrl>
#include <QVariantMap>

#include <botan/mem_ops.h>
#include <botan/secmem.h>

#include <memory>
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

// Convert a Qt password string to a Botan secure buffer.
// QByteArray is COW — the scrub below is best-effort; it zeroes the current
// backing store before QByteArray's internal bookkeeping releases it.
Botan::secure_vector<char> securePasswordFromQString(const QString& password)
{
    QByteArray utf8 = password.toUtf8();
    Botan::secure_vector<char> result(utf8.constData(), utf8.constData() + utf8.size());
    Botan::secure_scrub_memory(const_cast<char*>(utf8.constData()),
                               static_cast<size_t>(utf8.size()));
    return result;
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

QString progressStageLabel(FileManager::ProgressStage stage)
{
    switch (stage) {
        case FileManager::ProgressStage::ValidatingPassword:
            return QStringLiteral("Validating password...");
        case FileManager::ProgressStage::DerivingKey:
            return QStringLiteral("Deriving key from password (Argon2id)...");
        case FileManager::ProgressStage::GeneratingMasterKey:
            return QStringLiteral("Generating master key...");
        case FileManager::ProgressStage::WritingHeaders:
            return QStringLiteral("Writing container headers...");
        case FileManager::ProgressStage::EncryptingData:
            return QStringLiteral("Encrypting data...");
        case FileManager::ProgressStage::VerifyingHeader:
            return QStringLiteral("Verifying header integrity...");
        case FileManager::ProgressStage::UnwrappingKey:
            return QStringLiteral("Unwrapping master key...");
        case FileManager::ProgressStage::ReadingFileTable:
            return QStringLiteral("Reading file table...");
        case FileManager::ProgressStage::DecryptingData:
            return QStringLiteral("Decrypting data...");
        case FileManager::ProgressStage::Done:
            return QStringLiteral("Done");
    }
    return {};
}

// Returns -1.0 for stages where a determinate fraction is not meaningful
// (no byte-level progress counter exists). QML should hide the percent display
// when fraction < 0.
double stageFractionFromCallback(FileManager::ProgressStage stage, double fraction)
{
    switch (stage) {
        case FileManager::ProgressStage::EncryptingData:
        case FileManager::ProgressStage::DecryptingData:
            return std::clamp(fraction, 0.0, 1.0);
        default:
            return -1.0;
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

// containerFilePath: full path to the new container file (directory + filename).
// QML is responsible for constructing the path, e.g.:
//   dir + "/" + controller.defaultContainerName(dir)
// All heavy work (init, setCipher, setKdfParams, write) runs on a background thread.
QString ScefController::createContainer(const QString& containerFilePath,
                                         const QStringList& files,
                                         const QString& password,
                                         quint64 sizeMB,
                                         int kdfProfileIndex,
                                         int kdfM_MiB,
                                         int kdfT,
                                         int kdfP,
                                         int cipherIndex,
                                         bool includeBrowserViewer,
                                         int hashIndex)
{
    if (busy_) return QStringLiteral("Operation already in progress");

    auto paths       = toStdPaths(files);
    auto filePath    = toLocalPath(containerFilePath);
    auto pwd         = securePasswordFromQString(password);
    uint64_t sizeBytes = sizeMB * 1024ULL * 1024ULL;

    EKDFProfile profile = profileFromIndex(kdfProfileIndex);

    ECipher cipher;
    switch (cipherIndex) {
        case 0:  cipher = ECipher::AES_256_GCM;   break;
        case 1:  cipher = ECipher::Kuznechik_GCM; break;
        default: cipher = ECipher::AES_256_GCM;   break;
    }

    EHash hash;
    switch (hashIndex) {
        case 0:  hash = defaultHashForCipher(cipher); break;  // "Default — matches cipher"
        case 1:  hash = EHash::SHA_256;               break;
        case 2:  hash = EHash::Streebog_256;          break;
        case 3:  hash = EHash::Streebog_512;          break;
        default: hash = defaultHashForCipher(cipher); break;
    }

    // Derive the container's parent directory for the success callback.
    auto containerFilePathQ = QString::fromStdString(filePath);

    // Create a placeholder FileManager; actual init() runs inside runAsync worker
    // so that file pre-allocation does not block the UI thread.
    auto fm = std::make_unique<FileManager>();
    installProgressCallback(fm.get());
    emit progressChanged(QString(), -1.0);

    runAsync(std::move(fm),
        [paths, filePath, sizeBytes, profile, kdfM_MiB, kdfT, kdfP, cipher, hash,
         includeBrowserViewer, pwd = std::move(pwd)](FileManager* f) mutable {
            // All of this runs on the worker thread.
            f->init(paths, filePath, sizeBytes, DEFAULT_MAX_TABLE_SIZE,
                    /*create_new=*/true, pwd);

            f->setCipher(cipher);
            f->setHashAlgo(hash);

            const KdfProfileParams* p = (profile != EKDFProfile::None)
                                        ? getProfileParams(profile)
                                        : nullptr;
            if (p) {
                f->setKdfParams(profile, p->m_kib, p->t, p->p);
            } else {
                f->setKdfParams(EKDFProfile::None,
                                static_cast<uint32_t>(kdfM_MiB) * 1024u,
                                static_cast<uint32_t>(kdfT),
                                static_cast<uint32_t>(kdfP));
            }

            f->write();

            if (includeBrowserViewer) {
                const auto sourceDir = scef::getExecutableDir();
                const auto destDir = std::filesystem::path(filePath).parent_path();
                const auto result = scef::copyBrowserViewer(sourceDir, destDir);
                if (!result.success) {
                    throw std::runtime_error(result.errorMessage);
                }
            }
        },
        [this, containerFilePathQ]() {
            currentContainerDir_ = containerFilePathQ;
            containerOpen_ = true;
            emit containerOpenChanged();
            emit currentContainerPathChanged();
            refreshFileList();
        },
        /*restoreOnError=*/false);   // on failure leave fileManager_ null

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

// containerPath: full path to an existing .scef file (not just a directory).
QString ScefController::openContainer(const QString& containerPath,
                                       const QString& password)
{
    if (busy_) return QStringLiteral("Operation already in progress");

    auto filePath = toLocalPath(containerPath);
    auto pwd      = securePasswordFromQString(password);
    auto containerPathQ = QString::fromStdString(filePath);

    auto fm = std::make_unique<FileManager>();
    installProgressCallback(fm.get());
    emit progressChanged(QString(), -1.0);

    runAsync(std::move(fm),
        [filePath, pwd = std::move(pwd)](FileManager* f) mutable {
            f->init({}, filePath, 0, DEFAULT_MAX_TABLE_SIZE,
                    /*create_new=*/false, pwd);
        },
        [this, containerPathQ]() {
            currentContainerDir_ = containerPathQ;
            containerOpen_ = true;
            emit containerOpenChanged();
            emit currentContainerPathChanged();
            refreshFileList();
        },
        /*restoreOnError=*/false);   // on failure leave fileManager_ null

    return {};
}

QString ScefController::addFiles(const QStringList& filePaths)
{
    if (busy_) return QStringLiteral("Operation already in progress");
    if (!fileManager_) return QStringLiteral("No container is open");

    try {
        auto paths = toStdPaths(filePaths);
        fileManager_->setFilesList(paths);

        installProgressCallback(fileManager_.get());
        emit progressChanged(QString(), -1.0);

        runAsync(std::move(fileManager_),
            [](FileManager* f) { f->add(); },
            [this]() { refreshFileList(); },
            /*restoreOnError=*/true);    // keep container open even on error

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

        installProgressCallback(fileManager_.get());
        emit progressChanged(QString(), -1.0);

        runAsync(std::move(fileManager_),
            [outDir](FileManager* f) { f->extract(outDir); },
            []() {},
            /*restoreOnError=*/true);    // keep container open even on error

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
    emit currentContainerPathChanged();
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

QString ScefController::defaultContainerName(const QString& dir) const
{
    const std::string fullPath = nextAvailableContainerPath(dir.toStdString());
    return QString::fromStdString(std::filesystem::path(fullPath).filename().string());
}

QString ScefController::validateContainerName(const QString& name) const
{
    const std::string err = scef::validateContainerName(name.toStdString());
    return QString::fromStdString(err);
}

QStringList ScefController::containerFilesAtRow(int row) const
{
    if (!driveListModel_) return {};
    return driveListModel_->containerFilesAtRow(row);
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

void ScefController::installProgressCallback(FileManager* fm)
{
    if (!fm)
        return;

    // FileManager stores this callback while work runs on a worker thread.
    // QPointer prevents use-after-free if the controller is destroyed early.
    QPointer<ScefController> guard(this);
    fm->setProgressCallback([guard](FileManager::ProgressStage stage, double fraction) {
        const QString label         = progressStageLabel(stage);
        const double emittedFraction = stageFractionFromCallback(stage, fraction);

        if (!guard)
            return;

        QMetaObject::invokeMethod(guard.data(), [guard, label, emittedFraction]() {
            if (!guard)
                return;
            emit guard->progressChanged(label, emittedFraction);
        }, Qt::QueuedConnection);
    });
}

void ScefController::runAsync(std::unique_ptr<FileManager> fm,
                              std::function<void(FileManager*)> workFn,
                              std::function<void()> onSuccess,
                              bool restoreOnError)
{
    busy_ = true;
    emit busyChanged();

    auto* fmRaw = fm.get();
    QPointer<ScefController> guard(this);
    auto* thread = QThread::create([guard, fm = std::move(fm), fmRaw,
                                    workFn = std::move(workFn),
                                    onSuccess = std::move(onSuccess),
                                    restoreOnError]() mutable {
        QString error;
        try {
            workFn(fmRaw);
        } catch (const std::exception& e) {
            error = QString::fromUtf8(e.what());
        }

        QMetaObject::invokeMethod(qApp, [guard, error, fm = std::move(fm),
                                         onSuccess = std::move(onSuccess),
                                         restoreOnError]() mutable {
            if (!guard) {
                // Controller was destroyed while the worker was running — discard.
                fm.reset();
                return;
            }
            auto* self = guard.data();

            // Restore ownership:
            //   - on success: always restore (container is now open / usable).
            //   - on error + restoreOnError: restore (add/extract keep the container open).
            //   - on error + !restoreOnError: discard (create/open failed — not open).
            if (error.isEmpty()) {
                self->fileManager_ = std::move(fm);
                onSuccess();
            } else if (restoreOnError) {
                self->fileManager_ = std::move(fm);
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
