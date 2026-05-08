#include "DriveListModel.h"

#include <QStorageInfo>

#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

// ---------------------------------------------------------------------------
// Helper: scan a directory root for *.scef files.
// Returns filenames only (not full paths). Never throws — uses error_code
// overloads and catches filesystem_error defensively.
// ---------------------------------------------------------------------------
static QStringList scanScefFiles(const std::string& root)
{
    QStringList result;
    try {
        std::error_code ec;
        if (!std::filesystem::is_directory(root, ec) || ec)
            return result;

        std::filesystem::directory_iterator it(root, ec);
        if (ec)
            return result;

        for (const auto& entry : it) {
            if (ec) break;
            std::error_code ec2;
            if (!entry.is_regular_file(ec2) || ec2)
                continue;
            if (entry.path().extension() == ".scef")
                result << QString::fromStdString(entry.path().filename().string());
        }
    } catch (const std::filesystem::filesystem_error&) {
        // Drive ejected or otherwise inaccessible — return what we have so far.
    }
    return result;
}

// ---------------------------------------------------------------------------

DriveListModel::DriveListModel(QObject* parent)
    : QAbstractListModel(parent)
{
}

int DriveListModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid())
        return 0;
    return static_cast<int>(drives_.size());
}

QVariant DriveListModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 ||
        index.row() >= static_cast<int>(drives_.size()))
        return {};

    const auto& d = drives_[static_cast<size_t>(index.row())];

    switch (role) {
    case LetterRole:
        return QString::fromStdString(d.letter);
    case LabelRole:
        return QString::fromStdString(d.label);
    case FreeSpaceRole:
        return QVariant::fromValue(static_cast<quint64>(d.freeSpace));
    case TotalSpaceRole:
        return QVariant::fromValue(static_cast<quint64>(d.totalSpace));
    case HasContainerRole:
        return d.hasContainer;
    default:
        return {};
    }
}

QHash<int, QByteArray> DriveListModel::roleNames() const
{
    return {
        {LetterRole, "letter"},
        {LabelRole, "label"},
        {FreeSpaceRole, "freeSpace"},
        {TotalSpaceRole, "totalSpace"},
        {HasContainerRole, "hasContainer"}
    };
}

QString DriveListModel::pathAtRow(int row) const
{
    if (row < 0 || row >= static_cast<int>(drives_.size()))
        return {};
    return QString::fromStdString(drives_[static_cast<size_t>(row)].letter);
}

QStringList DriveListModel::containerFilesAtRow(int row) const
{
    if (row < 0 || row >= static_cast<int>(drives_.size()))
        return {};
    return drives_[static_cast<size_t>(row)].containerFiles;
}

bool DriveListModel::hasContainerAtRow(int row) const
{
    return !containerFilesAtRow(row).isEmpty();
}

void DriveListModel::refresh()
{
    beginResetModel();
    drives_.clear();

#ifdef _WIN32
    wchar_t driveStrings[512];
    DWORD len = GetLogicalDriveStringsW(512, driveStrings);
    if (len == 0) {
        endResetModel();
        emit countChanged();
        return;
    }

    wchar_t* current = driveStrings;
    while (*current) {
        UINT driveType = GetDriveTypeW(current);
        if (driveType == DRIVE_REMOVABLE) {
            try {
                DriveEntry entry;

                // Drive letter string (e.g. "E:\")
                int needed = WideCharToMultiByte(
                    CP_UTF8, 0, current, -1, nullptr, 0, nullptr, nullptr);
                std::string letterStr(static_cast<size_t>(needed - 1), '\0');
                WideCharToMultiByte(
                    CP_UTF8, 0, current, -1, letterStr.data(), needed, nullptr, nullptr);
                entry.letter = letterStr;

                // Volume label
                wchar_t volumeName[256] = {};
                if (GetVolumeInformationW(
                        current, volumeName, 256, nullptr, nullptr, nullptr, nullptr, 0)) {
                    int labelNeeded = WideCharToMultiByte(
                        CP_UTF8, 0, volumeName, -1, nullptr, 0, nullptr, nullptr);
                    std::string labelStr(static_cast<size_t>(labelNeeded - 1), '\0');
                    WideCharToMultiByte(
                        CP_UTF8, 0, volumeName, -1, labelStr.data(), labelNeeded, nullptr, nullptr);
                    entry.label = labelStr;
                }
                if (entry.label.empty())
                    entry.label = "Removable Drive";

                // Free/total space
                ULARGE_INTEGER freeBytesAvailable, totalBytes;
                if (GetDiskFreeSpaceExW(current, &freeBytesAvailable, &totalBytes, nullptr)) {
                    entry.freeSpace = freeBytesAvailable.QuadPart;
                    entry.totalSpace = totalBytes.QuadPart;
                } else {
                    entry.freeSpace = 0;
                    entry.totalSpace = 0;
                }

                // Scan for *.scef files in drive root
                entry.containerFiles = scanScefFiles(entry.letter);
                entry.hasContainer = !entry.containerFiles.isEmpty();

                drives_.push_back(std::move(entry));
            } catch (const std::filesystem::filesystem_error&) {
                // Drive ejected mid-enumeration — skip this entry, model stays consistent.
            }
        }
        current += wcslen(current) + 1;
    }

#else
    // Linux / macOS: enumerate mounted volumes via QStorageInfo.
    // Heuristic: include only mounts under /media/, /mnt/, or /run/media/
    // to approximate removable/user-mounted drives.
    const auto volumes = QStorageInfo::mountedVolumes();
    for (const auto& v : volumes) {
        if (!v.isReady() || !v.isValid())
            continue;

        const QString rootPath = v.rootPath();

        // Apply removable-drive heuristic
        const bool likelyRemovable =
            rootPath.startsWith(QLatin1String("/media/")) ||
            rootPath.startsWith(QLatin1String("/mnt/"))   ||
            rootPath.startsWith(QLatin1String("/run/media/"));

        if (!likelyRemovable)
            continue;

        try {
            DriveEntry entry;
            entry.letter = rootPath.toStdString();
            entry.label = v.displayName().isEmpty()
                ? "Removable Drive"
                : v.displayName().toStdString();
            entry.totalSpace = static_cast<uint64_t>(
                v.bytesTotal() >= 0 ? v.bytesTotal() : 0);
            entry.freeSpace = static_cast<uint64_t>(
                v.bytesAvailable() >= 0 ? v.bytesAvailable() : 0);

            entry.containerFiles = scanScefFiles(entry.letter);
            entry.hasContainer = !entry.containerFiles.isEmpty();

            drives_.push_back(std::move(entry));
        } catch (const std::filesystem::filesystem_error&) {
            // Mount disappeared during enumeration — skip.
        }
    }
#endif

    endResetModel();
    emit countChanged();
}
