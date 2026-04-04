#include "DriveListModel.h"

#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

DriveListModel::DriveListModel(QObject* parent)
    : QAbstractListModel(parent)
{
    refresh();
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

bool DriveListModel::hasContainerAtRow(int row) const
{
    if (row < 0 || row >= static_cast<int>(drives_.size()))
        return false;
    return drives_[static_cast<size_t>(row)].hasContainer;
}

void DriveListModel::refresh()
{
    beginResetModel();
    drives_.clear();

#ifdef _WIN32
    wchar_t driveStrings[512];
    DWORD len = GetLogicalDriveStringsW(511, driveStrings);
    if (len == 0) {
        endResetModel();
        return;
    }

    wchar_t* current = driveStrings;
    while (*current) {
        UINT driveType = GetDriveTypeW(current);
        if (driveType == DRIVE_REMOVABLE) {
            DriveEntry entry;

            // Drive letter string (e.g. "E:\")
            int needed = WideCharToMultiByte(CP_UTF8, 0, current, -1, nullptr, 0, nullptr, nullptr);
            std::string letterStr(static_cast<size_t>(needed - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, current, -1, letterStr.data(), needed, nullptr, nullptr);
            entry.letter = letterStr;

            // Volume label
            wchar_t volumeName[256] = {};
            if (GetVolumeInformationW(current, volumeName, 256, nullptr, nullptr, nullptr, nullptr, 0)) {
                int labelNeeded = WideCharToMultiByte(CP_UTF8, 0, volumeName, -1, nullptr, 0, nullptr, nullptr);
                std::string labelStr(static_cast<size_t>(labelNeeded - 1), '\0');
                WideCharToMultiByte(CP_UTF8, 0, volumeName, -1, labelStr.data(), labelNeeded, nullptr, nullptr);
                entry.label = labelStr;
            }
            if (entry.label.empty()) {
                entry.label = "Removable Drive";
            }

            // Free/total space
            ULARGE_INTEGER freeBytesAvailable, totalBytes;
            if (GetDiskFreeSpaceExW(current, &freeBytesAvailable, &totalBytes, nullptr)) {
                entry.freeSpace = freeBytesAvailable.QuadPart;
                entry.totalSpace = totalBytes.QuadPart;
            } else {
                entry.freeSpace = 0;
                entry.totalSpace = 0;
            }

            // Check for existing container
            std::filesystem::path containerPath = std::filesystem::path(letterStr) / "container.scef";
            entry.hasContainer = std::filesystem::exists(containerPath);

            drives_.push_back(std::move(entry));
        }
        current += wcslen(current) + 1;
    }
#else
    // TODO: Linux — enumerate /media/$USER or /run/media/$USER
    // For now, returns empty list on non-Windows platforms.
#endif

    endResetModel();
}
