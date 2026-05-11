#include "FileListModel.h"

FileListModel::FileListModel(QObject* parent)
    : QAbstractListModel(parent)
{
}

int FileListModel::rowCount(const QModelIndex& parent) const
{
    if (parent.isValid())
        return 0;
    return static_cast<int>(files_.size());
}

QVariant FileListModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 ||
        index.row() >= static_cast<int>(files_.size()))
        return {};

    const auto& entry = files_[static_cast<size_t>(index.row())];

    switch (role) {
    case NameRole:
        return QString::fromStdString(entry.name);
    case SizeRole:
        return QVariant::fromValue(static_cast<quint64>(entry.size));
    case ChecksumRole:
        return QString::fromStdString(entry.checksum);
    default:
        return {};
    }
}

QHash<int, QByteArray> FileListModel::roleNames() const
{
    return {
        {NameRole, "name"},
        {SizeRole, "size"},
        {ChecksumRole, "checksum"}
    };
}

QString FileListModel::nameAtRow(int row) const
{
    if (row < 0 || row >= static_cast<int>(files_.size()))
        return {};
    return QString::fromStdString(files_[static_cast<size_t>(row)].name);
}

void FileListModel::setFiles(const std::vector<FileEntry>& files)
{
    beginResetModel();
    files_ = files;
    endResetModel();
    emit countChanged();
}

void FileListModel::clear()
{
    beginResetModel();
    files_.clear();
    endResetModel();
    emit countChanged();
}
