#ifndef FILE_LIST_MODEL_H
#define FILE_LIST_MODEL_H

#include <QAbstractListModel>

#include "FileTable.h"

class FileListModel : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)

public:
    enum Roles {
        NameRole = Qt::UserRole + 1,
        SizeRole,
        ChecksumRole
    };

    explicit FileListModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE QString nameAtRow(int row) const;

    void setFiles(const std::vector<FileEntry>& files);
    void clear();

signals:
    void countChanged();

private:
    std::vector<FileEntry> files_;
};

#endif // FILE_LIST_MODEL_H
