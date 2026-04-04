#ifndef DRIVE_LIST_MODEL_H
#define DRIVE_LIST_MODEL_H

#include <QAbstractListModel>

#include <string>
#include <vector>

struct DriveEntry {
    std::string letter;     // "E:\"
    std::string label;      // "KINGSTON"
    uint64_t freeSpace;     // bytes
    uint64_t totalSpace;    // bytes
    bool hasContainer;      // container.scef exists
};

class DriveListModel : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)

public:
    enum Roles {
        LetterRole = Qt::UserRole + 1,
        LabelRole,
        FreeSpaceRole,
        TotalSpaceRole,
        HasContainerRole
    };

    explicit DriveListModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    Q_INVOKABLE void refresh();
    Q_INVOKABLE QString pathAtRow(int row) const;
    Q_INVOKABLE bool hasContainerAtRow(int row) const;

signals:
    void countChanged();

private:
    std::vector<DriveEntry> drives_;
};

#endif // DRIVE_LIST_MODEL_H
