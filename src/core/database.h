#pragma once
#include "model.h"
#include <QSqlDatabase>
#include <QSqlQuery>

namespace resheto {
class Database {
    QString name_;
    QSqlDatabase db_;
public:
    Database(const QString &path, bool readOnly);
    ~Database();
    Database(const Database &) = delete;
    Database &operator=(const Database &) = delete;
    QSqlQuery exec(const QString &sql, const QVariantList &args = {}, bool forwardOnly = false);
    void transaction();
    void commit();
    void rollback();
};
class Store {
    Database db_;
public:
    explicit Store(const QString &path, bool readOnly = false);
    void start(const Job &job);
    void append(const Result &result, const Job &progress);
    void finish(const Job &job);
    std::optional<Job> latest();
    // Постраничное чтение: GUI и CLI не загружают весь журнал в память.
    std::vector<Result> page(const QString &jobId, qint64 afterRow, int limit = 200);
    qint64 lastRow() const { return lastRow_; }
private:
    qint64 lastRow_ = 0;
    void event(const QString &job, const QString &type, const QString &object, const QString &code);
};
}
