#pragma once
#include <core/database.h>

namespace resheto::service {
void recordReaction(Database &db,const QString &action,const QString &object,const QString &jobId,const QString &itemId,
                    const QString &outcome,const QString &reason={});

QString resultKey(const Result &result);

class Quarantine {
    QString storage_,directory_;
    Database db_;
    QJsonObject item(const QString &id);
    void record(const QString &action,const QString &object,const QString &jobId,const QString &itemId,
                const QString &outcome,const QString &reason={});
    void update(const QString &id,const QString &state,const QString &reason={});
    void recover();
public:
    explicit Quarantine(const QString &storage,bool initialize=false);
    QJsonObject take(const QString &jobId,const QString &key);
    QJsonObject items(qint64 offset,int limit);
    QJsonObject restore(const QString &id,const QString &alternative);
    QJsonObject erase(const QString &id);
    QJsonObject journal(qint64 offset,int limit,const QString &text);
    void diagnostic(const QString &component,const QString &reason);
};
}
