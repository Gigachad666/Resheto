#pragma once

#include <core/database.h>

namespace resheto::service {

class Notifications {
    Database db_;
    const bool network_;
public:
    explicit Notifications(const QString &historyPath,bool networkHistory=false);
    qint64 unreadCount();
    QJsonObject page(qint64 offset,int limit);
    QJsonObject acknowledge(const QString &id);
};

}
