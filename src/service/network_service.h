#pragma once

#include "network/session.h"

namespace resheto::service {
class NetworkService {
    network::NetworkSession session_;
    const QString storage_,rules_,worker_;
    QString error_;
public:
    NetworkService(const QString &storage,const QString &rulesPath);
    QJsonObject dispatch(const QString &command,const QJsonObject &request);
};
}
