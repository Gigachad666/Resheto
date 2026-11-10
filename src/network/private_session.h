#pragma once
#include "core/model.h"
#include <QTemporaryDir>

namespace resheto::network::ipc {
struct SessionTicket {QString endpoint,token; qint64 controllerPid=0;};
class PrivateSession {
    QTemporaryDir directory_;
    QString path_;
    SessionTicket ticket_;
public:
    PrivateSession();
    const QString &path() const{return path_;}
    const SessionTicket &ticket() const{return ticket_;}
};
SessionTicket readSessionTicket(const QString &path);
}
