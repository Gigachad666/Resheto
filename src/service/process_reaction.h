#pragma once

#include <QJsonObject>

namespace resheto::service {
QJsonObject reactToProcess(const QString &storage,const QString &jobId,const QString &key,bool confirm);
}
