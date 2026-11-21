#pragma once

#include <core/model.h>

namespace resheto::service {
QJsonObject diagnose(const Request &request,const QString &quarantineError={});
void logSystemError(const QString &message);
}
