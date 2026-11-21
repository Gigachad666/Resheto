#pragma once
#include "client.h"

namespace resheto::service::protocol {
QJsonObject encodeMonitorOptions(const MonitorOptions &options);
MonitorOptions decodeMonitorOptions(const QJsonObject &object);
QJsonObject encodeMonitorStatus(const MonitorStatus &status);
MonitorStatus decodeMonitorStatus(const QJsonObject &object);
ProcessInfo decodeProcess(const QJsonObject &object);
}
