#pragma once
#include <core/database.h>

namespace resheto::service::protocol {
inline constexpr int version=1;
inline constexpr qsizetype headerSize=4;
inline constexpr qsizetype requestLimit=32*1024;
inline constexpr qsizetype replyLimit=4*1024*1024;
inline constexpr int pageLimit=200;

bool validEndpoint(const QString &name);
QByteArray frame(const QJsonObject &message,qsizetype limit);
std::optional<QJsonObject> readFrame(const QByteArray &bytes,qsizetype limit);
qint64 counter(const QJsonValue &value);
QJsonObject encodeQuery(const ResultQuery &query);
ResultQuery decodeQuery(const QJsonObject &object);
}
