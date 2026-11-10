#pragma once
#include "runner.h"
#include <QLocalSocket>

namespace resheto::network::ipc {
inline constexpr qsizetype maximumMessage=4*1024*1024;
inline constexpr int protocolVersion=1;
class Channel {
    QLocalSocket &socket_;
    QByteArray buffered_;
public:
    explicit Channel(QLocalSocket &socket):socket_(socket){socket_.setReadBufferSize(maximumMessage+4);}
    void send(const QJsonObject &message,int timeoutMs=10000);
    std::optional<QJsonObject> receive(int timeoutMs);
};
QJsonObject batchJson(const NetworkBatch &batch);
NetworkBatch parseBatch(const QJsonObject &object);
QJsonObject optionsJson(const AnalysisOptions &options);
AnalysisOptions parseOptions(const QJsonObject &object);
QJsonObject resultJson(const AnalysisResult &result);
AnalysisResult parseResult(const QJsonObject &object);
QStringList detectionIds(const NetworkBatch &batch);
QJsonArray stringArray(const QStringList &values);
QStringList parseIds(const QJsonValue &value,int maximum=200);
}
