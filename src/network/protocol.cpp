#include "protocol.h"
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSet>
#include <QtEndian>
#include <limits>

namespace resheto::network::ipc {
namespace {
void require(bool good){if(!good)throw Error(QStringLiteral("Некорректное сообщение сетевого процесса"));}
QString string(const QJsonObject &object,const char *key,int maximum,bool empty=false){require(object[key].isString());const auto value=object[key].toString();require(value.size()<=maximum && (empty || !value.trimmed().isEmpty()));return value;}
int number(const QJsonObject &object,const char *key,int minimum,int maximum){const auto value=object[key].toDouble(-1);require(object[key].isDouble() && value>=minimum && value<=maximum && value==static_cast<int>(value));return static_cast<int>(value);}
quint64 counter(const QJsonObject &object,const char *key){const auto text=string(object,key,32);bool valid=false;const auto value=text.toULongLong(&valid);require(valid && QString::number(value)==text && value<=static_cast<quint64>(std::numeric_limits<qint64>::max()));return value;}
QJsonArray array(const QJsonObject &object,const char *key,int maximum){require(object[key].isArray() && object[key].toArray().size()<=maximum);return object[key].toArray();}
}
void Channel::send(const QJsonObject &message,int timeoutMs) {
    require(timeoutMs>=1 && timeoutMs<=30000);
    const auto bytes=QJsonDocument(message).toJson(QJsonDocument::Compact);require(!bytes.isEmpty() && bytes.size()<=maximumMessage);
    if(socket_.state()!=QLocalSocket::ConnectedState || socket_.bytesToWrite()>maximumMessage)throw Error(QStringLiteral("Сетевой IPC отключён или переполнен"));
    QByteArray frame(4,0);qToBigEndian<quint32>(static_cast<quint32>(bytes.size()),frame.data());frame+=bytes;
    if(socket_.write(frame)!=frame.size())throw Error(QStringLiteral("Не удалось отправить сообщение сетевому процессу"));
    QElapsedTimer elapsed;elapsed.start();
    while(socket_.bytesToWrite())if(elapsed.elapsed()>=timeoutMs || !socket_.waitForBytesWritten(qMax(1,timeoutMs-static_cast<int>(elapsed.elapsed()))))throw Error(QStringLiteral("Истекло время отправки сетевого сообщения"));
}
std::optional<QJsonObject> Channel::receive(int timeoutMs) {
    require(timeoutMs>=0 && timeoutMs<=30000);QElapsedTimer elapsed;elapsed.start();
    while(true) {
        if(buffered_.size()>=4) {
            const auto size=qFromBigEndian<quint32>(buffered_.constData());require(size>0 && size<=maximumMessage);
            if(buffered_.size()>=static_cast<qsizetype>(size)+4) {
                const auto bytes=buffered_.mid(4,size);buffered_.remove(0,static_cast<qsizetype>(size)+4);QJsonParseError error;
                const auto document=QJsonDocument::fromJson(bytes,&error);require(error.error==QJsonParseError::NoError && document.isObject());return document.object();
            }
        }
        if(socket_.bytesAvailable()) {const auto capacity=maximumMessage+4-buffered_.size();require(capacity>0);buffered_+=socket_.read(capacity);continue;}
        if(socket_.state()==QLocalSocket::UnconnectedState)throw Error(QStringLiteral("Сетевой процесс разорвал локальное соединение"));
        if(elapsed.elapsed()>=timeoutMs)return {};
        socket_.waitForReadyRead(qMin(50,qMax(1,timeoutMs-static_cast<int>(elapsed.elapsed()))));
    }
}
QJsonArray stringArray(const QStringList &values){QJsonArray result;for(const auto &value:values)result.append(value);return result;}
QStringList parseIds(const QJsonValue &value,int maximum) {
    require(value.isArray() && value.toArray().size()<=maximum);QStringList result;QSet<QString> unique;
    for(const auto &entry:value.toArray()){require(entry.isString());const auto id=entry.toString();require(QRegularExpression("^[0-9a-f]{64}$").match(id).hasMatch() && !unique.contains(id));unique.insert(id);result<<id;}return result;
}
QStringList detectionIds(const NetworkBatch &batch){QStringList result;for(const auto &d:batch.detections)result<<d.id;return result;}
QJsonObject batchJson(const NetworkBatch &batch) {
    QJsonArray flows,detections,notes;for(const auto &flow:batch.flows)flows.append(flow.json());for(const auto &d:batch.detections)detections.append(d.json());for(const auto &d:batch.diagnostics)notes.append(QJsonObject{{"code",d.code},{"reason",d.reason}});
    return {{"flows",flows},{"detections",detections},{"diagnostics",notes},{"counters",batch.counters.json()}};
}
NetworkBatch parseBatch(const QJsonObject &object) {
    NetworkBatch result;QSet<QString> flows,detections;
    for(const auto &entry:array(object,"flows",200)){require(entry.isObject());auto flow=Flow::fromJson(entry.toObject());require(!flows.contains(flow.id));flows.insert(flow.id);result.flows.push_back(std::move(flow));}
    for(const auto &entry:array(object,"detections",200)){require(entry.isObject());auto detection=Detection::fromJson(entry.toObject());require(!detections.contains(detection.id));detections.insert(detection.id);result.detections.push_back(std::move(detection));}
    for(const auto &entry:array(object,"diagnostics",64)){require(entry.isObject());const auto note=entry.toObject();Diagnostic value{string(note,"code",64),string(note,"reason",2048)};require(QRegularExpression("^[a-z][a-z0-9_]{0,63}$").match(value.code).hasMatch());result.diagnostics.push_back(std::move(value));}
    require(object["counters"].isObject());result.counters=Counters::fromJson(object["counters"].toObject());return result;
}
QJsonObject optionsJson(const AnalysisOptions &options) {
    QJsonArray ports;for(const auto port:options.capture.tcpPorts)ports.append(port);
    return {{"source",options.source},{"input",options.input},{"duration_ms",options.durationMs},{"rules",options.rules->document},{"udp_port",options.capture.udpPort},{"tcp_ports",ports}};
}
AnalysisOptions parseOptions(const QJsonObject &object) {
    require(object.keys()==QStringList{"duration_ms","input","rules","source","tcp_ports","udp_port"});
    AnalysisOptions result;result.source=string(object,"source",16);require(result.source=="live" || result.source=="pcap");result.input=string(object,"input",4096);
    result.durationMs=number(object,"duration_ms",0,maximumDurationMs);require(validDuration(result.source=="live",result.durationMs));
    result.capture.interfaceId=result.input;result.capture.udpPort=static_cast<quint16>(number(object,"udp_port",0,65535));
    for(const auto &entry:array(object,"tcp_ports",64)){require(entry.isDouble() && entry.toDouble()>=1 && entry.toDouble()<=65535 && entry.toDouble()==entry.toInt());result.capture.tcpPorts.push_back(static_cast<quint16>(entry.toInt()));}captureFilter(result.capture);
    require(result.source=="live" || (!result.capture.udpPort && result.capture.tcpPorts.empty()));
    require(object["rules"].isObject());result.rules=parseNetworkRules(object["rules"].toObject());return result;
}
QJsonObject resultJson(const AnalysisResult &result) {
    return {{"state",result.state},{"error",result.error.isNull()?QString(""):result.error},{"backend",result.backendVersion.isNull()?QString(""):result.backendVersion},{"counters",result.counters.json()},
        {"drops_available",result.capture.dropsAvailable},{"received",QString::number(result.capture.received)},{"dropped",QString::number(result.capture.dropped)},{"interface_dropped",QString::number(result.capture.interfaceDropped)}};
}
AnalysisResult parseResult(const QJsonObject &object) {
    AnalysisResult result;result.state=string(object,"state",16);require(QStringList{"completed","cancelled","failed"}.contains(result.state));result.error=string(object,"error",4096,true);require((result.state=="failed")==!result.error.isEmpty());
    result.backendVersion=string(object,"backend",512,true);require(object["counters"].isObject() && object["drops_available"].isBool());result.counters=Counters::fromJson(object["counters"].toObject());result.capture.dropsAvailable=object["drops_available"].toBool();result.capture.received=counter(object,"received");result.capture.dropped=counter(object,"dropped");result.capture.interfaceDropped=counter(object,"interface_dropped");require(result.capture.dropsAvailable || (!result.capture.dropped && !result.capture.interfaceDropped));return result;
}
}
