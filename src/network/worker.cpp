#include "session.h"
#include "private_session.h"
#include "protocol.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QTextStream>

namespace resheto::network {
namespace {
void check(bool good,const QString &reason){if(!good)throw Error(reason);}
}
int networkWorkerMain(const QStringList &arguments) {
    try {
        if(arguments==QStringList{"--interfaces"}) {
            QJsonArray interfaces;for(const auto &item:captureInterfaces()){QJsonArray addresses;for(const auto &address:item.addresses)addresses.append(address);interfaces.append(QJsonObject{{"id",item.id},{"name",item.name},{"loopback",item.loopback},{"addresses",addresses}});}
            QTextStream(stdout)<<QJsonDocument(QJsonObject{{"format","resheto-network-interfaces-v1"},{"backend",captureBackendVersion()},{"interfaces",interfaces}}).toJson(QJsonDocument::Compact)<<Qt::endl;return 0;
        }
        check(arguments.size()==2 && arguments[0]=="--session",QStringLiteral("Допустимы --interfaces или --session <приватный файл>"));const auto ticket=ipc::readSessionTicket(arguments[1]);
        QLocalSocket socket;socket.connectToServer(ticket.endpoint);check(socket.waitForConnected(10000),QStringLiteral("Не удалось подключиться к контроллеру сети"));ipc::Channel channel(socket);
        channel.send({{"type","hello"},{"version",ipc::protocolVersion},{"token",ticket.token},{"worker_pid",QString::number(QCoreApplication::applicationPid())}});
        const auto start=channel.receive(10000);check(start && (*start)["type"]=="start" && (*start)["version"]==ipc::protocolVersion && (*start)["options"].isObject(),QStringLiteral("Не получены параметры сетевого задания"));const auto options=ipc::parseOptions((*start)["options"].toObject());
        bool cancelled=false;qint64 sequence=0;
        auto command=[&](const QJsonObject &message){check(message["version"]==ipc::protocolVersion && message["type"]=="cancel",QStringLiteral("Неожиданная команда контроллера сети"));cancelled=true;};
        const auto result=analyzeNetwork(options,[&](const NetworkBatch &batch){
            const auto expectedIds=ipc::detectionIds(batch);channel.send({{"type","batch"},{"version",ipc::protocolVersion},{"sequence",QString::number(++sequence)},{"batch",ipc::batchJson(batch)}});
            QElapsedTimer timeout;timeout.start();bool acknowledged=false;
            while(timeout.elapsed()<10000 && !acknowledged) {
                const auto message=channel.receive(100);if(!message)continue;
                if((*message)["type"]=="cancel"){command(*message);continue;}
                check((*message)["version"]==ipc::protocolVersion && (*message)["type"]=="ack" && (*message)["sequence"].toString()==QString::number(sequence) && ipc::parseIds((*message)["detections"])==expectedIds,QStringLiteral("Неверное подтверждение сохранения сетевых результатов"));acknowledged=true;
            }
            check(acknowledged,QStringLiteral("Контроллер не подтвердил commit за 10 секунд"));
        },[&]{while(const auto message=channel.receive(0))command(*message);return cancelled;});
        channel.send({{"type","done"},{"version",ipc::protocolVersion},{"result",ipc::resultJson(result)}});socket.disconnectFromServer();if(socket.state()!=QLocalSocket::UnconnectedState)socket.waitForDisconnected(1000);return 0;
    }catch(const Error &error){QTextStream(stderr)<<QJsonDocument(QJsonObject{{"type","error"},{"code","network_worker"},{"error",error.message}}).toJson(QJsonDocument::Compact)<<Qt::endl;return 2;}
    catch(const std::exception &error){QTextStream(stderr)<<QJsonDocument(QJsonObject{{"type","error"},{"code","network_worker"},{"error",QString::fromUtf8(error.what())}}).toJson(QJsonDocument::Compact)<<Qt::endl;return 2;}
}
}
