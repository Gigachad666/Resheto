#include "core/model.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTextStream>
#include <future>
#include <iostream>
#include <thread>

namespace {
using resheto::Error;
void report(const QJsonObject &object) {
    QTextStream(stdout)<<QJsonDocument(object).toJson(QJsonDocument::Compact)<<Qt::endl;
}
void connectOwn(QTcpServer &server) {
    QTcpSocket sender;
    sender.connectToHost(QHostAddress::LocalHost,server.serverPort());
    if(sender.state()!=QTcpSocket::ConnectedState && !sender.waitForConnected(1000))
        throw Error(QStringLiteral("Собственный порт не принял соединение"));
    if(!server.hasPendingConnections() && !server.waitForNewConnection(1000))
        throw Error(QStringLiteral("Локальное соединение не появилось у получателя"));
    std::unique_ptr<QTcpSocket> receiver(server.nextPendingConnection());
    const QByteArray message="own loopback";
    if(sender.write(message)!=message.size() || (sender.bytesToWrite() && !sender.waitForBytesWritten(1000)))
        throw Error(QStringLiteral("Не удалось отправить локальное сообщение"));
    QByteArray received;QElapsedTimer timer;timer.start();
    while(receiver && received.size()<message.size() && timer.elapsed()<1000) {
        if(!receiver->bytesAvailable() && !receiver->waitForReadyRead(100))continue;
        received+=receiver->read(message.size()-received.size());
    }
    if(received!=message)throw Error(QStringLiteral("Локальный получатель не подтвердил доставку"));
}
}
int main(int argc,char **argv) {
    using namespace std::chrono_literals;
    QCoreApplication app(argc,argv);
    try {
        if(app.arguments().mid(1)!=QStringList{"--wait"})throw Error(QStringLiteral("Нужен --wait. После сообщения ready передайте normal, sweep или periodic в stdin"));
        std::vector<std::unique_ptr<QTcpServer>> servers;QJsonArray ports;
        for(int i=0;i<20;++i) {
            auto server=std::make_unique<QTcpServer>();
            if(!server->listen(QHostAddress::LocalHost,0))throw Error(server->errorString());
            ports.append(server->serverPort());servers.push_back(std::move(server));
        }
        report({{"type","ready"},{"address","127.0.0.1"},{"ports",ports}});
        std::promise<QString> input;auto command=input.get_future();
        std::thread([input=std::move(input)]() mutable {
            char buffer[32]{};std::cin.getline(buffer,sizeof(buffer));
            input.set_value(std::cin.fail()?QString():QString::fromLatin1(buffer).trimmed());
        }).detach();
        if(command.wait_for(60s)!=std::future_status::ready)throw Error(QStringLiteral("Локальные порты закрыты: команда не получена за 60 секунд"));
        const auto scenario=command.get();
        if(scenario!="normal" && scenario!="sweep" && scenario!="periodic")throw Error(QStringLiteral("Неизвестный локальный сценарий"));
        const int count=scenario=="normal"?2:scenario=="periodic"?6:20;
        const auto start=std::chrono::steady_clock::now();
        for(int i=0;i<count;++i) {
            if(scenario=="periodic")std::this_thread::sleep_until(start+i*1200ms);
            connectOwn(*servers[scenario=="periodic"?0:i]);
        }
        report({{"type","sent"},{"scenario",scenario},{"connected",count}});return 0;
    }catch(const Error &error){QTextStream(stderr)<<error.message<<Qt::endl;return 2;}
}
