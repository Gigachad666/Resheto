#include "core/signatures.h"
#include "service/client.h"
#include "service/protocol.h"
#ifdef RESHETO_SERVICE_NETWORK
#include "service/network_client.h"
#include "network/fixtures.h"
#include <QTcpServer>
#include <QTcpSocket>
#endif
#include <QCryptographicHash>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalServer>
#include <QLocalSocket>
#include <QProcess>
#include <QTemporaryDir>
#include <QUuid>
#include <QtEndian>
#include <QtTest>
#include <functional>

using namespace resheto;
using namespace resheto::service;

namespace {
const QString source=QStringLiteral(RESHETO_SOURCE_DIR);
const QString executable=QStringLiteral(RESHETO_SERVICE_EXECUTABLE);

void put(const QString &path,const QByteArray &content) {
    QFile file(path);
    if(!file.open(QIODevice::WriteOnly|QIODevice::NewOnly) || file.write(content)!=content.size())
        throw Error(QStringLiteral("Не удалось записать тестовый файл: ")+path);
}

QString refusal(const std::function<void()> &operation) {
    try {operation();}
    catch(const Error &error) {return error.message;}
    return {};
}

class Fixture {
public:
    QTemporaryDir directory{QDir::currentPath()+"/service-test-XXXXXX"};
    QString endpoint="resheto-test-"+QUuid::createUuid().toString(QUuid::WithoutBraces);
    QProcess process;
    QStringList extraArguments;

    Fixture() {
        if(!directory.isValid())throw Error(QStringLiteral("Нужен новый каталог теста службы"));
        createSignatures(source+"/data/demo_signatures.json",signaturePath());
    }
    ~Fixture() {
        stop();
        QLocalServer::removeServer(endpoint);
    }
    QString signaturePath() const { return directory.filePath("test-signatures.db"); }
    QString historyPath() const { return directory.filePath("history.db"); }
    QStringList arguments() const {
        QStringList args{"--endpoint",endpoint,"--db",signaturePath(),"--storage",historyPath()};
#ifdef RESHETO_SERVICE_NETWORK
        args<<"--network-rules"<<source+"/data/network_rules.json";
#endif
        return args;
    }
    void start() {
#ifdef Q_OS_WIN
        // Именованный канал на Windows от TEMP не зависит. Lock остаётся в каталоге фикстуры.
        auto environment=QProcessEnvironment::systemEnvironment();
        environment.insert("TEMP",directory.path());
        environment.insert("TMP",directory.path());
        process.setProcessEnvironment(environment);
#endif
        process.start(executable,extraArguments.isEmpty()?arguments():extraArguments);
        if(!process.waitForStarted(3000))throw Error(QStringLiteral("Не запустилась тестовая служба: ")+process.errorString());
        QElapsedTimer elapsed;
        elapsed.start();
        QByteArray output;
        while(elapsed.elapsed()<5000 && process.state()!=QProcess::NotRunning) {
            process.waitForReadyRead(100);
            output+=process.readAllStandardOutput();
            if(output.contains("READY "+endpoint.toUtf8()+"\n") || output.contains("READY "+endpoint.toUtf8()+"\r\n"))return;
        }
        throw Error(QStringLiteral("Тестовая служба не готова: ")+QString::fromUtf8(process.readAllStandardError()));
    }
    void stop() {
        if(process.state()==QProcess::NotRunning)return;
        process.terminate();
        if(!process.waitForFinished(800)){process.kill();process.waitForFinished(3000);}
    }
};

QJsonObject exchange(const QString &endpoint,const QByteArray &command) {
    QLocalSocket socket;
    socket.connectToServer(endpoint);
    if(!socket.waitForConnected(1000) || socket.write(command)!=command.size())
        throw Error(QStringLiteral("Не отправился тестовый запрос"));
    if(socket.bytesToWrite() && !socket.waitForBytesWritten(1000))throw Error(QStringLiteral("Не записался тестовый запрос"));
    QByteArray buffer;
    QElapsedTimer elapsed;
    elapsed.start();
    while(elapsed.elapsed()<3000) {
        buffer+=socket.readAll();
        if(const auto reply=protocol::readFrame(buffer,protocol::replyLimit))return *reply;
        if(socket.state()==QLocalSocket::UnconnectedState)break;
        socket.waitForReadyRead(100);
    }
    throw Error(QStringLiteral("Служба не ответила на тестовый запрос"));
}
}

class ServiceTests : public QObject {
    Q_OBJECT
private slots:
    void monitoringUsesOwnJobAndCanQuarantineFileWhileActive() {
        Fixture fixture;
        const auto watched=fixture.directory.filePath("watched");
        const auto manualFolder=fixture.directory.filePath("manual");
        QVERIFY(QDir().mkdir(watched));
        QVERIFY(QDir().mkdir(manualFolder));
        for(int index=0;index<400;++index)put(manualFolder+"/own-"+QString::number(index)+".bin",QByteArray(1024,'q'));
        fixture.start();
        MonitorOptions scope;
        scope.directory=watched;
        scope.processes=false;
        const auto started=Client(fixture.endpoint).startMonitor(scope);
        QCOMPARE(started.job.source,QString("monitor"));
        QVERIFY(started.active);

        const Client otherWindow(fixture.endpoint);
        QTRY_VERIFY_WITH_TIMEOUT(otherWindow.monitorStatus().ready,7000);
        QVERIFY(otherWindow.getJob(started.job.id));
        QCOMPARE(otherWindow.getJob(started.job.id)->state,QString("running"));
        QCOMPARE(otherWindow.processes().size(),size_t(0));
        const auto manual=otherWindow.startScan(manualFolder,false);
        QVERIFY(otherWindow.status().busy && otherWindow.status().monitor.active);
        QVERIFY(!otherWindow.cancelMonitor(manual.id));
        QVERIFY(!otherWindow.cancel(started.job.id));
        QVERIFY(otherWindow.cancel(manual.id));
        QTRY_VERIFY_WITH_TIMEOUT(!otherWindow.status().busy,7000);
        QVERIFY(otherWindow.monitorStatus().active);

        const auto input=watched+"/own.bin";
        const auto bytes=QByteArray::fromHex("010200ff5245534845544f000304");
        put(input,bytes);
        QTRY_VERIFY_WITH_TIMEOUT(otherWindow.monitorStatus().job.matches>0,7000);
        ResultQuery query;
        query.filter=ResultFilter::Matches;
        query.object=ResultObject::Files;
        const auto rows=otherWindow.query(started.job.id,query).rows;
        QVERIFY(!rows.empty());
        QCOMPARE(rows.front().sha256,QString::fromLatin1(QCryptographicHash::hash(bytes,QCryptographicHash::Sha256).toHex()));
        const auto notice=otherWindow.notifications(0,10)["rows"].toArray().at(0).toObject();
        QCOMPARE(notice["view"].toString(),QString("files"));
        QCOMPARE(notice["job_id"].toString(),started.job.id);
        QCOMPARE(otherWindow.quarantine(started.job.id,resultKey(rows.front()))["state"].toString(),QString("stored"));
        QVERIFY(otherWindow.monitorStatus().active);
        QVERIFY(!QFileInfo::exists(input));
        QVERIFY(otherWindow.cancelMonitor(started.job.id));
        QTRY_VERIFY_WITH_TIMEOUT(!otherWindow.monitorStatus().active,7000);
        QVERIFY(otherWindow.getJob(started.job.id));
        QVERIFY(otherWindow.getJob(manual.id));
    }

    void scopedProcessDetectionIsSavedAndLinkedThroughService() {
        Fixture fixture;
        const auto area=fixture.directory.filePath("programs");
        QVERIFY(QDir().mkdir(area));
        const QFileInfo helperSource(QStringLiteral(RESHETO_HELPER_PATH));
        const auto helper=area+"/"+helperSource.fileName();
        QVERIFY(QFile::copy(helperSource.absoluteFilePath(),helper));
        fixture.start();
        const Client client(fixture.endpoint);
        MonitorOptions options;
        options.files=false;
        options.processImageDirectory=area;
        options.behaviorPath=source+"/data/behavior_rules.json";
        const auto job=client.startMonitor(options).job;
        QTRY_VERIFY_WITH_TIMEOUT(client.monitorStatus().ready,6000);
        QProcess ordinary;
        ordinary.start(helper,{"--children","1","--delay-ms","1000","--hold-ms","1500"});
        QVERIFY2(ordinary.waitForStarted(3000),qPrintable(ordinary.errorString()));
        QTRY_VERIFY_WITH_TIMEOUT(client.monitorStatus().processEvents>=1,4500);
        QVERIFY(ordinary.state()==QProcess::NotRunning || ordinary.waitForFinished(4500));
        QCOMPARE(ordinary.exitCode(),0);
        QCOMPARE(client.monitorStatus().job.matches,qint64(0));
        QProcess own;
        own.start(helper,{"--children","3","--delay-ms","1000","--hold-ms","2500"});
        QVERIFY2(own.waitForStarted(3000),qPrintable(own.errorString()));
        const auto pid=static_cast<quint64>(own.processId());
        QTRY_VERIFY_WITH_TIMEOUT(([&]{
            const auto snapshot=client.processes();
            return std::any_of(snapshot.begin(),snapshot.end(),[&](const auto &process){return process.pid==pid && process.image==helper;});
        })(),5000);
        QTRY_VERIFY_WITH_TIMEOUT(client.monitorStatus().job.matches>0,7000);
        ResultQuery query;
        query.object=ResultObject::Processes;
        query.filter=ResultFilter::Matches;
        const auto results=client.query(job.id,query);
        QVERIFY(!results.rows.empty());
        QCOMPARE(results.rows.front().outcome,QString("behavioral_match"));
        const auto notice=client.notifications(0,5)["rows"].toArray().at(0).toObject();
        QCOMPARE(notice["view"].toString(),QString("processes"));
        QCOMPARE(notice["path"].toString(),helper);
        QVERIFY(own.waitForFinished(6000));
        QCOMPARE(own.exitCode(),0);
        const auto expired=client.terminateProcess(job.id,resultKey(results.rows.front()));
#if defined(Q_OS_WIN) || defined(Q_OS_LINUX)
        QVERIFY(expired["code"]=="exited" || expired["code"]=="unavailable" || expired["code"]=="unsupported");
#endif
        QVERIFY(!expired["eligible"].toBool());
        QVERIFY(client.cancelMonitor(job.id));
        QTRY_VERIFY_WITH_TIMEOUT(!client.monitorStatus().active,5000);
    }

    void processActionRequiresLiveStoredIdentityAndMinimumAge() {
        Fixture fixture;
        const auto area=fixture.directory.filePath("process-action");
        QVERIFY(QDir().mkdir(area));
        const QFileInfo helperSource(QStringLiteral(RESHETO_HELPER_PATH));
        const auto helper=area+"/"+helperSource.fileName();
        QVERIFY(QFile::copy(helperSource.absoluteFilePath(),helper));
        QFile binary(helper);
        QVERIFY(binary.open(QIODevice::ReadOnly));
        const auto digest=QString::fromLatin1(QCryptographicHash::hash(binary.readAll(),QCryptographicHash::Sha256).toHex());
        binary.close();
        const auto rules=fixture.directory.filePath("own-image.json"),db=fixture.directory.filePath("own-image.db");
        const QJsonArray signatures{QJsonObject{{"id","fixture-image"},{"name","Own helper"},{"kind","HASH"},{"algorithm","SHA-256"},
            {"value",digest},{"enabled",1},{"version","1"}}};
        put(rules,QJsonDocument(QJsonObject{{"version","image-action-test"},{"signatures",signatures}}).toJson());
        createSignatures(rules,db);
        fixture.extraArguments=fixture.arguments();
        fixture.extraArguments[3]=db;
        fixture.start();

        const Client client(fixture.endpoint);
        MonitorOptions options;
        options.files=false;options.processes=true;options.scanProcessImages=true;options.processImageDirectory=area;
        const auto job=client.startMonitor(options).job;
        QTRY_VERIFY_WITH_TIMEOUT(client.monitorStatus().ready,6000);
        QProcess own;
        own.start(helper,{"--children","0","--delay-ms","250","--hold-ms","10000"});
        QVERIFY2(own.waitForStarted(3000),qPrintable(own.errorString()));
        const auto pid=QString::number(own.processId());
        QTRY_VERIFY_WITH_TIMEOUT(client.monitorStatus().job.matches>0,4500);
        ResultQuery query;query.object=ResultObject::Processes;query.filter=ResultFilter::Matches;
        const auto result=client.query(job.id,query).rows.at(0);
        const auto key=resultKey(result);
        QCOMPARE(result.signatureId,QString("fixture-image"));
        auto preview=client.inspectProcess(job.id,key);
        if(preview["code"]=="unsupported")QSKIP(qPrintable(preview["reason"].toString()));
        QCOMPARE(preview["pid"].toString(),pid);
        QCOMPARE(preview["code"].toString(),QString("too_young"));
        QCOMPARE(client.terminateProcess(job.id,key)["code"].toString(),QString("too_young"));
        QCOMPARE(own.state(),QProcess::Running);
        QVERIFY(!refusal([&]{client.terminateProcess(job.id,QString(64,'0'));}).isEmpty());
        QTRY_VERIFY_WITH_TIMEOUT(client.inspectProcess(job.id,key)["eligible"].toBool(),6500);
        QCOMPARE(client.terminateProcess(job.id,key)["code"].toString(),QString("completed"));
        QVERIFY(own.state()==QProcess::NotRunning || own.waitForFinished(3000));
        QVERIFY(QFileInfo::exists(helper));
        const auto after=client.inspectProcess(job.id,key)["code"].toString();
        QVERIFY(after=="exited" || after=="unavailable");
        const auto journal=client.journal(0,50,"terminate_process")["rows"].toArray();
        QSet<QString> recorded;
        for(const auto &entry:journal) {
            const auto row=entry.toObject();
            if(row["job_id"]==job.id && row["object"]==helper && row["reason"].toString().contains(pid))
                recorded.insert(row["outcome"].toString());
        }
        QVERIFY(recorded.contains("refused") && recorded.contains("requested") && recorded.contains("completed"));
        QVERIFY(client.monitorStatus().active);
        QVERIFY(client.cancelMonitor(job.id));
        QTRY_VERIFY_WITH_TIMEOUT(!client.monitorStatus().active,6000);
    }

#ifdef RESHETO_SERVICE_NETWORK
    void networkJobReadsThroughServiceAndJoinsJournalAndNotifications() {
        using namespace resheto::network;
        Fixture fixture;
        const auto pcap=fixture.directory.filePath("own.pcap");
        std::vector<CapturedPacket> packets;
        for(int index=0;index<20;++index)
            packets.push_back(fixtures::tcp(1000000+index*1000,40000,static_cast<quint16>(10000+index),static_cast<quint32>(index+1)));
        put(pcap,fixtures::pcap(packets));
        fixture.start();
        const Client client(fixture.endpoint);
        MonitorOptions scope;
        scope.directory=fixture.directory.path();
        scope.processes=false;
        const auto watch=client.startMonitor(scope);
        QTRY_VERIFY_WITH_TIMEOUT(client.monitorStatus().ready,5000);
        const NetworkClient network(fixture.endpoint);
        AnalysisOptions request;
        request.input=pcap;
        request.durationMs=0;
        const auto started=network.start(request);
        QVERIFY(client.monitorStatus().active);
        QVERIFY(!network.cancel(watch.job.id));
        QTRY_VERIFY_WITH_TIMEOUT(!network.status().busy,7000);
        const auto job=network.getJob(started.id);
        QVERIFY(job);
        QCOMPARE(job->exitCode(),1);
        QCOMPARE(network.jobs(0,10).front().id,started.id);
        NetworkQuery onlyMatches;
        onlyMatches.matchesOnly=true;
        QCOMPARE(network.flows(started.id,onlyMatches).total,qint64(1));
        std::vector<Flow> linked;
        const auto alerts=network.detections(started.id,{},{},0,10,&linked);
        QCOMPARE(alerts.total,qint64(1));
        QCOMPARE(linked.at(0).id,alerts.rows.at(0).flowId);
        QCOMPARE(network.flow(started.id,linked.at(0).id)->json(),linked.at(0).json());
        const auto notice=client.notifications(0,20)["rows"].toArray().at(0).toObject();
        QCOMPARE(notice["view"].toString(),QString("network"));
        QCOMPARE(notice["job_id"].toString(),started.id);
        QCOMPARE(notice["flow_id"].toString(),linked.at(0).id);
        QCOMPARE(notice["basis"].toString(),alerts.rows.at(0).basis);
        QCOMPARE(client.status().unreadNotifications,qint64(1));
        const auto events=client.journal(0,30,started.id)["rows"].toArray();
        QSet<QString> actions;
        for(const auto &entry:events)actions.insert(entry.toObject()["action"].toString());
        QVERIFY(actions.contains("job_started") && actions.contains("detection") && actions.contains("job_finished"));
        QVERIFY(client.acknowledgeNotification(notice["id"].toString())["acknowledged"].toBool());
        QCOMPARE(client.status().unreadNotifications,qint64(0));
        QVERIFY(client.monitorStatus().active);
        QVERIFY(client.cancelMonitor(watch.job.id));
        QTRY_VERIFY_WITH_TIMEOUT(!client.monitorStatus().active,5000);
        fixture.stop();
        fixture.start();
        QCOMPARE(client.status().unreadNotifications,qint64(0));
        QVERIFY(network.getJob(started.id));
    }

    void liveLoopbackAndIndependentStops() {
        if(!qEnvironmentVariableIntValue("RESHETO_SERVICE_LIVE"))QSKIP("Отдельная проверка захвата на loopback");
        using namespace resheto::network;
        Fixture fixture;
        const auto watched=fixture.directory.filePath("watched"),files=fixture.directory.filePath("manual");
        QVERIFY(QDir().mkdir(watched));
        QVERIFY(QDir().mkdir(files));
        for(int index=0;index<800;++index)put(files+"/own-"+QString::number(index)+".bin",QByteArray(1024,'q'));
        QTcpServer listener;
        QVERIFY(listener.listen(QHostAddress::LocalHost));
        fixture.start();
        const Client client(fixture.endpoint);
        const NetworkClient network(fixture.endpoint);
        MonitorOptions scope;
        scope.directory=watched;
        scope.processes=false;
        const auto watch=client.startMonitor(scope);
        QTRY_VERIFY_WITH_TIMEOUT(client.monitorStatus().ready,6000);
        AnalysisOptions options;
        options.source="live";
        options.input="loopback";
        options.durationMs=0;
        options.capture.tcpPorts={listener.serverPort()};
        const auto live=network.start(options);
        QTRY_VERIFY_WITH_TIMEOUT(([&]{
            const auto state=network.status();
            return state.job && (state.job->updated!=state.job->started || !state.busy);
        })(),7000);
        const auto ready=network.status();
        QVERIFY2(ready.busy,qPrintable(ready.job?ready.job->error:ready.error));
        QTcpSocket connection;
        connection.connectToHost(QHostAddress::LocalHost,listener.serverPort());
        QVERIFY(connection.waitForConnected(2000));
        if(!listener.hasPendingConnections())QVERIFY(listener.waitForNewConnection(2000));
        std::unique_ptr<QTcpSocket> accepted(listener.nextPendingConnection());
        QVERIFY(accepted);
        QCOMPARE(connection.write("own loopback",12),qint64(12));
        if(connection.bytesToWrite())QVERIFY(connection.waitForBytesWritten(2000));

        const auto manual=client.startScan(files,false);
        const auto all=client.status();
        QVERIFY(all.busy && all.monitor.active && network.status().busy);
        QVERIFY(client.cancel(manual.id));
        QTRY_VERIFY_WITH_TIMEOUT(!client.status().busy,7000);
        QVERIFY(client.monitorStatus().active && network.status().busy);
        QVERIFY(network.cancel(live.id));
        QTRY_VERIFY_WITH_TIMEOUT(!network.status().busy,7000);
        const auto captured=network.getJob(live.id);
        QVERIFY(captured);
        QVERIFY2(captured->counters.packets>0,qPrintable(captured->error));
        QCOMPARE(captured->state,QString("cancelled"));
        QVERIFY(client.monitorStatus().active);
        QVERIFY(client.cancelMonitor(watch.job.id));
        QTRY_VERIFY_WITH_TIMEOUT(!client.monitorStatus().active,6000);
    }
#endif

    void confirmedQuarantineAndNotificationSurviveRestart() {
        Fixture fixture;
        const auto input=fixture.directory.filePath("own.bin");
        const auto original=QByteArray::fromHex("010200ff5245534845544f000304");
        put(input,original);
        fixture.start();
        const Client client(fixture.endpoint);
        const auto job=client.startScan(input,false);
        QTRY_VERIFY_WITH_TIMEOUT(!client.status().busy,5000);
        const auto result=client.query(job.id,{}).rows.at(0);
        QCOMPARE(result.sha256,QString::fromLatin1(QCryptographicHash::hash(original,QCryptographicHash::Sha256).toHex()));
        const auto notifications=client.notifications(0,25)["rows"].toArray();
        QCOMPARE(notifications.size(),qsizetype(1));
        const auto notice=notifications.at(0).toObject();
        QCOMPARE(notice["path"].toString(),input);
        QCOMPARE(notice["basis"].toString(),result.basis);
        QCOMPARE(client.status().unreadNotifications,qint64(1));
        QVERIFY(QFileInfo::exists(input));

        // Правило сработало, но содержимое того же файла уже другое.
        QFile changed(input);
        QVERIFY(changed.open(QIODevice::WriteOnly|QIODevice::Truncate));
        QCOMPARE(changed.write(QByteArray(original.size(),'n')),qint64(original.size()));
        changed.close();
        const auto changedReason=refusal([&]{client.quarantine(job.id,resultKey(result));});
        QVERIFY2(changedReason.contains(QStringLiteral("Файл изменился")),qPrintable(changedReason));
        QVERIFY(QFileInfo::exists(input));
        QVERIFY(changed.open(QIODevice::WriteOnly|QIODevice::Truncate));
        QCOMPARE(changed.write(original),qint64(original.size()));
        changed.close();

        const auto item=client.quarantine(job.id,resultKey(result));
        QCOMPARE(item["state"].toString(),QString("stored"));
        QCOMPARE(item["sha256"].toString(),result.sha256);
        QCOMPARE(item["basis"].toString(),result.basis);
        const auto id=item["id"].toString();
        QVERIFY(!id.isEmpty());
        QVERIFY(!QFileInfo::exists(input));
        QVERIFY(client.acknowledgeNotification(notice["id"].toString())["acknowledged"].toBool());
        fixture.stop();
        fixture.start();
        QCOMPARE(client.status().unreadNotifications,qint64(0));
        QCOMPARE(client.notifications(0,25)["rows"].toArray().at(0).toObject()["acknowledged"].toBool(),true);
        auto storedRows=client.quarantineItems(0,25)["rows"].toArray();
        QCOMPARE(storedRows.at(0).toObject()["state"].toString(),QString("stored"));

        put(input,"occupant");
        const auto conflict=refusal([&]{client.restoreQuarantine(id);});
        QVERIFY2(conflict.contains(QStringLiteral("путь восстановления занят"),Qt::CaseInsensitive),qPrintable(conflict));
        QFile occupant(input);
        QVERIFY(occupant.open(QIODevice::ReadOnly));
        QCOMPARE(occupant.readAll(),QByteArray("occupant"));
        occupant.close();
        const auto alternate=fixture.directory.filePath("recovered.bin");
        QCOMPARE(client.restoreQuarantine(id,alternate)["state"].toString(),QString("restored"));
        QFile restored(alternate);
        QVERIFY(restored.open(QIODevice::ReadOnly));
        QCOMPARE(restored.readAll(),original);
        restored.close();
        QCOMPARE(client.deleteQuarantine(id)["state"].toString(),QString("deleted"));
        QVERIFY(QFileInfo::exists(alternate));
        QVERIFY(!QFileInfo::exists(fixture.historyPath()+".quarantine/"+id+".bin"));
        const auto journal=client.journal(0,50)["rows"].toArray();
        QSet<QString> actions;
        for(const auto &entry:journal)actions.insert(entry.toObject()["action"].toString()+":"+entry.toObject()["outcome"].toString());
        QVERIFY(actions.contains("job_started:running"));
        QVERIFY(actions.contains("detection:test-exact"));
        QVERIFY(actions.contains("quarantine:failed"));
        QVERIFY(actions.contains("quarantine:completed"));
        QVERIFY(actions.contains("restore:failed"));
        QVERIFY(actions.contains("restore:completed"));
        QVERIFY(actions.contains("delete:completed"));
    }

    void quarantineRestoresFileLargerThan256MiB() {
        Fixture fixture;
        const auto input=fixture.directory.filePath("large-own.bin");
        constexpr int mebibytes=257;
        constexpr qint64 blockSize=1024*1024;
        const auto signature=QByteArray::fromHex("010200ff5245534845544f000304");
        QCryptographicHash original(QCryptographicHash::Sha256);
        {
            QFile file(input);
            QVERIFY(file.open(QIODevice::WriteOnly|QIODevice::NewOnly));
            QByteArray block(blockSize,'z');
            block.replace(0,signature.size(),signature);
            QCOMPARE(file.write(block),blockSize);
            original.addData(block);
            block.fill('z');
            for(int i=1;i<mebibytes;++i) {
                QCOMPARE(file.write(block),blockSize);
                original.addData(block);
            }
            QVERIFY(file.flush());
        }
        const auto digest=original.result().toHex();
        fixture.start();
        const Client client(fixture.endpoint);
        const auto job=client.startScan(input,false);
        QTRY_VERIFY_WITH_TIMEOUT(!client.status().busy,20000);
        const auto result=client.query(job.id,{}).rows.at(0);
        QCOMPARE(result.signatureId,QStringLiteral("test-exact"));
        QCOMPARE(result.size,mebibytes*blockSize);
        QCOMPARE(result.sha256,QString::fromLatin1(digest));

        const auto item=client.quarantine(job.id,resultKey(result));
        QCOMPARE(item["state"].toString(),QStringLiteral("stored"));
        QCOMPARE(item["size"].toString(),QString::number(mebibytes*blockSize));
        QVERIFY(!QFileInfo::exists(input));
        const auto id=item["id"].toString();
        QCOMPARE(client.restoreQuarantine(id)["state"].toString(),QStringLiteral("restored"));
        QFile restored(input);
        QVERIFY(restored.open(QIODevice::ReadOnly));
        QCryptographicHash content(QCryptographicHash::Sha256);
        QVERIFY(content.addData(&restored));
        QCOMPARE(restored.size(),mebibytes*blockSize);
        QCOMPARE(content.result().toHex(),digest);
        restored.close();
        QCOMPARE(client.deleteQuarantine(id)["state"].toString(),QStringLiteral("deleted"));
        QVERIFY(QFileInfo::exists(input));
        qInfo()<<"large quarantine, restored bytes"<<mebibytes*blockSize<<"sha256"<<digest;
    }

    void configPathsOverridesAndDiagnosticStatus() {
        Fixture fixture;
        const auto config=fixture.directory.filePath("service.json");
        put(config,R"({"endpoint":"overridden","db":"absent.db","storage":"history.db"})");
        fixture.extraArguments={"--config",config,"--endpoint",fixture.endpoint};
        fixture.start();
        const Client client(fixture.endpoint);
        const auto state=client.status();
        QCOMPARE(state.signaturePath,fixture.directory.filePath("absent.db"));
        QCOMPARE(state.storagePath,fixture.historyPath());
        QVERIFY(state.diagnostics["history"].toString().isEmpty());
        QVERIFY(!state.diagnostics["signatures"].toString().isEmpty());
        const auto blockedScan=refusal([&]{client.startScan(config,false);});
        QVERIFY2(blockedScan.contains(QStringLiteral("Нет доступного анализатора")),qPrintable(blockedScan));
        QCOMPARE(client.journal(0,20,"diagnostic")["total"].toString(),QString("1"));
        fixture.stop();
        fixture.extraArguments<<"--db"<<fixture.signaturePath();
        fixture.start();
        QCOMPARE(client.status().signaturePath,fixture.signaturePath());
        QVERIFY(client.status().diagnostics["signatures"].toString().isEmpty());
    }

    void interruptedOperationIsVisibleAndVerifiedCopyCanBeRecovered() {
        Fixture fixture;
        const auto input=fixture.directory.filePath("own.bin");
        const auto bytes=QByteArray::fromHex("010200ff5245534845544f000304");
        put(input,bytes);
        fixture.start();
        const Client client(fixture.endpoint);
        const auto job=client.startScan(input,false);
        QTRY_VERIFY_WITH_TIMEOUT(!client.status().busy,5000);
        const auto key=resultKey(client.query(job.id,{}).rows.at(0));
        const auto isolated=client.quarantine(job.id,key);
        const auto id=isolated["id"].toString();
        fixture.stop();
        {
            // Воспроизводим уже зафиксированную фазу после остановки процесса.
            Database history(fixture.historyPath(),false);
            auto row=history.exec("SELECT data FROM service_quarantine WHERE id=?",{id});
            QVERIFY(row.next());
            auto metadata=QJsonDocument::fromJson(row.value(0).toByteArray()).object();
            row.finish();
            metadata["state"]="restoring";
            history.exec("UPDATE service_quarantine SET state='restoring',data=? WHERE id=?",
                         {QString::fromUtf8(QJsonDocument(metadata).toJson(QJsonDocument::Compact)),id});
        }
        fixture.start();
        const auto item=client.quarantineItems(0,20)["rows"].toArray().at(0).toObject();
        QCOMPARE(item["state"].toString(),QString("interrupted"));
        QVERIFY(!item["reason"].toString().isEmpty());
        QCOMPARE(client.journal(0,20,"recovery")["total"].toString(),QString("1"));
        QVERIFY(!QFileInfo::exists(input));
        QCOMPARE(client.restoreQuarantine(id)["state"].toString(),QString("restored"));
        QFile restored(input);
        QVERIFY(restored.open(QIODevice::ReadOnly));
        QCOMPARE(restored.readAll(),bytes);
    }

    void detectionSurvivesClientDisconnectAndHistoryReopens() {
        Fixture fixture;
        const auto input=fixture.directory.filePath("own.bin");
        put(input,QByteArray::fromHex("010200ff5245534845544f000304"));
        fixture.start();
        const auto accepted=Client(fixture.endpoint).startScan(input,false);
        QCOMPARE(accepted.state,QString("running"));

        const Client reconnected(fixture.endpoint);
        QTRY_VERIFY_WITH_TIMEOUT(!reconnected.status().busy,5000);
        const auto status=reconnected.status();
        QCOMPARE(status.storagePath,fixture.historyPath());
        QCOMPARE(status.signaturePath,fixture.signaturePath());
        QVERIFY(status.heuristicPath.isEmpty());
        QVERIFY(status.job);
        QCOMPARE(status.job->id,accepted.id);
        QCOMPARE(status.job->exitCode(),1);
        const auto job=reconnected.getJob(accepted.id);
        QVERIFY(job);
        QCOMPARE(job->json(),status.job->json());
        QCOMPARE(reconnected.jobs().front().id,accepted.id);

        ResultQuery query;
        query.filter=ResultFilter::Matches;
        query.text="test-exact";
        const auto page=reconnected.query(accepted.id,query);
        QCOMPARE(page.total,qint64(1));
        QCOMPARE(page.rows.size(),size_t(1));
        QCOMPARE(page.rows.front().signatureId,QString("test-exact"));
        QCOMPARE(page.rows.front().offset,qint64(2));
        QVERIFY(!reconnected.observation(accepted.id,"missing-event"));
        {
            Store history(fixture.historyPath(),true);
            const auto reopened=history.getJob(accepted.id);
            QVERIFY(reopened);
            QCOMPARE(reopened->json(),job->json());
        }

        const auto missing=reconnected.startScan(fixture.directory.filePath("missing.bin"),false);
        QTRY_VERIFY_WITH_TIMEOUT(!reconnected.status().busy,5000);
        const auto failed=reconnected.getJob(missing.id);
        QVERIFY(failed);
        QCOMPARE(failed->exitCode(),2);
        QVERIFY(failed->errors>0);
    }

    void explicitCancelIsScopedToActiveJob() {
        Fixture fixture;
        QVERIFY(QDir(fixture.directory.path()).mkdir("many"));
        const auto input=fixture.directory.filePath("many");
        for(int index=0;index<600;++index)put(input+"/own-"+QString::number(index)+".bin",QByteArray(8192,'a'));
        fixture.start();
        const Client client(fixture.endpoint);
        const auto job=client.startScan(input,true);
        QVERIFY(!client.cancel("unrelated-job"));
        QVERIFY(client.cancel(job.id));
        QTRY_VERIFY_WITH_TIMEOUT(!client.status().busy,7000);
        const auto cancelled=client.getJob(job.id);
        QVERIFY(cancelled);
        QCOMPARE(cancelled->state,QString("cancelled"));
        QCOMPARE(cancelled->exitCode(),3);
        QVERIFY(cancelled->results<600);
        QVERIFY(!client.cancel(job.id));
    }

    void invalidCommandsAndDuplicateEndpointLeaveOwnerRunning() {
        Fixture fixture;
        fixture.start();
        const Client client(fixture.endpoint);
        const auto request=[&](const QJsonObject &json){return exchange(fixture.endpoint,protocol::frame(json,protocol::requestLimit));};

        const auto escaped=request({{"version",1},{"command","start_scan"},{"path",fixture.directory.path()},
                                    {"recursive",true},{"storage_path",fixture.directory.filePath("unexpected.db")}});
        QCOMPARE(escaped["ok"].toBool(),false);
        QCOMPARE(escaped["code"].toString(),QString("invalid_request"));
        QVERIFY(!QFile::exists(fixture.directory.filePath("unexpected.db")));
        QCOMPARE(request({{"version",999},{"command","status"}})["code"].toString(),QString("invalid_request"));
        QCOMPARE(request({{"version",1},{"command","start_scan"},{"path","relative"},{"recursive",true}})["code"].toString(),QString("invalid_request"));
        QCOMPARE(request({{"version",1},{"command","start_scan"},{"path",fixture.directory.path()},{"recursive","yes"}})["code"].toString(),QString("invalid_request"));
        QByteArray oversized(protocol::headerSize,0);
        qToBigEndian<quint32>(static_cast<quint32>(protocol::requestLimit+1),oversized.data());
        QCOMPARE(exchange(fixture.endpoint,oversized)["code"].toString(),QString("invalid_frame"));

        QProcess duplicate;
        duplicate.setProcessEnvironment(fixture.process.processEnvironment());
        duplicate.start(executable,fixture.arguments());
        QVERIFY(duplicate.waitForStarted(3000));
        QVERIFY(duplicate.waitForFinished(3000));
        QCOMPARE(duplicate.exitCode(),2);
        QVERIFY(!duplicate.readAllStandardError().isEmpty());
        QCOMPARE(client.status().storagePath,fixture.historyPath());
        QVERIFY(client.jobs().empty());
    }
};

QTEST_GUILESS_MAIN(ServiceTests)
#include "service_tests.moc"
