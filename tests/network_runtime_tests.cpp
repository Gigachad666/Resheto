#include "network/runner.h"
#include "network/session.h"
#include "network/protocol.h"
#include "network/private_session.h"
#include "network/fixtures.h"
#include "core/scanner.h"
#include "core/signatures.h"
#include <QCryptographicHash>
#include <QFile>
#include <QDir>
#include <QJsonDocument>
#include <QLocalServer>
#include <QProcess>
#include <QTemporaryDir>
#include <QtTest>
#include <barrier>
#include <chrono>
#include <thread>
#include <QtEndian>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#include <aclapi.h>
#else
#include <sys/stat.h>
#endif
using namespace resheto;
using namespace resheto::network;
namespace fx=resheto::network::fixtures;
namespace {
template<class F>bool fails(F &&action){try{action();}catch(const Error &){return true;}return false;}
template<class F>QString failureReason(F &&action){try{action();}catch(const Error &error){return error.message;}return {};}
void put(const QString &path,const QByteArray &bytes){QFile file(path);if(!file.open(QIODevice::WriteOnly) || file.write(bytes)!=bytes.size())throw Error("fixture write");}
QString rulesPath(){return QStringLiteral(RESHETO_SOURCE_DIR)+"/data/network_rules.json";}
QByteArray bytes(const QString &path){QFile file(path);if(!file.open(QIODevice::ReadOnly))throw Error("fixture read");return file.readAll();}
std::vector<CapturedPacket> packets(int ordinary=2101) {
    std::vector<CapturedPacket> result;
    for(int i=0;i<ordinary;++i)result.push_back(fx::udp(1000000+i*100,"harmless",static_cast<quint16>(30000+i),9000));
    for(int i=0;i<20;++i)result.push_back(fx::tcp(2000000+i*1000,40000,static_cast<quint16>(10000+i),static_cast<quint32>(i+1)));
    for(int i=0;i<20;++i)result.push_back(fx::dns(3000000+i*1000,QString("missing%1.example.invalid").arg(i)));
    for(int i=0;i<6;++i)result.push_back(fx::tcp(4000000+i*1000000,static_cast<quint16>(45000+i),443,static_cast<quint32>(100+i)));
    return result;
}
NetworkRequest request(const QTemporaryDir &temp,const std::vector<CapturedPacket> &input=packets(2)) {
    NetworkRequest request;request.analysis.source="pcap";request.analysis.durationMs=0;request.analysis.input=temp.filePath("own.pcap");request.storagePath=temp.filePath("history.db");request.rulesPath=rulesPath();
    request.workerPath=QStringLiteral(RESHETO_NETWORK_WORKER);put(request.analysis.input,fx::pcap(input));return request;
}
QString ruleId(const QString &kind){const auto rules=loadNetworkRules(rulesPath());for(const auto &rule:rules->entries)if(rule.kind==kind)return rule.id;return {};}
bool connected(QLocalServer &server,int timeout=3000){return server.hasPendingConnections() || server.waitForNewConnection(timeout);}
bool finished(QProcess &process,int timeout=3000){return process.state()==QProcess::NotRunning || process.waitForFinished(timeout);}
}
class NetworkRuntimeTests:public QObject {
    Q_OBJECT
private slots:
    void directPcapAndGlobalQuery() {
        QTemporaryDir temp;QVERIFY(temp.isValid());auto input=packets();auto r=request(temp,input);const auto job=scanNetworkPcap(r);
        QCOMPARE(job.state,QString("completed"));QCOMPARE(job.exitCode(),1);QCOMPARE(job.counters.packets,static_cast<qint64>(input.size()));QCOMPARE(job.storedDetections,qint64(3));QVERIFY(job.storedFlows>2101);
        NetworkStore history(r.storagePath,true);const auto reread=history.getJob(job.id);QVERIFY(reread);QCOMPARE(reread->json(),job.json());
        NetworkQuery query;query.limit=10;query.matchesOnly=true;const auto page=history.flows(job.id,query);QCOMPARE(page.total,qint64(3));QCOMPARE(page.rows.size(),size_t(3));
        query.text=ruleId("tcp_periodic");QVERIFY(!query.text.isEmpty());QCOMPARE(query.text,QString("periodic-tcp-attempts"));query.sort=NetworkSort::Endpoint;QCOMPARE(history.flows(job.id,query).total,qint64(1));
        query.text="%_\\'";QCOMPARE(history.flows(job.id,query).total,qint64(0));
        const auto dnsRule=ruleId("dns_nxdomain");QVERIFY(!dnsRule.isEmpty());QCOMPARE(dnsRule,QString("dns-nxdomain-burst"));QCOMPARE(history.detections(job.id,{},dnsRule).total,qint64(1));QCOMPARE(history.jobs().size(),size_t(1));
        Store old(r.storagePath,true);QVERIFY(old.jobs().empty());
    }
    void coreFirstAndConcurrentFirstWriters() {
        QTemporaryDir temp;QVERIFY(temp.isValid());const auto path=temp.filePath("old.db");{Store store(path);}
        const auto before=bytes(path);{NetworkStore network(path,true);QVERIFY(network.jobs().empty());QVERIFY(!network.getJob("absent"));}QCOMPARE(bytes(path),before);
        const auto shared=temp.filePath("concurrent.db");std::barrier start(2);std::mutex mutex;QStringList errors;
        std::thread first([&]{start.arrive_and_wait();try{NetworkStore network(shared);}catch(const Error &error){std::lock_guard lock(mutex);errors<<error.message;}});
        std::thread second([&]{start.arrive_and_wait();try{Store core(shared);}catch(const Error &error){std::lock_guard lock(mutex);errors<<error.message;}});first.join();second.join();QVERIFY2(errors.empty(),qPrintable(errors.join("; ")));
        {Store core(shared);Job job;job.id="after-network";job.path="own";job.databaseVersion="test";job.started=now();core.start(job);QVERIFY(core.getJob(job.id,false));}
        NetworkStore network(shared,true);QVERIFY(network.jobs().empty());
    }
    void fileAndNetworkWritersCommitTogether() {
        QTemporaryDir temp;QVERIFY(temp.isValid());auto r=request(temp);{NetworkStore initialized(r.storagePath);}
        const auto folder=temp.filePath("files");QVERIFY(QDir().mkpath(folder));
        for(int i=0;i<160;++i)put(folder+QString("/%1.txt").arg(i),"harmless file");
        const auto signatures=temp.filePath("signatures.db"),source=temp.filePath("signatures.json");
        put(source,R"({"version":"concurrent-test","signatures":[{"id":"own","name":"own bytes","kind":"PATTERN","value":"aa00bb","version":"1","enabled":1}]})");createSignatures(source,signatures);
        Request core;core.path=folder;core.storagePath=r.storagePath;core.signaturePath=signatures;
        std::barrier together(2);std::optional<NetworkJob> netJob;QString failure;
        std::thread writer([&]{
            together.arrive_and_wait();
            try {
                auto options=r.analysis;options.rules=loadNetworkRules(rulesPath());
                NetworkStore store(r.storagePath);auto job=newNetworkJob(options);store.start(job,options.rules->document);
                NetworkAnalyzer analyzer(options.rules);
                for(int i=0;i<160;++i){const auto update=analyzer.observe(fx::udp(1000000+i*1000));NetworkBatch batch;batch.counters=update.counters;batch.flows.push_back(*update.flow);store.append(job.id,batch);}
                netJob=store.finish(job.id,"completed");
            }catch(const Error &error){failure=error.message;}
        });
        together.arrive_and_wait();const auto fileJob=runJob(core);writer.join();
        QVERIFY2(failure.isEmpty(),qPrintable(failure));QVERIFY(netJob);QCOMPARE(netJob->counters.parsed,qint64(160));QCOMPARE(fileJob.exitCode(),0);QCOMPARE(fileJob.checked,qint64(160));
        Store files(r.storagePath,true);QVERIFY(files.getJob(fileJob.id));NetworkStore network(r.storagePath,true);QCOMPARE(network.getJob(netJob->id)->json(),netJob->json());
    }
    void corruptionAndSnapshotsAreRejected() {
        QTemporaryDir temp;QVERIFY(temp.isValid());auto r=request(temp);const auto job=scanNetworkPcap(r);
        for(const auto &sql:QStringList{
            "UPDATE network_flows SET endpoint='invented' WHERE rowid=(SELECT min(rowid) FROM network_flows)",
            "UPDATE network_detections SET data=json_set(data,'$.evidence.source_address','192.0.2.99')",
            "UPDATE network_jobs SET rules=json_set(rules,'$.version','wrong')",
            "UPDATE network_jobs SET data=json_set(data,'$.counters.parsed','1')",
            "UPDATE network_flows SET data=json_set(data,'$.key','wrong')"}) {
            const auto copy=temp.filePath(QString("bad%1.db").arg(qHash(sql)));QVERIFY(QFile::copy(r.storagePath,copy));{Database db(copy,false);db.exec(sql);}
            QVERIFY(fails([&]{NetworkStore store(copy,true);store.getJob(job.id);}));
        }
        const auto truncated=temp.filePath("truncated.db");put(truncated,"not sqlite");QVERIFY(fails([&]{NetworkStore store(truncated,true);}));
        const auto partial=temp.filePath("partial.db");{Store core(partial);Database db(partial,false);db.exec("CREATE TABLE network_flows(fake INTEGER)");}QVERIFY(fails([&]{NetworkStore store(partial,true);}));
    }
    void cancelErrorPriorityAndInputIdentity() {
        QTemporaryDir temp;QVERIFY(temp.isValid());auto r=request(temp);std::atomic_bool cancel=true;auto job=scanNetworkPcap(r,&cancel);QCOMPARE(job.state,QString("cancelled"));QCOMPARE(job.exitCode(),3);
        const auto original=bytes(r.analysis.input);r.storagePath=r.analysis.input;QVERIFY(fails([&]{scanNetworkPcap(r);}));QCOMPARE(bytes(r.analysis.input),original);
        r=request(temp,{fx::tcp(1000000)});auto malformed=fx::tcp(2000000);malformed.bytes=QByteArray::fromHex("4500");malformed.originalLength=2;put(r.analysis.input,fx::pcap({malformed}));
        cancel=false;job=scanNetworkPcap(r,&cancel,[&](const NetworkJob &progress){if(progress.counters.packets)cancel=true;});QCOMPARE(job.state,QString("failed"));QCOMPARE(job.exitCode(),2);QVERIFY(!job.error.isEmpty());QCOMPARE(job.counters.truncated,qint64(1));
        auto hard=r;hard.storagePath=temp.filePath("linked.pcap");std::error_code error;std::filesystem::create_hard_link(nativePath(r.analysis.input),nativePath(hard.storagePath),error);if(!error)QVERIFY(fails([&]{scanNetworkPcap(hard);}));
    }
    void batchesRollbackAndCompleteAccounting() {
        QTemporaryDir temp;QVERIFY(temp.isValid());NetworkStore store(temp.filePath("history.db"));AnalysisOptions options;options.source="pcap";options.input="own.pcap";options.rules=loadNetworkRules(rulesPath());auto job=newNetworkJob(options);store.start(job,options.rules->document);
        NetworkAnalyzer analyzer(options.rules);const auto update=analyzer.observe(fx::tcp(1000000));NetworkBatch batch;batch.counters=update.counters;batch.flows.push_back(*update.flow);store.append(job.id,batch);
        auto bad=batch;bad.flows[0].packetsAToB+=10;QVERIFY(fails([&]{store.append(job.id,bad);}));QCOMPARE(store.getJob(job.id,false)->storedFlows,qint64(1));
        auto counters=batch.counters;counters.packets=counters.parsed=2;NetworkBatch incomplete;incomplete.counters=counters;store.append(job.id,incomplete);QVERIFY(fails([&]{store.finish(job.id,"completed");}));
        const auto failed=store.finish(job.id,"failed","own interruption");QCOMPARE(failed.exitCode(),2);QVERIFY(store.getJob(job.id));
    }
    void protocolBoundsAndPrivateSession() {
        CaptureOptions scope;scope.interfaceId="loopback";QCOMPARE(captureFilter(scope),QString("ip or ip6"));scope.tcpPorts={443,80};scope.udpPort=9000;QCOMPARE(captureFilter(scope),QString("(ip or ip6) and (udp port 9000 or tcp port 80 or tcp port 443)"));scope.tcpPorts={443,443};QVERIFY(fails([&]{captureFilter(scope);}));scope.tcpPorts={0};QVERIFY(fails([&]{captureFilter(scope);}));scope.tcpPorts.assign(65,443);QVERIFY(fails([&]{captureFilter(scope);}));
        ipc::PrivateSession privateSession;const auto ticket=ipc::readSessionTicket(privateSession.path());QCOMPARE(ticket.token,privateSession.ticket().token);QVERIFY(ticket.token.size()==64);QVERIFY(!privateSession.path().contains(ticket.token));
#ifdef Q_OS_WIN
        PSECURITY_DESCRIPTOR descriptor=nullptr;PACL dacl=nullptr;const auto native=QDir::toNativeSeparators(privateSession.path());
        const auto status=GetNamedSecurityInfoW(const_cast<LPWSTR>(reinterpret_cast<LPCWSTR>(native.utf16())),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&dacl,nullptr,&descriptor);QCOMPARE(status,DWORD(ERROR_SUCCESS));QVERIFY(dacl);QCOMPARE(dacl->AceCount,WORD(1));
        SECURITY_DESCRIPTOR_CONTROL control{};DWORD revision=0;QVERIFY(GetSecurityDescriptorControl(descriptor,&control,&revision));QVERIFY(control&SE_DACL_PROTECTED);LocalFree(descriptor);
#else
        struct stat info{};QCOMPARE(::stat(QFile::encodeName(privateSession.path()).constData(),&info),0);QCOMPARE(info.st_mode&0777,mode_t(0600));
#endif
        AnalysisOptions options;options.source="pcap";options.input="own";options.rules=loadNetworkRules(rulesPath());const auto encoded=ipc::optionsJson(options);QCOMPARE(ipc::parseOptions(encoded).rules->document,options.rules->document);
        auto unknown=encoded;unknown["storage_path"]="forbidden";QVERIFY(fails([&]{ipc::parseOptions(unknown);}));
        auto batch=ipc::batchJson(NetworkBatch{});batch["flows"]=QJsonArray{QJsonObject{}};QVERIFY(fails([&]{ipc::parseBatch(batch);}));
        QVERIFY(fails([&]{ipc::parseIds(QJsonArray{"bad"});}));
        QLocalSocket disconnected;ipc::Channel channel(disconnected);QVERIFY(fails([&]{channel.send(QJsonObject{{"large",QString(ipc::maximumMessage,'x')}});}));
    }
    void liveDurationRoundTripAndLegacyHistory() {
        QTemporaryDir temp;QVERIFY(temp.isValid());
        auto r=request(temp);r.analysis.source="live";r.analysis.input="loopback";r.analysis.capture.tcpPorts={8765};
        const auto prepared=prepareNetworkRequest(r);
        const auto options=ipc::optionsJson(prepared.analysis);QCOMPARE(ipc::parseOptions(options).durationMs,0);
        auto invalidOptions=options;invalidOptions["duration_ms"]=99;QVERIFY(fails([&]{ipc::parseOptions(invalidOptions);}));
        auto invalidRequest=r;invalidRequest.analysis.durationMs=99;QVERIFY(fails([&]{prepareNetworkRequest(invalidRequest);}));
        auto timed=options;timed["duration_ms"]=100;QCOMPARE(ipc::parseOptions(timed).durationMs,100);

        auto job=newNetworkJob(prepared.analysis);
        {NetworkStore store(r.storagePath);store.start(job,prepared.analysis.rules->document);job=store.finish(job.id,"cancelled");}
        {NetworkStore store(r.storagePath,true);const auto saved=store.getJob(job.id);QVERIFY(saved && saved->durationMs);QCOMPARE(*saved->durationMs,0);QCOMPARE(saved->json(),job.json());}
        QVERIFY(networkScopeText(job).contains(QStringLiteral("до остановки")));
        auto malformed=job.json();malformed["duration_ms"]="0";QVERIFY(fails([&]{NetworkJob::fromJson(malformed);}));
        malformed=job.json();malformed["duration_ms"]=maximumDurationMs+1;QVERIFY(fails([&]{NetworkJob::fromJson(malformed);}));
        malformed=job.json();malformed["state"]="completed";QVERIFY(fails([&]{NetworkJob::fromJson(malformed);}));

        {Database fixture(r.storagePath,false);fixture.exec("UPDATE network_jobs SET data=json_remove(data,'$.duration_ms') WHERE id=?",{job.id});}
        NetworkStore history(r.storagePath,true);const auto legacy=history.getJob(job.id);QVERIFY(legacy && !legacy->durationMs);
        QVERIFY(!legacy->json().contains("duration_ms"));QCOMPARE(legacy->state,QString("cancelled"));
    }
    void unsupportedPacketsStillPublishProgress() {
        QTemporaryDir temp;QVERIFY(temp.isValid());
        std::vector<CapturedPacket> input;
        const auto icmp=fx::ip(QByteArray::fromHex("0800f7ff00000000"),1,"192.0.2.1","192.0.2.2");
        for(int i=0;i<8;++i)input.push_back(fx::raw(icmp,1000000+i*10000));
        const auto prepared=prepareNetworkRequest(request(temp,input));
        bool countersBeforeEof=false;
        const auto result=analyzeNetwork(prepared.analysis,[&](const NetworkBatch &batch){
            if(batch.diagnostics.empty() && batch.flows.empty() && batch.detections.empty() && batch.counters.unsupported>0 && batch.counters.packets<8)
                countersBeforeEof=true;
        },[]{std::this_thread::sleep_for(std::chrono::milliseconds(50));return false;});
        QCOMPARE(result.counters.unsupported,qint64(8));QCOMPARE(result.counters.parsed,qint64(0));QVERIFY(countersBeforeEof);
    }
    void boundedRuleAndTicketReads() {
        QTemporaryDir temp;QVERIFY(temp.isValid());const auto path=temp.filePath("rules.json");auto rules=bytes(rulesPath());rules.append(QByteArray(1048576-rules.size(),' '));put(path,rules);QCOMPARE(loadNetworkRules(path)->version,QString("2026.11.05-1"));
        rules.append(' ');put(path,rules);QVERIFY(failureReason([&]{loadNetworkRules(path);}).contains("1048576"));
        ipc::PrivateSession session;const auto ticketPath=temp.filePath("ticket.json");auto ticket=bytes(session.path());ticket.append(QByteArray(4096-ticket.size(),' '));put(ticketPath,ticket);QVERIFY(QFile::setPermissions(ticketPath,QFileDevice::ReadOwner|QFileDevice::WriteOwner));QCOMPARE(ipc::readSessionTicket(ticketPath).token,session.ticket().token);
        ticket.append(' ');put(ticketPath,ticket);QVERIFY(failureReason([&]{ipc::readSessionTicket(ticketPath);}).contains("4096"));
    }
    void framedMessagesAndWorkerRejectsWrongProtocol() {
        QTemporaryDir temp;QVERIFY(temp.isValid());auto r=prepareNetworkRequest(request(temp));
        ipc::PrivateSession privateSession;QLocalServer server;server.setSocketOptions(QLocalServer::UserAccessOption);QVERIFY(server.listen(privateSession.ticket().endpoint));
        QLocalSocket client;client.connectToServer(privateSession.ticket().endpoint);QVERIFY(client.waitForConnected(1000));QVERIFY(connected(server,1000));std::unique_ptr<QLocalSocket> peer(server.nextPendingConnection());QVERIFY(peer);
        ipc::Channel sender(client),receiver(*peer);sender.send({{"type","own test"}});const auto message=receiver.receive(1000);QVERIFY(message);QCOMPARE((*message)["type"].toString(),QString("own test"));
        QByteArray oversized(4,0);qToBigEndian<quint32>(static_cast<quint32>(ipc::maximumMessage+1),oversized.data());QCOMPARE(client.write(oversized),qint64(4));if(client.bytesToWrite())QVERIFY(client.waitForBytesWritten(1000));QVERIFY(fails([&]{receiver.receive(1000);}));client.abort();peer.reset();
        QProcess process;process.start(QStringLiteral(RESHETO_NETWORK_WORKER),{"--session",privateSession.path()});QVERIFY(process.waitForStarted(2000));QVERIFY(connected(server));peer.reset(server.nextPendingConnection());QVERIFY(peer);ipc::Channel worker(*peer);
        const auto hello=worker.receive(3000);QVERIFY(hello);QCOMPARE((*hello)["token"].toString(),privateSession.ticket().token);QVERIFY(!process.arguments().contains(privateSession.ticket().token));
        worker.send({{"type","start"},{"version",999},{"options",ipc::optionsJson(r.analysis)}});QVERIFY(finished(process));QCOMPARE(process.exitCode(),2);QVERIFY(process.readAllStandardError().contains("network_worker"));peer.reset();
        process.start(QStringLiteral(RESHETO_NETWORK_WORKER),{"--session",privateSession.path()});QVERIFY(process.waitForStarted(2000));QVERIFY(connected(server));peer.reset(server.nextPendingConnection());QVERIFY(peer);ipc::Channel dropped(*peer);QVERIFY(dropped.receive(3000));
        dropped.send({{"type","start"},{"version",ipc::protocolVersion},{"options",ipc::optionsJson(r.analysis)}});const auto batch=dropped.receive(3000);QVERIFY(batch);QCOMPARE((*batch)["type"].toString(),QString("batch"));peer->abort();QVERIFY(finished(process,5000));QCOMPARE(process.exitCode(),2);
        QVERIFY(!QFileInfo::exists(r.storagePath));
    }
    void separateWorkerPcapCancelAndReuse() {
        QTemporaryDir temp;QVERIFY(temp.isValid());auto r=request(temp);NetworkSession session;QVERIFY(session.submit(r));QTRY_VERIFY_WITH_TIMEOUT(!session.busy(),15000);const auto done=session.progress();QVERIFY(done);QCOMPARE(done->state,QString("completed"));QCOMPARE(done->storedDetections,qint64(3));
        NetworkStore history(r.storagePath,true);QVERIFY(history.getJob(done->id));QCOMPARE(history.jobs().size(),size_t(1));
        std::vector<CapturedPacket> large;large.reserve(100000);for(int i=0;i<100000;++i)large.push_back(fx::udp(1000000+i,"own",40000,9000));put(r.analysis.input,fx::pcap(large));
        QVERIFY(session.submit(r));session.cancel();QTRY_VERIFY_WITH_TIMEOUT(!session.busy(),15000);QVERIFY(session.progress());QCOMPARE(session.progress()->state,QString("cancelled"));QCOMPARE(history.jobs().size(),size_t(2));QVERIFY(history.getJob(done->id));
        // Неверный исполняемый процесс завершается, а контроллер сохраняет конкретную причину.
        r.workerPath=QStringLiteral(RESHETO_NETWORK_TEST_SELF);QVERIFY(session.submit(r));QTRY_VERIFY_WITH_TIMEOUT(!session.busy(),15000);QCOMPARE(session.progress()->state,QString("failed"));QVERIFY(!session.progress()->error.isEmpty());
    }
};
QTEST_GUILESS_MAIN(NetworkRuntimeTests)
#include "network_runtime_tests.moc"
