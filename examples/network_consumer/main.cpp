#include "network/api.h"
#include "network/fixtures.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QTextStream>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif

using namespace resheto;
using namespace resheto::network;
namespace fx=resheto::network::fixtures;
namespace {
void check(bool condition,const QString &message){if(!condition)throw Error(message);}
void writeNew(const QString &path,const QByteArray &bytes) {
    QFile file(path);check(file.open(QIODevice::WriteOnly|QIODevice::NewOnly) && file.write(bytes)==bytes.size(),"fixture write");
}
void report(const QJsonObject &value){QTextStream(stdout)<<QJsonDocument(value).toJson(QJsonDocument::Compact)<<Qt::endl;}
qint64 peakBytes() {
#ifdef Q_OS_WIN
    PROCESS_MEMORY_COUNTERS usage{};
    check(GetProcessMemoryInfo(GetCurrentProcess(),&usage,sizeof(usage))!=0,"peak working set");
    return static_cast<qint64>(usage.PeakWorkingSetSize);
#else
    struct rusage usage{};check(getrusage(RUSAGE_SELF,&usage)==0,"peak RSS");
    return static_cast<qint64>(usage.ru_maxrss)*1024;
#endif
}
void smoke() {
    QTemporaryDir own;check(own.isValid(),"temporary directory");
    NetworkRequest request;request.storagePath=own.filePath("history.db");request.rulesPath=QStringLiteral(RESHETO_ROOT)+"/data/network_rules.json";
    request.analysis.durationMs=0;request.analysis.input=own.filePath("control.pcap");
    std::vector<CapturedPacket> attempts;
    for(int i=0;i<20;++i)attempts.push_back(fx::tcp(1000000+i*10000,40000,static_cast<quint16>(10000+i),i+1));
    check(parsePacket(attempts.front()).packet.destinationPort==10000,"packet parser");
    writeNew(request.analysis.input,fx::pcap(attempts));
    const auto detected=scanNetworkPcap(request);
    check(detected.exitCode()==1 && detected.storedDetections==1 && detected.counters.parsed==20,"PCAP detection");

    request.analysis.input=own.filePath("truncated-packet.pcap");
    writeNew(request.analysis.input,fx::pcap({fx::raw(QByteArray::fromHex("4500"),1000000)}));
    const auto damaged=scanNetworkPcap(request);
    check(damaged.exitCode()==2 && damaged.counters.truncated==1 && !damaged.error.isEmpty(),"PCAP incomplete outcome");

    request.analysis.input=own.filePath("cancel.pcap");std::vector<CapturedPacket> ordinary;
    for(int i=0;i<450;++i)ordinary.push_back(fx::udp(1000000+i*5,"own",static_cast<quint16>(30000+i),9000));
    writeNew(request.analysis.input,fx::pcap(ordinary));
    std::atomic_bool stop=false;
    const auto cancelled=scanNetworkPcap(request,&stop,[&](const NetworkJob &progress){if(progress.counters.parsed)stop=true;});
    check(cancelled.exitCode()==3 && cancelled.counters.parsed>0 && cancelled.counters.parsed<450,"cancel after a committed batch");

    NetworkStore history(request.storagePath,true);check(history.jobs().size()==3,"history count");
    for(const auto *job:{&detected,&damaged,&cancelled}) {
        const auto reopened=history.getJob(job->id);check(reopened && reopened->json()==job->json(),"strict history reopen");
    }
    const auto detections=history.detections(detected.id);
    check(detections.rows.size()==1 && detections.rows.front().ruleId=="tcp-port-sweep","saved rule");
    const auto flow=history.flow(detected.id,detections.rows.front().flowId);
    check(flow && (flow->portA==10019 || flow->portB==10019),"saved detection link");
    report({{"format","resheto-network-consumer-v1"},{"packet_parser",true},{"detected",detected.exitCode()},
        {"error",damaged.exitCode()},{"cancelled",cancelled.exitCode()},{"reopened",true},{"rule",detections.rows.front().ruleId}});
}
void profile(const QString &pcap,const QString &rules,const QString &db) {
    check(!QFileInfo::exists(db),"profile needs a new SQLite file");
    NetworkRequest request;request.analysis.input=pcap;request.analysis.durationMs=30000;request.rulesPath=rules;request.storagePath=db;
    QElapsedTimer timer;timer.start();const auto job=scanNetworkPcap(request);
    const auto elapsed=timer.elapsed(),peak=peakBytes();
    check(job.state=="completed" && job.counters.packets==100000 && job.storedDetections==3,"expected the prepared 100000 packet profile");
    timer.restart();NetworkStore history(db,true);const auto reopened=history.getJob(job.id);
    check(reopened && reopened->json()==job.json(),"profile history reopen");
    report({{"format","resheto-network-profile-v1"},{"process","direct-api"},{"elapsed_ms",QString::number(elapsed)},
        {"peak_bytes",QString::number(peak)},{"reopen_ms",QString::number(timer.elapsed())},{"job",job.json()}});
}
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    try {
        const auto args=app.arguments();
        if(args.size()==1)smoke();
        else if(args.size()==5 && args[1]=="--profile")profile(args[2],args[3],args[4]);
        else throw Error("resheto-network-consumer [--profile <pcap> <rules> <new-db>]");
        return 0;
    }catch(const Error &error){QTextStream(stderr)<<error.message<<Qt::endl;return 2;}
}
