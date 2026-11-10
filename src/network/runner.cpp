#include "runner.h"
#include <QElapsedTimer>
#include <QCryptographicHash>
#include <QFileInfo>
#include <QMap>
#include <QJsonDocument>
#include <QSet>
#include <QUuid>
#include <filesystem>

namespace resheto::network {
namespace {
bool samePath(const QString &a,const QString &b) {
    if(a.isEmpty() || b.isEmpty())return false;
#ifdef Q_OS_WIN
    if(absolute(a).compare(absolute(b),Qt::CaseInsensitive)==0)return true;
#else
    if(absolute(a)==absolute(b))return true;
#endif
    std::error_code error;return std::filesystem::equivalent(nativePath(a),nativePath(b),error) && !error;
}
void validate(const AnalysisOptions &options) {
    if(options.source!="pcap" && options.source!="live")throw Error(QStringLiteral("Источник сети должен быть live или pcap"));
    if(options.input.trimmed().isEmpty() || options.input.size()>4096 || !options.rules)throw Error(QStringLiteral("Не задан источник или набор сетевых правил"));
    parseNetworkRules(options.rules->document);
    const bool live=options.source=="live";
    if(!validDuration(live,options.durationMs))throw Error(live?QStringLiteral("Длительность захвата: 0 или 100..3600000 мс"):QStringLiteral("Неверное ограничение времени PCAP"));
    if(live)captureFilter(options.capture);
    if(options.source=="pcap" && (options.capture.udpPort || !options.capture.tcpPorts.empty()))throw Error(QStringLiteral("Ограничение портов доступно при живом захвате; PCAP анализируется целиком"));
}
}
NetworkRequest prepareNetworkRequest(NetworkRequest request) {
    if(request.storagePath.trimmed().isEmpty())throw Error(QStringLiteral("Укажите файл сетевой истории"));
    request.storagePath=absolute(request.storagePath);
    if(!request.rulesPath.isEmpty()) {
        request.rulesPath=absolute(request.rulesPath);
        if(samePath(request.storagePath,request.rulesPath))throw Error(QStringLiteral("История и сетевые правила должны быть разными файлами"));
        request.analysis.rules=loadNetworkRules(request.rulesPath);
    }
    if(request.analysis.source=="pcap") {
        request.analysis.input=absolute(request.analysis.input);
        if(samePath(request.storagePath,request.analysis.input) || samePath(request.rulesPath,request.analysis.input))throw Error(QStringLiteral("PCAP, правила и история должны быть разными файлами"));
        PcapReader checked(request.analysis.input);
    } else request.analysis.capture.interfaceId=request.analysis.input;
    validate(request.analysis);
    return request;
}
NetworkJob newNetworkJob(const AnalysisOptions &options) {
    NetworkJob job;job.id=QUuid::createUuid().toString(QUuid::WithoutBraces);job.source=options.source;job.input=options.input;job.started=now();job.updated=job.started;
    job.scope=options.capture;job.scope.interfaceId=job.input;job.durationMs=options.durationMs;
    if(options.rules){job.rulesVersion=options.rules->version;job.rulesChecksum=QString::fromLatin1(QCryptographicHash::hash(QJsonDocument(options.rules->document).toJson(QJsonDocument::Compact),QCryptographicHash::Sha256).toHex());}return job;
}
AnalysisResult analyzeNetwork(const AnalysisOptions &options,const BatchSink &sink,const std::function<bool()> &shouldCancel) {
    validate(options);if(!sink)throw Error(QStringLiteral("Не задан получатель сетевых результатов"));
    NetworkAnalyzer analyzer(options.rules);AnalysisResult result;QMap<QString,Flow> flows;QMap<QString,Detection> detections;std::vector<Diagnostic> diagnostics;QSet<QString> knownDiagnostics;
    QElapsedTimer elapsed,flushTime;elapsed.start();flushTime.start();std::unique_ptr<Capture> live;
    auto cancelled=[&]{return shouldCancel && shouldCancel();};
    auto flush=[&] {
        // Сначала все изменения потоков, затем небольшие пакеты доказательств.
        // Отдельное большое DNS-доказательство не раздувает сообщение до десятков МБ.
        bool sent=false;
        while(!flows.isEmpty()) {
            NetworkBatch batch;batch.counters=analyzer.counters();std::vector<QString> ids;
            for(auto it=flows.begin();it!=flows.end() && ids.size()<100;++it){batch.flows.push_back(it.value());ids.push_back(it.key());}
            sink(batch);for(const auto &id:ids)flows.remove(id);sent=true;
        }
        while(!detections.isEmpty()) {
            NetworkBatch batch;batch.counters=analyzer.counters();
            for(auto it=detections.begin();it!=detections.end() && batch.detections.size()<4;++it)batch.detections.push_back(it.value());
            sink(batch);for(const auto &d:batch.detections){analyzer.acknowledge(d.id);detections.remove(d.id);}sent=true;
        }
        if(!diagnostics.empty() || !sent){NetworkBatch batch;batch.counters=analyzer.counters();batch.diagnostics=diagnostics;sink(batch);diagnostics.clear();}
        flushTime.restart();
    };
    auto observe=[&](const CapturedPacket &packet) {
        const auto update=analyzer.observe(packet);if(update.flow)flows[update.flow->id]=*update.flow;
        for(const auto &d:update.detections)detections[d.id]=d;
        for(const auto &d:update.diagnostics)if(!knownDiagnostics.contains(d.code)){knownDiagnostics.insert(d.code);diagnostics.push_back(d);}
        // Активные потоки передаются инкрементально; retiring уже учтены последним observe.
        if(flows.size()>=100 || detections.size()>=16 || flushTime.elapsed()>=100)flush();
    };
    try {
        if(options.source=="pcap") {
            PcapReader reader(options.input);
            while(!cancelled()) {if(options.durationMs && elapsed.elapsed()>=options.durationMs)throw Error(QStringLiteral("Достигнут предел времени чтения PCAP"));const auto packet=reader.next();if(!packet)break;observe(*packet);}
        } else {
            result.backendVersion=captureBackendVersion();live=std::make_unique<Capture>(options.capture);
            while(!cancelled() && (!options.durationMs || elapsed.elapsed()<options.durationMs)) {
                const auto packet=live->poll(100);
                if(packet)observe(*packet);
                else if(flushTime.elapsed()>=((flows.isEmpty() && detections.isEmpty() && diagnostics.empty())?1000:100))flush();
            }
        }
        if(cancelled())result.state="cancelled";
    } catch(const Error &error){result.state="failed";result.error=error.message;}
    // Активные потоки уже были обновлены при последнем пакете; finish освобождает состояние.
    analyzer.finish();
    try {flush();}catch(const Error &error){result.state="failed";result.error=error.message;}
    if(live) {live->cancel();try{result.capture=live->statistics();}catch(const Error &error){result.state="failed";result.error=error.message;}}
    result.counters=analyzer.counters();return result;
}
NetworkJob scanNetworkPcap(NetworkRequest request,const std::atomic_bool *cancel,const std::function<void(const NetworkJob &)> &progress) {
    request=prepareNetworkRequest(std::move(request));if(request.analysis.source!="pcap")throw Error(QStringLiteral("Прямой API предназначен для PCAP; живой захват запускается отдельным процессом"));
    const auto path=Store::preparePath(request.storagePath);NetworkStore store(path);auto job=newNetworkJob(request.analysis);store.start(job,request.analysis.rules->document);if(progress)progress(job);
    const auto result=analyzeNetwork(request.analysis,[&](const NetworkBatch &batch){job=store.append(job.id,batch);if(progress)progress(job);},[&]{return cancel && cancel->load();});
    return store.finish(job.id,result.state,result.error,result.capture);
}
}
