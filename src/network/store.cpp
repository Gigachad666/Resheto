#include "store.h"
#include <QCryptographicHash>
#include <QDateTime>
#include <QHostAddress>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSqlError>
#include <algorithm>
#include <limits>

namespace resheto::network {
namespace {
void check(bool value,const QString &reason){if(!value)throw Error(QStringLiteral("Некорректная сетевая история: ")+reason);}
QString encode(const QJsonObject &object){return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Compact));}
QJsonObject decode(const QVariant &value,int maximum=1048576) {
    const auto bytes=value.toByteArray();check(bytes.size()<=maximum,"JSON size");QJsonParseError error;
    const auto document=QJsonDocument::fromJson(bytes,&error);check(error.error==QJsonParseError::NoError && document.isObject(),"JSON object");return document.object();
}
QString text(const QJsonObject &object,const char *key,int maximum=512,bool empty=false) {
    check(object[key].isString(),QString::fromLatin1(key));const auto value=object[key].toString();check(value.size()<=maximum && (empty || !value.trimmed().isEmpty()),QString::fromLatin1(key));return value;
}
qint64 integer(const QJsonObject &object,const char *key) {
    const auto value=text(object,key,32);static const QRegularExpression decimal("^(0|[1-9][0-9]*)$");bool good=false;const auto result=value.toLongLong(&good);
    check(good && decimal.match(value).hasMatch(),QString::fromLatin1(key));return result;
}
QString hash(const QByteArray &bytes){return QString::fromLatin1(QCryptographicHash::hash(bytes,QCryptographicHash::Sha256).toHex());}
QString rulesHash(const QJsonObject &document){return hash(QJsonDocument(document).toJson(QJsonDocument::Compact));}
QString storedText(const QString &value){return value.isNull()?QStringLiteral(""):value;}
void readComplete(const QSqlQuery &query){if(query.lastError().isValid())throw Error(QStringLiteral("Ошибка чтения сетевой истории: ")+query.lastError().text());}
void add(qint64 &sum,qint64 value){check(value>=0 && value<=std::numeric_limits<qint64>::max()-sum,"counter overflow");sum+=value;}
bool columnInteger(const QVariant &value,qint64 expected){return value.toString()==QString::number(expected);}
QString preparedCore(const QString &path,bool readOnly) {
    check(path!=":memory:","для общей истории нужен файл SQLite");Store core(path,readOnly);return path;
}
void validateDetection(const Detection &d,const NetworkRules &rules,const Flow &flow) {
    Detection::fromJson(d.json());check(d.setVersion==rules.version && d.flowId==flow.id,"detection association");
    const NetworkRule *matched=nullptr;for(const auto &rule:rules.entries)if(rule.id==d.ruleId){matched=&rule;break;}
    check(matched!=nullptr,"unknown rule");const auto &rule=*matched;const auto &e=d.evidence;
    check(d.ruleVersion==rule.version && d.description==rule.description && d.severity==rule.severity,"rule snapshot");
    check(e["kind"]==rule.kind && e["threshold"].toInt()==rule.threshold && e["window_ms"].toInt()==rule.windowMs,"rule condition");
    check(e["count"].toInt()<=rules.maxEventsPerKey && d.timestampUs>=flow.firstUs && d.timestampUs<=flow.lastUs,"detection time/count");
    const auto source=e["source_address"].toString(),destination=e["destination_address"].toString();
    const bool direct=source==flow.addressA && destination==flow.addressB,reverse=source==flow.addressB && destination==flow.addressA;
    check(direct || reverse,"evidence endpoints");QString group=source;
    QString basis;
    if(rule.kind!="dns_nxdomain") {
        check(flow.protocol==6,"TCP evidence protocol");group+="|"+destination;
        const auto last=e["items"].toArray().last().toObject()["value"].toString();
        const auto destinationPort=rule.kind=="tcp_periodic"?static_cast<quint16>(e["destination_port"].toInt()):static_cast<quint16>(last.toUInt());
        check((direct && destinationPort==flow.portB)||(reverse && destinationPort==flow.portA),"TCP evidence port");
        if(rule.kind=="tcp_periodic") {
            check(e["min_interval_ms"].toInt()==rule.minIntervalMs && e["max_interval_ms"].toInt()==rule.maxIntervalMs && e["jitter_percent"].toInt()==rule.jitterPercent,"periodic snapshot");
            const auto sourcePort=static_cast<quint16>(last.section('/',0,0).toUInt());check((direct && sourcePort==flow.portA)||(reverse && sourcePort==flow.portB),"TCP source port");group+="|"+QString::number(destinationPort);
            basis=QStringLiteral("%1 TCP-попыток %2 → %3:%4 с регулярными интервалами; окно %5 мс, допуск %6%").arg(e["count"].toInt()).arg(source,destination).arg(destinationPort).arg(rule.windowMs).arg(rule.jitterPercent);
        } else basis=QStringLiteral("%1 различных TCP-портов: %2 → %3; окно %4 мс, порог %5").arg(e["count"].toInt()).arg(source,destination).arg(rule.windowMs).arg(rule.threshold);
    } else {check(flow.protocol==17 && ((direct && flow.portB==53)||(reverse && flow.portA==53)),"DNS evidence protocol/port");basis=QStringLiteral("Клиент %1 получил NXDOMAIN для %2 различных DNS-имён; окно %3 мс, порог %4").arg(source).arg(e["count"].toInt()).arg(rule.windowMs).arg(rule.threshold);}
    check(d.basis==basis,"detection basis");
    check(d.id==hash((rule.id+"|"+group+"|"+QString::number(d.timestampUs)+"|"+d.flowId).toUtf8()),"detection key");
}
bool incomplete(const Counters &c){return c.unsupported || c.fragments || c.truncated || c.malformed || c.flowEvictions || c.ruleEvictions || c.reordered;}
void validateDiagnostic(const Diagnostic &value){check(QRegularExpression("^[a-z][a-z0-9_]{0,63}$").match(value.code).hasMatch() && !value.reason.isEmpty() && value.reason.size()<=2048,"diagnostic");}
void validateScope(const NetworkJob &job,const Flow &flow) {
    if(job.source!="live" || (!job.scope.udpPort && job.scope.tcpPorts.empty()))return;
    const bool tcp=flow.protocol==6 && (std::find(job.scope.tcpPorts.begin(),job.scope.tcpPorts.end(),flow.portA)!=job.scope.tcpPorts.end() || std::find(job.scope.tcpPorts.begin(),job.scope.tcpPorts.end(),flow.portB)!=job.scope.tcpPorts.end());
    const bool udp=flow.protocol==17 && job.scope.udpPort && (flow.portA==job.scope.udpPort || flow.portB==job.scope.udpPort);check(tcp || udp,"flow outside selected ports");
}
std::mutex schemaMutex;
}

QJsonObject NetworkJob::json() const {
    QJsonArray ports;for(const auto port:scope.tcpPorts)ports.append(port);
    QJsonObject object{{"format","resheto-network-job-v1"},{"id",id},{"source",source},{"input",input},{"started",started},{"updated",updated},{"finished",storedText(finished)},{"state",state},{"error",storedText(error)},
        {"rules_version",rulesVersion},{"rules_checksum",rulesChecksum},{"backend",storedText(backendVersion)},{"scope",QJsonObject{{"udp_port",scope.udpPort},{"tcp_ports",ports}}},{"counters",counters.json()},
        {"stored_flows",QString::number(storedFlows)},{"stored_detections",QString::number(storedDetections)},
        {"drops_available",dropsAvailable},{"reported_dropped",QString::number(reportedDropped)},{"reported_interface_dropped",QString::number(reportedInterfaceDropped)}};
    if(durationMs)object["duration_ms"]=*durationMs;
    return object;
}
NetworkJob NetworkJob::fromJson(const QJsonObject &object) {
    check(object["format"]=="resheto-network-job-v1","format");NetworkJob job;job.id=text(object,"id",64);
    check(QRegularExpression("^[A-Za-z0-9_-]+$").match(job.id).hasMatch(),"job id");job.source=text(object,"source",16);check(job.source=="live" || job.source=="pcap","source");
    job.input=text(object,"input",4096);job.state=text(object,"state",16);check(QStringList{"running","completed","cancelled","failed"}.contains(job.state),"state");
    if(object.contains("duration_ms")) {
        const auto duration=object["duration_ms"];
        const int value=duration.toInt(-1);
        check(duration.isDouble() && duration.toDouble()==value && validDuration(job.source=="live",value),"duration");
        check(job.source!="live" || value!=0 || job.state!="completed","continuous capture outcome");
        job.durationMs=value;
    }
    check(object["scope"].isObject(),"scope");const auto scope=object["scope"].toObject();const auto udp=scope["udp_port"].toDouble(-1);check(scope["udp_port"].isDouble() && udp>=0 && udp<=65535 && udp==static_cast<int>(udp),"UDP scope");job.scope.udpPort=static_cast<quint16>(udp);job.scope.interfaceId=job.input;
    check(scope["tcp_ports"].isArray() && scope["tcp_ports"].toArray().size()<=64,"TCP scope");for(const auto &port:scope["tcp_ports"].toArray()){const auto n=port.toDouble(-1);check(port.isDouble() && n>=1 && n<=65535 && n==static_cast<int>(n),"TCP scope port");job.scope.tcpPorts.push_back(static_cast<quint16>(n));}captureFilter(job.scope);check(job.source=="live" || (!job.scope.udpPort && job.scope.tcpPorts.empty()),"PCAP scope");
    job.started=text(object,"started",40);job.updated=text(object,"updated",40);job.finished=text(object,"finished",40,true);job.error=text(object,"error",4096,true);
    auto time=[](const QString &value){const auto parsed=QDateTime::fromString(value,Qt::ISODateWithMs);check(parsed.isValid() && parsed.offsetFromUtc()==0 && parsed.toUTC().toString(Qt::ISODateWithMs)==value,"UTC time");return parsed;};
    check(time(job.updated)>=time(job.started),"job time order");if(job.state=="running")check(job.finished.isEmpty() && job.error.isEmpty(),"running state");
    else {check(time(job.finished)>=time(job.started) && time(job.finished)>=time(job.updated),"finished time");check((job.state=="failed")==!job.error.isEmpty(),"failure reason");}
    job.rulesVersion=text(object,"rules_version",64);job.rulesChecksum=text(object,"rules_checksum",64);check(QRegularExpression("^[0-9a-f]{64}$").match(job.rulesChecksum).hasMatch(),"rules checksum");job.backendVersion=text(object,"backend",512,true);
    check(object["counters"].isObject(),"counters");job.counters=Counters::fromJson(object["counters"].toObject());job.storedFlows=integer(object,"stored_flows");job.storedDetections=integer(object,"stored_detections");
    check(job.storedFlows<=job.counters.flowsCreated && job.storedDetections<=job.counters.detections,"stored counters");
    check(object["drops_available"].isBool(),"drop availability");job.dropsAvailable=object["drops_available"].toBool();job.reportedDropped=integer(object,"reported_dropped");job.reportedInterfaceDropped=integer(object,"reported_interface_dropped");
    check(job.dropsAvailable || (!job.reportedDropped && !job.reportedInterfaceDropped),"unknown drop counters");return job;
}
int NetworkJob::exitCode() const {if(state=="failed" || !error.isEmpty())return 2;if(state=="cancelled")return 3;if(state!="completed")return 2;return storedDetections?1:0;}
QString networkStateText(const NetworkJob &job){if(job.state=="running")return QStringLiteral("Наблюдение");if(job.state=="cancelled")return QStringLiteral("Остановлено");if(job.state=="failed")return QStringLiteral("Ошибка / неполная проверка");return job.storedDetections?QStringLiteral("Есть срабатывания правил"):QStringLiteral("Срабатываний правил нет");}
QString networkScopeText(const NetworkJob &job) {
    QString scope=job.input;
    if(job.source=="pcap")scope+=QStringLiteral(" (PCAP)");
    else {
        QStringList ports;if(job.scope.udpPort)ports<<QStringLiteral("UDP %1").arg(job.scope.udpPort);
        for(const auto port:job.scope.tcpPorts)ports<<QStringLiteral("TCP %1").arg(port);
        scope+=" — "+(ports.empty()?QStringLiteral("весь IPv4/IPv6"):ports.join(", "));
    }
    if(job.durationMs && *job.durationMs>0)scope+=QStringLiteral(" · лимит %1 мс").arg(*job.durationMs);
    else if(job.durationMs && job.source=="live")scope+=QStringLiteral(" · до остановки");
    return scope;
}
QString networkIncompleteReason(){return QStringLiteral("Неполная проверка: есть пропуски, повреждённые пакеты или потери состояния; подробности в счётчиках и диагностике");}

NetworkStore::NetworkStore(const QString &path,bool readOnly):NetworkStore(path,readOnly,std::unique_lock<std::mutex>(schemaMutex)){}
NetworkStore::NetworkStore(const QString &path,bool readOnly,std::unique_lock<std::mutex> lock):db_(preparedCore(path,readOnly),readOnly) {
    Q_UNUSED(lock);db_.exec("PRAGMA foreign_keys=ON");auto exists=db_.exec("SELECT name FROM sqlite_master WHERE type='table' AND name='network_meta'");present_=exists.next();
    if(!present_ && readOnly){auto other=db_.exec("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'network_%'");check(!other.next(),"network_meta absent");return;}
    if(!present_) {
        db_.transaction();try {
            db_.exec("CREATE TABLE network_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL)");db_.exec("INSERT INTO network_meta VALUES(1,1)");
            db_.exec("CREATE TABLE network_jobs(id TEXT PRIMARY KEY,started TEXT NOT NULL,data TEXT NOT NULL,rules TEXT NOT NULL)");
            db_.exec("CREATE TABLE network_flows(job_id TEXT NOT NULL,id TEXT NOT NULL,flow_key TEXT NOT NULL,endpoint TEXT NOT NULL,first_us INTEGER NOT NULL,last_us INTEGER NOT NULL,packets INTEGER NOT NULL,data TEXT NOT NULL,PRIMARY KEY(job_id,id),FOREIGN KEY(job_id) REFERENCES network_jobs(id))");
            db_.exec("CREATE TABLE network_detections(job_id TEXT NOT NULL,id TEXT NOT NULL,flow_id TEXT NOT NULL,time_us INTEGER NOT NULL,rule_id TEXT NOT NULL,basis TEXT NOT NULL,search TEXT NOT NULL,data TEXT NOT NULL,PRIMARY KEY(job_id,id),FOREIGN KEY(job_id,flow_id) REFERENCES network_flows(job_id,id))");
            db_.exec("CREATE TABLE network_diagnostics(job_id TEXT NOT NULL,code TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(job_id,code),FOREIGN KEY(job_id) REFERENCES network_jobs(id))");
            db_.exec("CREATE INDEX network_flow_order ON network_flows(job_id,first_us,id)");db_.exec("CREATE INDEX network_detection_flow ON network_detections(job_id,flow_id,time_us,id)");db_.commit();present_=true;
        }catch(...){db_.rollback();throw;}
    }
    auto version=db_.exec("SELECT id,version FROM network_meta");check(version.next() && version.value(0).toInt()==1 && version.value(1).toInt()==1 && !version.next(),"schema version");
    db_.exec("SELECT id,started,data,rules FROM network_jobs LIMIT 0");db_.exec("SELECT job_id,id,flow_key,endpoint,first_us,last_us,packets,data FROM network_flows LIMIT 0");db_.exec("SELECT job_id,id,flow_id,time_us,rule_id,basis,search,data FROM network_detections LIMIT 0");db_.exec("SELECT job_id,code,reason FROM network_diagnostics LIMIT 0");
}
NetworkJob NetworkStore::basicJob(const QString &id) {
    check(present_,"network history absent");auto row=db_.exec("SELECT id,started,data FROM network_jobs WHERE id=?",{id});check(row.next(),"job absent");const auto job=NetworkJob::fromJson(decode(row.value(2),65536));check(job.id==id && row.value(0).toString()==id && row.value(1).toString()==job.started,"job columns");return job;
}
std::shared_ptr<const NetworkRules> NetworkStore::rulesForJob(const QString &id,const NetworkJob &job) {
    auto row=db_.exec("SELECT rules FROM network_jobs WHERE id=?",{id});check(row.next(),"job absent");const auto document=decode(row.value(0));const auto rules=parseNetworkRules(document);
    check(rules->version==job.rulesVersion && rulesHash(document)==job.rulesChecksum,"rules snapshot");return rules;
}
void NetworkStore::start(NetworkJob &job,const QJsonObject &document) {
    const auto rules=parseNetworkRules(document);job.rulesVersion=rules->version;job.rulesChecksum=rulesHash(document);job.updated=job.started;
    NetworkJob::fromJson(job.json());check(job.state=="running" && job.counters.json()==Counters{}.json() && !job.storedFlows && !job.storedDetections,"new job");
    // Захватить право записи до первого SELECT. Иначе одновременная запись Core
    // может сделать повышение read-lock до write-lock невозможным сразу.
    db_.exec("BEGIN IMMEDIATE");try {
        auto count=db_.exec("SELECT count(*) FROM network_jobs");check(count.next() && count.value(0).toLongLong()<10000,"предел сетевой истории: 10000 заданий");
        db_.exec("INSERT INTO network_jobs(id,started,data,rules) VALUES(?,?,?,?)",{job.id,job.started,encode(job.json()),encode(document)});db_.commit();
    }catch(...){db_.rollback();throw;}
}
NetworkJob NetworkStore::append(const QString &id,const NetworkBatch &batch) {
    check(batch.flows.size()<=200 && batch.detections.size()<=200 && batch.diagnostics.size()<=64,"batch size");Counters::fromJson(batch.counters.json());
    db_.exec("BEGIN IMMEDIATE");try {
        auto job=basicJob(id);check(job.state=="running","job already finished");const auto rules=rulesForJob(id,job);const auto before=job.counters.json(),after=batch.counters.json();
        for(auto it=before.begin();it!=before.end();++it)check(integer(after,it.key().toLatin1().constData())>=integer(before,it.key().toLatin1().constData()),"decreasing counters");
        for(const auto &value:batch.flows) {
            const auto flow=Flow::fromJson(value.json());validateScope(job,flow);auto old=db_.exec("SELECT data FROM network_flows WHERE job_id=? AND id=?",{id,flow.id});
            if(old.next()){const auto previous=Flow::fromJson(decode(old.value(0),8192));check(previous.key==flow.key && flow.firstUs<=previous.firstUs && flow.lastUs>=previous.lastUs && flow.packetsAToB>=previous.packetsAToB && flow.packetsBToA>=previous.packetsBToA && flow.bytesAToB>=previous.bytesAToB && flow.bytesBToA>=previous.bytesBToA && (flow.tcpFlagsAToB|previous.tcpFlagsAToB)==flow.tcpFlagsAToB && (flow.tcpFlagsBToA|previous.tcpFlagsBToA)==flow.tcpFlagsBToA,"flow regression");}
            qint64 packets=flow.packetsAToB;add(packets,flow.packetsBToA);
            db_.exec("INSERT INTO network_flows(job_id,id,flow_key,endpoint,first_us,last_us,packets,data) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(job_id,id) DO UPDATE SET first_us=excluded.first_us,last_us=excluded.last_us,packets=excluded.packets,data=excluded.data",{id,flow.id,flow.key,flowText(flow),flow.firstUs,flow.lastUs,packets,encode(flow.json())});
        }
        for(const auto &d:batch.detections) {
            auto flow=db_.exec("SELECT data FROM network_flows WHERE job_id=? AND id=?",{id,d.flowId});check(flow.next(),"detection without flow");validateDetection(d,*rules,Flow::fromJson(decode(flow.value(0),8192)));
            auto old=db_.exec("SELECT data FROM network_detections WHERE job_id=? AND id=?",{id,d.id});if(old.next()){check(decode(old.value(0))==d.json(),"changed duplicate detection");continue;}
            db_.exec("INSERT INTO network_detections(job_id,id,flow_id,time_us,rule_id,basis,search,data) VALUES(?,?,?,?,?,?,?,?)",{id,d.id,d.flowId,d.timestampUs,d.ruleId,d.basis,encode(d.evidence),encode(d.json())});
        }
        for(const auto &d:batch.diagnostics){validateDiagnostic(d);db_.exec("INSERT OR IGNORE INTO network_diagnostics(job_id,code,reason) VALUES(?,?,?)",{id,d.code,d.reason});}
        auto counts=db_.exec("SELECT (SELECT count(*) FROM network_flows WHERE job_id=?),(SELECT count(*) FROM network_detections WHERE job_id=?)",{id,id});check(counts.next(),"counts");job.storedFlows=counts.value(0).toLongLong();job.storedDetections=counts.value(1).toLongLong();job.counters=batch.counters;job.updated=now();NetworkJob::fromJson(job.json());
        check(job.storedFlows<=100000 && job.storedDetections<=100000,"предел задания: 100000 потоков / обнаружений");
        auto diagnostics=db_.exec("SELECT count(*) FROM network_diagnostics WHERE job_id=?",{id});check(diagnostics.next() && diagnostics.value(0).toLongLong()<=64,"diagnostic limit");
        db_.exec("UPDATE network_jobs SET data=? WHERE id=?",{encode(job.json()),id});db_.commit();return job;
    }catch(...){db_.rollback();throw;}
}
void NetworkStore::verifyRows(const NetworkJob &job,bool complete) {
    const auto rules=rulesForJob(job.id,job);qint64 flows=0,packets=0,detections=0;
    auto rows=db_.exec("SELECT id,flow_key,endpoint,first_us,last_us,packets,data FROM network_flows WHERE job_id=?",{job.id},true);
    while(rows.next()){
        const auto flow=Flow::fromJson(decode(rows.value(6),8192));validateScope(job,flow);qint64 count=flow.packetsAToB;add(count,flow.packetsBToA);
        check(rows.value(0).toString()==flow.id && rows.value(1).toString()==flow.key && rows.value(2).toString()==flowText(flow) && columnInteger(rows.value(3),flow.firstUs) && columnInteger(rows.value(4),flow.lastUs) && columnInteger(rows.value(5),count),"flow columns");++flows;add(packets,count);
    }
    readComplete(rows);
    auto alerts=db_.exec("SELECT d.id,d.flow_id,d.time_us,d.rule_id,d.basis,d.search,d.data,f.data FROM network_detections d LEFT JOIN network_flows f ON f.job_id=d.job_id AND f.id=d.flow_id WHERE d.job_id=?",{job.id},true);
    while(alerts.next()){
        const auto d=Detection::fromJson(decode(alerts.value(6)));const auto flow=Flow::fromJson(decode(alerts.value(7),8192));validateDetection(d,*rules,flow);
        check(alerts.value(0).toString()==d.id && alerts.value(1).toString()==d.flowId && columnInteger(alerts.value(2),d.timestampUs) && alerts.value(3).toString()==d.ruleId && alerts.value(4).toString()==d.basis && alerts.value(5).toString()==encode(d.evidence),"detection columns");++detections;
    }
    readComplete(alerts);
    check(flows==job.storedFlows && detections==job.storedDetections && packets<=job.counters.parsed,"stored counters");
    if(complete)check(flows==job.counters.flowsCreated && detections==job.counters.detections && packets==job.counters.parsed,"complete counters");
}
NetworkJob NetworkStore::finish(const QString &id,const QString &state,const QString &reason,const CaptureStatistics &capture,const QString &backendVersion) {
    check(QStringList{"completed","cancelled","failed"}.contains(state),"finished state");db_.exec("BEGIN IMMEDIATE");try {
        auto job=basicJob(id);check(job.state=="running","job already finished");verifyRows(job,state=="completed");job.state=state;job.error=reason;job.dropsAvailable=capture.dropsAvailable;job.backendVersion=backendVersion;
        check(capture.dropped<=static_cast<quint64>(std::numeric_limits<qint64>::max()) && capture.interfaceDropped<=static_cast<quint64>(std::numeric_limits<qint64>::max()),"drop overflow");job.reportedDropped=static_cast<qint64>(capture.dropped);job.reportedInterfaceDropped=static_cast<qint64>(capture.interfaceDropped);
        if(!reason.isEmpty())job.state="failed";
        const auto notes=diagnostics(id);const bool partial=std::any_of(notes.begin(),notes.end(),[](const auto &d){return d.code=="first_fragment" || d.code=="tcp_zero_port";});
        if(job.state!="failed" && (partial || incomplete(job.counters) || job.reportedDropped || job.reportedInterfaceDropped)){job.state="failed";job.error=networkIncompleteReason();}
        if(job.state=="failed" && job.error.isEmpty())job.error=QStringLiteral("Сетевой анализ не завершён");job.finished=now();job.updated=job.finished;NetworkJob::fromJson(job.json());db_.exec("UPDATE network_jobs SET data=? WHERE id=?",{encode(job.json()),id});db_.commit();return job;
    }catch(...){db_.rollback();throw;}
}
std::optional<NetworkJob> NetworkStore::getJob(const QString &id,bool recoverRunning) {
    if(!present_)return {};db_.transaction();try {
        auto exists=db_.exec("SELECT id FROM network_jobs WHERE id=?",{id});if(!exists.next()){db_.commit();return {};}
        auto job=basicJob(id);verifyRows(job,job.state=="completed");diagnostics(id);db_.commit();
        if(job.state=="running" && recoverRunning){job.state="failed";job.error=QStringLiteral("Сохранено незавершённое сетевое задание; непрерывность наблюдения не подтверждена");job.finished=job.updated;}
        return job;
    }catch(...){db_.rollback();throw;}
}
std::vector<NetworkJob> NetworkStore::jobs(qint64 offset,int limit) {
    check(offset>=0 && limit>=1 && limit<=200,"job page");std::vector<NetworkJob> result;if(!present_)return result;
    auto rows=db_.exec("SELECT id,started,data FROM network_jobs ORDER BY started DESC,id DESC LIMIT ? OFFSET ?",{limit,offset},true);
    while(rows.next()){const auto job=NetworkJob::fromJson(decode(rows.value(2),65536));check(rows.value(0).toString()==job.id && rows.value(1).toString()==job.started,"job columns");result.push_back(job);}readComplete(rows);return result;
}
NetworkFlowPage NetworkStore::flows(const QString &id,const NetworkQuery &query) {
    check(query.offset>=0 && query.limit>=1 && query.limit<=200 && query.text.size()<=4096,"flow page");NetworkFlowPage page;if(!present_)return page;
    QString where="f.job_id=?";QVariantList args{id};
    if(query.matchesOnly)where+=" AND EXISTS(SELECT 1 FROM network_detections d WHERE d.job_id=f.job_id AND d.flow_id=f.id)";
    if(!query.text.isEmpty()){where+=" AND (instr(lower(f.endpoint),lower(?))>0 OR EXISTS(SELECT 1 FROM network_detections d WHERE d.job_id=f.job_id AND d.flow_id=f.id AND (instr(lower(d.rule_id),lower(?))>0 OR instr(lower(d.basis),lower(?))>0 OR instr(lower(d.search),lower(?))>0)))";args<<query.text<<query.text<<query.text<<query.text;}
    auto count=db_.exec("SELECT count(*) FROM network_flows f WHERE "+where,args);check(count.next(),"flow count");page.total=count.value(0).toLongLong();
    QString order;switch(query.sort){case NetworkSort::FirstTime:order="f.first_us";break;case NetworkSort::LastTime:order="f.last_us";break;case NetworkSort::Endpoint:order="f.endpoint";break;case NetworkSort::Packets:order="f.packets";break;default:throw Error(QStringLiteral("Неизвестная сортировка потоков"));}
    args<<query.limit<<query.offset;auto rows=db_.exec("SELECT f.data,(SELECT count(*) FROM network_detections d WHERE d.job_id=f.job_id AND d.flow_id=f.id),(SELECT group_concat(DISTINCT d.rule_id) FROM network_detections d WHERE d.job_id=f.job_id AND d.flow_id=f.id) FROM network_flows f WHERE "+where+" ORDER BY "+order+(query.descending?" DESC":" ASC")+",f.id ASC LIMIT ? OFFSET ?",args,true);
    while(rows.next())page.rows.push_back({Flow::fromJson(decode(rows.value(0),8192)),rows.value(1).toLongLong(),rows.value(2).toString()});readComplete(rows);return page;
}
NetworkDetectionPage NetworkStore::detections(const QString &id,const QString &flowId,const QString &text,qint64 offset,int limit) {
    check(offset>=0 && limit>=1 && limit<=200 && text.size()<=4096,"detection page");NetworkDetectionPage page;if(!present_)return page;
    const QString from=" FROM network_detections d LEFT JOIN network_flows f ON f.job_id=d.job_id AND f.id=d.flow_id WHERE ";
    QString where="d.job_id=?";QVariantList args{id};
    if(!flowId.isEmpty()){where+=" AND d.flow_id=?";args<<flowId;}
    if(!text.isEmpty()) {
        where+=" AND (instr(lower(d.rule_id),lower(?))>0 OR instr(lower(d.basis),lower(?))>0 OR instr(lower(d.search),lower(?))>0 OR instr(lower(f.endpoint),lower(?))>0)";
        args<<text<<text<<text<<text;
    }
    auto count=db_.exec("SELECT count(*)"+from+where,args);check(count.next(),"detection count");page.total=count.value(0).toLongLong();args<<limit<<offset;
    auto rows=db_.exec("SELECT d.data,f.id"+from+where+" ORDER BY d.time_us,d.id LIMIT ? OFFSET ?",args,true);
    while(rows.next()) {
        auto detection=Detection::fromJson(decode(rows.value(0)));check(rows.value(1).toString()==detection.flowId,"detection without flow");page.rows.push_back(std::move(detection));
    }
    readComplete(rows);return page;
}
std::optional<Flow> NetworkStore::flow(const QString &id,const QString &flowId) {
    if(!present_)return {};
    auto row=db_.exec("SELECT data FROM network_flows WHERE job_id=? AND id=?",{id,flowId});
    if(!row.next()){readComplete(row);return {};}
    const auto result=Flow::fromJson(decode(row.value(0),8192));check(result.id==flowId,"flow id");return result;
}
std::vector<Diagnostic> NetworkStore::diagnostics(const QString &id) {
    std::vector<Diagnostic> result;if(!present_)return result;auto rows=db_.exec("SELECT code,reason FROM network_diagnostics WHERE job_id=? ORDER BY code LIMIT 65",{id},true);
    while(rows.next()){check(result.size()<64,"diagnostic limit");Diagnostic value{rows.value(0).toString(),rows.value(1).toString()};validateDiagnostic(value);result.push_back(std::move(value));}readComplete(rows);return result;
}
}
