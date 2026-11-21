#include "network_service.h"
#include "protocol.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSet>

namespace resheto::service {
using namespace network;
namespace {
QString workerPath() {
    QString path=QCoreApplication::applicationDirPath()+"/resheto-network-worker";
#ifdef Q_OS_WIN
    path+=".exe";
#endif
    return path;
}

void require(bool valid,const QString &reason=QStringLiteral("Некорректные параметры сетевой команды")) {
    if(!valid)throw Error(reason);
}

void fields(const QJsonObject &request,std::initializer_list<const char *> keys) {
    require(request.size()==2+static_cast<qsizetype>(keys.size()));
    for(const auto key:keys)require(request.contains(key));
}

QString text(const QJsonValue &value,int max,bool allowEmpty=false) {
    const auto string=value.toString();
    require(value.isString() && (allowEmpty || !string.trimmed().isEmpty()) && string.size()<=max && !string.contains(QChar(u'\0')));
    return string;
}

int integer(const QJsonValue &value,int minimum,int maximum) {
    const auto number=value.toInt(-1);
    require(value.isDouble() && value.toDouble()==number && number>=minimum && number<=maximum);
    return number;
}

bool flag(const QJsonValue &value) {
    require(value.isBool());
    return value.toBool();
}

template<class T>
QJsonValue optionalJson(const std::optional<T> &value) {
    return value?QJsonValue(value->json()):QJsonValue(QJsonValue::Null);
}
}

NetworkService::NetworkService(const QString &storage,const QString &rulesPath):
    storage_(storage),rules_(absolute(rulesPath.isEmpty()?QStringLiteral("data/network_rules.json"):rulesPath)),worker_(workerPath()) {
    NetworkStore history(storage_);
    try {
        loadNetworkRules(rules_);
        require(QFileInfo(worker_).isFile(),QStringLiteral("Не найден сетевой процесс рядом со службой"));
    } catch(const Error &error) {error_=error.message;}
}

QJsonObject NetworkService::dispatch(const QString &command,const QJsonObject &request) {
    if(command=="network_status") {
        fields(request,{});
        const auto current=session_.progress();
        return {{"busy",session_.busy()},{"rules",rules_},{"error",error_},{"job",optionalJson(current)}};
    }
    if(command=="network_interfaces") {
        fields(request,{});
        QJsonArray rows;
        for(const auto &item:captureInterfaces())rows.append(QJsonObject{{"id",item.id},{"name",item.name}});
        return {{"rows",rows}};
    }
    if(command=="network_start") {
        fields(request,{"source","input","duration_ms","tcp_ports"});
        NetworkRequest job;
        job.analysis.source=text(request["source"],8);
        job.analysis.input=text(request["input"],4096);
        job.analysis.durationMs=integer(request["duration_ms"],0,3600000);
        require(job.analysis.source=="live" || (job.analysis.source=="pcap" && QDir::isAbsolutePath(job.analysis.input) &&
                QFileInfo(job.analysis.input).isNativePath()));
        const auto ports=request["tcp_ports"].toArray();
        require(request["tcp_ports"].isArray() && ports.size()<=64);
        QSet<int> seen;
        for(const auto &value:ports) {
            const int port=integer(value,1,65535);
            require(!seen.contains(port));
            seen.insert(port);
            job.analysis.capture.tcpPorts.push_back(static_cast<quint16>(port));
        }
        require(job.analysis.source=="live" || ports.isEmpty());
        job.rulesPath=rules_;
        job.storagePath=storage_;
        job.workerPath=worker_;
        require(session_.submit(std::move(job)),QStringLiteral("Сетевое задание уже выполняется"));
        error_.clear();
        return session_.progress()->json();
    }
    if(command=="network_cancel") {
        fields(request,{"job_id"});
        const auto id=text(request["job_id"],64);
        const auto current=session_.progress();
        const bool active=session_.busy() && current && current->id==id;
        if(active)session_.cancel();
        return {{"accepted",active}};
    }
    NetworkStore history(storage_,true);
    if(command=="network_jobs") {
        fields(request,{"offset","limit"});
        QJsonArray rows;
        for(const auto &job:history.jobs(protocol::counter(request["offset"]),integer(request["limit"],1,protocol::pageLimit)))
            rows.append(job.json());
        return {{"rows",rows}};
    }
    const auto id=text(request["job_id"],64);
    if(command=="network_job") {
        fields(request,{"job_id"});
        const auto current=session_.progress();
        return {{"job",optionalJson(history.getJob(id,!(session_.busy() && current && current->id==id)))}};
    }
    if(command=="network_flows") {
        fields(request,{"job_id","text","matches","descending","sort","offset","limit"});
        NetworkQuery query{text(request["text"],4096,true),flag(request["matches"]),flag(request["descending"]),
            static_cast<NetworkSort>(integer(request["sort"],0,static_cast<int>(NetworkSort::Packets))),
            protocol::counter(request["offset"]),integer(request["limit"],1,protocol::pageLimit)};
        const auto page=history.flows(id,query);
        QJsonArray rows;
        for(const auto &row:page.rows)rows.append(QJsonObject{{"flow",row.flow.json()},{"matches",QString::number(row.matches)},{"rules",row.rules}});
        return {{"rows",rows},{"total",QString::number(page.total)}};
    }
    if(command=="network_flow") {
        fields(request,{"job_id","flow_id"});
        return {{"flow",optionalJson(history.flow(id,text(request["flow_id"],64)))}};
    }
    if(command=="network_detections") {
        fields(request,{"job_id","flow_id","text","offset","limit","linked"});
        const auto page=history.detections(id,text(request["flow_id"],64,true),text(request["text"],4096,true),
            protocol::counter(request["offset"]),integer(request["limit"],1,protocol::pageLimit));
        QJsonArray rows,flows;
        const bool linked=flag(request["linked"]);
        qsizetype bytes=0;
        for(const auto &row:page.rows) {
            const auto detection=row.json();
            const auto size=QJsonDocument(detection).toJson(QJsonDocument::Compact).size();
            if(!rows.isEmpty() && bytes+size>protocol::replyLimit*3/4)break;
            bytes+=size;
            rows.append(detection);
            if(linked) {
                const auto flow=history.flow(id,row.flowId);
                require(flow.has_value(),QStringLiteral("В истории отсутствует поток обнаружения"));
                const auto detail=flow->json();
                bytes+=QJsonDocument(detail).toJson(QJsonDocument::Compact).size();
                flows.append(detail);
            }
        }
        return {{"rows",rows},{"flows",flows},{"total",QString::number(page.total)}};
    }
    if(command=="network_diagnostics") {
        fields(request,{"job_id"});
        QJsonArray rows;
        for(const auto &row:history.diagnostics(id))rows.append(QJsonObject{{"code",row.code},{"reason",row.reason}});
        return {{"rows",rows}};
    }
    throw Error(QStringLiteral("Неизвестная сетевая команда службы"));
}
}
