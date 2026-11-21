#include "network_client.h"
#include "protocol.h"

namespace resheto::service {
using namespace network;
namespace {
QJsonArray array(const QJsonObject &reply) {
    if(!reply["rows"].isArray())throw Error(QStringLiteral("Некорректный список сетевой службы"));
    return reply["rows"].toArray();
}

template<class T>
std::optional<T> optional(const QJsonValue &value) {
    if(value.isNull())return {};
    if(!value.isObject())throw Error(QStringLiteral("Некорректный объект сетевой службы"));
    return T::fromJson(value.toObject());
}
}

NetworkStatus NetworkClient::status() const {
    const auto reply=client_.call({{"command","network_status"}});
    return {reply["busy"].toBool(),reply["rules"].toString(),reply["error"].toString(),optional<NetworkJob>(reply["job"])};
}

NetworkJob NetworkClient::start(const AnalysisOptions &options) const {
    QJsonArray ports;
    for(const auto port:options.capture.tcpPorts)ports.append(port);
    const auto input=options.source=="pcap" && !options.input.trimmed().isEmpty()?absolute(options.input):options.input;
    return NetworkJob::fromJson(client_.call({{"command","network_start"},{"source",options.source},{"input",input},
                                              {"duration_ms",options.durationMs},{"tcp_ports",ports}}));
}

bool NetworkClient::cancel(const QString &id) const {
    return client_.call({{"command","network_cancel"},{"job_id",id}})["accepted"].toBool();
}

QJsonArray NetworkClient::interfaces() const {
    return array(client_.call({{"command","network_interfaces"}}));
}

std::vector<NetworkJob> NetworkClient::jobs(qint64 offset,int limit) const {
    std::vector<NetworkJob> jobs;
    for(const auto &value:array(client_.call({{"command","network_jobs"},{"offset",QString::number(offset)},{"limit",limit}})))
        jobs.push_back(NetworkJob::fromJson(value.toObject()));
    return jobs;
}

std::optional<NetworkJob> NetworkClient::getJob(const QString &id) const {
    return optional<NetworkJob>(client_.call({{"command","network_job"},{"job_id",id}})["job"]);
}

NetworkFlowPage NetworkClient::flows(const QString &id,const NetworkQuery &query) const {
    const auto reply=client_.call({{"command","network_flows"},{"job_id",id},{"text",query.text},{"matches",query.matchesOnly},
        {"descending",query.descending},{"sort",static_cast<int>(query.sort)},{"offset",QString::number(query.offset)},{"limit",query.limit}});
    NetworkFlowPage page;
    page.total=protocol::counter(reply["total"]);
    for(const auto &value:array(reply)) {
        const auto row=value.toObject();
        page.rows.push_back({Flow::fromJson(row["flow"].toObject()),protocol::counter(row["matches"]),row["rules"].toString()});
    }
    return page;
}

std::optional<Flow> NetworkClient::flow(const QString &id,const QString &flowId) const {
    return optional<Flow>(client_.call({{"command","network_flow"},{"job_id",id},{"flow_id",flowId}})["flow"]);
}

NetworkDetectionPage NetworkClient::detections(const QString &id,const QString &flowId,const QString &text,qint64 offset,int limit,
                                                std::vector<Flow> *linked) const {
    NetworkDetectionPage page;
    if(linked)linked->clear();
    auto remaining=limit;
    do {
        const auto reply=client_.call({{"command","network_detections"},{"job_id",id},{"flow_id",flowId},{"text",text},
                                      {"offset",QString::number(offset)},{"limit",remaining},{"linked",linked!=nullptr}});
        page.total=protocol::counter(reply["total"]);
        const auto rows=array(reply);
        if(rows.size()>remaining || (rows.isEmpty() && offset<page.total))
            throw Error(QStringLiteral("Некорректная страница сетевых обнаружений"));
        for(const auto &row:rows)page.rows.push_back(Detection::fromJson(row.toObject()));
        if(linked) {
            const auto flows=reply["flows"].toArray();
            if(flows.size()!=rows.size())throw Error(QStringLiteral("В ответе сети отсутствуют связанные потоки"));
            for(const auto &value:flows)linked->push_back(Flow::fromJson(value.toObject()));
        }
        if(rows.isEmpty())break;
        offset+=rows.size();
        remaining-=static_cast<int>(rows.size());
    } while(remaining>0 && offset<page.total);
    return page;
}

std::vector<Diagnostic> NetworkClient::diagnostics(const QString &id) const {
    std::vector<Diagnostic> diagnostics;
    for(const auto &value:array(client_.call({{"command","network_diagnostics"},{"job_id",id}}))) {
        const auto row=value.toObject();
        diagnostics.push_back({row["code"].toString(),row["reason"].toString()});
    }
    return diagnostics;
}
}
