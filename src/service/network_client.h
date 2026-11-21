#pragma once

#include "client.h"
#include "network/runner.h"
#include <QJsonArray>

namespace resheto::service {
struct NetworkStatus {
    bool busy=false;
    QString rulesPath,error;
    std::optional<network::NetworkJob> job;
};

class NetworkClient {
    Client client_;
public:
    explicit NetworkClient(const QString &endpoint):client_(endpoint) {}
    NetworkStatus status() const;
    network::NetworkJob start(const network::AnalysisOptions &options) const;
    bool cancel(const QString &id) const;
    QJsonArray interfaces() const;
    std::vector<network::NetworkJob> jobs(qint64 offset,int limit) const;
    std::optional<network::NetworkJob> getJob(const QString &id) const;
    network::NetworkFlowPage flows(const QString &id,const network::NetworkQuery &query) const;
    std::optional<network::Flow> flow(const QString &id,const QString &flowId) const;
    network::NetworkDetectionPage detections(const QString &id,const QString &flowId={},const QString &text={},qint64 offset=0,int limit=200,
                                             std::vector<network::Flow> *linked=nullptr) const;
    std::vector<network::Diagnostic> diagnostics(const QString &id) const;
};
}
