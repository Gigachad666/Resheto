#pragma once
#include "packet.h"

namespace resheto::network {
struct NetworkRule {
    QString id,kind,version,description,severity;
    int threshold=0,windowMs=0,suppressMs=0,minIntervalMs=0,maxIntervalMs=0,jitterPercent=0;
};
struct NetworkRules {
    QString version;
    int maxFlows=4096,idleTimeoutMs=30000,maxRuleKeys=256,maxEventsPerKey=256,maxSuppressionKeys=4096;
    std::vector<NetworkRule> entries;
    QJsonObject document;
};
std::shared_ptr<const NetworkRules> parseNetworkRules(const QJsonObject &document);
std::shared_ptr<const NetworkRules> loadNetworkRules(const QString &path);
class NetworkAnalyzer {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    explicit NetworkAnalyzer(std::shared_ptr<const NetworkRules> rules);
    ~NetworkAnalyzer();
    NetworkAnalyzer(const NetworkAnalyzer &)=delete;
    NetworkAnalyzer &operator=(const NetworkAnalyzer &)=delete;
    AnalysisUpdate observe(const CapturedPacket &packet);
    // Подтверждение после commit. Оно не изменяет окна и решение правил.
    void acknowledge(const QString &detectionId);
    std::vector<Detection> pendingDetections() const;
    std::vector<Flow> finish();
    Counters counters() const;
    size_t activeFlows() const;
};
}
