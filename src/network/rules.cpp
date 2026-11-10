#include "analyzer.h"
#include "core/file_access.h"
#include <QJsonDocument>
#include <QSet>
#include <QRegularExpression>

namespace resheto::network {
std::shared_ptr<const NetworkRules> parseNetworkRules(const QJsonObject &document) {
    auto require=[](bool good){if(!good)throw Error(QStringLiteral("Некорректный набор сетевых правил"));};
    auto string=[&](const QJsonObject &o,const char *key,int max){require(o[key].isString());const auto s=o[key].toString();require(!s.trimmed().isEmpty() && s.size()<=max);return s;};
    auto number=[&](const QJsonObject &o,const char *key,int lo,int hi){const auto n=o[key].toDouble(-1);require(o[key].isDouble() && n>=lo && n<=hi && n==static_cast<int>(n));return static_cast<int>(n);};
    require(document["format"]=="resheto-network-v1");auto rules=std::make_shared<NetworkRules>();rules->version=string(document,"version",64);rules->document=document;
    require(QJsonDocument(document).toJson(QJsonDocument::Compact).size()<=1048576 && document["limits"].isObject());const auto limits=document["limits"].toObject();
    rules->maxFlows=number(limits,"max_flows",1,65536);rules->idleTimeoutMs=number(limits,"idle_timeout_ms",100,600000);
    rules->maxRuleKeys=number(limits,"max_rule_keys",1,4096);rules->maxEventsPerKey=number(limits,"max_events_per_key",2,256);rules->maxSuppressionKeys=number(limits,"max_suppression_keys",1,65536);
    require(document["rules"].isArray() && !document["rules"].toArray().isEmpty() && document["rules"].toArray().size()<=32);QSet<QString> ids;
    for(const auto &value:document["rules"].toArray()) {
        require(value.isObject());const auto object=value.toObject();NetworkRule rule;
        rule.id=string(object,"id",64);require(QRegularExpression("^[A-Za-z0-9][A-Za-z0-9_-]*$").match(rule.id).hasMatch() && !ids.contains(rule.id));ids.insert(rule.id);
        rule.kind=string(object,"kind",32);require(QStringList{"tcp_ports","tcp_periodic","dns_nxdomain"}.contains(rule.kind));
        rule.version=string(object,"version",64);rule.description=string(object,"description",512);rule.severity=string(object,"severity",16);require(QStringList{"low","medium","high"}.contains(rule.severity));
        rule.threshold=number(object,"threshold",2,rules->maxEventsPerKey);rule.windowMs=number(object,"window_ms",100,120000);rule.suppressMs=number(object,"suppress_ms",100,120000);
        if(rule.kind=="tcp_periodic") {rule.minIntervalMs=number(object,"min_interval_ms",100,60000);rule.maxIntervalMs=number(object,"max_interval_ms",rule.minIntervalMs,60000);rule.jitterPercent=number(object,"jitter_percent",0,50);require(rule.threshold>=4 && static_cast<qint64>(rule.threshold-1)*rule.minIntervalMs<=rule.windowMs);}
        require(object["enabled"].isBool());if(object["enabled"].toBool())rules->entries.push_back(std::move(rule));
    }
    require(!rules->entries.empty());return rules;
}
std::shared_ptr<const NetworkRules> loadNetworkRules(const QString &path) {
    ReadFile file(path);const auto bytes=file.read(1048577);
    if(bytes.size()>1048576)throw Error(QStringLiteral("Сетевые правила превышают предел 1048576 байт"));
    if(bytes.size()!=file.size() || !file.unchanged())throw Error(QStringLiteral("Сетевые правила изменились или прочитаны не полностью"));
    QJsonParseError error;const auto document=QJsonDocument::fromJson(bytes,&error);
    if(error.error!=QJsonParseError::NoError || !document.isObject())throw Error(QStringLiteral("Сетевые правила должны содержать JSON-объект"));return parseNetworkRules(document.object());
}
}
