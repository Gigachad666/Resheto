#include "analyzer.h"
#include <QCryptographicHash>
#include <QHostAddress>
#include <QMap>
#include <QSet>
#include <deque>
#include <algorithm>

namespace resheto::network {
namespace {
QString hash(const QByteArray &value){return QString::fromLatin1(QCryptographicHash::hash(value,QCryptographicHash::Sha256).toHex());}
QString endpointKey(const QString &address,quint16 port){return canonicalEndpointKey(address,port);}
}
struct NetworkAnalyzer::Impl {
    struct Event {qint64 time=0;QString value;};
    struct RuleState {NetworkRule rule;QMap<QString,std::deque<Event>> windows;};
    struct Suppressed {qint64 time=0;int suppressMs=0;QString detectionId;};
    std::shared_ptr<const NetworkRules> rules;
    std::vector<RuleState> states;
    QMap<QString,Flow> flows;
    QMap<QString,qint64> synSeen,acknowledged;
    QMap<QString,Detection> pending;
    QMap<QString,Suppressed> suppressed;
    Counters counters;
    qint64 tick=-1,lastSweep=-1,ackSequence=0;
    QSet<QString> reported;

    void diagnostic(AnalysisUpdate &update,const QString &code,const QString &reason){if(!reported.contains(code)){reported.insert(code);update.diagnostics.push_back({code,reason});}}
    void loss(AnalysisUpdate &update,const QString &code,const QString &reason){++counters.ruleEvictions;diagnostic(update,code,reason);}
    void sweep(AnalysisUpdate &update) {
        if(lastSweep>=0 && tick-lastSweep<1000000)return;lastSweep=tick;
        for(auto it=flows.begin();it!=flows.end();)if(tick-it->lastUs>static_cast<qint64>(rules->idleTimeoutMs)*1000){update.retiredFlows.push_back(it.value());it=flows.erase(it);++counters.flowsExpired;}else ++it;
        for(auto it=synSeen.begin();it!=synSeen.end();)if(tick-it.value()>120000000)it=synSeen.erase(it);else ++it;
        for(auto it=suppressed.begin();it!=suppressed.end();)if(tick-it->time>=static_cast<qint64>(it->suppressMs)*1000)it=suppressed.erase(it);else ++it;
        for(auto &state:states)for(auto it=state.windows.begin();it!=state.windows.end();){while(!it->empty() && tick-it->front().time>static_cast<qint64>(state.rule.windowMs)*1000)it->pop_front();if(it->empty())it=state.windows.erase(it);else ++it;}
    }
    Flow &flow(const PacketInfo &packet,AnalysisUpdate &update) {
        const auto source=endpointKey(packet.sourceAddress,packet.sourcePort),destination=endpointKey(packet.destinationAddress,packet.destinationPort);const bool forward=source<=destination;
        const auto key=canonicalFlowKey(packet.family,packet.protocol,packet.sourceAddress,packet.sourcePort,packet.destinationAddress,packet.destinationPort);
        auto found=flows.find(key);
        if(found==flows.end()) {
            if(flows.size()>=rules->maxFlows){auto oldest=flows.begin();for(auto it=flows.begin();it!=flows.end();++it)if(it->lastUs<oldest->lastUs)oldest=it;update.retiredFlows.push_back(oldest.value());flows.erase(oldest);++counters.flowEvictions;diagnostic(update,"flow_capacity",QStringLiteral("Достигнут предел активных потоков; старый поток завершён с потерей непрерывности"));}
            Flow value;value.key=key;value.family=packet.family;value.protocol=packet.protocol;value.addressA=forward?packet.sourceAddress:packet.destinationAddress;value.addressB=forward?packet.destinationAddress:packet.sourceAddress;
            value.portA=forward?packet.sourcePort:packet.destinationPort;value.portB=forward?packet.destinationPort:packet.sourcePort;value.firstUs=value.lastUs=packet.timestampUs;
            ++counters.flowsCreated;value.id=hash((key+"@"+QString::number(packet.timestampUs)+"#"+QString::number(counters.flowsCreated)).toUtf8());found=flows.insert(key,std::move(value));
        }
        auto &value=found.value();value.firstUs=qMin(value.firstUs,packet.timestampUs);value.lastUs=qMax(value.lastUs,packet.timestampUs);
        if(forward){++value.packetsAToB;value.bytesAToB+=packet.originalBytes;value.tcpFlagsAToB|=packet.tcpFlags;}
        else{++value.packetsBToA;value.bytesBToA+=packet.originalBytes;value.tcpFlagsBToA|=packet.tcpFlags;}return value;
    }
    void observeRule(RuleState &state,const PacketInfo &packet,const Flow &flow,AnalysisUpdate &update) {
        const auto &rule=state.rule;QString group,item,source=packet.sourceAddress,destination=packet.destinationAddress;
        if(rule.kind=="dns_nxdomain") {if(!packet.dnsResponse || packet.dnsRcode!=3 || packet.dnsName.isEmpty())return;source=packet.destinationAddress;destination=packet.sourceAddress;group=source;item=packet.dnsName;}
        else {if(packet.protocol!=6 || !(packet.tcpFlags&2) || (packet.tcpFlags&16) || !packet.sourcePort || !packet.destinationPort)return;group=source+"|"+destination;
            if(rule.kind=="tcp_ports")item=QString::number(packet.destinationPort);
            else{group+="|"+QString::number(packet.destinationPort);item=QString::number(packet.sourcePort)+"/"+QString::number(packet.tcpSequence);}}
        const auto suppression=rule.id+"|"+group;
        const auto previous=suppressed.find(suppression);
        if(previous!=suppressed.end()) {
            if(tick-previous->time<static_cast<qint64>(previous->suppressMs)*1000) {
                const auto candidate=pending.find(previous->detectionId);
                if(candidate!=pending.end()) update.detections.push_back(candidate.value());
                return;
            }
            suppressed.erase(previous);
        }
        if(!state.windows.contains(group) && state.windows.size()>=rules->maxRuleKeys){auto oldest=state.windows.begin();for(auto it=state.windows.begin();it!=state.windows.end();++it)if(it->back().time<oldest->back().time)oldest=it;state.windows.erase(oldest);loss(update,"rule_key_capacity",QStringLiteral("Достигнут предел наблюдаемых групп сетевого правила"));}
        auto &events=state.windows[group];while(!events.empty() && tick-events.front().time>static_cast<qint64>(rule.windowMs)*1000)events.pop_front();
        for(const auto &event:events)if(event.value==item)return;
        if(static_cast<int>(events.size())>=rules->maxEventsPerKey){events.pop_front();loss(update,"rule_event_capacity",QStringLiteral("Достигнут предел событий в окне сетевого правила"));}
        events.push_back({packet.timestampUs,item});if(static_cast<int>(events.size())<rule.threshold)return;
        std::vector<Event> evidenceEvents;
        if(rule.kind=="tcp_periodic") {
            auto begin=events.end()-rule.threshold;evidenceEvents.assign(begin,events.end());const auto interval=(evidenceEvents.back().time-evidenceEvents.front().time)/(rule.threshold-1);
            if(interval<static_cast<qint64>(rule.minIntervalMs)*1000 || interval>static_cast<qint64>(rule.maxIntervalMs)*1000)return;
            for(size_t i=1;i<evidenceEvents.size();++i){const auto value=evidenceEvents[i].time-evidenceEvents[i-1].time;if(value<=0 || qAbs(value-interval)*100>interval*rule.jitterPercent)return;}
        } else evidenceEvents.assign(events.begin(),events.end());
        QJsonArray items;for(const auto &event:evidenceEvents)items.push_back(QJsonObject{{"value",event.value},{"time_us",QString::number(event.time)}});
        Detection detection;detection.flowId=flow.id;detection.ruleId=rule.id;detection.ruleVersion=rule.version;detection.setVersion=rules->version;detection.description=rule.description;detection.severity=rule.severity;detection.timestampUs=packet.timestampUs;
        detection.evidence={{"kind",rule.kind},{"count",static_cast<int>(evidenceEvents.size())},{"threshold",rule.threshold},{"window_ms",rule.windowMs},{"source_address",source},{"destination_address",destination},{"items",items}};
        if(rule.kind=="tcp_periodic"){detection.evidence["destination_port"]=packet.destinationPort;detection.evidence["jitter_percent"]=rule.jitterPercent;detection.evidence["min_interval_ms"]=rule.minIntervalMs;detection.evidence["max_interval_ms"]=rule.maxIntervalMs;detection.basis=QStringLiteral("%1 TCP-попыток %2 → %3:%4 с регулярными интервалами; окно %5 мс, допуск %6%").arg(evidenceEvents.size()).arg(source,destination).arg(packet.destinationPort).arg(rule.windowMs).arg(rule.jitterPercent);}
        else if(rule.kind=="tcp_ports")detection.basis=QStringLiteral("%1 различных TCP-портов: %2 → %3; окно %4 мс, порог %5").arg(evidenceEvents.size()).arg(source,destination).arg(rule.windowMs).arg(rule.threshold);
        else detection.basis=QStringLiteral("Клиент %1 получил NXDOMAIN для %2 различных DNS-имён; окно %3 мс, порог %4").arg(source).arg(evidenceEvents.size()).arg(rule.windowMs).arg(rule.threshold);
        detection.id=hash((suppression+"|"+QString::number(detection.timestampUs)+"|"+flow.id).toUtf8());
        if(pending.size()>=rules->maxSuppressionKeys) throw Error(QStringLiteral("Достигнут предел неподтверждённых сетевых обнаружений; сохранение не подтверждено"));
        if(suppressed.size()>=rules->maxSuppressionKeys) {
            auto oldest=suppressed.begin();for(auto it=suppressed.begin();it!=suppressed.end();++it)if(it->time<oldest->time)oldest=it;
            suppressed.erase(oldest);loss(update,"suppression_capacity",QStringLiteral("Достигнут предел ключей подавления сетевых обнаружений"));
        }
        suppressed.insert(suppression,{detection.timestampUs,rule.suppressMs,detection.id});pending.insert(detection.id,detection);
        ++counters.detections;update.detections.push_back(std::move(detection));
    }
};
NetworkAnalyzer::NetworkAnalyzer(std::shared_ptr<const NetworkRules> rules):impl_(std::make_unique<Impl>()) {
    if(!rules)throw Error(QStringLiteral("Нет сетевых правил"));impl_->rules=parseNetworkRules(rules->document);for(const auto &rule:impl_->rules->entries)impl_->states.push_back({rule,{}});
}
NetworkAnalyzer::~NetworkAnalyzer()=default;
AnalysisUpdate NetworkAnalyzer::observe(const CapturedPacket &input) {
    AnalysisUpdate update;auto &impl=*impl_;++impl.counters.packets;const auto result=parsePacket(input);const auto &packet=result.packet;
    if(result.state=="parsed")++impl.counters.parsed;else if(result.state=="unsupported")++impl.counters.unsupported;else if(result.state=="fragment")++impl.counters.fragments;else if(result.state=="truncated")++impl.counters.truncated;else ++impl.counters.malformed;
    if(!result.code.isEmpty())impl.diagnostic(update,result.code,result.reason);
    const bool reordered=impl.tick>=0 && input.timestampUs<impl.tick;if(reordered){++impl.counters.reordered;impl.diagnostic(update,"packet_time_order",QStringLiteral("Время пакетов немонотонно; временные правила для переставленного пакета не применены"));}
    impl.tick=qMax(impl.tick,input.timestampUs);impl.sweep(update);
    if(result.state=="parsed" && packet.hasTransport) {
        auto &flow=impl.flow(packet,update);update.flow=flow;
        if(packet.protocol==6 && (!packet.sourcePort || !packet.destinationPort))impl.diagnostic(update,"tcp_zero_port",QStringLiteral("TCP с нулевым портом учтён в потоке, но не участвует в правилах TCP-попыток"));
        bool newAttempt=true;
        if(packet.protocol==6 && (packet.tcpFlags&2) && !(packet.tcpFlags&16)) {
            const auto syn=endpointKey(packet.sourceAddress,packet.sourcePort)+"/"+endpointKey(packet.destinationAddress,packet.destinationPort)+"/"+QString::number(packet.tcpSequence);
            if(impl.synSeen.contains(syn))newAttempt=false;
            else {if(impl.synSeen.size()>=impl.rules->maxFlows){auto oldest=impl.synSeen.begin();for(auto it=impl.synSeen.begin();it!=impl.synSeen.end();++it)if(it.value()<oldest.value())oldest=it;impl.synSeen.erase(oldest);impl.loss(update,"syn_capacity",QStringLiteral("Достигнут предел подавления TCP-ретрансляций"));}impl.synSeen.insert(syn,impl.tick);}
        }
        if(!reordered && newAttempt)for(auto &state:impl.states)impl.observeRule(state,packet,flow,update);
    }
    update.counters=impl.counters;return update;
}
void NetworkAnalyzer::acknowledge(const QString &id) {
    auto &impl=*impl_;if(impl.acknowledged.contains(id))return;
    const auto found=impl.pending.find(id);
    if(found==impl.pending.end()) throw Error(QStringLiteral("Нет ожидающего сетевого обнаружения для подтверждения"));
    if(impl.acknowledged.size()>=impl.rules->maxSuppressionKeys) {
        auto oldest=impl.acknowledged.begin();for(auto it=impl.acknowledged.begin();it!=impl.acknowledged.end();++it)if(it.value()<oldest.value())oldest=it;impl.acknowledged.erase(oldest);
    }
    impl.acknowledged.insert(id,++impl.ackSequence);impl.pending.erase(found);
}
std::vector<Detection> NetworkAnalyzer::pendingDetections() const {std::vector<Detection> result;for(const auto &value:impl_->pending)result.push_back(value);return result;}
std::vector<Flow> NetworkAnalyzer::finish(){std::vector<Flow> flows;for(const auto &flow:impl_->flows)flows.push_back(flow);impl_->flows.clear();return flows;}
Counters NetworkAnalyzer::counters() const{return impl_->counters;}
size_t NetworkAnalyzer::activeFlows() const{return static_cast<size_t>(impl_->flows.size());}
}
