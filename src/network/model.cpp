#include "model.h"
#include <QHostAddress>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QSet>
#include <limits>

namespace resheto::network {
namespace {
void check(bool good,const QString &reason){if(!good)throw Error(QStringLiteral("Некорректная сетевая запись: ")+reason);}
QString text(const QJsonObject &o,const char *key,int maximum=512) {
    check(o[key].isString(),QString::fromLatin1(key)); const auto s=o[key].toString();
    check(!s.trimmed().isEmpty() && s.size()<=maximum,QString::fromLatin1(key)); return s;
}
qint64 integer(const QJsonObject &o,const char *key) {
    const auto value=o[key]; check(value.isString(),QString::fromLatin1(key));
    const auto s=value.toString(); static const QRegularExpression decimal("^(0|[1-9][0-9]*)$"); bool good=false; const auto n=s.toLongLong(&good);
    check(good && decimal.match(s).hasMatch(),QString::fromLatin1(key)); return n;
}
int number(const QJsonObject &o,const char *key,int minimum,int maximum) {
    const auto n=o[key].toDouble(-1); check(o[key].isDouble() && n>=minimum && n<=maximum && n==static_cast<int>(n),QString::fromLatin1(key)); return static_cast<int>(n);
}
QString digest(const QJsonObject &o,const char *key) {const auto s=text(o,key,64);check(QRegularExpression("^[0-9a-f]{64}$").match(s).hasMatch(),QString::fromLatin1(key));return s;}
void address(const QString &value) {
    const QHostAddress parsed(value);
    check((parsed.protocol()==QAbstractSocket::IPv4Protocol || parsed.protocol()==QAbstractSocket::IPv6Protocol) && parsed.toString()==value,"address");
}
void domainName(const QString &name) {
    check(name.size()<=1024 && name==name.toLower(),"DNS name");
    int total=0;
    for(const auto &label:name.split('.')) {
        check(!label.isEmpty(),"DNS label");int length=0;
        for(int offset=0;offset<label.size();++offset) {
            if(label[offset]=='\\') {
                check(offset+3<label.size(),"DNS escape");const auto digits=label.mid(offset+1,3);bool good=false;const int byte=digits.toInt(&good);
                check(good && digits.size()==3 && digits[0].isDigit() && digits[1].isDigit() && digits[2].isDigit() && byte<=255,"DNS escape");offset+=3;
            } else check(label[offset].unicode()>=33 && label[offset].unicode()<=126,"DNS character");
            ++length;
        }
        check(length<=63,"DNS label length");total+=length+1;
    }
    check(total<=254,"DNS length");
}
}
QString canonicalEndpointKey(const QString &value,quint16 port) {
    const QHostAddress parsed(value);QString key;
    if(parsed.protocol()==QAbstractSocket::IPv4Protocol) key=QString::number(parsed.toIPv4Address(),16).rightJustified(8,'0');
    else if(parsed.protocol()==QAbstractSocket::IPv6Protocol){const auto bytes=parsed.toIPv6Address();key=QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(bytes.c),16).toHex());}
    else throw Error(QStringLiteral("Некорректный адрес конечной точки"));
    return key+":"+QString::number(port,16).rightJustified(4,'0');
}
QString canonicalFlowKey(int family,int protocol,const QString &source,quint16 sourcePort,const QString &destination,quint16 destinationPort) {
    const auto a=canonicalEndpointKey(source,sourcePort),b=canonicalEndpointKey(destination,destinationPort);
    return QString::number(family)+"/"+QString::number(protocol)+"/"+qMin(a,b)+"/"+qMax(a,b);
}
QString endpointText(const QString &address,quint16 port){return (address.contains(':')?"["+address+"]":address)+":"+QString::number(port);}
QString flowText(const Flow &f){return endpointText(f.addressA,f.portA)+QStringLiteral(" ↔ ")+endpointText(f.addressB,f.portB)+(f.protocol==6?" TCP":" UDP");}
QJsonObject Flow::json() const {
    return {{"id",id},{"key",key},{"family",family},{"protocol",protocol},{"address_a",addressA},{"address_b",addressB},{"port_a",portA},{"port_b",portB},
        {"first_us",QString::number(firstUs)},{"last_us",QString::number(lastUs)},{"packets_a_b",QString::number(packetsAToB)},{"packets_b_a",QString::number(packetsBToA)},
        {"bytes_a_b",QString::number(bytesAToB)},{"bytes_b_a",QString::number(bytesBToA)},{"tcp_flags_a_b",tcpFlagsAToB},{"tcp_flags_b_a",tcpFlagsBToA}};
}
Flow Flow::fromJson(const QJsonObject &o) {
    Flow f;f.id=digest(o,"id");f.key=text(o,"key",256);f.family=number(o,"family",4,6);check(f.family==4 || f.family==6,"family");
    f.protocol=number(o,"protocol",6,17);check(f.protocol==6 || f.protocol==17,"protocol"); f.addressA=text(o,"address_a",64);f.addressB=text(o,"address_b",64);
    for(const auto &a:{f.addressA,f.addressB}){address(a);QHostAddress ip(a);check(f.family==4?ip.protocol()==QAbstractSocket::IPv4Protocol:ip.protocol()==QAbstractSocket::IPv6Protocol,"family/address");}
    f.portA=static_cast<quint16>(number(o,"port_a",0,65535));f.portB=static_cast<quint16>(number(o,"port_b",0,65535));
    check(canonicalEndpointKey(f.addressA,f.portA)<=canonicalEndpointKey(f.addressB,f.portB),"endpoint order");
    check(f.key==canonicalFlowKey(f.family,f.protocol,f.addressA,f.portA,f.addressB,f.portB),"flow key");
    f.firstUs=integer(o,"first_us");f.lastUs=integer(o,"last_us");check(f.firstUs<=f.lastUs,"time order");
    f.packetsAToB=integer(o,"packets_a_b");f.packetsBToA=integer(o,"packets_b_a");f.bytesAToB=integer(o,"bytes_a_b");f.bytesBToA=integer(o,"bytes_b_a");
    check(f.packetsAToB || f.packetsBToA,"empty flow");check((f.packetsAToB==0)==(f.bytesAToB==0) && (f.packetsBToA==0)==(f.bytesBToA==0),"counters");
    const int minimum=(f.family==4?20:40)+(f.protocol==6?20:8);
    check(f.packetsAToB<=f.bytesAToB/minimum && f.packetsBToA<=f.bytesBToA/minimum,"byte counters");
    f.tcpFlagsAToB=static_cast<quint8>(number(o,"tcp_flags_a_b",0,255));f.tcpFlagsBToA=static_cast<quint8>(number(o,"tcp_flags_b_a",0,255));
    check(f.protocol==6 || (!f.tcpFlagsAToB && !f.tcpFlagsBToA),"UDP flags"); return f;
}
QJsonObject Detection::json() const {
    return {{"id",id},{"flow_id",flowId},{"rule_id",ruleId},{"rule_version",ruleVersion},{"set_version",setVersion},{"description",description},{"severity",severity},{"basis",basis},{"timestamp_us",QString::number(timestampUs)},{"evidence",evidence}};
}
Detection Detection::fromJson(const QJsonObject &o) {
    Detection d;d.id=digest(o,"id");d.flowId=digest(o,"flow_id");d.ruleId=text(o,"rule_id",64);d.ruleVersion=text(o,"rule_version",64);d.setVersion=text(o,"set_version",64);
    check(QRegularExpression("^[A-Za-z0-9][A-Za-z0-9_-]*$").match(d.ruleId).hasMatch(),"rule id");
    d.description=text(o,"description",512);d.basis=text(o,"basis",2048);d.severity=text(o,"severity",16);check(QStringList{"low","medium","high"}.contains(d.severity),"severity");
    d.timestampUs=integer(o,"timestamp_us");check(o["evidence"].isObject(),"evidence");d.evidence=o["evidence"].toObject();
    check(QJsonDocument(d.evidence).toJson(QJsonDocument::Compact).size()<=524288,"evidence size");
    check(d.evidence["kind"].isString() && d.evidence["count"].isDouble() && d.evidence["threshold"].isDouble() && d.evidence["window_ms"].isDouble(),"evidence fields");
    const int count=number(d.evidence,"count",2,4096),threshold=number(d.evidence,"threshold",2,256);check(count>=threshold,"evidence threshold");
    const int window=number(d.evidence,"window_ms",100,120000);check(d.evidence["items"].isArray() && d.evidence["items"].toArray().size()==count,"evidence items");
    const auto kind=d.evidence["kind"].toString();check(QStringList{"tcp_ports","tcp_periodic","dns_nxdomain"}.contains(kind),"evidence kind");
    const auto source=text(d.evidence,"source_address",64),destination=text(d.evidence,"destination_address",64);address(source);address(destination);
    check(QHostAddress(source).protocol()==QHostAddress(destination).protocol(),"evidence family");
    qint64 previous=-1;QSet<QString> unique;
    std::vector<qint64> times;
    for(const auto &value:d.evidence["items"].toArray()) {
        check(value.isObject(),"evidence item");const auto item=value.toObject();const auto key=text(item,"value",1024);const auto time=integer(item,"time_us");
        check(!unique.contains(key) && time>=previous && time<=d.timestampUs && d.timestampUs-time<=static_cast<qint64>(window)*1000,"evidence time/value");
        if(kind=="tcp_ports") {bool good=false;const auto port=key.toUInt(&good);check(good && port>=1 && port<=65535 && QString::number(port)==key,"evidence port");}
        else if(kind=="tcp_periodic") {
            const auto parts=key.split('/');check(parts.size()==2,"TCP attempt key");bool portGood=false,sequenceGood=false;
            const auto port=parts[0].toUInt(&portGood),sequence=parts[1].toUInt(&sequenceGood);
            check(portGood && sequenceGood && port>=1 && port<=65535 && QString::number(port)==parts[0] && QString::number(sequence)==parts[1],"TCP attempt value");
        } else domainName(key);
        unique.insert(key);previous=time;times.push_back(time);
    }
    check(previous==d.timestampUs,"evidence latest time");
    if(kind=="tcp_periodic") {
        check(count==threshold && threshold>=4,"periodic count");number(d.evidence,"destination_port",1,65535);
        const int minimum=number(d.evidence,"min_interval_ms",100,60000),maximum=number(d.evidence,"max_interval_ms",minimum,60000),jitter=number(d.evidence,"jitter_percent",0,50);
        const auto interval=(times.back()-times.front())/(threshold-1);
        check(interval>=static_cast<qint64>(minimum)*1000 && interval<=static_cast<qint64>(maximum)*1000,"periodic interval");
        for(size_t i=1;i<times.size();++i){const auto gap=times[i]-times[i-1];check(gap>0 && qAbs(gap-interval)*100<=interval*jitter,"periodic jitter");}
    }
    return d;
}
QJsonObject Counters::json() const {
    return {{"packets",QString::number(packets)},{"parsed",QString::number(parsed)},{"unsupported",QString::number(unsupported)},{"fragments",QString::number(fragments)},
        {"truncated",QString::number(truncated)},{"malformed",QString::number(malformed)},{"flows_created",QString::number(flowsCreated)},{"flows_expired",QString::number(flowsExpired)},
        {"flow_evictions",QString::number(flowEvictions)},{"rule_evictions",QString::number(ruleEvictions)},{"detections",QString::number(detections)},{"reordered",QString::number(reordered)}};
}
Counters Counters::fromJson(const QJsonObject &o) {
    Counters c;c.packets=integer(o,"packets");c.parsed=integer(o,"parsed");c.unsupported=integer(o,"unsupported");c.fragments=integer(o,"fragments");c.truncated=integer(o,"truncated");c.malformed=integer(o,"malformed");
    c.flowsCreated=integer(o,"flows_created");c.flowsExpired=integer(o,"flows_expired");c.flowEvictions=integer(o,"flow_evictions");c.ruleEvictions=integer(o,"rule_evictions");c.detections=integer(o,"detections");c.reordered=integer(o,"reordered");
    qint64 left=c.packets;for(const auto n:{c.parsed,c.unsupported,c.fragments,c.truncated,c.malformed}){check(n<=left,"packet counters");left-=n;}check(left==0,"packet counters");
    check(c.flowsCreated<=c.parsed && c.flowsExpired<=c.flowsCreated && c.flowEvictions<=c.flowsCreated-c.flowsExpired && c.reordered<=c.packets,"flow counters");return c;
}
}
