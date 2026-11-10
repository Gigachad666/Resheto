#pragma once
#include "capture.h"
#include <QJsonArray>

namespace resheto::network {
inline constexpr int maximumDurationMs=3600000;
inline constexpr bool validDuration(bool live,int milliseconds) {
    return milliseconds>=0 && milliseconds<=maximumDurationMs && (!live || milliseconds==0 || milliseconds>=100);
}
struct PacketInfo {
    qint64 timestampUs=0;
    int family=0,protocol=0;
    QString sourceAddress,destinationAddress;
    quint16 sourcePort=0,destinationPort=0;
    quint8 tcpFlags=0;
    quint32 tcpSequence=0;
    quint32 capturedBytes=0,originalBytes=0;
    bool hasTransport=false,fragmented=false;
    QString dnsName;
    bool dnsResponse=false;
    int dnsRcode=-1;
};
struct PacketResult {
    PacketInfo packet;
    // parsed, fragment, unsupported, truncated, malformed.
    QString state="malformed",code,reason;
};
struct Flow {
    QString id,key,addressA,addressB;
    int family=0,protocol=0;
    quint16 portA=0,portB=0;
    qint64 firstUs=0,lastUs=0,packetsAToB=0,packetsBToA=0,bytesAToB=0,bytesBToA=0;
    quint8 tcpFlagsAToB=0,tcpFlagsBToA=0;
    QJsonObject json() const;
    static Flow fromJson(const QJsonObject &object);
};
struct Detection {
    QString id,flowId,ruleId,ruleVersion,setVersion,description,severity,basis;
    qint64 timestampUs=0;
    QJsonObject evidence;
    QJsonObject json() const;
    static Detection fromJson(const QJsonObject &object);
};
struct Counters {
    qint64 packets=0,parsed=0,unsupported=0,fragments=0,truncated=0,malformed=0;
    qint64 flowsCreated=0,flowsExpired=0,flowEvictions=0,ruleEvictions=0,detections=0,reordered=0;
    QJsonObject json() const;
    static Counters fromJson(const QJsonObject &object);
};
struct Diagnostic {QString code,reason;};
struct AnalysisUpdate {
    std::optional<Flow> flow;
    std::vector<Flow> retiredFlows;
    std::vector<Detection> detections;
    std::vector<Diagnostic> diagnostics;
    Counters counters;
};
QString endpointText(const QString &address,quint16 port);
QString flowText(const Flow &flow);
QString canonicalEndpointKey(const QString &address,quint16 port);
QString canonicalFlowKey(int family,int protocol,const QString &source,quint16 sourcePort,const QString &destination,quint16 destinationPort);
}
