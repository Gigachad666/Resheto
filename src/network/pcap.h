#pragma once
#include "capture.h"
#include "core/file_access.h"

namespace resheto::network {
// Потоковое чтение classic PCAP 2.4, обоих порядков байтов, micro/nanoseconds.
class PcapReader {
    ReadFile file_;
    bool little_=true,nano_=false,cancelled_=false;
    quint32 snapLength_=0;
    LinkType link_=LinkType::RawIp;
    qint64 packets_=0;
public:
    explicit PcapReader(const QString &path);
    std::optional<CapturedPacket> next(const std::atomic_bool *cancel=nullptr);
    bool cancelled() const{return cancelled_;}
    qint64 packetCount() const{return packets_;}
};
}
