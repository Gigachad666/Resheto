#pragma once
#include "core/model.h"
#include <QStringList>

namespace resheto::network {
// Значения соответствуют LINKTYPE_* в классическом PCAP, не выдуманным заголовкам.
enum class LinkType : int { Loopback=0, Ethernet=1, RawIp=101, LinuxCooked=113, LinuxCookedV2=276 };
struct CaptureInterface {
    QString id,name;
    QStringList addresses;
    bool loopback=false;
    quint32 index=0,ipv6Index=0;
};
struct CapturedPacket {
    QByteArray bytes;
    qint64 timestampUs=0;
    LinkType linkType=LinkType::RawIp;
    quint32 originalLength=0,interfaceIndex=0;
    bool directionKnown=false,outbound=false,loopback=false;
};
struct CaptureOptions {
    QString interfaceId;
    // 0 — весь IP-трафик области; ненулевой порт ограничивает безопасный явный показ.
    quint16 udpPort=0;
    // Только числовой список, до64 уникальных ненулевых портов; произвольного BPF нет.
    std::vector<quint16> tcpPorts;
};
struct CaptureStatistics {
    bool dropsAvailable=false;
    quint64 received=0,dropped=0,interfaceDropped=0;
};
std::vector<CaptureInterface> captureInterfaces();
QString captureBackendVersion();
QString captureFilter(const CaptureOptions &options);
class Capture {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    explicit Capture(const CaptureOptions &options);
    ~Capture();
    Capture(const Capture &)=delete;
    Capture &operator=(const Capture &)=delete;
    // Один читатель; cancel() допустим из другого потока. Задержка отмены <=250мс.
    std::optional<CapturedPacket> poll(int timeoutMs=100);
    void cancel();
    bool cancelled() const;
    CaptureStatistics statistics() const;
};
}
