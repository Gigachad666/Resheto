#include "capture.h"
#include <QElapsedTimer>
#include <QDir>
#include <QThread>
#include <QSet>
#include <algorithm>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pcap/pcap.h>
#else
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

namespace resheto::network {
namespace {
constexpr int maximumPacket=262144;
// Отправляющие функции намеренно отсутствуют в интерфейсе адаптера.
#define PCAP_FUNCTIONS(X) \
    X(pcap_init) X(pcap_lib_version) X(pcap_findalldevs) X(pcap_freealldevs) X(pcap_create) \
    X(pcap_set_snaplen) X(pcap_set_promisc) X(pcap_set_timeout) X(pcap_set_immediate_mode) \
    X(pcap_activate) X(pcap_geterr) X(pcap_setnonblock) X(pcap_datalink) \
    X(pcap_compile) X(pcap_setfilter) X(pcap_freecode) X(pcap_next_ex) X(pcap_stats) X(pcap_close)
class PcapApi {
#ifdef _WIN32
    HMODULE library_=nullptr;
#endif
public:
#define DECLARE(name) decltype(&name) name##_fn=nullptr;
    PCAP_FUNCTIONS(DECLARE)
#undef DECLARE
    PcapApi() {
#ifdef _WIN32
        wchar_t system[MAX_PATH+1]{};
        const auto length=GetSystemDirectoryW(system,MAX_PATH);
        if(!length || length>=MAX_PATH) throw Error(QStringLiteral("Не найден системный каталог Npcap"));
        const auto file=QDir::toNativeSeparators(QString::fromWCharArray(system)+QStringLiteral("/Npcap/wpcap.dll"));
        library_=LoadLibraryExW(reinterpret_cast<LPCWSTR>(file.utf16()),nullptr,LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32);
        if(!library_) throw Error(QStringLiteral("Npcap не загружен из системного каталога (Windows %1). Проверьте отдельную установку Npcap").arg(GetLastError()));
        try {
#define RESOLVE(name) name##_fn=reinterpret_cast<decltype(name##_fn)>(GetProcAddress(library_,#name)); if(!name##_fn) throw Error(QStringLiteral("Npcap не предоставляет ")+QStringLiteral(#name));
            PCAP_FUNCTIONS(RESOLVE)
#undef RESOLVE
            char error[PCAP_ERRBUF_SIZE]{};
            if(pcap_init_fn(PCAP_CHAR_ENC_UTF_8,error)!=0) throw Error(QStringLiteral("Инициализация Npcap: ")+QString::fromUtf8(error));
        } catch(...) {FreeLibrary(library_);library_=nullptr;throw;}
#else
#define RESOLVE(name) name##_fn=&name;
        PCAP_FUNCTIONS(RESOLVE)
#undef RESOLVE
        char error[PCAP_ERRBUF_SIZE]{};
        if(pcap_init_fn(PCAP_CHAR_ENC_UTF_8,error)!=0) throw Error(QStringLiteral("Инициализация libpcap: ")+QString::fromUtf8(error));
#endif
    }
    ~PcapApi(){
#ifdef _WIN32
        if(library_) FreeLibrary(library_);
#endif
    }
    PcapApi(const PcapApi &)=delete;
    PcapApi &operator=(const PcapApi &)=delete;
};
#undef PCAP_FUNCTIONS
PcapApi &api(){static PcapApi instance;return instance;}
QString addressText(const sockaddr *address) {
    if(!address) return {};
    char text[INET6_ADDRSTRLEN]{};const void *bytes=nullptr;
    if(address->sa_family==AF_INET) bytes=&reinterpret_cast<const sockaddr_in *>(address)->sin_addr;
    else if(address->sa_family==AF_INET6) bytes=&reinterpret_cast<const sockaddr_in6 *>(address)->sin6_addr;
    else return {};
#ifdef _WIN32
    if(!InetNtopA(address->sa_family,bytes,text,sizeof(text))) return {};
#else
    if(!inet_ntop(address->sa_family,bytes,text,sizeof(text))) return {};
#endif
    return QString::fromLatin1(text);
}
LinkType packetLinkType(int type) {
    switch(type) {
    case DLT_EN10MB:return LinkType::Ethernet;
    case DLT_RAW:return LinkType::RawIp;
    case DLT_NULL:return LinkType::Loopback;
    case DLT_LINUX_SLL:return LinkType::LinuxCooked;
#ifdef DLT_LINUX_SLL2
    case DLT_LINUX_SLL2:return LinkType::LinuxCookedV2;
#endif
    default:throw Error(QStringLiteral("Неподдержанный канальный заголовок pcap: %1").arg(type));
    }
}
}
QString captureBackendVersion(){return QString::fromUtf8(api().pcap_lib_version_fn());}
std::vector<CaptureInterface> captureInterfaces() {
    auto &pcap=api();char error[PCAP_ERRBUF_SIZE]{};pcap_if_t *devices=nullptr;
    if(pcap.pcap_findalldevs_fn(&devices,error)<0) throw Error(QStringLiteral("Перечень pcap: ")+QString::fromUtf8(error));
    struct Guard{PcapApi &pcap;pcap_if_t *devices;~Guard(){if(devices)pcap.pcap_freealldevs_fn(devices);}}guard{pcap,devices};
    std::vector<CaptureInterface> result;
    for(const auto *device=devices;device;device=device->next) {
        if(!device->name) continue;
        CaptureInterface item;item.id=QString::fromUtf8(device->name);item.name=device->description?QString::fromUtf8(device->description):item.id;
        item.loopback=(device->flags&PCAP_IF_LOOPBACK)!=0;
        for(const auto *address=device->addresses;address;address=address->next){const auto text=addressText(address->addr);if(!text.isEmpty())item.addresses.push_back(text);}
        result.push_back(std::move(item));
    }
    return result;
}
struct Capture::Impl {
    PcapApi &pcap=api();
    pcap_t *handle=nullptr;
    LinkType link=LinkType::Ethernet;
    bool loopback=false;
    std::atomic_bool stop=false;
    std::atomic<quint64> received=0;
    ~Impl(){if(handle)pcap.pcap_close_fn(handle);}
};
QString captureFilter(const CaptureOptions &options) {
    if(options.interfaceId.trimmed().isEmpty() || options.interfaceId.size()>4096)throw Error(QStringLiteral("Выберите сетевой интерфейс"));
    if(options.tcpPorts.size()>64)throw Error(QStringLiteral("Область захвата допускает не более 64 TCP-портов"));
    QSet<quint16> unique;for(const auto port:options.tcpPorts){if(!port || unique.contains(port))throw Error(QStringLiteral("TCP-порты области должны быть уникальными числами 1..65535"));unique.insert(port);}
    QStringList scope;if(options.udpPort)scope<<QStringLiteral("udp port %1").arg(options.udpPort);
    auto ports=options.tcpPorts;std::sort(ports.begin(),ports.end());for(const auto port:ports)scope<<QStringLiteral("tcp port %1").arg(port);
    return scope.isEmpty()?QStringLiteral("ip or ip6"):QStringLiteral("(ip or ip6) and (%1)").arg(scope.join(" or "));
}
Capture::Capture(const CaptureOptions &options) {
    const auto filter=captureFilter(options);impl_=std::make_unique<Impl>();
    std::optional<CaptureInterface> selected;
    for(const auto &item:captureInterfaces())if(item.id==options.interfaceId || (options.interfaceId=="loopback" && item.loopback)){selected=item;break;}
    if(!selected) throw Error(QStringLiteral("Выбранный сетевой интерфейс недоступен"));
    auto &pcap=impl_->pcap;char error[PCAP_ERRBUF_SIZE]{};const auto name=selected->id.toUtf8();
    impl_->handle=pcap.pcap_create_fn(name.constData(),error);
    if(!impl_->handle) throw Error(QStringLiteral("Открытие pcap: ")+QString::fromUtf8(error));
    if(pcap.pcap_set_snaplen_fn(impl_->handle,maximumPacket)<0 || pcap.pcap_set_promisc_fn(impl_->handle,0)<0 || pcap.pcap_set_timeout_fn(impl_->handle,50)<0 || pcap.pcap_set_immediate_mode_fn(impl_->handle,1)<0)
        throw Error(QStringLiteral("Не удалось задать параметры захвата pcap"));
    const int activated=pcap.pcap_activate_fn(impl_->handle);
    if(activated<0) throw Error(QStringLiteral("Захват pcap недоступен: ")+QString::fromUtf8(pcap.pcap_geterr_fn(impl_->handle)));
    if(pcap.pcap_setnonblock_fn(impl_->handle,1,error)<0) throw Error(QStringLiteral("Неблокирующий захват pcap: ")+QString::fromUtf8(error));
    impl_->link=packetLinkType(pcap.pcap_datalink_fn(impl_->handle));impl_->loopback=selected->loopback;
    bpf_program program{};
    if(pcap.pcap_compile_fn(impl_->handle,&program,filter.toLatin1().constData(),1,PCAP_NETMASK_UNKNOWN)<0) throw Error(QStringLiteral("Фильтр pcap: ")+QString::fromUtf8(pcap.pcap_geterr_fn(impl_->handle)));
    const int installed=pcap.pcap_setfilter_fn(impl_->handle,&program);pcap.pcap_freecode_fn(&program);
    if(installed<0) throw Error(QStringLiteral("Не удалось включить фильтр захвата"));
}
Capture::~Capture()=default;
std::optional<CapturedPacket> Capture::poll(int timeoutMs) {
    if(timeoutMs<0 || timeoutMs>250) throw Error(QStringLiteral("Ожидание захвата должно быть 0..250 мс"));
    QElapsedTimer elapsed;elapsed.start();
    while(!impl_->stop.load()) {
        pcap_pkthdr *header=nullptr;const u_char *data=nullptr;const int result=impl_->pcap.pcap_next_ex_fn(impl_->handle,&header,&data);
        if(result==1) {
            if(!header || !data || !header->caplen || header->caplen>maximumPacket || header->len<header->caplen || header->ts.tv_sec<0 || header->ts.tv_usec<0 || header->ts.tv_usec>=1000000)
                throw Error(QStringLiteral("Некорректные метаданные пакета pcap"));
            CapturedPacket packet;packet.bytes=QByteArray(reinterpret_cast<const char *>(data),static_cast<int>(header->caplen));packet.originalLength=header->len;
            packet.timestampUs=static_cast<qint64>(header->ts.tv_sec)*1000000+header->ts.tv_usec;packet.linkType=impl_->link;packet.loopback=impl_->loopback;
            ++impl_->received;return packet;
        }
        if(result==-2) throw Error(QStringLiteral("Источник живого захвата неожиданно завершён"));
        if(result<0) throw Error(QStringLiteral("Чтение pcap: ")+QString::fromUtf8(impl_->pcap.pcap_geterr_fn(impl_->handle)));
        const auto remaining=timeoutMs-elapsed.elapsed();if(remaining<=0) return {};
        QThread::msleep(static_cast<unsigned long>(qMin<qint64>(remaining,10)));
    }
    return {};
}
void Capture::cancel(){impl_->stop=true;}
bool Capture::cancelled() const{return impl_->stop.load();}
CaptureStatistics Capture::statistics() const {
    CaptureStatistics result;result.received=impl_->received.load();pcap_stat value{};
    if(impl_->pcap.pcap_stats_fn(impl_->handle,&value)==0){result.dropsAvailable=true;result.dropped=value.ps_drop;result.interfaceDropped=value.ps_ifdrop;}
    return result;
}
}
