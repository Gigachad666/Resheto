#include "pcap.h"
#include <QFileInfo>

namespace resheto::network {
namespace {
quint32 integer(const QByteArray &b,int p,bool little,int size) {quint32 n=0;for(int i=0;i<size;++i)n|=static_cast<quint32>(static_cast<quint8>(b[p+i]))<<(8*(little?i:size-1-i));return n;}
}
PcapReader::PcapReader(const QString &path):file_(path) {
    const auto header=file_.read(24);if(header.size()!=24)throw Error(QStringLiteral("Обрезан заголовок PCAP"));const auto magic=header.left(4).toHex();
    if(magic=="d4c3b2a1"){little_=true;nano_=false;}else if(magic=="a1b2c3d4"){little_=false;nano_=false;}else if(magic=="4d3cb2a1"){little_=true;nano_=true;}else if(magic=="a1b23c4d"){little_=false;nano_=true;}else throw Error(QStringLiteral("Поддержан classic PCAP; формат pcapng или иной заголовок недоступен"));
    if(integer(header,4,little_,2)!=2 || integer(header,6,little_,2)!=4)throw Error(QStringLiteral("Нужен PCAP версии 2.4"));
    snapLength_=integer(header,16,little_,4);if(!snapLength_ || snapLength_>262144)throw Error(QStringLiteral("snaplen PCAP должен быть 1..262144"));
    const auto link=integer(header,20,little_,4);switch(link){case 0:case 1:case 101:case 113:case 276:link_=static_cast<LinkType>(link);break;default:throw Error(QStringLiteral("Неподдержанный LINKTYPE PCAP: %1").arg(link));}
}
std::optional<CapturedPacket> PcapReader::next(const std::atomic_bool *cancel) {
    if(cancelled_ || (cancel && cancel->load())){cancelled_=true;return {};}
    const auto header=file_.read(16);if(header.isEmpty()){if(!file_.unchanged())throw Error(QStringLiteral("PCAP-файл изменился во время чтения"));return {};}
    if(header.size()!=16)throw Error(QStringLiteral("Обрезан заголовок записи PCAP"));
    if(packets_>=10000000)throw Error(QStringLiteral("Предел PCAP: 10000000 пакетов за задание"));
    const auto seconds=integer(header,0,little_,4),fraction=integer(header,4,little_,4),captured=integer(header,8,little_,4),original=integer(header,12,little_,4);
    if(fraction>=(nano_?1000000000u:1000000u) || captured>snapLength_ || original<captured || original>262144)throw Error(QStringLiteral("Некорректные время или длины записи PCAP"));
    CapturedPacket packet;packet.bytes=file_.read(captured);if(packet.bytes.size()!=captured)throw Error(QStringLiteral("Обрезаны данные пакета PCAP"));
    // На Windows проверка имени открывает второй handle. Проверяем первый пакет,
    // затем каждые 256 записей и EOF, чтобы не делать это для каждого кадра.
    if((packets_==0 || (packets_+1)%256==0) && !file_.unchanged())throw Error(QStringLiteral("PCAP-файл изменился во время чтения"));
    packet.originalLength=original;packet.timestampUs=static_cast<qint64>(seconds)*1000000+(nano_?fraction/1000:fraction);packet.linkType=link_;++packets_;return packet;
}
}
