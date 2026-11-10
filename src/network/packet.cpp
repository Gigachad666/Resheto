#include "packet.h"
#include <QHostAddress>
#include <QSet>

namespace resheto::network {
namespace {
quint16 u16(const QByteArray &b,int p){return static_cast<quint16>((static_cast<quint8>(b[p])<<8)|static_cast<quint8>(b[p+1]));}
quint32 u32(const QByteArray &b,int p){return (static_cast<quint32>(u16(b,p))<<16)|u16(b,p+2);}
QString ipText(const QByteArray &b,int p,int family){if(family==4)return QHostAddress(u32(b,p)).toString();Q_IPV6ADDR a{};for(int i=0;i<16;++i)a[i]=static_cast<quint8>(b[p+i]);return QHostAddress(a).toString();}
QString dnsName(const QByteArray &b,int &position) {
    QStringList labels;QSet<int> visited;int offset=position,after=-1,total=0;
    for(int step=0;step<128;++step) {
        if(offset<0 || offset>=b.size() || visited.contains(offset))throw Error("dns_name");visited.insert(offset);
        const auto length=static_cast<quint8>(b[offset++]);
        if((length&0xc0)==0xc0){if(offset>=b.size())throw Error("dns_pointer");const int target=((length&0x3f)<<8)|static_cast<quint8>(b[offset++]);if(after<0)after=offset;offset=target;continue;}
        if(length&0xc0)throw Error("dns_label");
        if(!length){position=after<0?offset:after;return labels.join('.').toLower();}
        if(length>63 || offset+length>b.size() || total+length+1>254)throw Error("dns_length");
        QString label;for(int i=0;i<length;++i){const auto ch=static_cast<quint8>(b[offset+i]);if(ch>=33 && ch<=126 && ch!='.' && ch!='\\')label+=QChar(ch);else label+='\\'+QString::number(ch).rightJustified(3,'0');}
        labels.push_back(label);total+=length+1;offset+=length;
    }
    throw Error("dns_chain");
}
void dns(const QByteArray &b,PacketInfo &packet) {
    if(b.size()<12)throw Error("dns_header");
    const auto flags=u16(b,2);if(flags&0x0200)throw Error("dns_truncated");
    if(((flags>>11)&15)!=0 || u16(b,4)!=1)return;
    int offset=12;const auto name=dnsName(b,offset);if(offset+4>b.size())throw Error("dns_question");
    const auto type=u16(b,offset),klass=u16(b,offset+2);offset+=4;
    const int records=static_cast<int>(u16(b,6))+u16(b,8)+u16(b,10);if(records>128)throw Error("dns_record_limit");
    for(int i=0;i<records;++i){dnsName(b,offset);if(offset+10>b.size())throw Error("dns_record");const int length=u16(b,offset+8);offset+=10;if(offset+length>b.size())throw Error("dns_record_data");offset+=length;}
    if(offset!=b.size())throw Error("dns_trailing_data");
    if(klass==1 && (type==1 || type==28 || type==255)){packet.dnsName=name;packet.dnsResponse=(flags&0x8000)!=0;packet.dnsRcode=flags&15;}
}
}
PacketResult parsePacket(const CapturedPacket &input) {
    PacketResult result;auto &packet=result.packet;packet.timestampUs=input.timestampUs;packet.capturedBytes=static_cast<quint32>(input.bytes.size());packet.originalBytes=input.originalLength;
    auto fail=[&](const QString &state,const QString &code,const QString &reason){result.state=state;result.code=code;result.reason=reason;return result;};
    const auto &b=input.bytes; if(input.timestampUs<0 || b.isEmpty() || b.size()>262144 || input.originalLength<static_cast<quint32>(b.size()))return fail("malformed","capture_record",QStringLiteral("Некорректные метаданные пакета"));
    if(input.originalLength>static_cast<quint32>(b.size()))return fail("truncated","capture_truncated",QStringLiteral("Захвачена только часть исходного кадра"));
    int offset=0;quint16 etherType=0;quint32 nullFamily=0;
    switch(input.linkType) {
    case LinkType::Ethernet:
        if(b.size()<14)return fail("truncated","ethernet_header",QStringLiteral("Обрезан Ethernet-заголовок"));
        etherType=u16(b,12);offset=14;
        for(int tags=0;etherType==0x8100 || etherType==0x88a8;++tags){if(tags>=2)return fail("unsupported","vlan_depth",QStringLiteral("Поддержаны не более двух VLAN-заголовков"));if(offset+4>b.size())return fail("truncated","vlan_header",QStringLiteral("Обрезан VLAN-заголовок"));etherType=u16(b,offset+2);offset+=4;}
        break;
    case LinkType::RawIp:break;
    case LinkType::Loopback:
        if(b.size()<4)return fail("truncated","null_header",QStringLiteral("Обрезан loopback-заголовок"));
        nullFamily=u32(b,0);if(nullFamily!=2 && nullFamily!=10 && nullFamily!=24 && nullFamily!=28 && nullFamily!=30)nullFamily=static_cast<quint32>(static_cast<quint8>(b[0]))|(static_cast<quint32>(static_cast<quint8>(b[1]))<<8)|(static_cast<quint32>(static_cast<quint8>(b[2]))<<16)|(static_cast<quint32>(static_cast<quint8>(b[3]))<<24);
        if(nullFamily!=2 && nullFamily!=10 && nullFamily!=24 && nullFamily!=28 && nullFamily!=30)return fail("malformed","null_family",QStringLiteral("Неизвестное семейство loopback-заголовка"));offset=4;break;
    case LinkType::LinuxCooked:
        if(b.size()<16)return fail("truncated","sll_header",QStringLiteral("Обрезан Linux SLL-заголовок"));etherType=u16(b,14);offset=16;break;
    case LinkType::LinuxCookedV2:
        if(b.size()<20)return fail("truncated","sll2_header",QStringLiteral("Обрезан Linux SLL2-заголовок"));etherType=u16(b,0);offset=20;break;
    default:return fail("unsupported","link_type",QStringLiteral("Неподдержанный канальный заголовок"));
    }
    if(etherType && etherType!=0x0800 && etherType!=0x86dd)return fail("unsupported","network_protocol",QStringLiteral("Вне области IPv4/IPv6"));
    if(offset>=b.size())return fail("truncated","ip_header",QStringLiteral("Нет IP-заголовка"));
    packet.family=static_cast<quint8>(b[offset])>>4;
    if(nullFamily && ((nullFamily==2 && packet.family!=4)||(nullFamily!=2 && packet.family!=6)))return fail("malformed","null_family",QStringLiteral("Семейство loopback не соответствует IP"));
    if(etherType && ((etherType==0x0800 && packet.family!=4)||(etherType==0x86dd && packet.family!=6)))return fail("malformed","ip_version",QStringLiteral("Тип кадра не соответствует версии IP"));
    int end=0,transport=0;bool firstFragment=false;
    if(packet.family==4) {
        if(offset+20>b.size())return fail("truncated","ipv4_header",QStringLiteral("Обрезан IPv4-заголовок"));
        const int header=(static_cast<quint8>(b[offset])&15)*4,total=u16(b,offset+2);if(header<20 || total<header)return fail("malformed","ipv4_length",QStringLiteral("Некорректная длина IPv4"));
        if(offset+header>b.size() || offset+total>b.size())return fail("truncated","ipv4_payload",QStringLiteral("IPv4-пакет захвачен не полностью"));
        end=offset+total;transport=offset+header;packet.protocol=static_cast<quint8>(b[offset+9]);packet.sourceAddress=ipText(b,offset+12,4);packet.destinationAddress=ipText(b,offset+16,4);
        const auto fragments=u16(b,offset+6);packet.fragmented=(fragments&0x3fff)!=0;
        if(fragments&0x1fff)return fail("fragment","ip_fragment",QStringLiteral("IP-фрагмент без транспортного заголовка; сборка не выполняется"));firstFragment=packet.fragmented;
    } else if(packet.family==6) {
        if(offset+40>b.size())return fail("truncated","ipv6_header",QStringLiteral("Обрезан IPv6-заголовок"));
        const int length=u16(b,offset+4);if(!length)return fail("unsupported","ipv6_jumbo",QStringLiteral("IPv6 jumbogram не поддержан"));
        end=offset+40+length;if(end>b.size())return fail("truncated","ipv6_payload",QStringLiteral("IPv6-пакет захвачен не полностью"));
        packet.sourceAddress=ipText(b,offset+8,6);packet.destinationAddress=ipText(b,offset+24,6);transport=offset+40;int next=static_cast<quint8>(b[offset+6]);
        for(int extensions=0;next==0 || next==43 || next==60 || next==44 || next==51;++extensions) {
            if(extensions>=8)return fail("unsupported","ipv6_extensions",QStringLiteral("Цепочка IPv6-заголовков длиннее восьми"));
            if(transport+2>end)return fail("malformed","ipv6_extension",QStringLiteral("Обрезан дополнительный IPv6-заголовок"));
            const int kind=next;next=static_cast<quint8>(b[transport]);int size=0;
            if(kind==44){size=8;if(transport+size>end)return fail("malformed","ipv6_fragment",QStringLiteral("Обрезан заголовок фрагмента"));const auto bits=u16(b,transport+2);packet.fragmented=true;if(bits&0xfff8)return fail("fragment","ip_fragment",QStringLiteral("IPv6-фрагмент без транспорта; сборка не выполняется"));firstFragment=(bits&1)!=0;}
            else size=kind==51?(static_cast<quint8>(b[transport+1])+2)*4:(static_cast<quint8>(b[transport+1])+1)*8;
            if(size<8 || transport+size>end)return fail("malformed","ipv6_extension_length",QStringLiteral("Некорректная длина IPv6-заголовка"));transport+=size;
        }
        packet.protocol=next;
    } else return fail("unsupported","ip_version",QStringLiteral("Вне области IPv4/IPv6"));
    if(packet.protocol!=6 && packet.protocol!=17)return fail("unsupported","transport_protocol",QStringLiteral("Вне области TCP/UDP; шифрованный ESP не разбирается"));
    const int minimum=packet.protocol==6?20:8;if(transport+minimum>end)return fail(firstFragment?"fragment":"malformed","transport_header",QStringLiteral("Недостаточно транспортного заголовка"));
    packet.sourcePort=u16(b,transport);packet.destinationPort=u16(b,transport+2);packet.hasTransport=true;
    if(packet.protocol==6){const int header=(static_cast<quint8>(b[transport+12])>>4)*4;if(header<20 || transport+header>end)return fail(firstFragment?"fragment":"malformed","tcp_header",QStringLiteral("Некорректная длина TCP-заголовка"));packet.tcpFlags=static_cast<quint8>(b[transport+13]);packet.tcpSequence=u32(b,transport+4);}
    else {const int length=u16(b,transport+4);if(length<8 || (!firstFragment && transport+length>end))return fail("malformed","udp_length",QStringLiteral("Некорректная длина UDP"));
        if(!firstFragment && (packet.sourcePort==53 || packet.destinationPort==53)){try{dns(b.mid(transport+8,length-8),packet);}catch(const Error &){return fail("malformed","dns_format",QStringLiteral("Некорректный или обрезанный DNS-заголовок/имя"));}}}
    result.state="parsed";if(firstFragment){result.code="first_fragment";result.reason=QStringLiteral("Учтён транспорт первого фрагмента, DNS недоступен без сборки");}return result;
}
}
