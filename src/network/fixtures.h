#pragma once
// Собственные безвредные байтовые примеры для проверки и воспроизводимого показа.
#include "capture.h"
#include <QHostAddress>
#include <QtEndian>

namespace resheto::network::fixtures {
inline void n16(QByteArray &b,int offset,quint16 value){qToBigEndian(value,b.data()+offset);}
inline void n32(QByteArray &b,int offset,quint32 value){qToBigEndian(value,b.data()+offset);}
inline quint16 checksum(const QByteArray &bytes) {
    quint32 sum=0;
    for(int i=0;i<bytes.size();i+=2)sum+=(static_cast<quint32>(static_cast<quint8>(bytes[i]))<<8)+(i+1<bytes.size()?static_cast<quint8>(bytes[i+1]):0);
    while(sum>>16)sum=(sum&65535)+(sum>>16);
    return static_cast<quint16>(~sum);
}
inline QByteArray ip(QByteArray transport,int protocol,const QString &source,const QString &destination) {
    const QHostAddress from(source),to(destination);const bool v6=from.protocol()==QAbstractSocket::IPv6Protocol;
    QByteArray pseudo,packet(v6?40:20,0);
    if(v6) {
        packet[0]=0x60;n16(packet,4,static_cast<quint16>(transport.size()));packet[6]=static_cast<char>(protocol);packet[7]=64;
        const auto a=from.toIPv6Address(),b=to.toIPv6Address();for(int i=0;i<16;++i){packet[8+i]=static_cast<char>(a[i]);packet[24+i]=static_cast<char>(b[i]);}
        pseudo=packet.mid(8,32)+QByteArray(8,0);n32(pseudo,32,static_cast<quint32>(transport.size()));pseudo[39]=static_cast<char>(protocol);
    } else {
        packet[0]=0x45;n16(packet,2,static_cast<quint16>(20+transport.size()));packet[8]=64;packet[9]=static_cast<char>(protocol);
        n32(packet,12,from.toIPv4Address());n32(packet,16,to.toIPv4Address());n16(packet,10,checksum(packet));
        pseudo=packet.mid(12,8)+QByteArray(4,0);pseudo[9]=static_cast<char>(protocol);n16(pseudo,10,static_cast<quint16>(transport.size()));
    }
    if(protocol==6 || protocol==17){auto value=checksum(pseudo+transport);if(!value)value=65535;n16(transport,protocol==6?16:6,value);}
    return packet+transport;
}
inline CapturedPacket raw(const QByteArray &bytes,qint64 timestampUs) {
    CapturedPacket packet;packet.bytes=bytes;packet.originalLength=static_cast<quint32>(bytes.size());packet.timestampUs=timestampUs;packet.linkType=LinkType::RawIp;return packet;
}
inline CapturedPacket tcp(qint64 timestampUs,quint16 sourcePort=40000,quint16 destinationPort=443,quint32 sequence=1,quint8 flags=2,const QString &source="192.0.2.1",const QString &destination="192.0.2.2") {
    QByteArray transport(20,0);n16(transport,0,sourcePort);n16(transport,2,destinationPort);n32(transport,4,sequence);transport[12]=0x50;transport[13]=static_cast<char>(flags);n16(transport,14,4096);
    return raw(ip(transport,6,source,destination),timestampUs);
}
inline CapturedPacket udp(qint64 timestampUs,const QByteArray &payload="own harmless UDP",quint16 sourcePort=40000,quint16 destinationPort=9000,const QString &source="192.0.2.1",const QString &destination="192.0.2.2") {
    QByteArray transport(8,0);n16(transport,0,sourcePort);n16(transport,2,destinationPort);n16(transport,4,static_cast<quint16>(8+payload.size()));return raw(ip(transport+payload,17,source,destination),timestampUs);
}
inline QByteArray dnsMessage(const QString &name,bool response=true,int rcode=3) {
    QByteArray message(12,0);n16(message,0,42);n16(message,2,static_cast<quint16>((response?0x8180:0x0100)|rcode));n16(message,4,1);
    for(const auto &label:name.toLatin1().split('.')){message.append(static_cast<char>(label.size()));message.append(label);}message.append('\0');message.append(QByteArray::fromHex("00010001"));return message;
}
inline CapturedPacket dns(qint64 timestampUs,const QString &name,int rcode=3) {return udp(timestampUs,dnsMessage(name,true,rcode),53,40000,"192.0.2.53","192.0.2.1");}
inline CapturedPacket wrapped(CapturedPacket packet,LinkType type,bool bigEndianNull=false) {
    const bool v6=(static_cast<quint8>(packet.bytes[0])>>4)==6;QByteArray prefix;
    if(type==LinkType::Ethernet){prefix=QByteArray(14,0);prefix[0]=2;prefix[6]=2;prefix[11]=1;n16(prefix,12,v6?0x86dd:0x0800);}
    else if(type==LinkType::Loopback){prefix=QByteArray(4,0);if(bigEndianNull)qToBigEndian<quint32>(v6?24:2,prefix.data());else qToLittleEndian<quint32>(v6?24:2,prefix.data());}
    else if(type==LinkType::LinuxCooked){prefix=QByteArray(16,0);n16(prefix,2,1);n16(prefix,4,6);n16(prefix,14,v6?0x86dd:0x0800);}
    else if(type==LinkType::LinuxCookedV2){prefix=QByteArray(20,0);n16(prefix,0,v6?0x86dd:0x0800);n32(prefix,4,1);n16(prefix,8,1);prefix[11]=6;}
    packet.bytes.prepend(prefix);packet.originalLength=static_cast<quint32>(packet.bytes.size());packet.linkType=type;return packet;
}
inline QByteArray pcap(const std::vector<CapturedPacket> &packets,LinkType type=LinkType::RawIp,bool little=true,bool nano=false) {
    QByteArray bytes(24,0);
    auto integer=[&](int offset,quint32 value,int size){for(int i=0;i<size;++i)bytes[offset+i]=static_cast<char>(value>>(8*(little?i:size-1-i)));};
    integer(0,nano?0xa1b23c4d:0xa1b2c3d4,4);integer(4,2,2);integer(6,4,2);integer(16,262144,4);integer(20,static_cast<quint32>(type),4);
    for(const auto &packet:packets){const int offset=static_cast<int>(bytes.size());bytes.append(QByteArray(16,0));integer(offset,static_cast<quint32>(packet.timestampUs/1000000),4);integer(offset+4,static_cast<quint32>((packet.timestampUs%1000000)*(nano?1000:1)),4);integer(offset+8,static_cast<quint32>(packet.bytes.size()),4);integer(offset+12,packet.originalLength,4);bytes.append(packet.bytes);}
    return bytes;
}
}
