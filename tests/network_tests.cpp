#include "network/api.h"
#include "network/fixtures.h"
#include <QFile>
#include <QJsonDocument>
#include <QMap>
#include <QSet>
#include <QTemporaryDir>
#include <QtTest>
#include <limits>
using namespace resheto;
using namespace resheto::network;
namespace fx=resheto::network::fixtures;
namespace {
template<class F>bool fails(F &&action){try{action();}catch(const Error &){return true;}return false;}
void put(const QString &path,const QByteArray &bytes){QFile f(path);if(!f.open(QIODevice::WriteOnly)||f.write(bytes)!=bytes.size())throw Error("fixture write");}
std::shared_ptr<const NetworkRules> workingRules(){return loadNetworkRules(QStringLiteral(RESHETO_SOURCE_DIR)+"/data/network_rules.json");}
std::shared_ptr<const NetworkRules> oneRule(const QString &kind,int threshold=3,int windowMs=2000,int suppressMs=2000) {
    auto document=workingRules()->document;QJsonArray rules;
    for(const auto &value:document["rules"].toArray())if(value.toObject()["kind"]==kind){auto rule=value.toObject();rule["threshold"]=threshold;rule["window_ms"]=windowMs;rule["suppress_ms"]=suppressMs;rules.append(rule);}
    document["rules"]=rules;return parseNetworkRules(document);
}
QMap<QString,QJsonObject> observe(NetworkAnalyzer &analyzer,const std::vector<CapturedPacket> &packets,bool acknowledge=true) {
    QMap<QString,QJsonObject> result;
    for(const auto &packet:packets){const auto update=analyzer.observe(packet);Counters::fromJson(update.counters.json());if(update.flow)Flow::fromJson(update.flow->json());for(const auto &flow:update.retiredFlows)Flow::fromJson(flow.json());for(const auto &d:update.detections){Detection::fromJson(d.json());result[d.id]=d.json();if(acknowledge)analyzer.acknowledge(d.id);}}
    return result;
}
}
class NetworkTests:public QObject {
    Q_OBJECT
private slots:
    void packetsAndLinkTypes() {
        for(const auto &address:QStringList{"192.0.2.1","2001:db8::1"}){
            const bool v6=address.contains(':');const auto destination=v6?QString("2001:db8::2"):QString("192.0.2.2");
            for(const auto type:{LinkType::RawIp,LinkType::Ethernet,LinkType::Loopback,LinkType::LinuxCooked,LinkType::LinuxCookedV2}){
                const auto packet=fx::wrapped(fx::tcp(1234567,40000,443,17,2,address,destination),type);const auto parsed=parsePacket(packet);
                QCOMPARE(parsed.state,QString("parsed"));QCOMPARE(parsed.packet.family,v6?6:4);QCOMPARE(parsed.packet.protocol,6);QCOMPARE(parsed.packet.sourceAddress,address);QCOMPARE(parsed.packet.destinationAddress,destination);QCOMPARE(parsed.packet.sourcePort,quint16(40000));QCOMPARE(parsed.packet.destinationPort,quint16(443));QCOMPARE(parsed.packet.tcpSequence,quint32(17));
            }
            QCOMPARE(parsePacket(fx::wrapped(fx::udp(5,"data",5000,5001,address,destination),LinkType::Loopback,true)).state,QString("parsed"));
        }
        auto vlan=fx::wrapped(fx::udp(100),LinkType::Ethernet);QByteArray tag=QByteArray::fromHex("00010800");vlan.bytes.replace(12,2,QByteArray::fromHex("8100"));vlan.bytes.insert(14,tag);vlan.originalLength=static_cast<quint32>(vlan.bytes.size());QCOMPARE(parsePacket(vlan).state,QString("parsed"));
    }
    void boundariesFragmentsAndDns() {
        auto packet=fx::tcp(100);for(int size=0;size<packet.bytes.size();++size){auto shortPacket=packet;shortPacket.bytes.truncate(size);shortPacket.originalLength=static_cast<quint32>(size);QVERIFY(parsePacket(shortPacket).state!="parsed");}
        auto bad=packet;bad.bytes[0]=0x44;QCOMPARE(parsePacket(bad).state,QString("malformed"));
        bad=packet;bad.bytes[32]=0x40;QCOMPARE(parsePacket(bad).code,QString("tcp_header"));
        bad=packet;bad.originalLength+=1;QCOMPARE(parsePacket(bad).state,QString("truncated"));
        auto fragment=fx::udp(200);fx::n16(fragment.bytes,6,1);const auto nonfirst=parsePacket(fragment);QCOMPARE(nonfirst.state,QString("fragment"));QVERIFY(!nonfirst.packet.hasTransport);
        fragment=fx::udp(200);fx::n16(fragment.bytes,6,0x2000);const auto first=parsePacket(fragment);QCOMPARE(first.state,QString("parsed"));QVERIFY(first.packet.fragmented && first.packet.hasTransport);QVERIFY(first.packet.dnsName.isEmpty());
        const auto dns=parsePacket(fx::dns(1000,"Test.Example.invalid"));QCOMPARE(dns.state,QString("parsed"));QCOMPARE(dns.packet.dnsName,QString("test.example.invalid"));QCOMPARE(dns.packet.dnsRcode,3);
        auto loop=fx::dnsMessage("x.invalid");loop.replace(12,loop.size()-12,QByteArray::fromHex("c00c00010001"));QCOMPARE(parsePacket(fx::udp(2000,loop,53,40000)).code,QString("dns_format"));
        auto truncated=fx::dnsMessage("x.invalid");fx::n16(truncated,2,0x8383);QCOMPARE(parsePacket(fx::udp(2000,truncated,53,40000)).code,QString("dns_format"));
        auto hugeChain=fx::tcp(1,10,20,1,2,"2001:db8::1","2001:db8::2");hugeChain.bytes[6]=0;QByteArray extensions(9*8,0);for(int i=0;i<9;++i)extensions[i*8]=static_cast<char>(i==8?6:0);hugeChain.bytes.insert(40,extensions);fx::n16(hugeChain.bytes,4,static_cast<quint16>(hugeChain.bytes.size()-40));hugeChain.originalLength=static_cast<quint32>(hugeChain.bytes.size());QCOMPARE(parsePacket(hugeChain).code,QString("ipv6_extensions"));
    }
    void classicPcapFormatsErrorsAndCancel() {
        QTemporaryDir directory;QVERIFY(directory.isValid());const auto path=directory.path()+"/own.pcap";
        for(bool little:{false,true})for(bool nano:{false,true}){
            put(path,fx::pcap({fx::tcp(1234567)},LinkType::RawIp,little,nano));PcapReader reader(path);const auto packet=reader.next();QVERIFY(packet);QCOMPARE(packet->timestampUs,qint64(1234567));QCOMPARE(parsePacket(*packet).state,QString("parsed"));QVERIFY(!reader.next());QCOMPARE(reader.packetCount(),qint64(1));
        }
        put(path,fx::pcap({fx::tcp(100)}));{PcapReader reader(path);std::atomic_bool cancel=true;QVERIFY(!reader.next(&cancel));QVERIFY(reader.cancelled());QCOMPARE(reader.packetCount(),qint64(0));}
        put(path,"not pcap");QVERIFY(fails([&]{PcapReader reader(path);}));
        auto bytes=fx::pcap({fx::tcp(100)});bytes.chop(1);put(path,bytes);QVERIFY(fails([&]{PcapReader reader(path);reader.next();}));
        bytes=fx::pcap({fx::tcp(100)});qToLittleEndian<quint32>(262145,bytes.data()+32);put(path,bytes);QVERIFY(fails([&]{PcapReader reader(path);reader.next();}));
        put(path,fx::pcap({fx::tcp(100)}));{PcapReader reader(path);QFile changed(path);QVERIFY(changed.open(QIODevice::Append));QVERIFY(changed.write("changed")==7);changed.close();QVERIFY(fails([&]{reader.next();}));}
        put(path,fx::pcap({fx::tcp(100)}));{
            PcapReader reader(path);QVERIFY(reader.next());
            const auto record=fx::pcap({fx::tcp(200)}).mid(24);
            QFile changed(path);QVERIFY(changed.open(QIODevice::Append));QCOMPARE(changed.write(record),record.size());changed.close();
            const auto later=reader.next();QVERIFY(later);QCOMPARE(later->timestampUs,qint64(200));
            QVERIFY(fails([&]{reader.next();}));
        }
    }
    void bidirectionalFlowAndStrictJson() {
        NetworkAnalyzer analyzer(workingRules());const auto a=analyzer.observe(fx::tcp(10,40000,443,1));QVERIFY(a.flow);
        const auto b=analyzer.observe(fx::tcp(20,443,40000,8,18,"192.0.2.2","192.0.2.1"));QVERIFY(b.flow);QCOMPARE(a.flow->id,b.flow->id);QCOMPARE(b.flow->packetsAToB,qint64(1));QCOMPARE(b.flow->packetsBToA,qint64(1));QCOMPARE(b.flow->bytesAToB,qint64(40));
        auto json=b.flow->json();QCOMPARE(Flow::fromJson(json).json(),json);json["key"]="forged";QVERIFY(fails([&]{Flow::fromJson(json);}));json=b.flow->json();json["last_us"]="9";QVERIFY(fails([&]{Flow::fromJson(json);}));json=b.flow->json();json["bytes_a_b"]="1";QVERIFY(fails([&]{Flow::fromJson(json);}));json=b.flow->json();json["packets_a_b"]="9223372036854775808";QVERIFY(fails([&]{Flow::fromJson(json);}));
        auto counters=b.counters.json();counters["packets"]="1";QVERIFY(fails([&]{Counters::fromJson(counters);}));
    }
    void workingRulesPositiveAndNegative() {
        std::vector<CapturedPacket> ports,periodic,domains;
        for(int i=0;i<20;++i){ports.push_back(fx::tcp(i*100000,static_cast<quint16>(40000+i),static_cast<quint16>(1000+i),static_cast<quint32>(i+1)));domains.push_back(fx::dns(i*100000,QString("own%1.example.invalid").arg(i)));}
        for(int i=0;i<6;++i)periodic.push_back(fx::tcp(i*1000000,static_cast<quint16>(40000+i),443,static_cast<quint32>(i+1)));
        for(const auto *packets:{&ports,&periodic,&domains}){NetworkAnalyzer analyzer(workingRules());const auto found=observe(analyzer,*packets);QCOMPARE(found.size(),1);QCOMPARE(analyzer.counters().detections,qint64(1));QVERIFY(!found.first()["basis"].toString().isEmpty());}
        ports.pop_back();{NetworkAnalyzer analyzer(workingRules());QVERIFY(observe(analyzer,ports).isEmpty());}
        {NetworkAnalyzer analyzer(workingRules());std::vector<CapturedPacket> retransmissions(30,fx::tcp(100,40000,443,7));QVERIFY(observe(analyzer,retransmissions).isEmpty());QCOMPARE(analyzer.counters().parsed,qint64(30));}
        {NetworkAnalyzer analyzer(workingRules());std::vector<CapturedPacket> irregular;const int times[]={0,1,2,4,7,11};for(int i=0;i<6;++i)irregular.push_back(fx::tcp(times[i]*1000000,static_cast<quint16>(40000+i),443,static_cast<quint32>(i+1)));QVERIFY(observe(analyzer,irregular).isEmpty());}
        {NetworkAnalyzer analyzer(workingRules());std::vector<CapturedPacket> normal;for(int i=0;i<30;++i)normal.push_back(fx::dns(i*100000,"same.example.invalid"));QVERIFY(observe(analyzer,normal).isEmpty());}
        {NetworkAnalyzer analyzer(workingRules());std::vector<CapturedPacket> normal;for(int i=0;i<30;++i)normal.push_back(fx::dns(i*100000,QString("normal%1.example.invalid").arg(i),0));QVERIFY(observe(analyzer,normal).isEmpty());}
    }
    void delayedAcknowledgementKeepsAllWindows() {
        std::vector<CapturedPacket> packets;
        for(int window=0;window<2;++window)for(int i=0;i<4;++i)packets.push_back(fx::tcp(window*4000000+i*100000,static_cast<quint16>(40000+i),static_cast<quint16>(1000+i),static_cast<quint32>(window*10+i+1)));
        NetworkAnalyzer immediate(oneRule("tcp_ports")),delayed(oneRule("tcp_ports"));const auto expected=observe(immediate,packets),actual=observe(delayed,packets,false);
        QCOMPARE(expected.size(),2);QCOMPARE(actual,expected);QCOMPARE(immediate.counters().detections,qint64(2));QCOMPARE(delayed.counters().detections,qint64(2));QCOMPARE(delayed.pendingDetections().size(),size_t(2));
        for(const auto &d:delayed.pendingDetections()){delayed.acknowledge(d.id);delayed.acknowledge(d.id);}QVERIFY(delayed.pendingDetections().empty());QVERIFY(fails([&]{delayed.acknowledge(QString(64,'0'));}));
    }
    void evidenceIsStrict() {
        std::vector<CapturedPacket> packets;for(int i=0;i<6;++i)packets.push_back(fx::tcp(i*1000000,static_cast<quint16>(40000+i),443,static_cast<quint32>(i+1)));
        NetworkAnalyzer analyzer(workingRules());const auto found=observe(analyzer,packets);QCOMPARE(found.size(),1);const auto original=found.first();
        auto broken=original;auto evidence=broken["evidence"].toObject();evidence["source_address"]="not an IP";broken["evidence"]=evidence;QVERIFY(fails([&]{Detection::fromJson(broken);}));
        broken=original;evidence=broken["evidence"].toObject();evidence["destination_port"]=70000;broken["evidence"]=evidence;QVERIFY(fails([&]{Detection::fromJson(broken);}));
        broken=original;evidence=broken["evidence"].toObject();auto items=evidence["items"].toArray();auto item=items[2].toObject();item["time_us"]="2500000";items[2]=item;evidence["items"]=items;broken["evidence"]=evidence;QVERIFY(fails([&]{Detection::fromJson(broken);}));
    }
    void zeroTcpPortsDoNotCreateInvalidEvidence() {
        NetworkAnalyzer analyzer(workingRules());bool diagnostic=false;
        for(int i=0;i<30;++i) {
            for(const auto &packet:{fx::tcp(i*100000,0,static_cast<quint16>(1000+i),static_cast<quint32>(i+1)),fx::tcp(i*100000,static_cast<quint16>(40000+i),0,static_cast<quint32>(i+1))}) {
                const auto update=analyzer.observe(packet);QVERIFY(update.flow);Flow::fromJson(update.flow->json());QVERIFY(update.detections.empty());
                for(const auto &item:update.diagnostics)diagnostic|=item.code=="tcp_zero_port";
            }
        }
        QVERIFY(diagnostic);QCOMPARE(analyzer.counters().parsed,qint64(60));QCOMPARE(analyzer.counters().detections,qint64(0));
    }
    void limitsAndReorderedPackets() {
        auto document=oneRule("tcp_ports",2)->document;auto limits=document["limits"].toObject();limits["max_flows"]=2;limits["max_rule_keys"]=2;limits["max_suppression_keys"]=1;document["limits"]=limits;
        NetworkAnalyzer analyzer(parseNetworkRules(document));analyzer.observe(fx::tcp(100,40000,1000,1));const auto hit=analyzer.observe(fx::tcp(200,40001,1001,2));QCOMPARE(hit.detections.size(),size_t(1));
        analyzer.observe(fx::tcp(300,40002,2000,3,2,"192.0.2.3","192.0.2.4"));QVERIFY(fails([&]{analyzer.observe(fx::tcp(400,40003,2001,4,2,"192.0.2.3","192.0.2.4"));}));QVERIFY(analyzer.activeFlows()<=2);QVERIFY(analyzer.counters().flowEvictions>0);
        NetworkAnalyzer order(workingRules());order.observe(fx::tcp(1000));const auto past=order.observe(fx::tcp(900,40001,444,2));QCOMPARE(past.counters.reordered,qint64(1));QCOMPARE(past.detections.size(),size_t(0));
        auto bad=workingRules()->document;bad["version"]=1;QVERIFY(fails([&]{parseNetworkRules(bad);}));bad=workingRules()->document;auto rules=bad["rules"].toArray();auto rule=rules[0].toObject();rule["kind"]="execute";rules[0]=rule;bad["rules"]=rules;QVERIFY(fails([&]{parseNetworkRules(bad);}));
    }
};
QTEST_GUILESS_MAIN(NetworkTests)
#include "network_tests.moc"
