#include "network/analyzer.h"
#include "network/fixtures.h"
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QTextStream>

using namespace resheto;
using namespace resheto::network;
namespace fx=resheto::network::fixtures;
namespace {
QString sha(const QByteArray &bytes) {return QString::fromLatin1(QCryptographicHash::hash(bytes,QCryptographicHash::Sha256).toHex());}
void writeNew(const QString &path,const QByteArray &bytes) {
    QFile file(path);
    if(!file.open(QIODevice::WriteOnly|QIODevice::NewOnly) || file.write(bytes)!=bytes.size() || !file.flush())
        throw Error(QStringLiteral("Не удалось записать новый файл: %1").arg(path));
}
std::vector<CapturedPacket> controlled(int ordinary,int ordinaryFlows,bool positives) {
    std::vector<CapturedPacket> packets;packets.reserve(ordinary+46);
    for(int i=0;i<ordinary;++i)
        packets.push_back(fx::udp(1000000+i*5,"own harmless datagram",static_cast<quint16>(30000+i%ordinaryFlows),9000));
    if(!positives) {
        packets.push_back(fx::tcp(2000000,40000,80,1));packets.push_back(fx::tcp(2100000,40001,443,2));return packets;
    }
    for(int i=0;i<20;++i)packets.push_back(fx::tcp(2000000+i*1000,40000,static_cast<quint16>(10000+i),i+1));
    for(int i=0;i<20;++i)packets.push_back(fx::dns(3000000+i*1000,QString("absent%1.example.invalid").arg(i)));
    for(int i=0;i<6;++i)packets.push_back(fx::tcp(4000000+i*1200000,static_cast<quint16>(45000+i),443,100+i));
    return packets;
}
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);QCommandLineParser args;args.addHelpOption();
    args.addOption({"output",QStringLiteral("Новый каталог для собственных PCAP"),"directory"});
    args.addOption({"rules",QStringLiteral("Проверяемый набор сетевых правил"),"file","data/network_rules.json"});
    try {
        if(!args.parse(app.arguments()))throw Error(args.errorText());
        if(args.isSet("help")){QTextStream(stdout)<<args.helpText();return 0;}
        if(args.value("output").trimmed().isEmpty())throw Error(QStringLiteral("Укажите новый каталог --output"));
        const auto rules=loadNetworkRules(args.value("rules"));
        const auto root=absolute(args.value("output"));
        if(!QDir().mkpath(QFileInfo(root).absolutePath()) || !QDir().mkdir(root))throw Error(QStringLiteral("Нужен новый выходной каталог: ")+root);
        QJsonArray files;
        auto generate=[&](const QString &name,int packets,int flows,bool positives){
            const auto records=controlled(packets,flows,positives);const auto bytes=fx::pcap(records);
            writeNew(root+"/"+name,bytes);
            files.append(QJsonObject{{"file",name},{"sha256",sha(bytes)},{"packets",static_cast<qint64>(records.size())},{"bytes",bytes.size()}});
        };
        generate("ordinary.pcap",100,20,false);
        generate("control.pcap",2101,2101,true);
        generate("profile-100k.pcap",99954,2048,true);
        const auto manifest=QJsonDocument(QJsonObject{{"format","resheto-network-fixtures-v1"},{"rules_version",rules->version},
            {"rules_compact_sha256",sha(QJsonDocument(rules->document).toJson(QJsonDocument::Compact))},{"files",files}}).toJson(QJsonDocument::Indented);
        writeNew(root+"/manifest.json",manifest);QTextStream(stdout)<<manifest;return 0;
    }catch(const Error &error){QTextStream(stderr)<<error.message<<Qt::endl;return 2;}
}
