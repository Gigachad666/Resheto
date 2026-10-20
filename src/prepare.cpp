#include "core/signatures.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTextStream>

using namespace resheto;
static void write(const QString &p,const QByteArray &b) {
    QFile f(p);
    if(!f.open(QIODevice::WriteOnly|QIODevice::NewOnly) || f.write(b)!=b.size()) throw Error(QStringLiteral("Ошибка создания фикстуры: ")+p);
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); app.setApplicationName("resheto-prepare");
    QCommandLineParser parser; parser.setApplicationDescription(QStringLiteral("Подготовка безопасных тестовых данных АС Решето; выходной каталог должен отсутствовать")); parser.addHelpOption();
    parser.addOption({"source",QStringLiteral("JSON сигнатур"),"json"});
    parser.addOption({"output",QStringLiteral("Новый тестовый каталог"),"dir"});
    parser.addOption({"large-mib",QStringLiteral("Дополнительная фикстура 0..4096 МиБ"),"n","0"});
    parser.addOption({"database-only",QStringLiteral("Создать только базу из JSON")});
    parser.process(app);
    try {
        if(!parser.isSet("source") || !parser.isSet("output")) throw Error(QStringLiteral("Требуются --source и --output"));
        const auto dest=absolute(parser.value("output"));
        if(QFileInfo::exists(dest)) throw Error(QStringLiteral("Каталог уже существует; выберите новый --output"));
        bool ok=false; int large=parser.value("large-mib").toInt(&ok);
        if(!ok || large<0 || large>4096) throw Error(QStringLiteral("large-mib вне 0..4096"));
        if(!QDir().mkpath(dest)) throw Error(QStringLiteral("Не создать выходной каталог"));
        createSignatures(parser.value("source"),dest+"/signatures.db");
        if(!parser.isSet("database-only")) {
            QDir().mkpath(dest+QStringLiteral("/fixtures/вложенный каталог"));
            const auto dir=dest+"/fixtures/";
            QJsonArray expected;
            auto fixture=[&](const QString &name,const QByteArray &bytes,const QString &id,qint64 offset=-1) {
                write(dir+name,bytes);
                expected.push_back(QJsonObject{{"path",name},{"outcome",id.isEmpty()?"no_match":"signature_match"},{"signature_id",id},{"offset",QString::number(offset)}});
            };
            fixture("hash.bin","Resheto HASH fixture v1\n","test-hash");
            fixture("hash-changed.bin","Resheto HASH fixture v2\n",{});
            fixture("exact.bin",QByteArray("prefix\0",7)+QByteArray::fromHex("00ff5245534845544f00")+"end","test-exact",7);
            fixture("exact-near.bin",QByteArray::fromHex("00fe5245534845544f00"),{});
            fixture("masked.bin",QByteArray::fromHex("ab77cd12"),"test-mask",0);
            fixture("masked-near.bin",QByteArray::fromHex("ab77ce12"),{});
            QByteArray fixed(32,'z'); fixed.replace(17,4,QByteArray::fromHex("feed0062"));
            fixture("fixed.bin",fixed,"test-fixed",17);
            fixed.replace(17,4,"zzzz"); fixed.replace(18,4,QByteArray::fromHex("feed0062"));
            fixture("fixed-near.bin",fixed,{});
            QByteArray boundary(65534,'q'); boundary+=QByteArray::fromHex("d1d200d3d4"); boundary+="tail";
            fixture("boundary.bin",boundary,"test-boundary",65534);
            fixture("empty",{},{});
            fixture(QStringLiteral("вложенный каталог/данные с пробелом.dat"),"ordinary harmless bytes",{});
            if(large>0) {
                QFile file(dir+"large.bin");
                if(!file.open(QIODevice::WriteOnly|QIODevice::NewOnly)) throw Error(QStringLiteral("Не создать large.bin"));
                QByteArray chunk(1024*1024,'q');
                for(int i=0;i<large;++i) if(file.write(chunk)!=chunk.size()) throw Error(QStringLiteral("Ошибка записи large.bin"));
                expected.push_back(QJsonObject{{"path","large.bin"},{"outcome","no_match"},{"signature_id",""},{"offset","-1"}});
            }
            write(dest+"/expected.json",QJsonDocument(expected).toJson());
        }
        QTextStream(stdout)<<QStringLiteral("Подготовлено: ")<<dest<<Qt::endl; return 0;
    } catch(const Error &e) { QTextStream(stderr)<<e.message<<Qt::endl; return 2; }
}
