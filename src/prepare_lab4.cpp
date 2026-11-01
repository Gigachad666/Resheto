#include "core/api.h"
#include "fixtures.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
using namespace resheto;
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); QCommandLineParser p; p.addHelpOption(); p.addOption({"output",QStringLiteral("Новый выходной каталог"),"directory"});
    p.addOption({"heuristics",QStringLiteral("Исходные эвристические правила"),"file"}); p.addOption({"behavior",QStringLiteral("Исходные поведенческие правила"),"file"});
    try {
        if(!p.parse(app.arguments())) throw Error(p.errorText()); if(p.isSet("help")) { QTextStream(stdout)<<p.helpText(); return 0; }
        if(!p.isSet("output") || !p.isSet("heuristics") || !p.isSet("behavior")) throw Error(QStringLiteral("Требуются --output --heuristics --behavior"));
        loadHeuristicRules(p.value("heuristics")); loadBehaviorRules(p.value("behavior")); const auto root=absolute(p.value("output"));
        if(QFileInfo::exists(root)) throw Error(QStringLiteral("Нужен новый выходной каталог")); if(!QDir().mkpath(root+"/fixtures")) throw Error(QStringLiteral("Не создать каталог"));
        if(!QFile::copy(p.value("heuristics"),root+"/heuristic_rules.json") || !QFile::copy(p.value("behavior"),root+"/behavior_rules.json")) throw Error(QStringLiteral("Не скопировать правила"));
        auto put=[&](const QString &name,const QByteArray &bytes){QFile f(root+"/fixtures/"+name); if(!f.open(QIODevice::WriteOnly) || f.write(bytes)!=bytes.size()) throw Error(QStringLiteral("Ошибка подготовки безопасных байтов"));};
        put("positive.exe",fixtures::pe(true)); put("negative.exe",fixtures::pe(false)); put("positive.elf",fixtures::elf(true)); put("negative.elf",fixtures::elf(false));
        put("renamed.txt",fixtures::pe(false)); put("broken.exe","MZ");
        QTextStream(stdout)<<QStringLiteral("Подготовлены безопасные PE/ELF и правила: ")<<root<<Qt::endl; return 0;
    } catch(const Error &e) { QTextStream(stderr)<<e.message<<Qt::endl; return 2; }
}
