#include "network/session.h"
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QMap>
#include <QTextStream>
#include <QTimer>
using namespace resheto;
using namespace resheto::network;
namespace {
int positive(const QString &text,int maximum){bool good=false;const int value=text.toInt(&good);if(!good || value<=0 || value>maximum || QString::number(value)!=text)throw Error(QStringLiteral("Ожидается целое число 1..%1: %2").arg(maximum).arg(text));return value;}
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);bool argumentsReady=false;
    try {
        const auto arguments=app.arguments().mid(1);
        if(arguments==QStringList{"--help"}){QTextStream(stdout)<<QStringLiteral("Решето: сетевой анализ отдельным процессом\n--pcap <файл> | --interface <id> --rules <json> --storage <db>\n[--duration-ms <мс>] [--udp-port <1..65535>] [--tcp-ports <порт,порт,...>] [--cancel-after-ms <мс>]\nДля интерфейса --duration-ms принимает 0 или 100..3600000, по умолчанию 30000. 0 отключает таймер.\nДля штатной отмены из CLI задайте --cancel-after-ms.\nИнтерфейсы: resheto-network-worker --interfaces\n")<<Qt::endl;return 0;}
        QMap<QString,QString> values;const QStringList allowed{"--pcap","--interface","--rules","--storage","--duration-ms","--udp-port","--tcp-ports","--cancel-after-ms"};
        for(int i=0;i<arguments.size();i+=2){if(!allowed.contains(arguments[i]) || i+1>=arguments.size() || arguments[i+1].startsWith("--") || values.contains(arguments[i]))throw Error(QStringLiteral("Неизвестный, повторный или незавершённый аргумент: ")+arguments[i]);values[arguments[i]]=arguments[i+1];}
        if(values.contains("--pcap")==values.contains("--interface") || !values.contains("--rules") || !values.contains("--storage"))throw Error(QStringLiteral("Нужны один источник (--pcap/--interface), --rules и --storage"));
        NetworkRequest request;request.analysis.source=values.contains("--pcap")?"pcap":"live";request.analysis.input=values.value(request.analysis.source=="pcap"?"--pcap":"--interface");request.analysis.durationMs=request.analysis.source=="pcap"?0:30000;
        if(values.contains("--duration-ms"))request.analysis.durationMs=values["--duration-ms"]=="0"?0:positive(values["--duration-ms"],maximumDurationMs);
        if(values.contains("--udp-port"))request.analysis.capture.udpPort=static_cast<quint16>(positive(values["--udp-port"],65535));
        if(values.contains("--tcp-ports"))for(const auto &value:values["--tcp-ports"].split(','))request.analysis.capture.tcpPorts.push_back(static_cast<quint16>(positive(value,65535)));
        request.rulesPath=values["--rules"];request.storagePath=values["--storage"];request.workerPath=QDir(QCoreApplication::applicationDirPath()).filePath(
#ifdef Q_OS_WIN
            "resheto-network-worker.exe"
#else
            "resheto-network-worker"
#endif
        );
        const int cancelAfter=values.contains("--cancel-after-ms")?positive(values["--cancel-after-ms"],3600000):0;
        request=prepareNetworkRequest(std::move(request));argumentsReady=true;NetworkSession session;session.submit(std::move(request));QElapsedTimer elapsed;elapsed.start();QTimer timer;
        QObject::connect(&timer,&QTimer::timeout,&app,[&]{if(cancelAfter && elapsed.elapsed()>=cancelAfter)session.cancel();if(!session.busy()){const auto job=session.progress();if(!job){app.exit(2);return;}QTextStream(stdout)<<QJsonDocument(QJsonObject{{"type","network_job"},{"job",job->json()}}).toJson(QJsonDocument::Compact)<<Qt::endl;app.exit(job->exitCode());}});timer.start(50);return app.exec();
    }catch(const Error &error){QTextStream(stdout)<<QJsonDocument(QJsonObject{{"type","error"},{"code",argumentsReady?"network_error":"invalid_arguments"},{"error",error.message}}).toJson(QJsonDocument::Compact)<<Qt::endl;return 2;}
}
