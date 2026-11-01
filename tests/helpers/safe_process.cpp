#include <QCoreApplication>
#include <QProcess>
#include <QTextStream>
#include <chrono>
#include <thread>
#include <memory>
#include <vector>

// Явно запускаемый безопасный помощник: только свои дочерние процессы и ожидание.
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); const auto args=app.arguments();
    auto number=[&](const QString &name,int fallback) { const auto at=args.indexOf(name); if(at<0) return fallback; bool ok=false; const int n=at+1<args.size()?args[at+1].toInt(&ok):0; return ok?n:-1; };
    const int hold=number("--hold-ms",2500),children=number("--children",0),delay=number("--delay-ms",500);
    if(hold<500 || hold>10000 || children<0 || children>8 || delay<250 || delay>2000) return 2;
    if(args.contains("--child")) { std::this_thread::sleep_for(std::chrono::milliseconds(hold)); return 0; }
    QTextStream(stdout)<<"READY"<<Qt::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    std::vector<std::unique_ptr<QProcess>> processes;
    for(int i=0;i<children;++i) {
        auto p=std::make_unique<QProcess>(); p->setProgram(QCoreApplication::applicationFilePath()); p->setArguments({"--child","--hold-ms",QString::number(hold)});
        p->start(); if(!p->waitForStarted(2000)) return 2; processes.push_back(std::move(p));
    }
    for(auto &p:processes) if(!p->waitForFinished(hold+3000) || p->exitCode()!=0) return 2;
    if(children==0) std::this_thread::sleep_for(std::chrono::milliseconds(hold));
    return 0;
}
