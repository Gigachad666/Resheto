#include <core/api.h>
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QElapsedTimer>
#include <QTextStream>
#include <thread>
#include <chrono>
using namespace resheto;
namespace {
void require(bool good,const QString &message) { if(!good) throw Error(message); }
template<class F> void until(F condition,int timeout=6000) {
    QElapsedTimer timer; timer.start(); while(!condition() && timer.elapsed()<timeout) std::this_thread::sleep_for(std::chrono::milliseconds(20));
    require(condition(),QStringLiteral("Истёк срок ожидания внешнего потребителя"));
}
void copyBytes(const QString &source,const QString &target) {
    QFile from(source),to(target); require(from.open(QIODevice::ReadOnly) && to.open(QIODevice::WriteOnly),QStringLiteral("Не открыть собственные контрольные данные"));
    const auto bytes=from.readAll(); require(to.write(bytes)==bytes.size(),QStringLiteral("Не записать контрольные данные"));
}
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    if(argc!=6) { QTextStream(stderr)<<"lab4-consumer <signature-db> <heuristic-rules> <positive-file> <negative-file> <new-output-directory>\n"; return 2; }
    try {
        const auto args=app.arguments(); const auto root=absolute(args[5]); require(!QFileInfo::exists(root),QStringLiteral("Нужен новый выходной каталог")); require(QDir().mkpath(root+"/observed"),QStringLiteral("Не создать каталог"));
        Request r; r.signaturePath=args[1]; r.heuristicPath=args[2]; r.path=args[3]; r.storagePath=root+"/manual.db";
        const auto positive=runJob(r); require(positive.matches==1 && positive.exitCode()==1,QStringLiteral("Эвристика не обнаружила положительный контроль"));
        r.path=args[4]; require(runJob(r).exitCode()==0,QStringLiteral("Отрицательный контроль"));
        r.path=args[3]+".missing"; require(runJob(r).exitCode()==2,QStringLiteral("Ошибка отсутствующего объекта"));
        r.path=args[3]; r.cancel->store(true); require(runJob(r).exitCode()==3,QStringLiteral("Предварительная отмена нового маршрута")); r.cancel->store(false);
        MonitorRequest watch; watch.directory=root+"/observed"; watch.storagePath=root+"/monitor.db"; watch.signaturePath=args[1]; watch.heuristicPath=args[2]; watch.files=true; watch.processes=false;
        MonitorRuntime runtime; require(runtime.start(watch),QStringLiteral("Не запустить Runtime")); until([&]{return runtime.status().ready || !runtime.status().active;}); require(runtime.status().ready, runtime.status().reason);
        copyBytes(args[4],watch.directory+"/file.exe"); until([&]{return runtime.status().fileEvents>=1;});
        copyBytes(args[3],watch.directory+"/file.exe"); until([&]{return runtime.status().job.matches>=1;});
        r.path=args[4]; r.storagePath=watch.storagePath; const auto parallelManual=runJob(r); require(parallelManual.exitCode()==0 && runtime.status().active,QStringLiteral("Ручной маршрут мешает наблюдению")); runtime.cancel(); runtime.wait();
        const auto j=runtime.status().job; require(j.exitCode()==3,QStringLiteral("Неверный приоритет отмены"));
        { Store reopened(watch.storagePath,true); require(reopened.getJob(j.id)->id==j.id && reopened.getJob(parallelManual.id)->id==parallelManual.id,QStringLiteral("Раздельное повторное чтение заданий")); ResultQuery q; q.filter=ResultFilter::Matches;
          const auto rows=reopened.query(j.id,q).rows; require(!rows.empty() && rows.front().outcome=="heuristic_match" && !rows.front().eventId.isEmpty() && !rows.front().details.isEmpty(),QStringLiteral("Не сохранены основания/событие")); }
        // Собственный уже запущенный consumer — безопасный baseline процесс для проверки файла образа.
        watch.files=false; watch.processes=true; watch.scanProcessImages=true; watch.processImageDirectory=QCoreApplication::applicationDirPath();
        require(runtime.start(watch),QStringLiteral("Процессный запуск Runtime")); until([&]{return runtime.status().processImages>=1 || !runtime.status().active;}); require(runtime.status().processImages>=1,runtime.status().reason); runtime.cancel(); runtime.wait();
        { Store reopened(watch.storagePath,true); const auto imageJob=reopened.getJob(runtime.status().job.id); require(bool(imageJob),QStringLiteral("Процессное задание не сохранилось")); ResultQuery q; q.object=ResultObject::Processes; q.text=QString::number(QCoreApplication::applicationPid());
          const auto rows=reopened.query(imageJob->id,q).rows; require(!rows.empty() && rows.front().analyzers.contains("HEURISTIC"),QStringLiteral("Файл процесса не прошёл статический анализ")); const auto context=reopened.observation(imageJob->id,rows.front().eventId); require(context && (*context)["type"]=="process_image",QStringLiteral("Потеряна связь PID+старт")); }
        QTextStream(stdout)<<QStringLiteral("Внешний вызов: PE-эвристика, отрицательный контроль, create/modify, параллельные задания, файл процесса, отмена и повторное чтение — успешно\n"); return 0;
    } catch(const Error &e) { QTextStream(stderr)<<e.message<<Qt::endl; return 2; }
}
