#include "core/api.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTextStream>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif
using namespace resheto;
static void require(bool ok,const QString &why) { if(!ok) throw Error(why); }
static void put(const QString &p,const QByteArray &b) { QFile f(p); require(f.open(QIODevice::WriteOnly|QIODevice::NewOnly) && f.write(b)==b.size(),"fixture write: "+p); }
static qint64 peak() {
#ifdef Q_OS_WIN
    PROCESS_MEMORY_COUNTERS counters{}; require(GetProcessMemoryInfo(GetCurrentProcess(),&counters,sizeof(counters)),"memory counters"); return static_cast<qint64>(counters.PeakWorkingSetSize);
#else
    struct rusage usage{}; getrusage(RUSAGE_SELF,&usage); return static_cast<qint64>(usage.ru_maxrss)*1024;
#endif
}
static void prepare(const QString &root) {
    require(!QFileInfo::exists(root) && QDir().mkpath(root+"/small"),QStringLiteral("Нужен новый выходной каталог"));
    QElapsedTimer timer; timer.start(); QJsonArray signatures;
    const QByteArray hashFixture="synthetic harmless hash control";
    for(int i=0;i<100000;++i) {
        const auto data=i==99999?hashFixture:QByteArray("synthetic hash ")+QByteArray::number(i);
        signatures.push_back(QJsonObject{{"id",QString("synthetic-hash-%1").arg(i,6,10,QChar('0'))},{"name","СИНТЕТИКА: HASH"},{"kind","HASH"},{"algorithm","SHA-256"},{"value",QString::fromLatin1(QCryptographicHash::hash(data,QCryptographicHash::Sha256).toHex())},{"enabled",1},{"version","1"}});
    }
    auto pattern=[&](int i,const QByteArray &value,const QString &mask=QString(),const QString &offset=QString()) {
        QJsonObject o{{"id",QString("synthetic-pattern-%1").arg(i,4,10,QChar('0'))},{"name","СИНТЕТИКА: PATTERN"},{"kind","PATTERN"},{"value",QString::fromLatin1(value.toHex())},{"enabled",1},{"version","1"}};
        if(!mask.isEmpty()) o["mask"]=mask; if(!offset.isEmpty()) o["offset"]=offset; signatures.push_back(o);
    };
    const auto boundary=QByteArray::fromHex("a1a200a3a4a5"), end=QByteArray::fromHex("f1f2f3f400f5"), mask=QByteArray::fromHex("b100b200b3"), fixed=QByteArray::fromHex("c100c2c3");
    pattern(0,boundary); pattern(1,end); pattern(2,mask,"10101"); pattern(3,fixed,{},"17");
    pattern(4,QByteArray(59999,'q')+"z");
    // 995 длинных почти совпадающих шаблонов с разными хвостами, 9000..12979 байт.
    for(int i=5;i<1000;++i) pattern(i,QByteArray(9000+i*4,'q')+"Z"+QByteArray::number(i));
    put(root+"/large.json",QJsonDocument(QJsonObject{{"version","synthetic-100000-1000-v1"},{"purpose","synthetic"},{"source","Детерминированный нагрузочный набор"},{"signatures",signatures}}).toJson(QJsonDocument::Compact));
    createSignatures(root+"/large.json",root+"/large.db");
    QJsonArray baselineRules; baselineRules.append(signatures[99999]); for(int i=100000;i<100005;++i) baselineRules.append(signatures[i]);
    put(root+"/small.json",QJsonDocument(QJsonObject{{"version","synthetic-small-v1"},{"purpose","synthetic"},{"source","Малый нагрузочный контроль"},{"signatures",baselineRules}}).toJson()); createSignatures(root+"/small.json",root+"/small.db");
    for(int mib:{64,256}) {
        QFile f(root+QString("/file-%1.bin").arg(mib)); require(f.open(QIODevice::WriteOnly|QIODevice::NewOnly),"large fixture");
        for(int i=0;i<mib;++i) { QByteArray b(1024*1024,'q'); if(i==0) b.replace(65534,boundary.size(),boundary); if(i==mib-1) b.replace(b.size()-end.size(),end.size(),end); require(f.write(b)==b.size(),"large write"); }
    }
    for(int i=0;i<1000;++i) {
        QByteArray b(8192,'q');
        switch(i%8) { case 0: b=hashFixture; break; case 1: b.replace(4094,boundary.size(),boundary); break; case 2: b.replace(b.size()-end.size(),end.size(),end); break; case 3: b.replace(50,5,QByteArray::fromHex("b177b288b3")); break; case 4: b.replace(17,fixed.size(),fixed); break; case 5: b.replace(18,fixed.size(),fixed); break; case 6: b=QByteArray(59999,'q')+"y"; break; default: break; }
        put(root+QString("/small/%1").arg(i,4,10,QChar('0')),b);
    }
    QTextStream(stdout)<<QJsonDocument(QJsonObject{{"prepare_ms",QString::number(timer.elapsed())},{"peak_bytes",QString::number(peak())},{"hash",100000},{"pattern",1000}}).toJson();
}
static void run(const QString &root,const QString &kind,int mib) {
    QElapsedTimer timer; timer.start(); const auto db=root+"/"+kind+".db"; auto snapshot=loadSignatures(db); const auto loadMs=timer.elapsed();
    Request r; r.snapshot=snapshot; r.id="benchmark"; r.path=root+QString("/file-%1.bin").arg(mib);
    QJsonArray runs;
    for(int block:{4096,65536,1048576}) {
        r.blockSize=block; timer.restart(); const auto result=scanFile(r.path,r); const auto elapsed=timer.elapsed();
        require(result.outcome=="signature_match" && result.offset==65534 && result.signatureId=="synthetic-pattern-0000",QStringLiteral("Неверный результат большого файла"));
        runs.append(QJsonObject{{"block",block},{"scan_ms",QString::number(elapsed)}});
    }
    // Малые файлы: независимое ожидаемое основание/смещение для каждого из восьми случаев.
    timer.restart(); qint64 matches=0;
    for(int i=0;i<1000;++i) {
        r.path=root+QString("/small/%1").arg(i,4,10,QChar('0')); const auto result=scanFile(r.path,r); const bool positive=i%8<5;
        require(result.outcome==(positive?"signature_match":"no_match"),QStringLiteral("Малый файл %1").arg(i));
        if(positive) {
            ++matches; const QString id=i%8==0?"synthetic-hash-099999":QString("synthetic-pattern-%1").arg(i%8-1,4,10,QChar('0'));
            const qint64 offsets[]={-1,4094,8186,50,17}; require(result.signatureId==id && result.offset==offsets[i%8],QStringLiteral("Основание малого файла %1").arg(i));
        }
    }
    const auto smallMs=timer.elapsed(); snapshot.reset(); r.snapshot.reset();
    r.path=root+"/small"; r.signaturePath=db; r.storagePath=root+"/history-"+kind+QString::number(mib)+".db"; timer.restart(); const auto job=runJob(r); const auto treeMs=timer.elapsed();
    require(job.checked==1000 && job.matches==625 && job.exitCode()==1,"tree counts");
    { Store history(r.storagePath,true); require(history.latest()->id==job.id,"replay"); }
    QTextStream(stdout)<<QJsonDocument(QJsonObject{{"profile",kind},{"mib",mib},{"load_ms",QString::number(loadMs)},{"runs",runs},{"small_files",1000},{"small_matches",QString::number(matches)},{"small_scan_ms",QString::number(smallMs)},{"tree_with_storage_ms",QString::number(treeMs)},{"peak_bytes",QString::number(peak())}}).toJson();
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); try {
        const auto args=app.arguments(); require(args.size()>=3,"resheto-benchmark prepare <new-dir> | run <dir> <large|small> <64|256>");
        if(args[1]=="prepare") prepare(absolute(args[2]));
        else { require(args.size()==5 && (args[3]=="large" || args[3]=="small") && (args[4]=="64" || args[4]=="256"),"arguments"); run(absolute(args[2]),args[3],args[4].toInt()); } return 0;
    } catch(const Error &e) { QTextStream(stderr)<<e.message<<Qt::endl; return 2; }
}
