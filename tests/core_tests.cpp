#include "core/controller.h"
#include "core/database.h"
#include "core/file_access.h"
#include "core/signatures.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QtTest>
#include <condition_variable>
#include <future>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#endif
using namespace resheto;
template<class F> bool throwsError(F &&f) { try { f(); } catch(const Error &) { return true; } return false; }

class CoreTests : public QObject {
    Q_OBJECT
    std::unique_ptr<QTemporaryDir> tmp;
    QString dir,db,storage;
    void put(const QString &name,const QByteArray &bytes) {
        QFile f(name); QVERIFY(f.open(QIODevice::WriteOnly)); QCOMPARE(f.write(bytes),bytes.size()); f.close();
    }
    void database(QJsonArray sigs,QString version="test-v1") {
        const auto json=dir+"/input.json";
        put(json,QJsonDocument(QJsonObject{{"version",version},{"signatures",sigs}}).toJson());
        createSignatures(json,db);
    }
    QJsonObject pattern(QByteArray bytes=QByteArray::fromHex("aa00bb")) {
        return {{"id","test-pattern"},{"name",QStringLiteral("ТЕСТ: шаблон")},{"kind","PATTERN"},{"value",QString::fromLatin1(bytes.toHex())},{"version","1"},{"enabled",1}};
    }
    Request request(const QString &path={}) {
        Request r; r.path=path.isEmpty()?dir+"/file":path; r.signaturePath=db; r.storagePath=storage; r.blockSize=4096; return r;
    }
    Result single(Request r) {
        r.id="unit"; r.snapshot=loadSignatures(db); return scanFile(r.path,r);
    }
    std::vector<Result> saved(const Job &j) { Store s(storage); return s.page(j.id,0,1000); }
private slots:
    void initTestCase() { Database runtime(":memory:",false); auto q=runtime.exec("SELECT sqlite_version()"); QVERIFY(q.next()); qInfo()<<"SQLite"<<q.value(0).toString(); }
    void init() {
        tmp=std::make_unique<QTemporaryDir>(QDir::currentPath()+"/resheto-test-XXXXXX"); QVERIFY(tmp->isValid());
        dir=tmp->path(); db=dir+"/signatures.db"; storage=dir+"/resheto.db";
    }
    void hashAndOneByte() {
        const QByteArray data("hello\0binary",12);
        auto s=pattern(); s["kind"]="HASH"; s["value"]=QString::fromLatin1(QCryptographicHash::hash(data,QCryptographicHash::Sha256).toHex()); s["algorithm"]="SHA-256";
        database({s}); put(dir+"/file",data);
        auto r=single(request()); QCOMPARE(r.outcome,"signature_match"); QCOMPARE(r.completeness,"full"); QVERIFY(!r.identity.isEmpty());
        auto changed=data; changed[1]='X'; put(dir+"/file",changed);
        QCOMPARE(single(request()).outcome,"no_match");
    }
    void exactBinaryAndNear() {
        database({pattern()}); put(dir+"/file",QByteArray("abc\0",4)+QByteArray::fromHex("aa00bb"));
        auto r=single(request()); QCOMPARE(r.outcome,"signature_match"); QCOMPARE(r.offset,4);
        put(dir+"/file",QByteArray::fromHex("aa00bc")); QCOMPARE(single(request()).outcome,"no_match");
    }
    void mask() {
        auto s=pattern(); s["mask"]="101"; database({s});
        put(dir+"/file",QByteArray::fromHex("aa77bb")); QCOMPARE(single(request()).outcome,"signature_match");
        put(dir+"/file",QByteArray::fromHex("aa77bc")); QCOMPARE(single(request()).outcome,"no_match");
    }
    void boundaryAndLongPattern() {
        const QByteArray bytes(9000,'x'); auto s=pattern(bytes); database({s});
        QByteArray content(4094,'q'); content+=bytes; content+="tail"; put(dir+"/file",content);
        auto r=single(request()); QCOMPARE(r.outcome,"signature_match"); QCOMPARE(r.offset,4094);
        content[4094+8000]='y'; put(dir+"/file",content); QCOMPARE(single(request()).outcome,"no_match");
        // Соседние блоки не склеиваются повторно в ложный шаблон.
        QByteArray w="abcabc"; Signature p; p.value="cabcab";
        QCOMPARE(findPattern(w,0,3,p,[]{return false;}),-1);
    }
    void offsetSizeAndEnd() {
        auto s=pattern(); s["offset"]="4094"; s["min_size"]="4097"; s["max_size"]="4097"; database({s});
        QByteArray content(4094,'q'); content+=QByteArray::fromHex("aa00bb"); put(dir+"/file",content);
        auto r=single(request()); QCOMPARE(r.outcome,"signature_match"); QCOMPARE(r.offset,4094);
        put(dir+"/file","q"+content); QCOMPARE(single(request()).outcome,"no_match");
        content[4094]='q'; content.replace(4093,3,QByteArray::fromHex("aa00bb")); put(dir+"/file",content); QCOMPARE(single(request()).outcome,"no_match");
        put(dir+"/file",QByteArray::fromHex("aa00")); QCOMPARE(single(request()).outcome,"no_match");
    }
    void emptyAndLarge() {
        database({pattern()}); put(dir+"/file",{}); QCOMPARE(single(request()).outcome,"no_match");
        QFile f(dir+"/file"); QVERIFY(f.open(QIODevice::WriteOnly)); QByteArray chunk(1024*1024,'q');
        for(int i=0;i<12;++i) QCOMPARE(f.write(chunk),chunk.size()); f.close();
        auto r=request(); int blocks=0; qint64 last=0;
        r.hooks.afterBlock=[&](const QString &,qint64 n){QVERIFY(n-last<=4096); last=n; ++blocks;};
        auto result=single(r); QCOMPARE(result.outcome,"no_match"); QCOMPARE(blocks,3072); QCOMPARE(result.size,12*1024*1024);
    }
    void traversalUnicodeAndServiceFiles() {
        database({pattern()}); const auto root=dir+QStringLiteral("/дерево с пробелом");
        QVERIFY(QDir().mkpath(root+"/nested")); put(root+"/a.unusual",QByteArray::fromHex("aa00bb")); put(root+QStringLiteral("/nested/пустой"),{});
        auto req=request(root); req.recursive=false; auto j=runJob(req); QCOMPARE(j.checked,1); QCOMPARE(j.skipped,1); QCOMPARE(j.matches,1);
        req.recursive=true; j=runJob(req); QCOMPARE(j.checked,2); QCOMPARE(j.matches,1);
        auto all=runJob(request(dir)); QVERIFY(all.skipped>=3); // База, manifest и хранилище.
        for(const auto &r:saved(all)) if(r.path==storage || r.path==db) { QVERIFY(r.skipped); QCOMPARE(r.outcome,"not_checked"); }
    }
    void fileErrorContinuesAndDirectoryError() {
        database({pattern()}); const auto root=dir+"/tree"; QVERIFY(QDir().mkpath(root+"/denied"));
        put(root+"/bad",QByteArray(10000,'q')); put(root+"/good",QByteArray::fromHex("aa00bb"));
        auto req=request(root);
        req.hooks.afterBlock=[](const QString &p,qint64){if(p.endsWith("bad")) throw Error(QStringLiteral("Внедрённый отказ чтения"));};
        req.hooks.beforeDirectory=[](const QString &p){return p.endsWith("denied")?QStringLiteral("Внедрённый отказ каталога"):QString();};
        auto j=runJob(req); QCOMPARE(j.state,"failed"); QCOMPARE(j.errors,2); QCOMPARE(j.matches,1); QCOMPARE(j.checked,1); QCOMPARE(j.exitCode(),2);
        const auto rows=saved(j); QCOMPARE(rows.size(),size_t(3));
        for(const auto &r:rows) if(!r.code.isEmpty()) { QCOMPARE(r.outcome,"not_checked"); QCOMPARE(r.completeness,"none"); }
    }
    void missing() {
        database({pattern()}); auto j=runJob(request()); QCOMPARE(j.errors,1); QCOMPARE(j.state,"failed");
        put(dir+"/file",QByteArray(5000,'q')); auto req=request();
        req.hooks.beforeOpen=[](const QString &p){QFile::remove(p); return QString();};
        QCOMPARE(single(req).outcome,"not_checked");
    }
    void changedAndReplaced() {
        database({pattern()}); put(dir+"/file",QByteArray(10000,'q'));
        auto req=request(); bool once=false;
        req.hooks.afterBlock=[&](const QString &p,qint64){if(!once) {once=true; QFile f(p); QVERIFY(f.open(QIODevice::Append)); QCOMPARE(f.write("x"),1); f.close();}};
        auto r=single(req); QCOMPARE(r.outcome,"not_checked"); QCOMPARE(r.code,"changed");
        put(dir+"/file",QByteArray(10000,'q')); once=false;
        req.hooks.afterBlock=[&](const QString &p,qint64){if(!once) {once=true; QVERIFY(QFile::rename(p,p+".old")); put(p,QByteArray(10000,'q'));}};
        r=single(req); QCOMPARE(r.outcome,"not_checked"); QCOMPARE(r.code,"changed");
    }
    void cancelReadingAndTraversal() {
        database({pattern()}); const auto root=dir+"/tree"; QVERIFY(QDir().mkpath(root));
        for(int i=0;i<8;++i) put(root+QString("/%1").arg(i),QByteArray(9000,'q'));
        auto req=request(root); int opened=0;
        req.hooks.beforeOpen=[&](const QString &){++opened; return QString();};
        req.hooks.afterBlock=[&](const QString &,qint64){if(opened==2) *req.cancel=true;};
        auto j=runJob(req); QCOMPARE(j.state,"cancelled"); QCOMPARE(j.exitCode(),3); QCOMPARE(j.checked,1); QCOMPARE(j.results,2); QCOMPARE(opened,2);
        auto rows=saved(j); QCOMPARE(rows.size(),size_t(2)); QCOMPARE(rows.back().code,"cancelled");
        req=request(root); *req.cancel=true; j=runJob(req); QCOMPARE(j.state,"cancelled"); QCOMPARE(j.results,0);
    }
    void cancelLongSearch() {
        Signature s; s.value=QByteArray(60000,'q'); s.value[59999]='x';
        QByteArray w(65536,'q'); int calls=0;
        QCOMPARE(findPattern(w,0,0,s,[&]{return ++calls>=4;}),-2); QCOMPARE(calls,4);
    }
    void validation_data() {
        QTest::addColumn<QString>("sql");
        for(const auto &sql:QStringList{
            "PRAGMA user_version=2", "UPDATE signatures SET value=''", "UPDATE signatures SET mask='00'",
            "UPDATE signatures SET mask='000'", "UPDATE signatures SET mask='1x1'", "UPDATE signatures SET offset=-1",
            "UPDATE signatures SET min_size=10,max_size=2", "UPDATE signatures SET kind='OTHER'",
            "UPDATE signatures SET enabled=0", "UPDATE signatures SET enabled=2", "UPDATE signatures SET name=''",
            "UPDATE signatures SET kind='HASH',algorithm='SHA-256'", "UPDATE signatures SET offset=1.5",
            "UPDATE signatures SET offset=9223372036854775807", "UPDATE signatures SET value='gg'",
            "DROP TABLE signatures", "UPDATE metadata SET version=''"}) QTest::newRow(qPrintable(sql))<<sql;
    }
    void validation() {
        QFETCH(QString,sql); database({pattern()}); { Database d(db,false); d.exec(sql); } writeManifest(db);
        QVERIFY(throwsError([&]{loadSignatures(db);}));
    }
    void checksumMissingCorruptDuplicateAndLimits() {
        QVERIFY(throwsError([&]{loadSignatures(db);}));
        database({pattern()}); put(db+".sha256",QByteArray(64,'0')); QVERIFY(throwsError([&]{loadSignatures(db);}));
        writeManifest(db); { Database d(db,false); d.exec("ALTER TABLE signatures RENAME TO old"); d.exec("CREATE TABLE signatures AS SELECT * FROM old UNION ALL SELECT * FROM old"); } writeManifest(db);
        QVERIFY(throwsError([&]{loadSignatures(db);}));
        put(db,"not a database"); writeManifest(db); QVERIFY(throwsError([&]{loadSignatures(db);}));
        QFile::remove(db); QFile::remove(db+".sha256");
        auto s=pattern(QByteArray(65537,'q')); QVERIFY(throwsError([&]{database({s});}));
    }
    void boundsAndProtectDatabases() {
        database({pattern()}); put(dir+"/file","ordinary"); const auto checksum=loadSignatures(db)->checksum;
        auto req=request(); req.storagePath=db; auto j=runJob(req); QCOMPARE(j.state,"failed"); QCOMPARE(loadSignatures(db)->checksum,checksum);
        QVERIFY(throwsError([&]{Store wrong(db);})); QCOMPARE(loadSignatures(db)->checksum,checksum);
        req=request(); req.blockSize=1; QCOMPARE(runJob(req).state,"failed");
        req.blockSize=4*1024*1024+1; QCOMPARE(runJob(req).state,"failed");
        req=request(); QCOMPARE(scanFile(req.path,req).code,"analyzer_not_ready");
    }
    void disabledAndSnapshotReload() {
        auto disabled=pattern(QByteArray("ordinary")); disabled["id"]="test-disabled"; disabled["enabled"]=0;
        database({pattern(),disabled}); put(dir+"/file",QByteArray::fromHex("aa00bb"));
        auto req=request(); bool changed=false;
        req.hooks.afterBlock=[&](const QString &,qint64){if(!changed) { changed=true; { Database d(db,false); d.exec("UPDATE signatures SET name='ТЕСТ: новое имя' WHERE id='test-pattern'"); d.exec("UPDATE metadata SET version='test-v2'"); } writeManifest(db); }};
        auto first=runJob(req); QCOMPARE(first.databaseVersion,"test-v1"); QVERIFY(saved(first).front().signatureName!=QStringLiteral("ТЕСТ: новое имя"));
        auto second=runJob(request()); QCOMPARE(second.databaseVersion,"test-v2"); QCOMPARE(saved(second).front().signatureName,QStringLiteral("ТЕСТ: новое имя"));
        put(dir+"/file","ordinary"); QCOMPARE(single(request()).outcome,"no_match");
    }
    void persistenceAndWriteFailure() {
        database({pattern()}); put(dir+"/file",QByteArray::fromHex("aa00bb")); auto j=runJob(request()); QCOMPARE(j.matches,1);
        { Store s(storage); auto last=s.latest(); QVERIFY(last.has_value()); QCOMPARE(last->id,j.id); QCOMPARE(last->state,"completed"); QCOMPARE(s.page(j.id,0).front().signatureId,"test-pattern"); }
        { Database d(storage,true); auto q=d.exec("SELECT count(*) FROM detections"); QVERIFY(q.next()); QCOMPARE(q.value(0).toInt(),1); q=d.exec("SELECT count(*) FROM events"); QVERIFY(q.next()); QVERIFY(q.value(0).toInt()>=3); }
        { Database d(storage,false); d.exec("CREATE TRIGGER fail_write BEFORE INSERT ON results BEGIN SELECT RAISE(FAIL,'injected write failure'); END"); }
        j=runJob(request()); QCOMPARE(j.state,"failed"); QVERIFY(j.error.contains("injected write failure")); QCOMPARE(j.checked,0); QCOMPARE(j.exitCode(),2);
        auto req=request(); req.storagePath=dir+"/absent/store.db"; j=runJob(req); QCOMPARE(j.state,"failed"); QVERIFY(!j.error.isEmpty());
    }
    void nativeLinks() {
        database({pattern()}); const auto root=dir+"/tree"; QVERIFY(QDir().mkpath(root)); put(root+"/a",QByteArray::fromHex("aa00bb"));
        std::error_code ec; std::filesystem::create_directory_symlink(nativePath(root),nativePath(root+"/loop"),ec);
        if(ec) QSKIP("ОС не разрешила создать symlink; проверка ссылок здесь не выполнена");
        auto j=runJob(request(root)); QCOMPARE(j.checked,1); QCOMPARE(j.skipped,1); QCOMPARE(j.state,"completed");
    }
#ifdef Q_OS_WIN
    void nativeJunctionCycle() {
        database({pattern()}); const auto root=dir+"/tree"; QVERIFY(QDir().mkpath(root));
        put(root+"/a",QByteArray::fromHex("aa00bb")); const auto link=root+"/cycle";
        const int code=QProcess::execute("cmd.exe",{"/c","mklink","/J",QDir::toNativeSeparators(link),QDir::toNativeSeparators(root)});
        if(code!=0) QSKIP("ОС не разрешила создать junction; проверка не выполнена");
        const auto cleanup=qScopeGuard([&]{std::error_code ec; std::filesystem::remove(nativePath(link),ec);});
        auto j=runJob(request(root)); QCOMPARE(j.checked,1); QCOMPARE(j.skipped,1); QCOMPARE(j.state,"completed");
    }
    void nativeSharingDenied() {
        database({pattern()}); put(dir+"/file","bytes"); const auto path=dir+"/file";
        HANDLE h=CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()),GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr); QVERIFY(h!=INVALID_HANDLE_VALUE);
        auto result=single(request()); CloseHandle(h); QCOMPARE(result.outcome,"not_checked"); QCOMPARE(result.code,"file_io");
    }
#endif
    void boundedController() {
        database({pattern()}); put(dir+"/file",QByteArray(9000,'q'));
        Controller controller; auto req=request(); std::promise<void> entered,release; auto gate=release.get_future().share();
        req.hooks.beforeOpen=[&](const QString &){entered.set_value(); gate.wait(); return QString();};
        QVERIFY(controller.submit(req));
        const auto status=entered.get_future().wait_for(std::chrono::seconds(5));
        if(status!=std::future_status::ready) { release.set_value(); QFAIL("Рабочий поток не запущен"); }
        const bool accepted=controller.submit(request()); const bool overflow=controller.submit(request());
        controller.cancel(); release.set_value(); QVERIFY(accepted); QVERIFY(!overflow);
        QTRY_VERIFY_WITH_TIMEOUT(!controller.busy(),10000); QCOMPARE(controller.progress().state,"cancelled");
    }
};
QTEST_GUILESS_MAIN(CoreTests)
#include "core_tests.moc"
