#include "core/api.h"
#include <QFile>
#include <QDir>
#include <QTemporaryDir>
#include <QJsonDocument>
#include <QProcess>
#include <QElapsedTimer>
#include <QCryptographicHash>
#include <QScopeGuard>
#include <QtTest>
#include <condition_variable>
#include <chrono>
using namespace resheto;
namespace {
void put(const QString &path,const QByteArray &bytes) { QFile f(path); if(!f.open(QIODevice::WriteOnly) || f.write(bytes)!=bytes.size()) throw Error("fixture write"); }
ProcessInfo process(quint64 pid,quint64 parent,const QString &start) { ProcessInfo p; p.pid=pid; p.parentPid=parent; p.startTime=start; p.image="controlled-process"; return p; }
ProcessEvent child(int number,qint64 tick) {
    ProcessEvent e; e.id=QString::number(number); e.operation="child_start"; e.time=now(); e.source="controlled"; e.monotonicMs=tick;
    e.parent=process(100,1,"10"); e.process=process(1000+number,100,QString::number(2000+number)); return e;
}
template<class F> bool rejected(F &&f) { try { f(); } catch(const Error &) { return true; } return false; }
}
class MonitorTests : public QObject {
    Q_OBJECT
    std::unique_ptr<QTemporaryDir> temporary;
    QString root,area,db;
    std::shared_ptr<const BehaviorRules> rules() { return loadBehaviorRules(QStringLiteral(RESHETO_SOURCE_DIR)+"/data/behavior_rules.json"); }
    MonitorRequest request(bool processes=false) {
        MonitorRequest r; r.directory=area; r.storagePath=root+"/history.db"; r.signaturePath=db; r.processes=processes;
        r.behaviorPath=QStringLiteral(RESHETO_SOURCE_DIR)+"/data/behavior_rules.json"; r.processIntervalMs=150; r.debounceMs=100; return r;
    }
private slots:
    void init() {
        temporary=std::make_unique<QTemporaryDir>(QDir::currentPath()+"/monitor-XXXXXX"); QVERIFY(temporary->isValid()); root=temporary->path(); area=root+"/observed"; QVERIFY(QDir().mkpath(area));
        put(root+"/signatures.json",R"({"version":"monitor-control","signatures":[{"id":"control","name":"CONTROL","kind":"PATTERN","value":"aabbcc","version":"1","enabled":1}]})");
        db=root+"/signatures.db"; createSignatures(root+"/signatures.json",db);
    }
    void windowOrderAcknowledgementAndUnknown() {
        BehaviorAnalyzer analyzer(rules());
        QVERIFY(analyzer.observe(child(1,100),100).empty()); QVERIFY(analyzer.observe(child(2,200),200).empty());
        auto last=child(3,300); auto found=analyzer.observe(last,300); QCOMPARE(found.size(),size_t(1)); QCOMPARE(found.front().evidence.size(),3);
        const auto pending=analyzer.observe(last,300); QCOMPARE(pending.size(),size_t(1)); QCOMPARE(pending.front().key,found.front().key);
        analyzer.acknowledge(found.front(),300); QVERIFY(analyzer.observe(last,300).empty());
        analyzer.reset(); QVERIFY(analyzer.observe(child(1,100),100).empty()); QVERIFY(analyzer.observe(child(2,5001),5001).empty()); QVERIFY(analyzer.observe(child(3,5101),5101).empty());
        auto invalid=child(4,5102); invalid.parent.startTime="999999"; QVERIFY(rejected([&]{analyzer.observe(invalid,5102);}));
        invalid=child(4,5000); QVERIFY(rejected([&]{analyzer.observe(invalid,5000);}));
        invalid=child(4,5102); invalid.id.clear(); QVERIFY(rejected([&]{analyzer.observe(invalid,5102);}));
        invalid=child(4,5102); invalid.process.parentPid=9; QVERIFY(rejected([&]{analyzer.observe(invalid,5102);}));
        analyzer.reset();
        for(int i=0;i<1025;++i) analyzer.observe(child(i,i),i);
        QVERIFY(analyzer.overflowed()); analyzer.reset(); QVERIFY(!analyzer.overflowed());
    }
    void trackerDoesNotInventRepeatedLifetimesOrParents() {
        ProcessTracker tracker; ProcessSnapshot snap; snap.processes={process(100,1,"10")}; QVERIFY(tracker.update(snap,0).empty());
        const auto p=process(200,100,"20"); snap.processes.push_back(p); auto events=tracker.update(snap,10); QCOMPARE(events.size(),size_t(1)); QCOMPARE(events.front().operation,"child_start");
        snap.complete=false; snap.processes.resize(1); tracker.update(snap,20); snap.processes.push_back(p);
        events=tracker.update(snap,30); QVERIFY(events.empty());
        snap.processes.back().startTime="21"; events=tracker.update(snap,40);
        int starts=0; for(const auto &e:events) if(e.operation=="child_start") ++starts; QCOMPARE(starts,1);
        // Старый PPID уже принадлежит более молодому процессу: связь не подтверждается.
        snap.processes.front().startTime="100"; snap.processes.back().startTime="22"; events=tracker.update(snap,50);
        for(const auto &e:events) if(e.process.pid==200) QVERIFY(e.operation!="child_start");
        snap.processes.resize(4097); QVERIFY(tracker.update(snap,60).empty()); QVERIFY(tracker.takeLoss());
    }
    void nativeFileCreateModifyAndStopRestart() {
        MonitorRuntime runtime; auto r=request(); QVERIFY(runtime.start(r)); QVERIFY(!runtime.start(r));
        QTRY_VERIFY_WITH_TIMEOUT(runtime.status().ready,5000); const auto firstId=runtime.status().job.id;
        put(area+"/sample.bin","ordinary bytes"); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().fileEvents>=1,5000);
        const auto before=runtime.status().fileEvents; put(area+"/sample.bin",QByteArray::fromHex("aabbcc"));
        QTRY_VERIFY_WITH_TIMEOUT(runtime.status().job.matches>=1 && runtime.status().fileEvents>before,5000);
        QVERIFY(QDir().mkpath(area+"/nested")); put(area+"/nested/new.bin",QByteArray::fromHex("aabbcc"));
        QTRY_VERIFY_WITH_TIMEOUT(runtime.status().job.matches>=2,5000);
        QElapsedTimer stop; stop.start(); runtime.cancel(); runtime.wait(); QVERIFY(stop.elapsed()<3000); QVERIFY(!runtime.status().active);
        { Store store(r.storagePath,true); const auto j=store.latest(); QVERIFY(j); QCOMPARE(j->id,firstId); QVERIFY(j->matches>=2);
          ResultQuery q; q.filter=ResultFilter::Matches; const auto found=store.query(firstId,q); QVERIFY(found.total>=2); QVERIFY(!found.rows.front().eventId.isEmpty());
          const auto events=store.observations(firstId,0,1000); int fileEvents=0; for(const auto &e:events) if(e["type"]=="file_event") ++fileEvents; QVERIFY(fileEvents>=3); }
        const auto stopped=runtime.status().fileEvents; put(area+"/after-stop.bin",QByteArray::fromHex("aabbcc")); QCOMPARE(runtime.status().fileEvents,stopped);
        QVERIFY(runtime.start(r)); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().ready,5000); QVERIFY(runtime.status().job.id!=firstId);
        put(area+"/restart.bin",QByteArray::fromHex("aabbcc")); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().job.matches>=1,5000); runtime.cancel(); runtime.wait();
        { Store store(r.storagePath,true); QVERIFY(store.query(firstId,{}).total>=3); }
    }
    void ownFilesAndScopeAreExcluded() {
        QVERIFY(!insideObservedRoot(root+"/outside.bin",area)); QVERIFY(!insideObservedRoot(area+"/../outside.bin",area));
        MonitorRuntime runtime; auto r=request(); r.storagePath=area+"/own.db"; QVERIFY(runtime.start(r)); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().ready,5000);
        put(area+"/ordinary","plain"); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().fileEvents>=1,5000);
        runtime.cancel(); runtime.wait();
        Store store(r.storagePath,true); const auto rows=store.page(runtime.status().job.id,0,1000);
        for(const auto &row:rows) QVERIFY(!row.path.contains("own.db"));
    }
    void boundedQueueReportsLoss() {
        std::mutex mutex; std::condition_variable wake; bool entered=false,release=false;
        MonitorRuntime runtime; auto r=request(); r.queueLimit=1; r.debounceMs=50;
        r.fileHooks.beforeOpen=[&](const QString &){std::unique_lock lock(mutex); entered=true; wake.notify_all(); wake.wait(lock,[&]{return release;}); return QString();};
        auto cleanup=qScopeGuard([&]{{std::lock_guard lock(mutex); release=true;} wake.notify_all(); runtime.cancel(); runtime.wait();});
        QVERIFY(runtime.start(r)); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().ready,5000); put(area+"/first",QByteArray::fromHex("aabbcc"));
        { std::unique_lock lock(mutex); QVERIFY(wake.wait_for(lock,std::chrono::seconds(5),[&]{return entered;})); }
        for(int i=0;i<5;++i) put(area+QString("/extra-%1").arg(i),QByteArray::fromHex("aabbcc"));
        QTRY_VERIFY_WITH_TIMEOUT(runtime.status().lost>0,5000); QVERIFY(runtime.status().queued<=1); QVERIFY(!runtime.status().reason.isEmpty());
        { std::lock_guard lock(mutex); release=true; } wake.notify_all();
        QTRY_VERIFY_WITH_TIMEOUT(runtime.status().job.results>=1,5000); runtime.cancel(); runtime.wait();
        QCOMPARE(runtime.status().job.state,"failed"); Store store(r.storagePath,true); QVERIFY(!store.latest()->error.isEmpty());
        bool found=false; for(const auto &e:store.observations(runtime.status().job.id,0,1000)) found|=e["type"]=="observation_loss" || (e["type"]=="monitor_stopped" && !e["details"].toObject()["reason"].toString().isEmpty()); QVERIFY(found);
    }
    void unavailableBehaviorDoesNotStopFiles() {
        MonitorRuntime runtime; auto r=request(true); r.behaviorPath=root+"/missing-rules.json";
        QVERIFY(runtime.start(r)); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().ready,5000); QCOMPARE(runtime.status().state,"degraded");
        put(area+"/file.bin",QByteArray::fromHex("aabbcc")); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().job.matches>=1,5000);
        runtime.cancel(); runtime.wait(); Store store(r.storagePath,true); QCOMPARE(store.latest()->matches,1); QCOMPARE(store.latest()->exitCode(),2);
        bool recorded=false; for(const auto &e:store.observations(runtime.status().job.id,0,1000)) recorded|=e["type"]=="component_unavailable"; QVERIFY(recorded);
        r=request(false); r.signaturePath=root+"/missing.db"; QVERIFY(runtime.start(r)); QTRY_VERIFY_WITH_TIMEOUT(!runtime.status().active,5000); QCOMPARE(runtime.status().state,"failed"); runtime.wait();
        { Store reopened(r.storagePath,true); const auto failed=reopened.latest(); QVERIFY(failed); QCOMPARE(failed->id,runtime.status().job.id); QCOMPARE(failed->state,"failed"); QVERIFY(!failed->error.isEmpty()); }
    }
    void scopedProcessImages_data() {
        QTest::addColumn<bool>("baseline"); QTest::addColumn<bool>("heuristics");
        QTest::newRow("existing-hash")<<true<<false; QTest::newRow("new-hash")<<false<<false;
        QTest::newRow("existing-static")<<true<<true; QTest::newRow("new-static")<<false<<true;
    }
    void scopedProcessImages() {
        QFETCH(bool,baseline); QFETCH(bool,heuristics);
#ifdef _WIN32
        const auto helper=area+"/helper.exe";
#else
        const auto helper=area+"/helper";
#endif
        QVERIFY(QFile::copy(QStringLiteral(RESHETO_HELPER_PATH),helper));
        QFile f(helper); QVERIFY(f.open(QIODevice::ReadOnly)); const auto hash=QCryptographicHash::hash(f.readAll(),QCryptographicHash::Sha256).toHex(); f.close();
        if(!heuristics) { put(root+"/image.json",QJsonDocument(QJsonObject{{"version","image-control"},{"signatures",QJsonArray{QJsonObject{{"id","safe-helper"},{"name","SAFE HELPER CONTROL"},{"kind","HASH"},{"algorithm","SHA-256"},{"value",QString::fromLatin1(hash)},{"version","1"},{"enabled",1}}}}}).toJson()); createSignatures(root+"/image.json",root+"/image.db"); }
        QProcess p; auto start=[&] { p.start(helper,{"--children","0","--hold-ms","6000"}); QVERIFY(p.waitForStarted(2000)); };
        auto cleanup=qScopeGuard([&]{if(p.state()!=QProcess::NotRunning) { p.kill(); p.waitForFinished(2000); }});
        if(baseline) start();
        MonitorRuntime runtime; auto r=request(true); r.files=false; r.scanProcessImages=true; r.processImageDirectory=area;
        if(heuristics) { r.signaturePath.clear(); r.heuristicPath=QStringLiteral(RESHETO_SOURCE_DIR)+"/data/heuristic_rules.json"; } else r.signaturePath=root+"/image.db";
        QVERIFY(runtime.start(r)); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().ready,5000); if(!baseline) start();
        QTRY_VERIFY_WITH_TIMEOUT(runtime.status().processImages>=1,5000); const auto pid=static_cast<quint64>(p.processId());
        const auto list=runtime.processes(); QVERIFY(!list.empty()); for(const auto &info:list) QVERIFY(info.image.startsWith(area));
        QTRY_COMPARE_WITH_TIMEOUT(runtime.status().processImages,1,1500); QTest::qWait(350); QCOMPARE(runtime.status().processImages,1);
        runtime.cancel(); runtime.wait(); Store store(r.storagePath,true); const auto j=store.getJob(runtime.status().job.id); QVERIFY(j); ResultQuery q; q.object=ResultObject::Processes; q.text=QString::number(pid);
        const auto rows=store.query(j->id,q); QCOMPARE(rows.total,1); const auto &out=rows.rows.front(); QCOMPARE(out.path,helper); QVERIFY(!out.eventId.isEmpty());
        const auto event=store.observation(j->id,out.eventId); QVERIFY(event); QCOMPARE((*event)["type"].toString(),"process_image"); const auto identity=(*event)["details"].toObject()["process"].toObject(); QCOMPARE(identity["pid"].toString(),QString::number(pid)); QVERIFY(!identity["start_time"].toString().isEmpty());
        if(heuristics) { QVERIFY(out.analyzers.contains("HEURISTIC")); QCOMPARE(out.outcome,"no_match"); } else { QCOMPARE(out.outcome,"signature_match"); QCOMPARE(out.signatureId,"safe-helper"); }
        q.object=ResultObject::Files; q.text.clear(); QCOMPARE(store.query(j->id,q).total,0);
        // История не должна принимать подмену процессной связи.
        auto damaged=(*event)["details"].toObject(); auto proc=damaged["process"].toObject(); proc["start_time"]="invalid"; damaged["process"]=proc;
        { Database sql(r.storagePath,false); sql.exec("UPDATE events SET details=? WHERE type='process_image'",{QString::fromUtf8(QJsonDocument(damaged).toJson())}); }
        QVERIFY(rejected([&]{store.getJob(j->id);}));
    }
    void processExitDuringImageReadIsPartial() {
#ifdef _WIN32
        const auto helper=area+"/helper.exe";
#else
        const auto helper=area+"/helper";
#endif
        QVERIFY(QFile::copy(QStringLiteral(RESHETO_HELPER_PATH),helper)); QProcess p; p.start(helper,{"--children","0","--hold-ms","6000"}); QVERIFY(p.waitForStarted(2000));
        auto childCleanup=qScopeGuard([&]{if(p.state()!=QProcess::NotRunning) {p.kill(); p.waitForFinished(2000);}});
        std::mutex mutex; std::condition_variable wake; bool entered=false,release=false;
        MonitorRuntime runtime; auto r=request(true); r.files=false; r.scanProcessImages=true; r.processImageDirectory=area;
        r.fileHooks.afterBlock=[&](const QString &,qint64) { std::unique_lock lock(mutex); if(entered) return; entered=true; wake.notify_all(); wake.wait(lock,[&]{return release;}); };
        auto cleanup=qScopeGuard([&]{{std::lock_guard lock(mutex);release=true;}wake.notify_all();runtime.cancel();runtime.wait();});
        QVERIFY(runtime.start(r)); { std::unique_lock lock(mutex); QVERIFY(wake.wait_for(lock,std::chrono::seconds(5),[&]{return entered;})); }
        p.kill(); QVERIFY(p.waitForFinished(2000)); {std::lock_guard lock(mutex);release=true;} wake.notify_all();
        QTRY_COMPARE_WITH_TIMEOUT(runtime.status().processImages,1,5000); runtime.cancel(); runtime.wait(); Store store(r.storagePath,true); const auto j=store.getJob(runtime.status().job.id); QVERIFY(j); const auto rows=store.page(j->id,0); QCOMPARE(rows.size(),size_t(1)); QCOMPARE(rows.front().completeness,"partial"); QCOMPARE(rows.front().code,"process_changed"); QVERIFY(rows.front().reason.contains("PID")); QCOMPARE(j->exitCode(),2);
    }
    void legacyProcessOnlyRequest() {
        MonitorRuntime runtime; auto r=request(true); r.directory.clear(); r.processImageDirectory=area;
        QVERIFY(runtime.start(r)); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().ready,5000); QVERIFY(runtime.status().coverage.contains(QStringLiteral("Файлы: выкл"))); QCOMPARE(runtime.processes().size(),size_t(0));
        runtime.cancel(); runtime.wait(); QCOMPARE(runtime.status().job.exitCode(),3);
    }
    void liveHelper_data() {
        QTest::addColumn<int>("children"); QTest::addColumn<bool>("fileUnavailable");
        QTest::newRow("negative-one")<<1<<false; QTest::newRow("positive-three")<<3<<false;
        QTest::newRow("positive-without-file-analysis")<<3<<true;
    }
    void liveHelper() {
        QFETCH(int,children);
        QFETCH(bool,fileUnavailable);
#ifdef _WIN32
        const auto helper=area+"/safe-helper.exe";
#else
        const auto helper=area+"/safe-helper";
#endif
        QVERIFY(QFile::copy(QStringLiteral(RESHETO_HELPER_PATH),helper));
#ifndef _WIN32
        QVERIFY(QFile::setPermissions(helper,QFile::permissions(helper)|QFile::ExeOwner));
#endif
        MonitorRuntime runtime; auto r=request(true); r.processImageDirectory=area; if(fileUnavailable) r.signaturePath=root+"/missing.db";
        QVERIFY(runtime.start(r)); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().ready,5000); if(fileUnavailable) QCOMPARE(runtime.status().state,"degraded");
        QProcess p; p.setProgram(helper); p.setArguments({"--children",QString::number(children),"--hold-ms","1800","--delay-ms","600"}); p.start(); QVERIFY(p.waitForStarted(2000)); const auto pid=static_cast<quint64>(p.processId());
        QTRY_VERIFY_WITH_TIMEOUT(([&]{for(const auto &info:runtime.processes()) if(info.pid==pid) return true; return false;})(),3000);
        if(children==3) QTRY_VERIFY_WITH_TIMEOUT(runtime.status().job.matches>=1,5000);
        QVERIFY(p.waitForFinished(6000)); QCOMPARE(p.exitCode(),0); QTRY_VERIFY_WITH_TIMEOUT(runtime.status().processEvents>=2,3000);
        runtime.cancel(); runtime.wait(); const auto j=runtime.status().job;
        Store store(r.storagePath,true); QCOMPARE(store.latest()->matches,j.matches);
        if(children==1) QCOMPARE(j.matches,0);
        else {
            QVERIFY(j.matches>=1); ResultQuery q; q.filter=ResultFilter::Matches; const auto rows=store.query(j.id,q).rows; QVERIFY(!rows.empty());
            const auto &out=rows.front(); QCOMPARE(out.outcome,"behavioral_match"); QCOMPARE(out.source,"behavioral"); QCOMPARE(out.size,-1); QVERIFY(out.signatureId.isEmpty());
            QCOMPARE(out.details["process"].toObject()["pid"].toString(),QString::number(pid)); QCOMPARE(out.details["coverage"].toString(),"lifecycle_polling"); QCOMPARE(out.details["events"].toArray().size(),3);
            QCOMPARE(Result::fromJson(out.json()).json(),out.json());
            auto bad=out.json(); bad["size"]="0"; QVERIFY(rejected([&]{Result::fromJson(bad);}));
        }
    }
};
QTEST_GUILESS_MAIN(MonitorTests)
#include "monitor_tests.moc"
