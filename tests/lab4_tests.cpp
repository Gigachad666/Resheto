#include "core/api.h"
#include <QFile>
#include <QDir>
#include <QTemporaryDir>
#include <QJsonDocument>
#include <QtEndian>
#include <QtTest>
#include <limits>
#include <future>
using namespace resheto;
namespace {
void put(const QString &path,const QByteArray &bytes) { QFile f(path); if(!f.open(QIODevice::WriteOnly) || f.write(bytes)!=bytes.size()) throw Error("fixture write"); }
void n16(QByteArray &b,int p,quint16 v) { qToLittleEndian(v,b.data()+p); }
void n32(QByteArray &b,int p,quint32 v) { qToLittleEndian(v,b.data()+p); }
void n64(QByteArray &b,int p,quint64 v) { qToLittleEndian(v,b.data()+p); }
QByteArray pe(bool writable=false) {
    QByteArray b(1024,0); b.replace(0,2,"MZ"); n32(b,60,128); b.replace(128,4,QByteArray("PE\0\0",4));
    n16(b,132,0x8664); n16(b,134,1); n16(b,148,240); n16(b,150,0x22);
    n16(b,152,0x20b); n32(b,168,0x1000); n64(b,176,0x140000000); n32(b,184,0x1000); n32(b,188,0x200);
    n32(b,208,0x2000); n32(b,212,512); n32(b,260,16);
    b.replace(392,5,".text"); n32(b,400,512); n32(b,404,0x1000); n32(b,408,512); n32(b,412,512); n32(b,428,writable?0xe0000020:0x60000020);
    return b;
}
QByteArray elf(bool writable=false) {
    QByteArray b(512,0); b.replace(0,4,QByteArray("\x7f" "ELF",4)); b[4]=2; b[5]=1; b[6]=1;
    n16(b,16,2); n16(b,18,62); n32(b,20,1); n64(b,24,0x400080); n64(b,32,64);
    n16(b,52,64); n16(b,54,56); n16(b,56,1); n32(b,64,1); n32(b,68,writable?7:5);
    n64(b,72,0); n64(b,80,0x400000); n64(b,88,0x400000); n64(b,96,512); n64(b,104,512); n64(b,112,4096);
    return b;
}
template<class F> bool fails(F &&f) { try { f(); } catch(const Error &) { return true; } return false; }
}
class Lab4Tests : public QObject {
    Q_OBJECT
    std::unique_ptr<QTemporaryDir> temp;
    QString root,rulesPath;
    QJsonObject rulesJson() { QFile f(QStringLiteral(RESHETO_SOURCE_DIR)+"/data/heuristic_rules.json"); if(!f.open(QIODevice::ReadOnly)) throw Error("rules fixture"); return QJsonDocument::fromJson(f.readAll()).object(); }
    Request request(const QString &path) {
        Request r; r.path=path; r.heuristicPath=rulesPath; r.storagePath=root+"/history.db"; return r;
    }
    ExecutableFeatures features(const QString &path) { ReadFile f(path); return executableFeatures(f,path,[]{return false;}); }
    QString signatures() {
        const auto input=root+"/signatures.json",db=root+"/signatures.db";
        put(input,R"({"version":"control","signatures":[{"id":"control","name":"CONTROL","kind":"PATTERN","value":"fa11ab1ec001beef","version":"1","enabled":1}]})");
        createSignatures(input,db); return db;
    }
private slots:
    void init() {
        temp=std::make_unique<QTemporaryDir>(QDir::currentPath()+"/lab4-XXXXXX"); QVERIFY(temp->isValid()); root=temp->path(); rulesPath=root+"/heuristic.json";
        put(rulesPath,QJsonDocument(rulesJson()).toJson());
    }
    void peAndElfUseVirtualRanges() {
        const auto rules=loadHeuristicRules(rulesPath);
        for(const auto &format:QStringList{"PE","ELF"}) {
            const auto path=root+(format=="PE"?"/sample.exe":"/sample.elf");
            put(path,format=="PE"?pe(true):elf(true)); auto f=features(path); QVERIFY(f.complete); QCOMPARE(f.format,format);
            QVERIFY(f.values["writable_executable"].toBool()); QVERIFY(!f.values["entry_outside_executable"].toBool());
            auto d=evaluateHeuristics(f,*rules,[]{return false;}); QVERIFY(d.suspicious); QCOMPARE(d.score,60); QCOMPARE(d.matched.size(),1);
            put(path,format=="PE"?pe():elf()); f=features(path); QVERIFY(f.complete); QVERIFY(!evaluateHeuristics(f,*rules,[]{return false;}).suspicious);
            auto bytes=format=="PE"?pe():elf(); if(format=="PE") n32(bytes,168,0x9000); else n64(bytes,24,0x900000);
            put(path,bytes); QVERIFY(features(path).values["entry_outside_executable"].toBool());
            d=evaluateHeuristics(features(path),*rules,[]{return false;}); QVERIFY(d.suspicious); QCOMPARE(d.score,60); QCOMPARE(d.matched.size(),1);
            if(format=="PE") n32(bytes,168,0); else n64(bytes,24,0);
            put(path,bytes); QVERIFY(!features(path).values["entry_outside_executable"].toBool());
        }
        // Флаги пустого диапазона не означают существование W+X области.
        auto emptyPe=pe(true); n32(emptyPe,168,0); n32(emptyPe,400,0); n32(emptyPe,408,0); put(root+"/empty.exe",emptyPe);
        QVERIFY(!features(root+"/empty.exe").values["writable_executable"].toBool());
        auto emptyElf=elf(true); n64(emptyElf,24,0); n64(emptyElf,96,0); n64(emptyElf,104,0); put(root+"/empty.elf",emptyElf);
        QVERIFY(!features(root+"/empty.elf").values["writable_executable"].toBool());
    }
    void malformedAndUnsupportedAreDifferent() {
        const auto rules=loadHeuristicRules(rulesPath);
        put(root+"/short.exe","MZ"); auto f=features(root+"/short.exe"); QVERIFY(f.supported); QVERIFY(!f.complete); QVERIFY(f.values.isEmpty());
        auto d=evaluateHeuristics(f,*rules,[]{return false;}); QCOMPARE(d.state,"partial"); QVERIFY(!d.suspicious); QVERIFY(!d.code.isEmpty());
        put(root+"/text.txt","ordinary harmless bytes"); f=features(root+"/text.txt"); QVERIFY(!f.supported); QCOMPARE(evaluateHeuristics(f,*rules,[]{return false;}).state,"not_applicable");
        auto bytes=pe(); n32(bytes,412,0xfffffff0); put(root+"/broken.exe",bytes); QVERIFY(!features(root+"/broken.exe").complete);
        bytes=elf(); n64(bytes,80,std::numeric_limits<quint64>::max()-10); put(root+"/broken.elf",bytes); QVERIFY(!features(root+"/broken.elf").complete);
        bytes=elf(); bytes[5]=2; put(root+"/big-endian.elf",bytes); QCOMPARE(features(root+"/big-endian.elf").code,"unsupported_arch");
    }
    void conditionsCriticalAndUnknown() {
        auto rootJson=rulesJson(); auto rule=rootJson["rules"].toArray().first().toObject();
        rule["weight"]=0; rule["critical"]=true;
        rule["condition"]=QJsonObject{{"all",QJsonArray{QJsonObject{{"feature","writable_executable"},{"equals",false}},QJsonObject{{"not",QJsonObject{{"feature","entry_outside_executable"},{"equals",true}}}}}}};
        rootJson["rules"]=QJsonArray{rule}; put(rulesPath,QJsonDocument(rootJson).toJson());
        auto rules=loadHeuristicRules(rulesPath); put(root+"/clean.exe",pe());
        auto d=evaluateHeuristics(features(root+"/clean.exe"),*rules,[]{return false;}); QVERIFY(d.suspicious); QCOMPARE(d.score,0);
        put(root+"/broken.exe","MZ"); d=evaluateHeuristics(features(root+"/broken.exe"),*rules,[]{return false;}); QVERIFY(!d.suspicious); QCOMPARE(d.state,"partial");
        rule["condition"]=QJsonObject{{"any",QJsonArray{QJsonObject{{"feature","entry_outside_executable"},{"equals",true}},QJsonObject{{"feature","writable_executable"},{"equals",true}}}}};
        rootJson["rules"]=QJsonArray{rule}; put(rulesPath,QJsonDocument(rootJson).toJson()); rules=loadHeuristicRules(rulesPath);
        QVERIFY(!evaluateHeuristics(features(root+"/clean.exe"),*rules,[]{return false;}).suspicious);
        put(root+"/wx.exe",pe(true)); QVERIFY(evaluateHeuristics(features(root+"/wx.exe"),*rules,[]{return false;}).suspicious);
        rule["condition"]=QJsonObject{{"feature","unknown"},{"equals",true}}; rootJson["rules"]=QJsonArray{rule}; put(rulesPath,QJsonDocument(rootJson).toJson()); QVERIFY(fails([&]{loadHeuristicRules(rulesPath);}));
        rootJson=rulesJson(); auto a=rootJson["rules"].toArray(); a.push_back(a.first()); rootJson["rules"]=a; put(rulesPath,QJsonDocument(rootJson).toJson()); QVERIFY(fails([&]{loadHeuristicRules(rulesPath);}));
        rootJson=rulesJson(); rootJson["threshold"]=-1; put(rulesPath,QJsonDocument(rootJson).toJson()); QVERIFY(fails([&]{loadHeuristicRules(rulesPath);}));
    }
    void sharedRouteAndStoredEvidence() {
        put(root+"/wx.exe",pe(true)); auto r=request(root+"/wx.exe"); r.signaturePath=signatures();
        auto j=runJob(r); QCOMPARE(j.state,"completed"); QCOMPARE(j.matches,1); QCOMPARE(j.errors,0); QCOMPARE(j.exitCode(),1);
        { Store s(r.storagePath,true); QCOMPARE(s.latest()->json(),j.json()); auto rows=s.page(j.id,0); QCOMPARE(rows.size(),size_t(1));
          const auto &out=rows.front(); QCOMPARE(out.outcome,"heuristic_match"); QCOMPARE(out.completeness,"full"); QCOMPARE(out.analyzers,"SHA-256,PATTERN,HEURISTIC");
          QVERIFY(out.signatureId.isEmpty()); QCOMPARE(out.details["score"].toInt(),60); QCOMPARE(Result::fromJson(out.json()).json(),out.json());
          ResultQuery q; q.filter=ResultFilter::Matches; QCOMPARE(s.query(j.id,q).total,1); }
        put(root+"/renamed.txt",pe()); r.path=root+"/renamed.txt"; j=runJob(r); QCOMPARE(j.matches,0); QCOMPARE(j.exitCode(),0);
        // Старый путь остаётся v1 и не получает эвристику автоматически.
        r.heuristicPath.clear(); r.path=root+"/wx.exe"; j=runJob(r); QCOMPARE(j.formatVersion,1); QCOMPARE(j.matches,0);
        { Store s(r.storagePath,true); const auto out=s.page(j.id,0).front(); QCOMPARE(out.formatVersion,1); QVERIFY(!out.json().contains("schema_version")); }
    }
    void signatureFailureIsPartialAndHasPriority() {
        put(root+"/wx.exe",pe(true)); auto r=request(root+"/wx.exe"); r.signaturePath=root+"/missing.db";
        const auto j=runJob(r); QCOMPARE(j.matches,1); QCOMPARE(j.checked,1); QCOMPARE(j.errors,1); QCOMPARE(j.state,"failed"); QCOMPARE(j.exitCode(),2);
        { Store s(r.storagePath,true); QCOMPARE(s.latest()->errors,1); const auto out=s.page(j.id,0).front(); QCOMPARE(out.completeness,"partial"); QCOMPARE(out.code,"analyzer_unavailable"); QVERIFY(!out.reason.isEmpty()); }
        r.signaturePath.clear(); const auto only=runJob(r); QCOMPARE(only.exitCode(),1); QCOMPARE(only.errors,0);
        *r.cancel=true; const auto cancelled=runJob(r); QCOMPARE(cancelled.exitCode(),3);
        *r.cancel=false; r.hooks.afterBlock=[&](const QString &,qint64){put(r.path,pe(false));};
        const auto changed=runJob(r); QCOMPARE(changed.exitCode(),2); QCOMPARE(changed.matches,0);
    }
    void strictV2AndLegacyMigration() {
        put(root+"/wx.exe",pe(true)); auto r=request(root+"/wx.exe"); const auto j=runJob(r);
        QVERIFY2(j.matches==1,qPrintable(j.error));
        QJsonObject data; { Store s(r.storagePath,true); data=s.page(j.id,0).front().json(); }
        for(auto i=data.begin();i!=data.end();++i) {
            auto broken=data; broken.remove(i.key()); QVERIFY2(fails([&]{Result::fromJson(broken);}),qPrintable(i.key()));
        }
        auto bad=data; auto details=bad["details"].toObject(); details["score"]=0; bad["details"]=details; QVERIFY(fails([&]{Result::fromJson(bad);}));
        bad=data; bad["rule_id"]="not-in-evidence"; QVERIFY(fails([&]{Result::fromJson(bad);}));
        bad=data; bad["analyzers"]="SHA-256,PATTERN"; QVERIFY(fails([&]{Result::fromJson(bad);}));
        put(root+"/partial.exe","MZ"); auto incomplete=request(root+"/partial.exe"); incomplete.signaturePath=signatures(); const auto partialJob=runJob(incomplete);
        { Store s(incomplete.storagePath,true); bad=s.page(partialJob.id,0).front().json(); QCOMPARE(bad["completeness"].toString(),"partial"); }
        bad["completeness"]="full"; bad["code"]=""; bad["reason"]=""; QVERIFY(fails([&]{Result::fromJson(bad);}));
        // Настоящая старая схема; payload сохраняется побайтно при миграции.
        const auto legacy=root+"/legacy.db";
        Job old; old.id="old"; old.path="old-file"; old.started=now(); old.finished=now(); old.state="completed"; old.databaseVersion="old-db"; old.results=1; old.checked=1;
        Result oldResult; oldResult.jobId=old.id; oldResult.path=old.path; oldResult.identity="old-identity"; oldResult.size=0; oldResult.time=now(); oldResult.databaseVersion=old.databaseVersion; oldResult.outcome="no_match"; oldResult.completeness="full"; oldResult.analyzers="SHA-256,PATTERN";
        const auto oldData=QString::fromUtf8(QJsonDocument(oldResult.json()).toJson(QJsonDocument::Compact));
        { Database db(legacy,false); db.exec("CREATE TABLE jobs(id TEXT PRIMARY KEY,started TEXT NOT NULL,data TEXT NOT NULL)");
          db.exec("CREATE TABLE results(row_id INTEGER PRIMARY KEY,job_id TEXT NOT NULL REFERENCES jobs(id),data TEXT NOT NULL)");
          db.exec("CREATE TABLE detections(id TEXT PRIMARY KEY,job_id TEXT,result_id INTEGER,source TEXT,time TEXT,signature_id TEXT,signature_version TEXT,basis TEXT)");
          db.exec("CREATE TABLE events(id INTEGER PRIMARY KEY,time TEXT,type TEXT,source TEXT,object TEXT,code TEXT,job_id TEXT)");
          db.exec("PRAGMA user_version=1"); db.exec("PRAGMA application_id=1381189442");
          db.exec("INSERT INTO jobs VALUES(?,?,?)",{old.id,old.started,QString::fromUtf8(QJsonDocument(old.json()).toJson(QJsonDocument::Compact))}); db.exec("INSERT INTO results(job_id,data) VALUES(?,?)",{old.id,oldData}); }
        { Store s(legacy,true); QCOMPARE(s.latest()->id,old.id); }
        { Store s(legacy); QCOMPARE(s.latest()->id,old.id); }
        { Database db(legacy,true); auto q=db.exec("PRAGMA user_version"); QVERIFY(q.next()); QCOMPARE(q.value(0).toInt(),3); q=db.exec("SELECT data FROM results"); QVERIFY(q.next()); QCOMPARE(q.value(0).toString(),oldData); }
    }
    void interruptedV2JobHasValidRoundTrip() {
        Job job; job.formatVersion=2; job.id="interrupted"; job.path=root; job.started=now(); job.source="monitor"; job.rulesVersion="rules-v1";
        { Store store(root+"/interrupted.db"); store.start(job); }
        Store store(root+"/interrupted.db",true); const auto recovered=store.latest(); QVERIFY(recovered); QCOMPARE(recovered->state,"failed"); QVERIFY(recovered->finished.isEmpty()); QVERIFY(!recovered->error.isEmpty());
        QCOMPARE(Job::fromJson(recovered->json()).json(),recovered->json());
    }
    void concurrentJobsAndSelectedHistory() {
        put(root+"/safe.exe",pe(true)); const auto db=signatures();
        auto a=request(root+"/safe.exe"),b=a; a.signaturePath=db; b.signaturePath=db;
        auto first=std::async(std::launch::async,[a]{return runJob(a);}); auto second=std::async(std::launch::async,[b]{return runJob(b);});
        const auto ja=first.get(),jb=second.get(); QCOMPARE(ja.exitCode(),1); QCOMPARE(jb.exitCode(),1); QVERIFY(ja.id!=jb.id);
        Store history(a.storagePath,true); QCOMPARE(history.jobs(0,1).size(),size_t(1)); QCOMPARE(history.jobs(1,1).size(),size_t(1)); QVERIFY(history.jobs(2,1).empty());
        QCOMPARE(history.getJob(ja.id)->json(),ja.json()); QCOMPARE(history.getJob(jb.id)->json(),jb.json()); QVERIFY(!history.getJob("missing"));
        { Database sql(a.storagePath,false); sql.exec("UPDATE detections SET basis='corrupt' WHERE job_id=?",{ja.id}); }
        QVERIFY(fails([&]{history.getJob(ja.id);})); QCOMPARE(history.getJob(jb.id)->json(),jb.json());
    }
    void processQueryFiltersBeforePagination() {
        Job j; j.formatVersion=2; j.source="monitor"; j.id="scoped-history"; j.path=root; j.started=now(); j.databaseVersion="control";
        Store history(root+"/query.db"); history.start(j);
        for(int i=0;i<2102;++i) {
            Result r; r.formatVersion=2; r.jobId=j.id; r.databaseVersion=j.databaseVersion; r.path=root+QString("/%1").arg(i); r.size=8; r.identity="file-identity"; r.time=now(); r.outcome="no_match"; r.completeness="full"; r.analyzers="SHA-256,PATTERN";
            if(i==2101) {
                r.eventId="image-event"; const QJsonObject p{{"pid","424242"},{"parent_pid","1"},{"start_time","123456789"},{"image",r.path}};
                history.recordObservation(j.id,"process_monitor","process_image",r.path,{{"id",r.eventId},{"operation","image_file"},{"time",r.time},{"process",p},{"coverage","image_file_by_path"}});
                r.outcome="signature_match"; r.signatureId="specific-id"; r.signatureName="CONTROL"; r.signatureVersion="1"; r.basis="SHA-256: control";
                ++j.matches; j.detectionName=r.signatureName; j.detectionPath=r.path;
            }
            ++j.results; ++j.checked; history.append(r,j);
        }
        j.state="cancelled"; j.finished=now(); history.finish(j);
        ResultQuery q; q.object=ResultObject::Processes; q.text="424242"; q.limit=1; auto page=history.query(j.id,q); QCOMPARE(page.total,1); QCOMPARE(page.rows.front().path,j.detectionPath);
        q.text="specific-id"; QCOMPARE(history.query(j.id,q).total,1); q.offset=1; QCOMPARE(history.query(j.id,q).rows.size(),size_t(0));
        q={}; q.object=ResultObject::Manual; QCOMPARE(history.query(j.id,q).total,2101); QCOMPARE(history.getJob(j.id)->json(),j.json());
    }
};
QTEST_GUILESS_MAIN(Lab4Tests)
#include "lab4_tests.moc"
