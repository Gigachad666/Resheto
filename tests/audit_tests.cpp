#include "core/database.h"
#include "core/file_access.h"
#include "core/scanner.h"
#include "core/signatures.h"
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QtTest>
#include <limits>
using namespace resheto;
template<class F> bool rejected(F &&f) { try { f(); } catch(const Error &) { return true; } return false; }

class AuditTests : public QObject {
    Q_OBJECT
    static Job validJob() {
        Job j; j.id="test-job"; j.path="test-file"; j.databaseVersion="test-v1";
        j.started=now(); j.finished=now(); j.state="completed";
        j.results=2; j.checked=1; j.matches=1; j.skipped=1;
        j.detectionPath="test-file"; j.detectionName=QStringLiteral("ТЕСТ: сигнатура"); return j;
    }
    static Result validResult() {
        Result r; r.jobId="test-job"; r.path="test-file"; r.identity="test-identity";
        r.databaseVersion="test-v1"; r.size=3; r.offset=0; r.time=now();
        r.outcome="signature_match"; r.completeness="full"; r.analyzers="SHA-256,PATTERN";
        r.signatureId="test-id"; r.signatureName=QStringLiteral("ТЕСТ: сигнатура"); r.signatureVersion="1";
        r.basis=QStringLiteral("PATTERN, абсолютное смещение 0"); return r;
    }
private slots:
    void invalidCounters_data() {
        QTest::addColumn<QString>("field"); QTest::addColumn<QJsonValue>("value");
        const QList<QJsonValue> bad={"not-a-number",QJsonValue(QJsonValue::Undefined),QJsonValue(),"-1","9223372036854775808",1,true,"1.5"," 1","+1"};
        for(const auto &field:QStringList{"results","checked","matches","errors","skipped"})
            for(int i=0;i<bad.size();++i) QTest::newRow(qPrintable(field+QString::number(i)))<<field<<bad[i];
    }
    void invalidCounters() {
        QFETCH(QString,field); QFETCH(QJsonValue,value); auto o=validJob().json(); o[field]=value;
        QVERIFY2(rejected([&]{Job::fromJson(o);}),qPrintable(field));
    }
    void invalidJobInvariants() {
        const auto good=validJob().json();
        auto reject=[&](const QString &key,QJsonValue value){auto o=good; o[key]=value; return rejected([&]{Job::fromJson(o);});};
        QVERIFY(reject("state","unknown")); QVERIFY(reject("state",5));
        QVERIFY(reject("checked","0")); QVERIFY(reject("skipped","2"));
        QVERIFY(reject("errors","1")); QVERIFY(reject("last_detection_name",""));
        QVERIFY(reject("last_detection_path",QJsonValue(QJsonValue::Undefined)));
        QVERIFY(reject("id","")); QVERIFY(reject("source","other"));
        QVERIFY(reject("started","bad-time")); QVERIFY(reject("finished",""));
        QVERIFY(reject("database_version","")); QVERIFY(reject("error",false));
    }
    void everySerializedFieldIsRequiredAndTyped() {
        const auto job=validJob().json(); const auto result=validResult().json();
        for(auto i=job.begin();i!=job.end();++i) {
            auto o=job; o.remove(i.key()); QVERIFY2(rejected([&]{Job::fromJson(o);}),qPrintable(i.key()));
            o=job; o[i.key()]=true; QVERIFY2(rejected([&]{Job::fromJson(o);}),qPrintable(i.key()));
        }
        for(auto i=result.begin();i!=result.end();++i) {
            auto o=result; o.remove(i.key()); QVERIFY2(rejected([&]{Result::fromJson(o);}),qPrintable(i.key()));
            o=result; o[i.key()]=i.key()=="skipped" ? QJsonValue("false") : QJsonValue(true);
            QVERIFY2(rejected([&]{Result::fromJson(o);}),qPrintable(i.key()));
        }
    }
    void invalidResult_data() {
        QTest::addColumn<QString>("field"); QTest::addColumn<QJsonValue>("value");
        const QList<QPair<QString,QJsonValue>> mutations={
            {"size","not-a-number"},{"size",QJsonValue(QJsonValue::Undefined)},{"size","-2"},{"size","9223372036854775808"},{"size",3},{"size","-1"},
            {"offset","not-a-number"},{"offset","-2"},{"offset","9223372036854775808"},{"offset","3"},
            {"outcome","other"},{"completeness","partial"},{"completeness","none"},{"skipped",true},{"skipped","false"},
            {"identity",""},{"job_id",""},{"path",""},{"database_version",""},{"analyzers",""},
            {"signature_id",""},{"signature_name",QJsonValue(QJsonValue::Undefined)},{"signature_version",""},{"basis",""},
            {"code","file_io"},{"reason","error"},{"time","bad-time"}};
        for(int i=0;i<mutations.size();++i) QTest::newRow(qPrintable(QString::number(i)+mutations[i].first))<<mutations[i].first<<mutations[i].second;
    }
    void invalidResult() {
        QFETCH(QString,field); QFETCH(QJsonValue,value); auto o=validResult().json(); o[field]=value;
        QVERIFY2(rejected([&]{Result::fromJson(o);}),qPrintable(field));
    }
    void validRoundTripsAndIncompleteObjects() {
        const auto goodJob=validJob(); QCOMPARE(Job::fromJson(goodJob.json()).json(),goodJob.json());
        auto r=validResult(); QCOMPARE(Result::fromJson(r.json()).json(),r.json());
        r.outcome="no_match"; r.offset=-1; r.signatureId.clear(); r.signatureName.clear(); r.signatureVersion.clear(); r.basis.clear();
        QCOMPARE(Result::fromJson(r.json()).outcome,"no_match");
        r.outcome="not_checked"; r.completeness="none"; r.analyzers.clear(); r.identity.clear(); r.size=-1;
        r.code="link"; r.reason=QStringLiteral("Пропуск ссылки"); r.skipped=true;
        QCOMPARE(Result::fromJson(r.json()).size,-1);
        auto wrong=r.json(); wrong["completeness"]="full"; QVERIFY(rejected([&]{Result::fromJson(wrong);}));
        wrong=r.json(); wrong["reason"]=""; QVERIFY(rejected([&]{Result::fromJson(wrong);}));
        r.skipped=false; r.code="cancelled"; QCOMPARE(Result::fromJson(r.json()).outcome,"not_checked");
        auto j=validJob(); j.state="cancelled"; j.results=3; // Сохранён также незавершённый отменённый объект.
        QCOMPARE(Job::fromJson(j.json()).exitCode(),3);
        j.state="failed"; j.error=QStringLiteral("Ошибка хранения"); QCOMPARE(Job::fromJson(j.json()).exitCode(),2);
        j=validJob(); j.state="running"; j.finished.clear(); QCOMPARE(Job::fromJson(j.json()).state,"running");
        j.results=std::numeric_limits<qint64>::max(); j.checked=j.results; j.matches=j.results; j.skipped=0;
        QCOMPARE(Job::fromJson(j.json()).results,j.results);
        j=Job(); j.id="empty"; j.path="dir"; j.started=now(); j.finished=now(); j.state="failed"; j.error="analyzer unavailable";
        QCOMPARE(Job::fromJson(j.json()).results,0);
    }
    void storeRejectsInconsistentCountersAndRowIdentity() {
        QTemporaryDir tmp(QDir::currentPath()+"/resheto-history-XXXXXX"); QVERIFY(tmp.isValid()); const auto path=tmp.path()+"/results.db";
        auto j=validJob(); j.results=1; j.skipped=0;
        { Store store(path); store.start(j); store.append(validResult(),j); store.finish(j); }
        { Store store(path,true); QCOMPARE(store.latest()->matches,1); QCOMPARE(store.page(j.id,0).size(),size_t(1)); }
        auto corrupt=j.json(); corrupt["matches"]="0"; corrupt["last_detection_path"]=""; corrupt["last_detection_name"]="";
        { Database d(path,false); d.exec("UPDATE jobs SET data=?",{QString::fromUtf8(QJsonDocument(corrupt).toJson())}); }
        { Store store(path,true); QVERIFY(rejected([&]{store.latest();})); }
        corrupt=j.json(); corrupt["id"]="other-job";
        { Database d(path,false); d.exec("UPDATE jobs SET data=?",{QString::fromUtf8(QJsonDocument(corrupt).toJson())}); }
        { Store store(path,true); QVERIFY(rejected([&]{store.latest();})); }
        { Database d(path,false); d.exec("UPDATE jobs SET data=?",{QString::fromUtf8(QJsonDocument(j.json()).toJson())});
          auto bad=validResult().json(); bad["size"]="9223372036854775808";
          d.exec("UPDATE results SET data=?",{QString::fromUtf8(QJsonDocument(bad).toJson())}); }
        { Store store(path,true); QVERIFY(rejected([&]{store.page(j.id,0);})); QCOMPARE(store.lastRow(),0); QVERIFY(rejected([&]{store.latest();})); }
        { Database d(path,false); d.exec("UPDATE results SET data='[]'"); }
        { Store store(path,true); QVERIFY(rejected([&]{store.page(j.id,0);})); QVERIFY(rejected([&]{store.latest();})); }
        { Database d(path,false); d.exec("UPDATE results SET data=?",{QString::fromUtf8(QJsonDocument(validResult().json()).toJson())}); }
        { Store store(path,true); QCOMPARE(store.latest()->matches,1); QCOMPARE(store.page(j.id,0).size(),size_t(1)); }
    }
    void traversalDepthBoundary() {
        QTemporaryDir tmp(QDir::currentPath()+"/resheto-depth-XXXXXX"); QVERIFY(tmp.isValid());
        const auto root=tmp.path()+"/tree"; QVERIFY(QDir().mkpath(root)); QString current=root;
        // Предварительно проверяем реальные возможности тех же std::filesystem API.
        QString atLimit,overLimit;
        for(int depth=1;depth<=257;++depth) {
            current+="/d"; std::error_code ec;
            if(!std::filesystem::create_directory(nativePath(current),ec) || ec) QSKIP("Граница 256 не проверена: ОС/API не разрешили длинный путь");
            std::filesystem::directory_iterator probe(nativePath(current),ec);
            if(ec) QSKIP("Граница 256 не проверена: ОС/API не могут читать длинный путь");
            if(depth==256) atLimit=current;
            if(depth==257) overLimit=current;
        }
        auto put=[](const QString &p,const QByteArray &b){QFile f(p); if(!f.open(QIODevice::WriteOnly) || f.write(b)!=b.size()) throw Error("fixture write");};
        put(atLimit+"/edge",QByteArray::fromHex("aa00bb")); put(overLimit+"/unvisited",QByteArray::fromHex("aa00bb"));
        QVERIFY(QDir().mkpath(root+"/other")); put(root+"/other/accessible","harmless");
        put(tmp.path()+"/source.json",R"({"version":"test-depth","signatures":[{"id":"test-depth","name":"ТЕСТ: глубина","kind":"PATTERN","value":"aa00bb","version":"1","enabled":1}]})");
        createSignatures(tmp.path()+"/source.json",tmp.path()+"/signatures.db");
        Request req; req.path=root; req.signaturePath=tmp.path()+"/signatures.db"; req.storagePath=tmp.path()+"/results.db";
        auto j=runJob(req); QCOMPARE(j.state,"failed"); QCOMPARE(j.errors,1); QCOMPARE(j.checked,2); QCOMPARE(j.matches,1);
        Store store(req.storagePath,true); auto rows=store.page(j.id,0); bool found=false;
        for(const auto &r:rows) if(r.code=="depth_limit") { found=true; QCOMPARE(r.path,overLimit); QVERIFY(!r.reason.isEmpty()); QCOMPARE(r.outcome,"not_checked"); }
        QVERIFY(found);
    }
    void singleChildDepthIsIndependentOfIterators() {
        QTemporaryDir tmp(QDir::currentPath()+"/resheto-depth-short-XXXXXX"); QVERIFY(tmp.isValid());
        const auto root=tmp.path()+"/tree"; QString current=root; QMap<QString,int> expected;
        expected[root]=0;
        for(int i=1;i<=8;++i) { current+="/d"; expected[current]=i; }
        QVERIFY(QDir().mkpath(current)); QVERIFY(QDir().mkpath(root+"/other")); expected[root+"/other"]=1;
        QFile json(tmp.path()+"/source.json"); QVERIFY(json.open(QIODevice::WriteOnly));
        json.write(R"({"version":"test-depth","signatures":[{"id":"test","name":"ТЕСТ","kind":"PATTERN","value":"aa00bb","version":"1","enabled":1}]})"); json.close();
        createSignatures(json.fileName(),tmp.path()+"/signatures.db");
        Request req; req.path=root; req.signaturePath=tmp.path()+"/signatures.db"; req.storagePath=tmp.path()+"/results.db";
        QMap<QString,int> observed; req.hooks.directoryDepth=[&](const QString &p,int depth){observed[p]=depth;};
        const auto j=runJob(req); QCOMPARE(j.state,"completed"); QCOMPARE(observed,expected);
    }
};
QTEST_GUILESS_MAIN(AuditTests)
#include "audit_tests.moc"
