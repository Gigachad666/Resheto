#include "core/api.h"
#include "core/search.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QtTest>
#include <random>
using namespace resheto;
static void put(const QString &p,const QByteArray &b) { QFile f(p); if(!f.open(QIODevice::WriteOnly) || f.write(b)!=b.size()) throw Error("fixture write"); }
template<class F> static bool fails(F f) { try { f(); } catch(const Error &) { return true; } return false; }
static QByteArray bytes(const QString &p) { QFile f(p); if(!f.open(QIODevice::ReadOnly)) throw Error("fixture read"); return f.readAll(); }
class CompletionTests : public QObject {
    Q_OBJECT
private slots:
    void indexedSearchAgainstOracle() {
        std::mt19937 random(314159); Snapshot snap;
        for(int i=0;i<1000;++i) {
            Signature s; s.id=QString("pattern-%1").arg(i,4,10,QChar('0')); s.kind="PATTERN";
            s.value=QByteArray(1+random()%64,Qt::Uninitialized);
            for(auto &c:s.value) c=static_cast<char>(random()%16);
            if(i%3==0) { s.mask=QByteArray(s.value.size(),'1'); for(qsizetype k=1;k<s.mask.size();k+=2) s.mask[k]='0'; }
            if(i%5==0) s.offset=random()%800;
            if(i%7==0) s.minSize=2000;
            if(i%11==0) s.maxSize=10;
            snap.maxPattern=qMax(snap.maxPattern,s.value.size()); snap.entries.push_back(s);
        }
        // Суффиксы якорей, одинаковые смещения и минимальный id.
        for(const auto &v:{QByteArray("abc"),QByteArray("bc"),QByteArray("c")}) { Signature s; s.id=QString::fromLatin1(v); s.kind="PATTERN"; s.value=v; snap.entries.push_back(s); }
        SearchIndex index(snap.entries);
        for(int trial=0;trial<30;++trial) {
            QByteArray data(1000,Qt::Uninitialized); for(auto &c:data) c=static_cast<char>(random()%16); data.replace(500,3,"abc");
            if(trial%2==0) data.replace(790,snap.entries[2].value.size(),snap.entries[2].value);
            qint64 expected=-1; const Signature *winner=nullptr;
            for(const auto &s:snap.entries) {
                if((s.minSize && data.size()<*s.minSize) || (s.maxSize && data.size()>*s.maxSize)) continue;
                for(qsizetype p=0;p+s.value.size()<=data.size();++p) {
                    if(s.offset && p!=*s.offset) continue; bool equal=true;
                    for(qsizetype k=0;k<s.value.size();++k) if((s.mask.isEmpty() || s.mask[k]=='1') && data[p+k]!=s.value[k]) { equal=false; break; }
                    if(equal) { if(!winner || p<expected || (p==expected && s.id.toUtf8()<winner->id.toUtf8())) { winner=&s; expected=p; } break; }
                }
            }
            for(int block:{17,65,257,1000}) {
                const Signature *found=nullptr; qint64 offset=-1; QByteArray tail;
                for(qsizetype p=0;p<data.size();p+=block) { auto window=tail+data.mid(p,block); QVERIFY(index.patterns(snap,window,p-tail.size(),p,data.size(),[]{return false;},found,offset)); tail=window.right(snap.maxPattern-1); }
                QCOMPARE(offset,expected); QCOMPARE(found?found->id:QString(),winner?winner->id:QString());
            }
        }
        const Signature *found=nullptr; qint64 offset=-1; int calls=0;
        QVERIFY(!index.patterns(snap,QByteArray(100000,'q'),0,0,100000,[&]{return ++calls>=3;},found,offset));
    }
    void hashIndexSizeAndOrder() {
        Snapshot s; const auto h=QByteArray(32,'h');
        Signature a; a.id="a"; a.kind="HASH"; a.value=h; a.minSize=3;
        Signature b=a; b.id="b"; b.minSize=1; s.entries={a,b}; SearchIndex i(s.entries);
        QCOMPARE(i.digest(s,h,3)->id,"a"); QCOMPARE(i.digest(s,h,2)->id,"b"); QVERIFY(!i.digest(s,h,0));
    }
    void realFeedProvenance() {
        QTemporaryDir tmp(QDir::currentPath()+"/completion-feed-XXXXXX"); QVERIFY(tmp.isValid());
        const auto source=QString::fromUtf8(RESHETO_SOURCE_DIR)+"/distribution/source/";
        const auto provenance=QJsonDocument::fromJson(bytes(source+"provenance.json")).object();
        QCOMPARE(provenance["source_sha256"].toString(),"07bf75ab004da3f5f5d1b25e41a8e3544ea7b66255d27ec7536672cb1f5e3b60");
        const auto report=importSnapshot({source+"full-hash-sha256-aa.txt","sha256-lines",tmp.path()+"/release","real-feed-check",provenance});
        QCOMPARE(report["hash"].toString(),"11632"); QCOMPARE(report["duplicates"].toString(),"4"); QCOMPARE(report["pattern"].toString(),"0");
        const auto snap=loadSignatures(tmp.path()+"/release/current.json"); QCOMPARE(snap->hashCount,11632); QCOMPARE(snap->patternCount,0);
        // Ожидаемые digest и строки закреплены независимо от импортера и алгоритма поиска.
        const QList<QPair<int,QByteArray>> expected={{1,"fffa96bbcf4e075c3c1af00d88c598b01683d411ff81a88ac654f98d21deb1b5"},{5819,"7f3169d20172caa22b51cc99c389ff6b87fead570cc656388335c25a062e0267"},{11636,"00000045ef6ec5eb590ef16ef79d467734ea7d9144d7990511514f08ed3cb673"}};
        const auto lines=bytes(source+"full-hash-sha256-aa.txt").split('\n'); Database db(snap->path,true);
        const auto working=loadSignatures(QString::fromUtf8(RESHETO_SOURCE_DIR)+"/distribution/working/current.json");
        QCOMPARE(working->purpose,"working"); QCOMPARE(working->hashCount,11632); QCOMPARE(working->patternCount,0);
        for(const auto &e:expected) {
            QCOMPARE(lines[e.first-1].trimmed(),e.second); const auto *sig=snap->index->digest(*snap,QByteArray::fromHex(e.second),123); QVERIFY(sig); QCOMPARE(sig->value.toHex(),e.second);
            auto q=db.exec("SELECT source_line,source_value FROM provenance WHERE signature_id=?",{sig->id}); QVERIFY(q.next()); QCOMPARE(q.value(0).toInt(),e.first); QCOMPARE(q.value(1).toByteArray(),e.second);
            const auto *shipped=working->index->digest(*working,QByteArray::fromHex(e.second),123); QVERIFY(shipped); QCOMPARE(shipped->value.toHex(),e.second);
        }
    }
    void offlineImportAtomicSelection() {
        QTemporaryDir tmp(QDir::currentPath()+"/completion-import-XXXXXX"); QVERIFY(tmp.isValid()); const auto root=tmp.path();
        const auto h=QCryptographicHash::hash("harmless",QCryptographicHash::Sha256).toHex();
        ImportRequest r; r.input=root+"/feed.hsb"; r.repository=root+"/releases"; r.format="clamav-hsb"; r.version="control-import-v1";
        auto input=[&](const QByteArray &content){put(r.input,content); r.provenance={{"source_url","fixture:control"},{"source_revision","1"},{"license","own-control"},{"attribution","control"},{"acquired_utc",now()},{"source_sha256",QString::fromLatin1(QCryptographicHash::hash(content,QCryptographicHash::Sha256).toHex())}};};
        input(h+":8:Control\n"+h+":8:Control\n"+QByteArray(40,'a')+":8:OldAlgorithm\n");
        const auto report=importSnapshot(r); QCOMPARE(report["hash"].toString(),"1"); QCOMPARE(report["duplicates"].toString(),"1"); QCOMPARE(report["unsupported_algorithms"].toString(),"1");
        const auto selection=r.repository+"/current.json"; const auto prior=bytes(selection); auto old=loadSignatures(selection); QCOMPARE(old->entries.size(),size_t(1));
        r.beforePublish=[]{throw Error(QStringLiteral("ENOSPC: управляемый отказ публикации"));};
        QVERIFY(fails([&]{importSnapshot(r);})); QCOMPARE(bytes(selection),prior); QCOMPARE(loadSignatures(selection)->checksum,old->checksum); r.beforePublish={};
        for(const auto &bad:QList<QByteArray>{h+":-1:Bad\n",h+":9223372036854775808:Bad\n",h+":8:Control\n"+h+":9:Conflict\n","gg:8:Bad\n",QByteArray(62,'a')+":1:Bad\n","",QByteArray(40,'a')+":1:NoSHA256\n"}) {
            input(bad); QVERIFY(fails([&]{importSnapshot(r);})); QCOMPARE(bytes(selection),prior); QCOMPARE(loadSignatures(selection)->checksum,old->checksum);
        }
        input(h+":8:Control\n"); r.provenance["source_sha256"]=QString(64,'0'); QVERIFY(fails([&]{importSnapshot(r);})); QCOMPARE(bytes(selection),prior);
        input(h+":8:NewName\n"); r.version="control-import-v2"; const auto second=importSnapshot(r); QCOMPARE(loadSignatures(selection)->version,r.version); QCOMPARE(old->version,"control-import-v1");
        activateVersion(r.repository,report["database"].toString()); QCOMPARE(loadSignatures(selection)->version,"control-import-v1");
        put(root+"/control-file","harmless"); Request jobRequest; jobRequest.path=root+"/control-file"; jobRequest.signaturePath=selection; jobRequest.storagePath=root+"/history.db";
        bool switched=false;
        jobRequest.hooks.afterBlock=[&](const QString &,qint64) { if(!switched) { switched=true; activateVersion(r.repository,second["database"].toString()); } };
        const auto firstJob=runJob(jobRequest); QCOMPARE(firstJob.databaseVersion,"control-import-v1"); QCOMPARE(firstJob.matches,1);
        const auto nextJob=runJob(jobRequest); QCOMPARE(nextJob.databaseVersion,"control-import-v2"); QCOMPARE(nextJob.matches,1);
        { Store history(jobRequest.storagePath,true); QCOMPARE(history.page(firstJob.id,0).front().signatureName,"Control"); QCOMPARE(history.page(nextJob.id,0).front().signatureName,"NewName"); }
        QVERIFY(fails([&]{activateVersion(r.repository,"../bad.db");}));
        // Ошибка публикации: current.json — каталог; предыдущая версия остаётся читаемой.
        const auto blocked=root+"/blocked"; QVERIFY(QDir().mkpath(blocked+"/current.json")); r.repository=blocked;
        QVERIFY(fails([&]{importSnapshot(r);})); QCOMPARE(loadSignatures(old->path)->checksum,old->checksum);
        r.repository=root+"/absent/parent"; r.input=root+"/missing"; QVERIFY(fails([&]{importSnapshot(r);}));
    }
    void queryWholeJobBeforePagination() {
        QTemporaryDir tmp(QDir::currentPath()+"/completion-query-XXXXXX"); QVERIFY(tmp.isValid()); const auto path=tmp.path()+"/history.db";
        Job j; j.id="query"; j.started=now(); j.path="controlled"; j.databaseVersion="control";
        { Store store(path); store.start(j);
          for(int i=0;i<2102;++i) {
            Result r; r.jobId=j.id; r.databaseVersion=j.databaseVersion; r.time=now(); r.path=QStringLiteral("/путь с пробелом/%1").arg(i,4,10,QChar('0')); r.size=8; r.identity="fixture"; r.completeness="full"; r.analyzers="SHA-256,PATTERN"; r.outcome="no_match";
            ++j.results; ++j.checked;
            if(i==2100) { r.outcome="signature_match"; r.signatureId="control"; r.signatureName="Control"; r.signatureVersion="1"; r.basis="SHA-256: control"; ++j.matches; j.detectionPath=r.path; j.detectionName=r.signatureName; }
            if(i==2101) { r.outcome="not_checked"; r.completeness="none"; r.analyzers.clear(); r.code="file_io"; r.reason="controlled error"; --j.checked; ++j.errors; }
            store.append(r,j);
          } j.state="failed"; j.finished=now(); store.finish(j);
        }
        Store store(path,true); QCOMPARE(store.latest()->results,2102);
        ResultQuery q; q.filter=ResultFilter::Matches; auto result=store.query(j.id,q); QCOMPARE(result.total,1); QCOMPARE(result.rows.front().path,j.detectionPath);
        q.filter=ResultFilter::NotChecked; QCOMPARE(store.query(j.id,q).total,1);
        q.filter=ResultFilter::All; q.path=QStringLiteral("путь с пробелом/210"); QCOMPARE(store.query(j.id,q).total,2);
        q.path="%"; QCOMPARE(store.query(j.id,q).total,0); q.path.clear();
        for(auto sort:{ResultSort::Path,ResultSort::Outcome,ResultSort::Signature}) for(bool desc:{false,true}) {
            q.sort=sort; q.descending=desc; q.offset=0; q.upperRow=0; q.limit=199; QSet<QString> seen;
            do { result=store.query(j.id,q); q.upperRow=result.upperRow; q.offset+=result.rows.size(); for(const auto &r:result.rows) { QVERIFY(!seen.contains(r.path)); seen.insert(r.path); } } while(!result.rows.empty());
            QCOMPARE(seen.size(),2102);
        }
    }
};
QTEST_GUILESS_MAIN(CompletionTests)
#include "completion_tests.moc"
