#include "core/model.h"
#include "core/database.h"
#include "core/signatures.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QProcess>
#include <QScopeGuard>
#include <QTemporaryDir>
#include <QtTest>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#endif
using namespace resheto;
class Integration : public QObject {
    Q_OBJECT
public:
    QString cli,prepare,source;
    QByteArray output;
    QByteArray diagnostics;
    int execute(const QString &exe,const QStringList &args) {
        QProcess p; p.start(exe,args);
        if(!p.waitForStarted(10000) || !p.waitForFinished(60000)) { p.kill(); p.waitForFinished(); return -99; }
        output=p.readAllStandardOutput();
        diagnostics=p.readAllStandardError();
        if(p.exitStatus()!=QProcess::NormalExit) return -98;
        return p.exitCode();
    }
    QJsonObject finalJob() { auto lines=output.trimmed().split('\n'); return QJsonDocument::fromJson(lines.last()).object(); }
private slots:
    void argumentErrorsAndHelp() {
        for(const auto &args:QList<QStringList>{{"--json","--unknown-option"},{"--json","--path"},{"--unknown-option","--json"}}) {
            QCOMPARE(execute(cli,args),2);
            const auto error=QJsonDocument::fromJson(output).object(); QCOMPARE(error["type"].toString(),"error");
            QCOMPARE(error["exit_code"].toInt(),2); QVERIFY(!error["error"].toString().isEmpty());
        }
        QCOMPARE(execute(cli,{"--unknown-option"}),2); QVERIFY(!diagnostics.isEmpty());
        QCOMPARE(execute(cli,{"--help"}),0); QVERIFY(output.contains("--path"));
    }
    void corruptedHistoryReturnsError() {
        QTemporaryDir temp(QDir::currentPath()+"/resheto-corruption-XXXXXX"); QVERIFY(temp.isValid()); const auto root=temp.path()+"/demo";
        QCOMPARE(execute(prepare,{"--source",source,"--output",root}),0);
        QCOMPARE(execute(cli,{"--path",root+"/fixtures","--db",root+"/signatures.db","--storage",root+"/resheto.db","--json"}),1);
        const auto good=finalJob()["data"].toObject(); QCOMPARE(good["matches"].toString(),"5");
        { Database d(root+"/resheto.db",false); auto bad=good; bad["matches"]="not-a-number"; d.exec("UPDATE jobs SET data=?",{QString::fromUtf8(QJsonDocument(bad).toJson())}); }
        QCOMPARE(execute(cli,{"--last","--storage",root+"/resheto.db","--json"}),2);
        QCOMPARE(QJsonDocument::fromJson(output).object()["type"].toString(),"error");
        { Database d(root+"/resheto.db",false); d.exec("UPDATE jobs SET data=?",{QString::fromUtf8(QJsonDocument(good).toJson())}); }
        QCOMPARE(execute(cli,{"--last","--storage",root+"/resheto.db","--json"}),1);
        { Database d(root+"/resheto.db",false); auto q=d.exec("SELECT row_id,data FROM results WHERE json_extract(data,'$.outcome')='signature_match' LIMIT 1"); QVERIFY(q.next());
          const auto row=q.value(0); auto bad=QJsonDocument::fromJson(q.value(1).toByteArray()).object(); bad["completeness"]="none"; q.finish();
          d.exec("UPDATE results SET data=? WHERE row_id=?",{QString::fromUtf8(QJsonDocument(bad).toJson()),row}); }
        QCOMPARE(execute(cli,{"--last","--storage",root+"/resheto.db","--json"}),2);
        QCOMPARE(QJsonDocument::fromJson(output).object()["type"].toString(),"error");
    }
    void corruptedSignatureDatabase() {
        QTemporaryDir temp(QDir::currentPath()+"/resheto-invalid-db-XXXXXX"); QVERIFY(temp.isValid()); const auto root=temp.path()+"/demo";
        QCOMPARE(execute(prepare,{"--source",source,"--output",root}),0);
        const auto args=QStringList{"--path",root+"/fixtures","--db",root+"/signatures.db","--storage",root+"/results.db","--json"};
        { QFile db(root+"/signatures.db"); QVERIFY(db.open(QIODevice::WriteOnly)); QCOMPARE(db.write("not a database"),14); }
        QCOMPARE(execute(cli,args),2); QCOMPARE(finalJob()["data"].toObject()["state"].toString(),"failed");
        writeManifest(root+"/signatures.db"); // Теперь checksum верна, но SQLite повреждён.
        QCOMPARE(execute(cli,args),2); QVERIFY(!finalJob()["data"].toObject()["error"].toString().isEmpty());
    }
#ifdef Q_OS_WIN
    void lockedFileDoesNotStopDirectory() {
        QTemporaryDir temp(QDir::currentPath()+"/resheto-locked-XXXXXX"); QVERIFY(temp.isValid()); const auto root=temp.path()+"/demo";
        QCOMPARE(execute(prepare,{"--source",source,"--output",root}),0);
        const auto path=root+"/fixtures/locked.bin";
        { QFile file(path); QVERIFY(file.open(QIODevice::WriteOnly)); QCOMPARE(file.write("harmless"),8); }
        HANDLE handle=CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()),GENERIC_READ,0,nullptr,OPEN_EXISTING,0,nullptr);
        QVERIFY(handle!=INVALID_HANDLE_VALUE); const auto cleanup=qScopeGuard([&]{CloseHandle(handle);});
        QCOMPARE(execute(cli,{"--path",root+"/fixtures","--db",root+"/signatures.db","--storage",root+"/results.db","--json"}),2);
        const auto job=finalJob()["data"].toObject(); QCOMPARE(job["checked"].toString(),"11"); QCOMPARE(job["matches"].toString(),"5"); QCOMPARE(job["errors"].toString(),"1");
    }
#endif
    void fixtureScanAndReplay() {
        QTemporaryDir temp(QDir::currentPath()+"/resheto-cli-test-XXXXXX"); QVERIFY(temp.isValid()); const auto root=temp.path()+"/demo";
        QCOMPARE(execute(prepare,{"--source",source,"--output",root}),0);
        const auto args=QStringList{"--path",root+"/fixtures","--db",root+"/signatures.db","--storage",root+"/resheto.db","--json"};
        QCOMPARE(execute(cli,args),1); QCOMPARE(finalJob()["data"].toObject()["matches"].toString(),"5");
        QFile expected(root+"/expected.json"); QVERIFY(expected.open(QIODevice::ReadOnly)); auto fixtures=QJsonDocument::fromJson(expected.readAll()).array();
        QMap<QString,QJsonObject> actual;
        for(const auto &line:output.trimmed().split('\n')) { auto o=QJsonDocument::fromJson(line).object(); if(o["type"]=="result") { auto r=o["data"].toObject(); actual.insert(QDir(root+"/fixtures").relativeFilePath(r["path"].toString()),r); } }
        QCOMPARE(actual.size(),fixtures.size());
        for(const auto &v:fixtures) { auto e=v.toObject(); auto a=actual.value(e["path"].toString()); QCOMPARE(a["outcome"],e["outcome"]); QCOMPARE(a["signature_id"],e["signature_id"]); QCOMPARE(a["offset"],e["offset"]); }
        const auto first=output;
        QCOMPARE(execute(cli,{"--last","--storage",root+"/resheto.db","--json"}),1); QCOMPARE(output,first);
        QCOMPARE(execute(cli,{"--path",root+"/fixtures/empty","--db",root+"/signatures.db","--storage",root+"/resheto.db","--json"}),0);
        QCOMPARE(execute(cli,{"--path",root+"/missing","--db",root+"/signatures.db","--storage",root+"/resheto.db","--json"}),2);
        auto cancelled=args; cancelled<<"--cancel-after-ms"<<"0";
        QCOMPARE(execute(cli,cancelled),3); QCOMPARE(finalJob()["data"].toObject()["state"].toString(),"cancelled");
        QCOMPARE(execute(prepare,{"--source",source,"--output",root}),2); // Никакой перезаписи.
    }
};
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); if(argc<4) return 2;
    Integration test; test.cli=QString::fromLocal8Bit(argv[1]); test.prepare=QString::fromLocal8Bit(argv[2]); test.source=QString::fromLocal8Bit(argv[3]);
    QStringList testArgs{QString::fromLocal8Bit(argv[0]),"-o","cli-results.txt,txt","-o","-,txt"};
    for(int i=4;i<argc;++i) testArgs<<QString::fromLocal8Bit(argv[i]);
    return QTest::qExec(&test,testArgs);
}
#include "integration.moc"
