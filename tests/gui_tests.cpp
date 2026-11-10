#include "gui/mainwindow.h"
#include "gui/startup.h"
#include "core/database.h"
#include "core/signatures.h"
#include "fixtures.h"
#include <QCheckBox>
#include <QPlainTextEdit>
#include <QElapsedTimer>
#include <QDateTime>
#include <QDir>
#include <QComboBox>
#include <QClipboard>
#include <QCommandLineParser>
#include <QFile>
#include <QFileInfo>
#include <QFontDatabase>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QScopeGuard>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTimer>
#include <QTabWidget>
#include <QProcess>
#include <QtTest>
#include <future>
using namespace resheto;
class GuiTests : public QObject {
    Q_OBJECT
private slots:
    void initTestCase() {
#ifdef Q_OS_WIN
        // Offscreen-платформа Windows не подхватывает системный шрифт автоматически.
        const int font=QFontDatabase::addApplicationFont(qEnvironmentVariable("WINDIR")+"/Fonts/segoeui.ttf");
        QVERIFY(font>=0); QApplication::setFont(QFont(QFontDatabase::applicationFontFamilies(font).front(),10));
#endif
    }
    void startupFillsRulesAndAreasAndRespectsArguments() {
        QTemporaryDir temp;
        QVERIFY(temp.isValid());
        const QDir source(QStringLiteral(RESHETO_SOURCE_DIR));
        const QDir appDir(source.filePath("data"));
        const QDir localData(temp.filePath("local"));
        const QDir workingDir(temp.path());
        QCommandLineParser parser;
        addGuiOptions(parser,appDir,workingDir);
        QVERIFY(parser.parse({"resheto"}));
        const auto defaults=guiStartup(parser,localData);
        QCOMPARE(defaults.request.signaturePath,source.filePath("distribution/working/current.json"));
        QCOMPARE(defaults.request.heuristicPath,source.filePath("data/heuristic_rules.json"));
        QCOMPARE(defaults.behaviorPath,source.filePath("data/behavior_rules.json"));
        QCOMPARE(defaults.request.storagePath,localData.filePath("resheto.db"));
        QCOMPARE(defaults.request.path,defaults.watchPath);
        QCOMPARE(defaults.watchPath,localData.filePath("resheto-work/watched"));
        QCOMPARE(defaults.processScope,localData.filePath("resheto-work/processes"));
        QVERIFY(QFileInfo(defaults.watchPath).isDir() && QFileInfo(defaults.processScope).isDir());
        QVERIFY(!QFileInfo::exists(defaults.request.storagePath));
        MainWindow window(defaults.request,defaults.behaviorPath,defaults.processScope,defaults.watchPath,defaults.networkRules);
        QCOMPARE(window.db_->text(),defaults.request.signaturePath);
        QCOMPARE(window.heuristics_->text(),defaults.request.heuristicPath);
        QCOMPARE(window.behavior_->text(),defaults.behaviorPath);
        QCOMPARE(window.path_->text(),defaults.watchPath);
        QCOMPARE(window.watchPath_->text(),defaults.watchPath);
        QCOMPARE(window.processScope_->text(),defaults.processScope);
        QVERIFY(window.heuristicEnabled_->isChecked() && window.processEnabled_->isChecked());
#ifdef RESHETO_WITH_NETWORK
        QCOMPARE(defaults.networkRules,source.filePath("data/network_rules.json"));
        auto *networkRules=window.findChild<QLineEdit *>("networkRules");
        QVERIFY(networkRules);
        QCOMPARE(networkRules->text(),defaults.networkRules);
#endif
        QVERIFY(!window.controller_.busy() && !window.monitor_.status().active);

        const auto history=temp.filePath("custom/history.db");
        const auto watch=temp.filePath("user-watch");
        const auto programs=temp.filePath("user-programs");
        QStringList args{"resheto","--db","custom.db","--heuristics","","--behavior","other.json",
                         "--path","one-file","--watch-path",watch,"--process-scope",programs,"--storage",history};
#ifdef RESHETO_WITH_NETWORK
        args << "--network-rules" << "own-network.json";
#endif
        QCommandLineParser customParser;
        addGuiOptions(customParser,workingDir,source);
        QVERIFY(customParser.parse(args));
        const auto custom=guiStartup(customParser,localData);
        QCOMPARE(custom.request.signaturePath,QString("custom.db"));
        QVERIFY(custom.request.heuristicPath.isEmpty());
        QCOMPARE(custom.behaviorPath,QString("other.json"));
        QCOMPARE(custom.request.path,QString("one-file"));
        QCOMPARE(custom.request.storagePath,history);
        QCOMPARE(custom.watchPath,watch);
        QCOMPARE(custom.processScope,programs);
        QVERIFY(!QFileInfo::exists(watch) && !QFileInfo::exists(programs));
        QVERIFY(!QFileInfo::exists(temp.filePath("custom")));
#ifdef RESHETO_WITH_NETWORK
        QCOMPARE(custom.networkRules,QString("own-network.json"));
#endif

        QCommandLineParser storageParser;
        addGuiOptions(storageParser,workingDir,source);
        QVERIFY(storageParser.parse({"resheto","--storage",history}));
        const auto otherHistory=guiStartup(storageParser,localData);
        QCOMPARE(otherHistory.request.signaturePath,defaults.request.signaturePath);
        QCOMPARE(otherHistory.watchPath,temp.filePath("custom/resheto-work/watched"));
        QVERIFY(QFileInfo(otherHistory.watchPath).isDir() && !QFileInfo::exists(history));
    }
    void missingPreparedDataAndNewHistoryDirectory() {
        QTemporaryDir tmp(QDir::currentPath()+"/resheto-gui-paths-XXXXXX"); QVERIFY(tmp.isValid()); const auto root=tmp.path();
        auto put=[](const QString &path,const QByteArray &bytes){QFile f(path); if(!f.open(QIODevice::WriteOnly) || f.write(bytes)!=bytes.size()) throw Error("fixture write");};
        put(root+"/source.json",R"({"version":"test-paths","signatures":[{"id":"test","name":"ТЕСТ","kind":"PATTERN","value":"aa00bb","version":"1","enabled":1}]})");
        createSignatures(root+"/source.json",root+"/signatures.db");
        Request req; req.path=root+"/missing/fixtures"; req.signaturePath=root+"/signatures.db"; req.storagePath=root+"/new/nested/results.db";
        MainWindow window(req); window.show(); auto *start=window.findChild<QPushButton *>("start"); auto *summary=window.findChild<QLabel *>("summary");
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000); QTest::mouseClick(start,Qt::LeftButton);
        QVERIFY(summary->text().contains(QStringLiteral("Объект проверки не найден"))); QVERIFY(!window.controller_.busy()); QVERIFY(!QFileInfo::exists(root+"/new"));
        put(root+"/file",QByteArray::fromHex("aa00bb")); window.path_->setText(root+"/file");
        QTest::mouseClick(start,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000);
        QVERIFY2(summary->text().contains(QStringLiteral("Завершено")),qPrintable(summary->text())); QVERIFY(QFileInfo::exists(req.storagePath));
        { Store history(req.storagePath,true); QCOMPARE(history.latest()->matches,1); }
        window.storage_->setText(root); QTest::mouseClick(start,Qt::LeftButton);
        QVERIFY(summary->text().contains(QStringLiteral("не каталог"))); QVERIFY(!window.controller_.busy());
        QVERIFY(window.grab().save(QDir::currentPath()+"/gui-paths-preview.png"));
    }
    void historyReadFailureDuringScanStaysVisible() {
        QTemporaryDir tmp(QDir::currentPath()+"/resheto-gui-error-XXXXXX"); QVERIFY(tmp.isValid()); const auto root=tmp.path();
        auto put=[](const QString &path,const QByteArray &bytes){QFile f(path); if(!f.open(QIODevice::WriteOnly) || f.write(bytes)!=bytes.size()) throw Error("fixture write");};
        put(root+"/source.json",R"({"version":"test-gui-error","signatures":[{"id":"test","name":"ТЕСТ","kind":"PATTERN","value":"aa00bb","version":"1","enabled":1}]})");
        createSignatures(root+"/source.json",root+"/signatures.db"); put(root+"/file",QByteArray(9000,'q')); put(root+"/broken.db","not SQLite");
        Request req; req.id="test-history-error"; req.path=root+"/file"; req.signaturePath=root+"/signatures.db"; req.storagePath=root+"/results.db";
        MainWindow window(req); window.show(); auto *start=window.findChild<QPushButton *>("start");
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000);
        std::promise<void> entered,release; auto gate=release.get_future().share(); bool released=false;
        const auto cleanup=qScopeGuard([&]{if(!released) release.set_value();});
        req.hooks.beforeOpen=[&](const QString &){entered.set_value(); gate.wait(); return QString();};
        QVERIFY(window.controller_.submit(req)); window.jobId_=req.id; window.running_=true;
        QCOMPARE(entered.get_future().wait_for(std::chrono::seconds(5)),std::future_status::ready);
        // Реальное ошибочное чтение готово именно перед обработкой очередного прогресса.
        window.storage_->setText(root+"/broken.db"); window.readPage(); window.view_.wait(); window.tick();
        auto *summary=window.findChild<QLabel *>("summary");
        QVERIFY2(summary->text().contains(QStringLiteral("из-за ошибки чтения")),qPrintable(summary->text()));
        release.set_value(); released=true;
        QTRY_VERIFY_WITH_TIMEOUT(!window.running_,10000);
        QVERIFY(summary->text().contains(QStringLiteral("из-за ошибки чтения")));
        auto *error=window.findChild<QLabel *>("historyError"); QVERIFY(error); QVERIFY(error->isVisible()); QVERIFY(error->text().contains("SQLite"));
        window.tick(); QVERIFY(error->text().contains("SQLite"));
        { Store store(req.storagePath,true); QCOMPARE(store.latest()->state,"cancelled"); }
        window.storage_->setText(req.storagePath);
        QTest::mouseClick(start,Qt::LeftButton); QVERIFY(!error->isVisible());
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000);
        QVERIFY(summary->text().contains(QStringLiteral("Завершено")));
    }
    void scanHistoryPaginationAndCancel() {
        QTemporaryDir tmp(QDir::currentPath()+"/resheto-gui-test-XXXXXX"); QVERIFY(tmp.isValid()); const auto root=tmp.path();
        auto write=[](const QString &p,const QByteArray &b){QFile f(p); if(!f.open(QIODevice::WriteOnly) || f.write(b)!=b.size()) throw Error("fixture write");};
        write(root+"/input.json",QJsonDocument(QJsonObject{{"version","gui-test"},{"signatures",QJsonArray{QJsonObject{{"id","test-gui"},{"name",QStringLiteral("ТЕСТ: двоичные байты")},{"kind","PATTERN"},{"value","aa00bb"},{"enabled",1},{"version","1"}}}}}).toJson());
        createSignatures(root+"/input.json",root+"/signatures.db");
        QVERIFY(QDir().mkpath(root+QStringLiteral("/данные с пробелом")));
        const auto tree=root+QStringLiteral("/данные с пробелом");
        for(int i=0;i<205;++i) write(tree+QString("/%1.bin").arg(i),i==0?QByteArray::fromHex("aa00bb"):QByteArray("harmless"));
        Request req; req.path=tree; req.signaturePath=root+"/signatures.db"; req.storagePath=root+"/results.db";
        QString originalJob;
        {
            MainWindow window(req); window.show();
            auto *start=window.findChild<QPushButton *>("start"); auto *stop=window.findChild<QPushButton *>("stop"); auto *table=window.findChild<QTableWidget *>("results"); auto *summary=window.findChild<QLabel *>("summary");
            QVERIFY(start && stop && table && summary); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000);
            QTest::mouseClick(start,Qt::LeftButton);
            int heartbeats=0; QTimer pulse; connect(&pulse,&QTimer::timeout,&window,[&]{++heartbeats;}); pulse.start(5);
            QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),15000); QVERIFY(heartbeats>0);
            QVERIFY2(summary->text().contains(QStringLiteral("Завершено")),qPrintable(summary->text()));
            QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),200,10000);
            QVERIFY(summary->text().contains(QStringLiteral("совпадений: 1")));
            { Store store(req.storagePath); const auto j=store.latest(); QVERIFY(j); QCOMPARE(j->checked,205); originalJob=j->id; }
            auto *next=window.findChild<QPushButton *>("next"); QVERIFY(next->isEnabled()); QTest::mouseClick(next,Qt::LeftButton);
            QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),5,10000);
        }
        {
            MainWindow window(req); window.show(); auto *table=window.findChild<QTableWidget *>("results"); auto *start=window.findChild<QPushButton *>("start");
            QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),200,10000); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000);
            QVERIFY(window.findChild<QLabel *>("summary")->text().contains(originalJob));
            // Снимок реального Qt Widgets интерфейса для визуальной проверки.
            QVERIFY(window.grab().save(QDir::currentPath()+"/gui-preview.png"));
            // Кнопка отмены проверяется до передачи управления обработчику событий.
            QTest::mouseClick(start,Qt::LeftButton); auto *stop=window.findChild<QPushButton *>("stop"); QVERIFY(stop->isEnabled()); QTest::mouseClick(stop,Qt::LeftButton);
            QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000);
            QVERIFY(window.findChild<QLabel *>("summary")->text().contains(QStringLiteral("Отменено")));
            QVERIFY(!window.findChild<QLabel *>("historyError")->isVisible());
            { Store store(req.storagePath); QCOMPARE(store.latest()->state,"cancelled"); }
            window.findChild<QLineEdit *>("database")->setText(root+"/missing.db");
            QTRY_VERIFY_WITH_TIMEOUT(window.findChild<QLabel *>("databaseState")->text().contains(QStringLiteral("Ошибка базы")),10000);
            QVERIFY(!start->isEnabled());
        }
    }
    void repeatedJobsAndAutomaticHistorySwitch() {
        QTemporaryDir tmp(QDir::currentPath()+"/resheto-gui-history-XXXXXX"); QVERIFY(tmp.isValid()); const auto root=tmp.path();
        auto put=[](const QString &path,const QByteArray &bytes){QFile f(path); if(!f.open(QIODevice::WriteOnly) || f.write(bytes)!=bytes.size()) throw Error("fixture write");};
        put(root+"/source.json",R"({"version":"test-history","signatures":[{"id":"test","name":"ТЕСТ","kind":"PATTERN","value":"aa00bb","version":"1","enabled":1}]})");
        createSignatures(root+"/source.json",root+"/signatures.db");
        put(root+"/match",QByteArray::fromHex("aa00bb")); put(root+"/clean","ordinary harmless bytes");
        Request req; req.path=root+"/match"; req.signaturePath=root+"/signatures.db"; req.storagePath=root+"/first.db";
        MainWindow window(req); window.show(); auto *start=window.findChild<QPushButton *>("start"); auto *summary=window.findChild<QLabel *>("summary");
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000);
        QTest::mouseClick(start,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000);
        QString firstId;
        { Store store(req.storagePath,true); const auto job=store.latest(); QVERIFY(job); firstId=job->id; QCOMPARE(job->matches,1); }
        window.path_->setText(root+"/clean"); QTest::mouseClick(start,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),10000);
        QString secondId;
        { Store store(req.storagePath,true); const auto job=store.latest(); QVERIFY(job); secondId=job->id; QVERIFY(firstId!=secondId); QCOMPARE(job->matches,0);
          const auto previous=store.query(firstId,{}); QCOMPARE(previous.total,1); QCOMPARE(previous.rows.front().outcome,"signature_match");
          const auto current=store.query(secondId,{}); QCOMPARE(current.total,1); QCOMPARE(current.rows.front().path,root+"/clean"); }
        Request other=req; other.storagePath=root+"/second.db"; const auto otherJob=runJob(other); QCOMPARE(otherJob.matches,1);
        auto selectHistory=[&](const QString &path){window.storage_->setText(path); return QMetaObject::invokeMethod(window.storage_,"editingFinished");};
        QVERIFY(selectHistory(other.storagePath));
        QTRY_VERIFY_WITH_TIMEOUT(summary->text().contains(otherJob.id) && window.visibleRows_.size()==1,10000);
        QCOMPARE(window.visibleRows_.front().path,req.path); QCOMPARE(window.visibleRows_.front().outcome,"signature_match");
        // Отсутствующая история не создаётся чтением и не оставляет строки предыдущей базы.
        const auto empty=root+"/absent.db"; QVERIFY(selectHistory(empty));
        QTRY_COMPARE_WITH_TIMEOUT(summary->text(),QStringLiteral("Нет сохранённых заданий"),10000);
        QVERIFY(window.visibleRows_.empty()); QVERIFY(!QFileInfo::exists(empty)); QVERIFY(!window.historyErrorLabel_->isVisible());
        QVERIFY(selectHistory(req.storagePath));
        QTRY_VERIFY_WITH_TIMEOUT(summary->text().contains(secondId) && window.visibleRows_.size()==1,10000);
        QCOMPARE(window.visibleRows_.front().path,root+"/clean");
        QVERIFY(window.grab().save(QDir::currentPath()+"/gui-history-preview.png"));
    }
    void globalFilterSearchSortAndCopy() {
        QTemporaryDir tmp(QDir::currentPath()+"/resheto-gui-global-XXXXXX"); QVERIFY(tmp.isValid()); const auto root=tmp.path();
        const auto storage=root+"/history.db";
        Job j; j.id="global-query"; j.path=root; j.started=now(); j.databaseVersion="control";
        { Store store(storage); store.start(j);
          for(int i=0;i<2101;++i) {
            Result r; r.jobId=j.id; r.databaseVersion=j.databaseVersion; r.path=root+QStringLiteral("/папка с пробелом/%1").arg(i,4,10,QChar('0')); r.time=now(); r.size=8; r.identity="control"; r.outcome="no_match"; r.completeness="full"; r.analyzers="SHA-256,PATTERN";
            ++j.results; ++j.checked;
            if(i==2100) { ++j.matches; r.outcome="signature_match"; r.signatureId="control"; r.signatureName=QStringLiteral("Контроль"); r.signatureVersion="1"; r.basis=QStringLiteral("PATTERN, абсолютное смещение 4"); r.offset=4; j.detectionPath=r.path; j.detectionName=r.signatureName; }
            store.append(r,j);
          } j.finished=now(); j.state="completed"; store.finish(j);
        }
        Request req; req.storagePath=storage; MainWindow window(req); window.show();
        auto *table=window.findChild<QTableWidget *>("results"); auto *filter=window.findChild<QComboBox *>("filter");
        QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),200,10000);
        filter->setCurrentIndex(1); QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),1,10000);
        QCOMPARE(table->item(0,0)->text(),j.detectionPath); table->setCurrentCell(0,0);
        QTest::mouseClick(window.findChild<QPushButton *>("copyPath"),Qt::LeftButton); QCOMPARE(QApplication::clipboard()->text(),j.detectionPath);
        QTest::mouseClick(window.findChild<QPushButton *>("copyBasis"),Qt::LeftButton); QCOMPARE(QApplication::clipboard()->text(),QStringLiteral("PATTERN, абсолютное смещение 4"));
        QVERIFY(window.grab().save(QDir::currentPath()+"/gui-global-preview.png"));
        filter->setCurrentIndex(0); auto *search=window.findChild<QLineEdit *>("search"); search->setText(QStringLiteral("папка с пробелом/2100")); QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),1,10000);
        // Дожидаемся завершения debounce, затем проверяем содержимое.
        QTRY_VERIFY_WITH_TIMEOUT(!window.view_.valid() && table->rowCount()==1 && table->item(0,0)->text()==j.detectionPath,10000);
        search->clear(); window.findChild<QComboBox *>("sort")->setCurrentIndex(1); window.findChild<QComboBox *>("direction")->setCurrentIndex(1);
        QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),200,10000); QCOMPARE(table->item(0,0)->text(),j.detectionPath);
        filter->setCurrentIndex(2); QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),0,10000);
    }
    void heuristicFallbackNotificationAndPartialFilter() {
        QTemporaryDir temp(QDir::currentPath()+"/gui-lab4-XXXXXX"); QVERIFY(temp.isValid()); const auto root=temp.path();
        const auto specimen=fixtures::pe(true);
        QFile file(root+"/positive.exe"); QVERIFY(file.open(QIODevice::WriteOnly)); QCOMPARE(file.write(specimen),specimen.size()); file.close();
        Request r; r.path=file.fileName(); r.signaturePath=root+"/missing.db"; r.heuristicPath=QStringLiteral(RESHETO_SOURCE_DIR)+"/data/heuristic_rules.json"; r.storagePath=root+"/history.db";
        MainWindow window(r); window.show(); QTRY_VERIFY_WITH_TIMEOUT(window.start_->isEnabled(),10000);
        QTest::mouseClick(window.start_,Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(window.notification_->isVisible() && window.notification_->text().contains(r.path),5000);
        const auto shownUtc=QDateTime::currentDateTimeUtc();
        const auto primary=QStringLiteral("Область одновременно разрешает запись и исполнение");
        QVERIFY(window.notification_->text().contains(primary));
        { Store store(r.storagePath,true); ResultQuery q; q.filter=ResultFilter::Matches; const auto rows=store.query(window.jobId_,q).rows; QCOMPARE(rows.size(),size_t(1));
          const auto latency=QDateTime::fromString(rows.front().time,Qt::ISODateWithMs).msecsTo(shownUtc); qInfo()<<"manual notification latency_ms"<<latency; QVERIFY(latency>=0 && latency<=5000); }
        QTRY_VERIFY_WITH_TIMEOUT(!window.running_,10000); QTRY_COMPARE_WITH_TIMEOUT(window.table_->rowCount(),1,10000);
        window.filter_->setCurrentIndex(2); QTRY_COMPARE_WITH_TIMEOUT(window.table_->rowCount(),1,10000);
        QVERIFY(window.table_->item(0,1)->text().contains(QStringLiteral("неполная")));
        QCOMPARE(window.table_->item(0,2)->text(),primary);
        window.table_->setCurrentCell(0,0); window.showDetails(); QVERIFY(window.details_->toPlainText().contains(QStringLiteral("Полнота"))); QVERIFY(window.details_->toPlainText().contains("writable-executable"));
        { Store store(r.storagePath,true); const auto j=store.latest(); QCOMPARE(j->matches,1); QCOMPARE(j->exitCode(),2); }
        QVERIFY(window.grab().save(QDir::currentPath()+"/gui-lab4-preview.png"));
    }
    void legacyHeuristicHistoryShowsAndSortsConcreteRules() {
        QTemporaryDir temp;QVERIFY(temp.isValid());const auto specimens=temp.filePath("files");QVERIFY(QDir().mkpath(specimens));
        auto outside=fixtures::pe(false),both=fixtures::pe(true);
        qToLittleEndian<quint32>(0x1900,outside.data()+168);qToLittleEndian<quint32>(0x1900,both.data()+168);
        for(const auto &[name,bytes]:std::initializer_list<std::pair<QString,QByteArray>>{{"a-writable.exe",both},{"z-entry.exe",outside}}) {
            QFile file(specimens+"/"+name);QVERIFY(file.open(QIODevice::WriteOnly));QCOMPARE(file.write(bytes),bytes.size());
        }
        Request r;r.path=specimens;r.heuristicPath=QStringLiteral(RESHETO_SOURCE_DIR)+"/data/heuristic_rules.json";r.storagePath=temp.filePath("history.db");
        const auto job=runJob(r);QCOMPARE(job.matches,qint64(2));QCOMPARE(job.exitCode(),1);
        const auto generic=QStringLiteral("Эвристические признаки PE");
        {
            Database legacy(r.storagePath,false);
            legacy.exec("UPDATE results SET data=json_set(data,'$.rule_name',?) WHERE job_id=?",{generic,job.id});
            legacy.exec("UPDATE jobs SET data=json_set(data,'$.last_detection_name',?) WHERE id=?",{generic,job.id});
        }
        {
            Store history(r.storagePath,true);const auto old=history.getJob(job.id);QVERIFY(old);QCOMPARE(old->detectionName,generic);
            ResultQuery query;query.sort=ResultSort::Signature;query.limit=1;const auto page=history.query(job.id,query);
            QCOMPARE(page.total,qint64(2));QCOMPARE(page.rows.size(),size_t(1));QCOMPARE(page.rows.front().ruleId,QString("entry-outside-executable"));
        }
        MainWindow window(r);window.show();window.sort_->setCurrentIndex(3);
        QTRY_COMPARE_WITH_TIMEOUT(window.table_->rowCount(),2,5000);
        QCOMPARE(window.table_->item(0,2)->text(),QStringLiteral("Ненулевая точка входа находится вне исполняемой области"));
        QCOMPARE(window.table_->item(1,2)->text(),QStringLiteral("Область одновременно разрешает запись и исполнение"));
        window.table_->setCurrentCell(1,0);window.showDetails();
        QVERIFY(window.details_->toPlainText().contains(QStringLiteral("• Область одновременно разрешает запись и исполнение [writable-executable")));
        QVERIFY(window.details_->toPlainText().contains(QStringLiteral("• Ненулевая точка входа находится вне исполняемой области [entry-outside-executable")));
    }
    void monitorControlsAndPersistentHistoryError() {
        QTemporaryDir temp(QDir::currentPath()+"/gui-monitor-XXXXXX"); QVERIFY(temp.isValid()); const auto root=temp.path(); QVERIFY(QDir().mkpath(root+"/area"));
        QFile source(root+"/signatures.json"); QVERIFY(source.open(QIODevice::WriteOnly)); source.write(R"({"version":"gui-monitor","signatures":[{"id":"control","name":"CONTROL","kind":"PATTERN","value":"aabbcc","version":"1","enabled":1}]})"); source.close(); createSignatures(source.fileName(),root+"/signatures.db");
        Request r; r.path=root+"/area"; r.signaturePath=root+"/signatures.db"; r.storagePath=root+"/history.db";
        MainWindow window(r); window.show(); QTRY_VERIFY_WITH_TIMEOUT(window.watch_->isEnabled() && !window.view_.valid() && !window.probe_.valid(),10000);
        QTest::mouseClick(window.watch_,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(window.monitor_.status().ready,5000); QVERIFY(window.start_->isEnabled());
        QFile file(r.path+"/sample"); QVERIFY(file.open(QIODevice::WriteOnly)); file.write(QByteArray::fromHex("aabbcc")); file.close();
        QTRY_VERIFY_WITH_TIMEOUT(window.notification_->isVisible(),5000); const auto shownUtc=QDateTime::currentDateTimeUtc();
        { Store store(r.storagePath,true); ResultQuery q; q.filter=ResultFilter::Matches; const auto rows=store.query(window.monitor_.status().job.id,q).rows; QCOMPARE(rows.size(),size_t(1));
          const auto latency=QDateTime::fromString(rows.front().time,Qt::ISODateWithMs).msecsTo(shownUtc); qInfo()<<"monitor notification latency_ms"<<latency; QVERIFY(latency>=0 && latency<=5000); }
        QTest::mouseClick(window.watchStop_,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(!window.monitorActive_,5000); QTRY_VERIFY_WITH_TIMEOUT(window.watch_->isEnabled(),5000);
        QTest::mouseClick(window.watch_,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(window.monitor_.status().ready,5000);
        QFile bad(root+"/broken.db"); QVERIFY(bad.open(QIODevice::WriteOnly)); bad.write("not SQLite"); bad.close();
        window.storage_->setText(bad.fileName()); window.readPage(); window.view_.wait(); window.tick();
        QTRY_VERIFY_WITH_TIMEOUT(!window.monitorActive_,5000); QVERIFY(window.historyErrorLabel_->isVisible()); QVERIFY(window.historyErrorLabel_->text().contains("SQLite"));
        window.tick(); QVERIFY(window.historyErrorLabel_->isVisible()); QVERIFY(window.summary_->text().contains(QStringLiteral("из-за ошибки чтения")));
    }
    void parallelJobsKeepSelectionAndIndependentCancel() {
        QTemporaryDir temp(QDir::currentPath()+"/gui-parallel-XXXXXX"); QVERIFY(temp.isValid()); const auto root=temp.path(); QVERIFY(QDir().mkpath(root+"/watched"));
        auto put=[](const QString &p,const QByteArray &b){QFile f(p); if(!f.open(QIODevice::WriteOnly) || f.write(b)!=b.size()) throw Error("fixture write");};
        put(root+"/source.json",R"({"version":"parallel","signatures":[{"id":"control","name":"CONTROL","kind":"PATTERN","value":"aabbcc","version":"1","enabled":1}]})"); createSignatures(root+"/source.json",root+"/signatures.db"); put(root+"/manual.bin",QByteArray::fromHex("aabbcc"));
        Request r; r.path=root+"/manual.bin"; r.signaturePath=root+"/signatures.db"; r.storagePath=root+"/new/history.db";
        std::mutex mutex; std::condition_variable wake; bool entered=false,release=false;
        r.hooks.beforeOpen=[&](const QString &){std::unique_lock lock(mutex);entered=true;wake.notify_all();wake.wait(lock,[&]{return release;});return QString();};
        MainWindow window(r,{}, {},root+"/watched"); window.show(); auto cleanup=qScopeGuard([&]{{std::lock_guard lock(mutex);release=true;}wake.notify_all();window.controller_.cancel();window.monitor_.cancel();});
        QTRY_VERIFY_WITH_TIMEOUT(window.watch_->isEnabled() && window.start_->isEnabled(),10000); QTest::mouseClick(window.watch_,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(window.monitor_.status().ready,5000); const auto monitorId=window.monitorJobId_;
        QTest::mouseClick(window.start_,Qt::LeftButton); {std::unique_lock lock(mutex);QVERIFY(wake.wait_for(lock,std::chrono::seconds(5),[&]{return entered;}));}
        const auto manualId=window.manualJobId_; QVERIFY(manualId!=monitorId); QVERIFY(window.running_ && window.monitorActive_); QVERIFY(!window.storage_->isEnabled());
        QCOMPARE(window.jobs_->currentData().toString(),manualId);
        put(root+"/watched/first",QByteArray::fromHex("aabbcc")); QTRY_VERIFY_WITH_TIMEOUT(window.monitor_.status().job.matches==1,5000); QCOMPARE(window.jobId_,manualId);
        QTest::mouseClick(window.stop_,Qt::LeftButton); {std::lock_guard lock(mutex);release=true;}wake.notify_all(); QTRY_VERIFY_WITH_TIMEOUT(!window.running_,5000); QVERIFY(window.monitorActive_);
        {Store history(r.storagePath,true); QCOMPARE(history.getJob(manualId)->state,"cancelled"); QCOMPARE(history.getJob(monitorId,false)->state,"running");}
        QTRY_VERIFY_WITH_TIMEOUT(window.currentMonitor_->isEnabled() && window.currentManual_->isEnabled(),5000);
        QTest::mouseClick(window.currentMonitor_,Qt::LeftButton); QCOMPARE(window.jobId_,monitorId); QCOMPARE(window.jobs_->currentData().toString(),window.jobId_);
        QTRY_VERIFY_WITH_TIMEOUT(window.summary_->text().contains(monitorId) && !window.view_.valid() && !window.visibleRows_.empty(),5000); QCOMPARE(window.visibleRows_.front().jobId,monitorId); QVERIFY(window.monitorActive_);
        QTest::mouseClick(window.currentManual_,Qt::LeftButton); QCOMPARE(window.jobId_,manualId); QCOMPARE(window.jobs_->currentData().toString(),window.jobId_);
        QTRY_VERIFY_WITH_TIMEOUT(window.summary_->text().contains(manualId) && !window.view_.valid(),5000); QVERIFY(window.monitorActive_);
        QTRY_VERIFY_WITH_TIMEOUT(window.jobs_->findData(manualId)>=0,5000); window.jobs_->setCurrentIndex(window.jobs_->findData(manualId));
        put(root+"/watched/second",QByteArray::fromHex("aabbcc")); QTRY_VERIFY_WITH_TIMEOUT(window.monitor_.status().job.matches==2,5000); QTest::qWait(350); QCOMPARE(window.jobId_,manualId); QVERIFY(window.summary_->text().contains(manualId));
        QCOMPARE(window.jobs_->currentData().toString(),manualId);
        {std::lock_guard lock(mutex);entered=false;release=false;} QTest::mouseClick(window.start_,Qt::LeftButton); {std::unique_lock lock(mutex);QVERIFY(wake.wait_for(lock,std::chrono::seconds(5),[&]{return entered;}));}
        QTest::mouseClick(window.watchStop_,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(!window.monitorActive_,5000); QVERIFY(window.running_); {std::lock_guard lock(mutex);release=true;}wake.notify_all();
        QTRY_VERIFY_WITH_TIMEOUT(!window.running_,5000); {Store history(r.storagePath,true); const auto job=history.getJob(window.manualJobId_); QCOMPARE(job->state,"completed"); QCOMPARE(job->matches,1); QCOMPARE(history.getJob(monitorId)->state,"cancelled");}
        QVERIFY(window.grab().save(QDir::currentPath()+"/gui-parallel-preview.png"));
    }
    void processImageResultsAreScopedAndSearchable() {
        QTemporaryDir temp(QDir::currentPath()+"/gui-process-XXXXXX"); QVERIFY(temp.isValid()); const auto root=temp.path(); QVERIFY(QDir().mkpath(root+"/programs"));
#ifdef _WIN32
        const auto helper=root+"/programs/helper.exe";
#else
        const auto helper=root+"/programs/helper";
#endif
        QVERIFY(QFile::copy(QStringLiteral(RESHETO_HELPER_PATH),helper));
        Request r; r.heuristicPath=QStringLiteral(RESHETO_SOURCE_DIR)+"/data/heuristic_rules.json"; r.storagePath=root+"/history.db";
        MainWindow window(r,QStringLiteral(RESHETO_SOURCE_DIR)+"/data/behavior_rules.json",root+"/programs"); window.show(); window.fileEnabled_->setChecked(false); window.processImages_->setChecked(true);
        QTRY_VERIFY_WITH_TIMEOUT(window.watch_->isEnabled(),10000); QTest::mouseClick(window.watch_,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(window.monitor_.status().ready,5000); QProcess p; p.start(helper,{"--children","3","--hold-ms","3000","--delay-ms","600"}); QVERIFY(p.waitForStarted(2000));
        auto cleanup=qScopeGuard([&]{if(p.state()!=QProcess::NotRunning){p.kill();p.waitForFinished(2000);}window.monitor_.cancel();}); const auto pid=QString::number(p.processId());
        QTRY_VERIFY_WITH_TIMEOUT(window.monitor_.status().job.matches>=1 && window.monitor_.status().processImages>=4,7000);
        window.processSearch_->setText(pid); QTRY_COMPARE_WITH_TIMEOUT(window.processTable_->rowCount(),1,3000); QCOMPARE(window.processTable_->item(0,0)->text(),pid); QVERIFY(window.processTable_->item(0,3)->text().startsWith(root+"/programs"));
        window.tabs_->setCurrentIndex(2); window.search_->setText(pid); window.filter_->setCurrentIndex(1); QTRY_COMPARE_WITH_TIMEOUT(window.table_->rowCount(),1,5000); window.table_->setCurrentCell(0,0); window.showDetails();
        QVERIFY(window.table_->item(0,0)->text().startsWith("PID "+pid+" — "));
        QVERIFY(window.details_->toPlainText().contains("PID "+pid)); QVERIFY(window.details_->toPlainText().contains("child-process-burst")); QVERIFY(window.details_->toPlainText().contains(QStringLiteral("Основание:")));
        window.filter_->setCurrentIndex(0); QTRY_VERIFY_WITH_TIMEOUT(window.table_->rowCount()>=2,5000); bool image=false; for(const auto &event:window.visibleEvents_) image|=event["type"]=="process_image"; QVERIFY(image);
        for(int i=0;i<static_cast<int>(window.visibleEvents_.size());++i) if(window.visibleEvents_[i]["type"]=="process_image" && window.visibleEvents_[i]["details"].toObject()["process"].toObject()["pid"].toString()==pid) {
            QVERIFY(window.table_->item(i,0)->text().startsWith("PID "+pid+" — ")); window.table_->setCurrentCell(i,0); QTest::mouseClick(window.findChild<QPushButton *>("copyPath"),Qt::LeftButton); QCOMPARE(QApplication::clipboard()->text(),helper); break;
        }
        QVERIFY(!window.monitorState_->text().contains(QStringLiteral("полный охват"))); QVERIFY(window.grab().save(QDir::currentPath()+"/gui-process-preview.png"));
        QVERIFY(p.waitForFinished(6000)); QCOMPARE(p.exitCode(),0);
        QTest::mouseClick(window.watchStop_,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(!window.monitorActive_,5000);
        QCOMPARE(window.processTable_->rowCount(),0); QVERIFY(window.processState_->text().contains(QStringLiteral("остановлено")));
    }
    void olderHistoryPagesHaveReturnToNew() {
        QTemporaryDir temp(QDir::currentPath()+"/gui-jobs-XXXXXX"); QVERIFY(temp.isValid()); Request r; r.storagePath=temp.path()+"/history.db";
        {Store store(r.storagePath); for(int i=0;i<52;++i) {Job j;j.id=QString("job-%1").arg(i);j.path="controlled";j.databaseVersion="control";j.started=now();j.finished=now();j.state="completed";store.start(j);store.finish(j);}}
        MainWindow window(r); window.show(); QTRY_VERIFY_WITH_TIMEOUT(window.jobs_->findData("job-51")>=0,5000); const auto selected=window.jobId_;
        QVERIFY(window.earlier_->isVisible());QVERIFY(!window.newer_->isVisible());
        QTest::mouseClick(window.earlier_,Qt::LeftButton); QTRY_VERIFY_WITH_TIMEOUT(window.jobs_->findData("job-0")>=0,5000); QVERIFY(!window.earlier_->isVisible());QVERIFY(window.newer_->isVisible());window.jobs_->setCurrentIndex(window.jobs_->findData("job-0")); QTRY_VERIFY_WITH_TIMEOUT(window.summary_->text().contains("job-0"),5000);
        QTest::mouseClick(window.newer_,Qt::LeftButton);
        QTRY_VERIFY_WITH_TIMEOUT(!window.view_.valid() && window.jobs_->findData("job-50")>=0 && !window.newer_->isVisible(),5000);
        QVERIFY(window.jobs_->findData(selected)>=0);QCOMPARE(window.jobId_,QString("job-0"));QVERIFY(window.summary_->text().contains("job-0"));
    }
};
QTEST_MAIN(GuiTests)
#include "gui_tests.moc"
