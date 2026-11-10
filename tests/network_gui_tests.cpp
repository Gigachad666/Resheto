#include "gui/mainwindow.h"
#include "gui/networkpanel.h"
#include "core/signatures.h"
#include "network/fixtures.h"
#include <QAction>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDialog>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFontDatabase>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScopeGuard>
#include <QSemaphore>
#include <QSpinBox>
#include <QTabBar>
#include <QTableWidget>
#include <QTabWidget>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QToolButton>
#include <QtTest>

using namespace resheto;
using namespace resheto::network;
namespace fx=resheto::network::fixtures;
namespace {
void put(const QString &path,const QByteArray &bytes) {
    QFile file(path);
    if(!file.open(QIODevice::WriteOnly) || file.write(bytes)!=bytes.size())throw Error("fixture write");
}
QString rulesPath(){return QStringLiteral(RESHETO_SOURCE_DIR)+"/data/network_rules.json";}
QString sweepDescription(){return QStringLiteral("TCP-попытки обращения ко многим различным портам одного узла");}
}

class NetworkGuiTests : public QObject {
    Q_OBJECT
private slots:
    void initTestCase() {
#ifdef Q_OS_WIN
        const int font=QFontDatabase::addApplicationFont(qEnvironmentVariable("WINDIR")+"/Fonts/segoeui.ttf");
        QVERIFY(font>=0);QApplication::setFont(QFont(QFontDatabase::applicationFontFamilies(font).front(),10));
#endif
    }
    void preservesHistoryAndFindsDetectionBeyondFirstPage() {
        QTemporaryDir temp;QVERIFY(temp.isValid());
        Request defaults;defaults.storagePath=temp.filePath("history.db");
        NetworkRequest old;old.analysis.input=temp.filePath("old.pcap");old.analysis.durationMs=0;old.rulesPath=rulesPath();old.storagePath=defaults.storagePath;
        put(old.analysis.input,fx::pcap({fx::udp(1000000)}));const auto previous=scanNetworkPcap(old);
        QCOMPARE(previous.exitCode(),0);
        std::vector<CapturedPacket> input;
        for(int i=0;i<2101;++i)input.push_back(fx::udp(1000000+i*5,"ordinary",static_cast<quint16>(30000+i),9000));
        for(int i=0;i<20;++i)input.push_back(fx::tcp(2000000+i*1000,40000,static_cast<quint16>(10000+i),i+1));
        const auto pcap=temp.filePath("later.pcap");put(pcap,fx::pcap(input));
        MainWindow window(defaults,{},{},{},rulesPath());window.show();
        auto *tabs=window.findChild<QTabWidget *>("resultTabs");auto *panel=window.findChild<NetworkPanel *>("networkPanel");QVERIFY(tabs && panel);
        const auto networkIndex=tabs->indexOf(panel);QVERIFY(networkIndex>=0);tabs->setCurrentIndex(networkIndex);
        auto *jobs=panel->findChild<QComboBox *>("networkJobs");auto *source=panel->findChild<QComboBox *>("networkSource");auto *interfaces=panel->findChild<QComboBox *>("networkInterface");
        auto *start=panel->findChild<QPushButton *>("networkStart");auto *notice=panel->findChild<QLabel *>("networkNotice");auto *current=panel->findChild<QPushButton *>("networkCurrent");
        auto *table=panel->findChild<QTableWidget *>("networkResults");auto *filter=panel->findChild<QComboBox *>("networkFilter");auto *search=panel->findChild<QLineEdit *>("networkSearch");
        auto *views=panel->findChild<QTabBar *>("networkResultView");
        auto *copy=panel->findChild<QPushButton *>("networkCopyBasis");auto *details=panel->findChild<QPlainTextEdit *>("networkDetails");auto *label=panel->findChild<QLabel *>("networkPage");
        auto *state=panel->findChild<QLabel *>("networkState");
        auto *older=panel->findChild<QPushButton *>("networkOlderJobs"),*newer=panel->findChild<QPushButton *>("networkNewerJobs");
        auto *prepare=panel->findChild<QPushButton *>("networkPrepareSample"),*send=panel->findChild<QPushButton *>("networkSendSample");
        auto *duration=panel->findChild<QSpinBox *>("networkDuration");
        QVERIFY(jobs && source && interfaces && start && notice && current && table && filter && search && copy && details && label && state && older && newer && prepare && send && views && duration);
        QCOMPARE(interfaces->count(),0);
        QCOMPARE(duration->value(),0);QCOMPARE(duration->specialValueText(),QStringLiteral("До остановки"));
        QVERIFY(!prepare->isVisible());source->setCurrentIndex(2);QVERIFY(prepare->isVisible());QVERIFY(!start->isEnabled() && !send->isEnabled());
        QCOMPARE(duration->value(),30);QCOMPARE(duration->minimum(),1);
        source->setCurrentIndex(0);QCOMPARE(duration->value(),0);
        QVERIFY(!window.findChild<QWidget *>("fileHistoryControls")->isVisible());
        QVERIFY(!window.findChild<QWidget *>("filePageControls")->isVisible());
        QTRY_COMPARE_WITH_TIMEOUT(jobs->currentData().toString(),previous.id,5000);
        QVERIFY(!older->isVisible() && !newer->isVisible() && !current->isVisible());
        source->setCurrentIndex(1);panel->findChild<QLineEdit *>("networkPcap")->setText(pcap);
        QElapsedTimer latency;latency.start();start->click();QVERIFY(panel->busy());QVERIFY(!window.findChild<QLineEdit *>("storage")->isEnabled());
        tabs->setCurrentIndex(0);
        QTRY_VERIFY_WITH_TIMEOUT(notice->text().contains("tcp-port-sweep"),5000);
        qInfo()<<"network notification from submit, latency_ms"<<latency.elapsed();
        QTRY_VERIFY_WITH_TIMEOUT(!panel->busy(),7000);QCOMPARE(tabs->tabText(networkIndex),QStringLiteral("Сеть · 1"));
        tabs->setCurrentIndex(networkIndex);QCOMPARE(jobs->currentData().toString(),previous.id);QVERIFY(state->isVisible());
        QTRY_VERIFY_WITH_TIMEOUT(current->isVisible() && current->isEnabled(),3000);current->click();
        QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),200,6000);QVERIFY(label->text().contains("2121"));
        QVERIFY(!current->isVisible() && !older->isVisible() && !newer->isVisible());QVERIFY(!state->isVisible());
        filter->setCurrentIndex(1);search->setText("tcp-port-sweep");
        QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),1,6000);QVERIFY(table->item(0,0)->text().contains(":10019"));
        table->setCurrentCell(0,0);QTRY_VERIFY_WITH_TIMEOUT(copy->isEnabled(),5000);
        QVERIFY(details->toPlainText().contains("tcp-port-sweep"));copy->click();QVERIFY(QApplication::clipboard()->text().contains(QStringLiteral("20 различных TCP-портов")));
        views->setCurrentIndex(1);search->setText("192.0.2.1:40000");
        QTRY_VERIFY_WITH_TIMEOUT(table->rowCount()==1 && table->item(0,2) && table->item(0,2)->text()==sweepDescription(),6000);
        table->setCurrentCell(0,0);QTRY_VERIFY_WITH_TIMEOUT(copy->isEnabled(),3000);copy->click();QCOMPARE(QApplication::clipboard()->text(),table->item(0,3)->text());
        QVERIFY(details->toPlainText().contains("tcp-port-sweep"));
        QVERIFY(window.grab().save(QDir::currentPath()+"/gui-network-preview.png"));
        const auto broken=temp.filePath("broken-rules.json");put(broken,"not a JSON object");panel->findChild<QLineEdit *>("networkRules")->setText(broken);start->click();
        QTest::qWait(350);QVERIFY(state->isVisible() && state->text().contains(QStringLiteral("JSON-объект")));QVERIFY(!panel->busy());
    }
    void compactDetailsAndSeparateResultViews() {
        QTemporaryDir temp;QVERIFY(temp.isValid());Request defaults;defaults.storagePath=temp.filePath("history.db");
        {
            Store history(defaults.storagePath);
            for(const auto &id:{QString("old-file"),QString("new-file")}) {
                Job job;job.id=id;job.path=temp.filePath(id);job.databaseVersion="control";job.started=now();history.start(job);
                job.state="completed";job.finished=now();history.finish(job);
            }
        }
        std::vector<CapturedPacket> input;
        for(int i=0;i<30;++i)input.push_back(fx::udp(1000000+i*5,"ordinary",static_cast<quint16>(30000+i),9000));
        for(int i=0;i<20;++i)input.push_back(fx::tcp(2000000+i*1000,40000,static_cast<quint16>(10000+i),i+1));
        input.push_back(fx::raw(QByteArray::fromHex("4500"),3000000));
        NetworkRequest request;request.analysis.input=temp.filePath("broken-record.pcap");request.analysis.durationMs=0;request.rulesPath=rulesPath();request.storagePath=defaults.storagePath;
        put(request.analysis.input,fx::pcap({})+"bad record");const auto broken=scanNetworkPcap(request);QCOMPARE(broken.exitCode(),2);QVERIFY(broken.error.contains(QStringLiteral("записи PCAP")));
        request.analysis.input=temp.filePath("fifty.pcap");
        put(request.analysis.input,fx::pcap(input));const auto network=scanNetworkPcap(request);
        QCOMPARE(network.storedFlows,qint64(50));QCOMPARE(network.storedDetections,qint64(1));QCOMPARE(network.exitCode(),2);
        MainWindow window(defaults,{},{},{},rulesPath());const QSize small(900,620);window.resize(small);window.show();
        auto *outer=window.findChild<QTabWidget *>("resultTabs");auto *panel=window.findChild<NetworkPanel *>("networkPanel");
        auto *fileJobs=window.findChild<QComboBox *>("jobs");auto *settings=window.findChild<QWidget *>("fileSettings");
        auto *settingsDialog=window.findChild<QDialog *>("fileSettingsDialog");
        auto *settingsToggle=window.findChild<QToolButton *>("fileSettingsToggle");auto *fileStart=window.findChild<QPushButton *>("start"),*watchStart=window.findChild<QPushButton *>("watch");
        QVERIFY(outer && panel && fileJobs && settings && settingsDialog && settingsToggle && fileStart && watchStart);
        QVERIFY(!settings->isVisible() && fileStart->isVisible() && watchStart->isVisible());
        QApplication::processEvents();QCOMPARE(window.size(),small);
        settingsToggle->click();QVERIFY(settings->isVisible());QApplication::processEvents();
        qInfo()<<"expanded file settings height"<<settings->height()<<"window"<<window.size()<<"minimum"<<window.minimumSizeHint();
        QCOMPARE(window.size(),small);QVERIFY(settings->height()>=150 && !settingsDialog->isModal());
        settingsDialog->close();QVERIFY(!settings->isVisible() && !settingsToggle->isChecked());
        QTRY_VERIFY_WITH_TIMEOUT(fileJobs->findData("old-file")>=0,4000);fileJobs->setCurrentIndex(fileJobs->findData("old-file"));
        QTRY_COMPARE_WITH_TIMEOUT(fileJobs->currentData().toString(),QString("old-file"),4000);
        outer->setCurrentWidget(panel);
        panel->findChild<QComboBox *>("networkSource")->setCurrentIndex(1);
        auto *table=panel->findChild<QTableWidget *>("networkResults");auto *views=panel->findChild<QTabBar *>("networkResultView");
        auto *jobs=panel->findChild<QComboBox *>("networkJobs");auto *summary=panel->findChild<QLabel *>("networkSummary");
        auto *details=panel->findChild<QPlainTextEdit *>("networkDetails"),*diagnostics=panel->findChild<QPlainTextEdit *>("networkDiagnostics");
        auto *detailToggle=panel->findChild<QToolButton *>("networkDetailsToggle"),*diagnosticToggle=panel->findChild<QToolButton *>("networkDiagnosticsToggle");
        QVERIFY(table && views && jobs && summary && details && diagnostics && detailToggle && diagnosticToggle);
        QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),50,5000);QCOMPARE(jobs->currentData().toString(),network.id);
        QCOMPARE(views->tabText(0),QStringLiteral("Трафик"));QCOMPARE(views->tabText(1),QStringLiteral("Обнаружения"));QCOMPARE(table->columnCount(),3);
        QVERIFY(summary->text().contains(QStringLiteral("неполная проверка")));QVERIFY(!summary->text().contains(QStringLiteral("Вне разбора:")));
        QVERIFY(!details->isVisible() && !diagnostics->isVisible());QCOMPARE(window.size(),small);
        // Строки могут быть загружены ещё до показа вкладки. Измеряем её после LayoutRequest.
        QApplication::processEvents();
        const int tableHeight=table->height();QVERIFY(table->viewport()->height()>=3*table->rowHeight(0));
        table->setCurrentCell(1,0);QTRY_VERIFY_WITH_TIMEOUT(details->isVisible(),1500);
        diagnosticToggle->click();QTRY_VERIFY_WITH_TIMEOUT(diagnostics->isVisible(),1500);
        QApplication::processEvents();
        QVERIFY(diagnostics->toPlainText().contains(QStringLiteral("Обрезано: 1")));
        QVERIFY(!diagnostics->toPlainText().contains(networkIncompleteReason()));
        qInfo()<<"compact table height before/after"<<tableHeight<<table->height()<<"viewport"<<table->viewport()->height();
        QCOMPARE(table->rowCount(),50);QCOMPARE(table->height(),tableHeight);QVERIFY(table->viewport()->height()>=3*table->rowHeight(0));
        QCOMPARE(window.size(),small);QVERIFY(window.minimumSizeHint().height()<=small.height() && window.minimumSizeHint().width()<=small.width());
        QVERIFY(details->width()>0 && details->height()>0 && diagnostics->width()>0 && diagnostics->height()>0);
        QVERIFY(window.grab().save(QDir::currentPath()+"/gui-network-compact.png"));
        detailToggle->click();QVERIFY(!details->isVisible() && diagnostics->isVisible());diagnosticToggle->click();QVERIFY(!diagnostics->isVisible());detailToggle->setChecked(true);
        views->setCurrentIndex(1);QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),1,5000);
        QCOMPARE(jobs->currentData().toString(),network.id);QCOMPARE(table->horizontalHeaderItem(2)->text(),QStringLiteral("Обнаружение"));QCOMPARE(table->item(0,2)->text(),sweepDescription());
        table->setCurrentCell(0,0);QVERIFY(details->toPlainText().contains("tcp-port-sweep"));
        outer->setCurrentIndex(0);QVERIFY(fileJobs->isVisible() && !jobs->isVisible());QCOMPARE(fileJobs->currentData().toString(),QString("old-file"));
        outer->setCurrentWidget(panel);QVERIFY(!fileJobs->isVisible() && jobs->isVisible());QCOMPARE(jobs->currentData().toString(),network.id);
        views->setCurrentIndex(0);QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),50,5000);QCOMPARE(table->columnCount(),3);
        const int brokenIndex=jobs->findData(broken.id);QVERIFY(brokenIndex>=0);jobs->setCurrentIndex(brokenIndex);diagnosticToggle->setChecked(true);
        QTRY_VERIFY_WITH_TIMEOUT(diagnostics->isVisible() && diagnostics->toPlainText().startsWith(broken.error),5000);
    }
    void networkCancelLeavesManualAndWatchRunning() {
        QTemporaryDir temp;QVERIFY(temp.isValid());
        const auto watched=temp.filePath("watched");QVERIFY(QDir().mkpath(watched));
        const auto bytes=QByteArray::fromHex("aa00bb");const auto manual=temp.filePath("manual.bin");put(manual,bytes);
        const auto json=temp.filePath("signatures.json"),signatures=temp.filePath("signatures.db");
        put(json,R"({"version":"gui-parallel","signatures":[{"id":"own","name":"own bytes","kind":"PATTERN","value":"aa00bb","version":"1","enabled":1}]})");createSignatures(json,signatures);
        const auto pcap=temp.filePath("own.pcap");put(pcap,fx::pcap({fx::udp(1000000)}));
        QSemaphore entered,release;Request defaults;defaults.path=manual;defaults.signaturePath=signatures;defaults.storagePath=temp.filePath("history.db");
        defaults.hooks.beforeOpen=[&](const QString &){entered.release();release.tryAcquire(1,15000);return QString();};
        MainWindow window(defaults,{},{},watched,rulesPath());window.show();auto unblock=qScopeGuard([&]{release.release();});
        auto *tabs=window.findChild<QTabWidget *>("resultTabs");auto *panel=window.findChild<NetworkPanel *>("networkPanel");QVERIFY(tabs && panel);
        auto *manualStart=window.findChild<QPushButton *>("start"),*manualStop=window.findChild<QPushButton *>("stop");
        auto *watchStart=window.findChild<QPushButton *>("watch"),*watchStop=window.findChild<QPushButton *>("watchStop");
        auto *netStart=panel->findChild<QPushButton *>("networkStart"),*netStop=panel->findChild<QPushButton *>("networkStop");
        auto *storage=window.findChild<QLineEdit *>("storage");auto *watchState=window.findChild<QLabel *>("monitorState");
        QVERIFY(manualStart && manualStop && watchStart && watchStop && netStart && netStop && storage && watchState);
        QTRY_VERIFY_WITH_TIMEOUT(watchStart->isEnabled() && manualStart->isEnabled(),8000);watchStart->click();
        QTRY_VERIFY_WITH_TIMEOUT(watchState->text().contains(QStringLiteral("Работает")),7000);
        QTRY_VERIFY_WITH_TIMEOUT(manualStart->isEnabled(),5000);manualStart->click();QTRY_VERIFY_WITH_TIMEOUT(entered.available()>0,5000);
        tabs->setCurrentWidget(panel);panel->findChild<QComboBox *>("networkSource")->setCurrentIndex(1);panel->findChild<QLineEdit *>("networkPcap")->setText(pcap);
        netStart->click();QVERIFY(panel->busy());QVERIFY(netStop->isEnabled() && manualStop->isEnabled() && watchStop->isEnabled());QVERIFY(!storage->isEnabled());
        netStop->click();QTRY_VERIFY_WITH_TIMEOUT(!panel->busy(),6000);QVERIFY(manualStop->isEnabled() && watchStop->isEnabled());
        {NetworkStore history(defaults.storagePath,true);const auto jobs=history.jobs();QCOMPARE(jobs.size(),size_t(1));const auto job=history.getJob(jobs.front().id);QVERIFY(job);QCOMPARE(job->state,QString("cancelled"));}
        put(watched+"/own.bin",bytes);
        QTRY_VERIFY_WITH_TIMEOUT(watchState->text().contains(QStringLiteral("События файлов: 1")),6000);
        release.release();QTRY_VERIFY_WITH_TIMEOUT(!manualStop->isEnabled(),6000);QVERIFY(watchStop->isEnabled() && !storage->isEnabled());
        watchStop->click();QTRY_VERIFY_WITH_TIMEOUT(storage->isEnabled(),6000);
        Store files(defaults.storagePath,true);const auto jobs=files.jobs();QCOMPARE(jobs.size(),size_t(2));
        for(const auto &job:jobs){const auto reopened=files.getJob(job.id);QVERIFY(reopened);QCOMPARE(reopened->matches,qint64(1));}
    }
    void liveOwnLoopback() {
        if(!QCoreApplication::arguments().contains("liveOwnLoopback"))QSKIP("Запускайте liveOwnLoopback явно. Нужен доступ к захвату loopback.");
        QTemporaryDir temp;QVERIFY(temp.isValid());Request defaults;defaults.storagePath=temp.filePath("history.db");
        MainWindow window(defaults,{},{},{},rulesPath());window.show();
        auto *tabs=window.findChild<QTabWidget *>("resultTabs");auto *panel=window.findChild<NetworkPanel *>("networkPanel");QVERIFY(tabs && panel);tabs->setCurrentWidget(panel);
        auto *prepare=panel->findChild<QPushButton *>("networkPrepareSample"),*send=panel->findChild<QPushButton *>("networkSendSample"),*start=panel->findChild<QPushButton *>("networkStart");
        auto *stop=panel->findChild<QPushButton *>("networkStop"),*current=panel->findChild<QPushButton *>("networkCurrent");
        auto *duration=panel->findChild<QSpinBox *>("networkDuration");auto *ports=panel->findChild<QLineEdit *>("networkPorts");auto *notice=panel->findChild<QLabel *>("networkNotice");
        auto *sampleState=panel->findChild<QLabel *>("networkSampleState");auto *table=panel->findChild<QTableWidget *>("networkResults");auto *views=panel->findChild<QTabBar *>("networkResultView");
        auto *details=panel->findChild<QPlainTextEdit *>("networkDetails");auto *source=panel->findChild<QComboBox *>("networkSource");auto *historyChoice=panel->findChild<QComboBox *>("networkJobs");
        auto *state=panel->findChild<QLabel *>("networkState"),*summary=panel->findChild<QLabel *>("networkSummary");
        QVERIFY(prepare && send && start && stop && current && duration && ports && notice && sampleState && table && views && details && source && historyChoice && state && summary);
        ports->setText("8765");source->setCurrentIndex(2);QVERIFY(!start->isEnabled() && !send->isEnabled());prepare->click();
        QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled() && sampleState->text().contains(QStringLiteral("20 локальных портов")),5000);
        duration->setValue(10);start->click();QTRY_VERIFY_WITH_TIMEOUT(send->isEnabled(),5000);
        stop->click();QTRY_VERIFY_WITH_TIMEOUT(!panel->busy() && prepare->isEnabled(),5000);
        QVERIFY(!start->isEnabled() && !send->isEnabled());QCOMPARE(sampleState->text(),QStringLiteral("Порты освобождены"));
        NetworkStore history(defaults.storagePath,true);const auto stopped=history.jobs();QCOMPARE(stopped.size(),size_t(1));
        QCOMPARE(stopped.front().state,QString("cancelled"));QCOMPARE(stopped.front().scope.tcpPorts.size(),size_t(20));
        source->setCurrentIndex(0);QCOMPARE(ports->text(),QString("8765"));QCOMPARE(duration->value(),0);QVERIFY(!prepare->isVisible());
        source->setCurrentIndex(2);QCOMPARE(duration->value(),10);QVERIFY(!start->isEnabled());prepare->click();QTRY_VERIFY_WITH_TIMEOUT(start->isEnabled(),5000);start->click();
        QTRY_VERIFY_WITH_TIMEOUT(send->isEnabled(),5000);
        const auto *menu=send->menu();QVERIFY(menu);auto *sweep=menu->findChild<QAction *>("networkSample_sweep");QVERIFY(sweep);
        QElapsedTimer latency;latency.start();sweep->trigger();
        QTRY_VERIFY_WITH_TIMEOUT(notice->text().contains("tcp-port-sweep"),5000);
        qInfo()<<"live loopback notification from command, latency_ms"<<latency.elapsed();
        QTRY_VERIFY_WITH_TIMEOUT(sampleState->text().contains(QStringLiteral("20 соединений")),5000);
        QTRY_VERIFY_WITH_TIMEOUT(!panel->busy(),15000);
        const auto jobs=history.jobs();QCOMPARE(jobs.size(),size_t(2));
        const auto saved=history.getJob(jobs.front().id);QVERIFY(saved);QVERIFY2(saved->state=="completed",qPrintable(saved->error));
        QVERIFY(saved->durationMs);QCOMPARE(*saved->durationMs,10000);
        QCOMPARE(saved->input,QString("loopback"));QCOMPARE(saved->scope.tcpPorts.size(),size_t(20));QCOMPARE(saved->storedFlows,qint64(20));QCOMPARE(saved->storedDetections,qint64(1));
        QCOMPARE(saved->counters.parsed,saved->counters.packets);QVERIFY(saved->counters.packets>=20);
        qInfo()<<"live loopback packets"<<saved->counters.packets<<"drops_available"<<saved->dropsAvailable<<"reported_dropped"<<saved->reportedDropped;
        QTRY_VERIFY_WITH_TIMEOUT(current->isVisible() && current->isEnabled(),5000);QCOMPARE(historyChoice->currentData().toString(),stopped.front().id);
        current->click();
        views->setCurrentIndex(1);QTRY_COMPARE_WITH_TIMEOUT(table->rowCount(),1,5000);QCOMPARE(table->item(0,2)->text(),sweepDescription());
        QVERIFY(!state->isVisible() && summary->isVisible() && summary->text().contains(QStringLiteral("Пакетов")));
        table->setCurrentCell(0,0);QVERIFY(details->toPlainText().contains(QStringLiteral("20 различных TCP-портов")));
        QVERIFY(window.grab().save(QDir::currentPath()+"/gui-network-live.png"));
    }
    void liveUntilStoppedOnOwnPort() {
        if(!QCoreApplication::arguments().contains("liveUntilStoppedOnOwnPort"))QSKIP("Явный тест живого loopback-захвата");
        QTemporaryDir temp;QVERIFY(temp.isValid());Request defaults;defaults.storagePath=temp.filePath("history.db");
        QTcpServer server;QVERIFY(server.listen(QHostAddress::LocalHost,0));
        MainWindow window(defaults,{},{},{},rulesPath());window.show();
        auto *tabs=window.findChild<QTabWidget *>("resultTabs");auto *panel=window.findChild<NetworkPanel *>("networkPanel");QVERIFY(tabs && panel);tabs->setCurrentWidget(panel);
        auto *interface=panel->findChild<QComboBox *>("networkInterface"),*jobs=panel->findChild<QComboBox *>("networkJobs");
        auto *ports=panel->findChild<QLineEdit *>("networkPorts");auto *duration=panel->findChild<QSpinBox *>("networkDuration");
        auto *start=panel->findChild<QPushButton *>("networkStart"),*stop=panel->findChild<QPushButton *>("networkStop");
        auto *table=panel->findChild<QTableWidget *>("networkResults");
        QVERIFY(interface && jobs && ports && duration && start && stop && table);QCOMPARE(duration->value(),0);
        interface->setEditText("loopback");ports->setText(QString::number(server.serverPort()));start->click();
        auto running=[&] {
            if(jobs->currentData().toString().isEmpty())return false;
            NetworkStore history(defaults.storagePath,true);const auto job=history.getJob(jobs->currentData().toString(),false);
            return job && job->state=="running" && job->updated!=job->started;
        };
        QTRY_VERIFY_WITH_TIMEOUT(running(),5000);
        QElapsedTimer observing;observing.start();
        QTcpSocket client;client.connectToHost(QHostAddress::LocalHost,server.serverPort());
        QTRY_VERIFY_WITH_TIMEOUT(client.state()==QAbstractSocket::ConnectedState && server.hasPendingConnections(),3000);
        std::unique_ptr<QTcpSocket> accepted(server.nextPendingConnection());QVERIFY(accepted);
        const QByteArray bytes="own continuous capture";QCOMPARE(client.write(bytes),bytes.size());
        QTRY_VERIFY_WITH_TIMEOUT(accepted->bytesAvailable()>=bytes.size(),3000);QCOMPARE(accepted->read(bytes.size()),bytes);
        client.disconnectFromHost();QTRY_VERIFY_WITH_TIMEOUT(table->rowCount()>0 && panel->busy() && stop->isEnabled(),3000);
        const auto remaining=31000-observing.elapsed();if(remaining>0)QTest::qWait(static_cast<int>(remaining));
        QVERIFY(observing.elapsed()>=31000 && panel->busy() && running());
        qInfo()<<"continuous elapsed before stop_ms"<<observing.elapsed();
        QElapsedTimer stopping;stopping.start();stop->click();QTRY_VERIFY_WITH_TIMEOUT(!panel->busy(),6000);
        NetworkStore history(defaults.storagePath,true);const auto summaries=history.jobs();QCOMPARE(summaries.size(),size_t(1));
        const auto job=history.getJob(summaries.front().id);QVERIFY(job && job->durationMs);
        QCOMPARE(*job->durationMs,0);QCOMPARE(job->state,QString("cancelled"));QCOMPARE(job->storedFlows,qint64(1));QVERIFY(job->counters.parsed>0);
        qInfo()<<"continuous stop latency_ms"<<stopping.elapsed()<<"packets"<<job->counters.packets;
    }
};
QTEST_MAIN(NetworkGuiTests)
#include "network_gui_tests.moc"
