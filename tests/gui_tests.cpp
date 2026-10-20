#include "gui/mainwindow.h"
#include "core/database.h"
#include "core/signatures.h"
#include <QDir>
#include <QFile>
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
};
QTEST_MAIN(GuiTests)
#include "gui_tests.moc"
