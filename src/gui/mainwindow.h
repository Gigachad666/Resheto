#pragma once
#include "core/controller.h"
#include "core/database.h"
#include <QMainWindow>
#include <future>
class QLineEdit;
class QLabel;
class QCheckBox;
class QPushButton;
class QTableWidget;
class QProgressBar;
class QComboBox;
class GuiTests;
namespace resheto {
struct ViewPage {
    QString jobId,error;
    std::optional<Job> job;
    std::vector<Result> rows;
    qint64 cursor=0;
    qint64 total=0, upperRow=0;
    quint64 generation=0;
};
class MainWindow : public QMainWindow {
    friend class ::GuiTests; // Управляемая проверка асинхронной границы чтения истории.
    Controller controller_;
    QLineEdit *path_, *db_, *storage_;
    QLabel *databaseState_, *summary_, *pageState_, *historyErrorLabel_;
    QCheckBox *recursive_;
    QPushButton *start_, *stop_, *last_, *next_, *first_;
    QTableWidget *table_;
    QProgressBar *progress_;
    QComboBox *filter_, *sort_, *direction_;
    QLineEdit *search_;
    std::vector<Result> visibleRows_;
    quint64 generation_=0;
    qint64 total_=0, upperRow_=0;
    QList<QWidget *> inputs_;
    std::future<QString> probe_;
    std::future<ViewPage> view_;
    QString probePath_, jobId_;
    QString historyError_;
    bool stoppedByHistoryError_=false;
    bool databaseReady_=false, running_=false, needRead_=false, wantLatest_=true;
    qint64 cursor_=0, knownResults_=-1;
    void probe();
    void tick();
    void start();
    void resetPage(bool resetCursor=true);
    void readPage();
    void showSummary(const Job &job);
public:
    explicit MainWindow(const Request &defaults);
    ~MainWindow() override;
};
}
