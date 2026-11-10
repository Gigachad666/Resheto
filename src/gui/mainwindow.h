#pragma once
#include "core/controller.h"
#include "core/database.h"
#include "core/monitor.h"
#include <QMainWindow>
#include <future>
class QLineEdit;
class QLabel;
class QCheckBox;
class QPushButton;
class QTableWidget;
class QProgressBar;
class QComboBox;
class QPlainTextEdit;
class QTabWidget;
class QToolButton;
class GuiTests;
namespace resheto {
#ifdef RESHETO_WITH_NETWORK
class NetworkPanel;
#endif
struct ViewPage {
    QString jobId,error;
    std::optional<Job> job;
    std::vector<Result> rows;
    std::vector<QJsonObject> rowEvents;
    qint64 cursor=0;
    qint64 total=0, upperRow=0;
    quint64 generation=0;
    std::vector<Job> jobs;
    bool listOnly=false,listed=false,hasEarlierJobs=false;
};
struct ResultView {
    QTableWidget *table=nullptr;
    QComboBox *filter=nullptr,*sort=nullptr,*direction=nullptr;
    QLineEdit *search=nullptr;
    ResultObject object=ResultObject::All;
};
struct DatabaseProbe { QString message; bool signatures=false,heuristics=false; };
class MainWindow : public QMainWindow {
    friend class ::GuiTests; // Управляемая проверка асинхронной границы чтения истории.
    Controller controller_;
    Hooks manualHooks_;
    MonitorRuntime monitor_;
    QLineEdit *path_, *db_, *storage_;
    QLineEdit *watchPath_;
    QLineEdit *heuristics_, *behavior_, *processScope_, *processSearch_;
    QLabel *databaseState_, *summary_, *pageState_, *historyErrorLabel_;
    QCheckBox *recursive_;
    QCheckBox *watchRecursive_;
    QCheckBox *heuristicEnabled_, *processEnabled_;
    QCheckBox *fileEnabled_,*processImages_;
    QPushButton *start_, *stop_, *next_, *first_;
    QPushButton *watch_, *watchStop_;
    QLabel *monitorState_, *processState_, *notification_;
    QTableWidget *table_;
    QTableWidget *processTable_;
    QTabWidget *tabs_;
    QWidget *fileHistory_,*filePages_;
#ifdef RESHETO_WITH_NETWORK
    NetworkPanel *networkPanel_=nullptr;
#endif
    QComboBox *jobs_;
    QPushButton *earlier_,*currentManual_,*currentMonitor_;
    QPushButton *newer_;
    QLabel *manualState_;
    std::vector<ResultView> resultViews_;
    int activeView_=0;
    QPlainTextEdit *details_;
    QToolButton *detailsToggle_,*settingsToggle_;
    QProgressBar *progress_;
    QComboBox *filter_, *sort_, *direction_;
    QLineEdit *search_;
    std::vector<Result> visibleRows_;
    std::vector<QJsonObject> visibleEvents_;
    quint64 generation_=0;
    qint64 total_=0, upperRow_=0;
    QList<QWidget *> inputs_;
    std::future<DatabaseProbe> probe_;
    std::future<ViewPage> view_;
    QString probePath_, probeHeuristicPath_, jobId_, historyPath_;
    QString manualJobId_,monitorJobId_;
    qint64 jobOffset_=0,manualNotified_=0,monitorNotified_=0;
    bool jobsDirty_=true,selectionRead_=true,hasEarlierJobs_=false;
    QList<QWidget *> manualInputs_,monitorInputs_;
    QString historyError_;
    bool stoppedByHistoryError_=false;
    bool databaseReady_=false, heuristicReady_=false, running_=false, monitorActive_=false, needRead_=false, wantLatest_=true;
    qint64 notifiedMatches_=0;
    int processTick_=0;
    qint64 cursor_=0, knownResults_=-1;
    void probe();
    void tick();
    void start();
    void loadHistory();
    void resetPage(bool resetCursor=true);
    void readPage();
    void showSummary(const Job &job);
    void startMonitor();
    void showProcesses();
    void showDetails();
    void setInputsEnabled(bool enabled);
    void selectJob(const QString &id);
    void selectView(int index);
    void notify(const Job &job,qint64 &known,const QString &source);
public:
    explicit MainWindow(const Request &defaults,const QString &behaviorPath={},const QString &processScope={},const QString &watchPath={},const QString &networkRulesPath={});
    ~MainWindow() override;
};
}
