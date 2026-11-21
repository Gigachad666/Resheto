#pragma once
#include "core/controller.h"
#include "core/database.h"
#include "core/monitor.h"
#ifdef RESHETO_WITH_SERVICE
#include "service/client.h"
#endif
#include <chrono>
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
#ifdef RESHETO_WITH_SERVICE
class ReactionPanel;
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
    QString manualSelection_,monitorSelection_;
    QString manualJobId_,monitorJobId_;
    qint64 jobOffset_=0,manualNotified_=0,monitorNotified_=0;
    bool jobsDirty_=true,selectionRead_=true,hasEarlierJobs_=false;
    QList<QWidget *> manualInputs_,monitorInputs_;
    QString historyError_;
    bool stoppedByHistoryError_=false;
    bool databaseReady_=false, heuristicReady_=false, running_=false, monitorActive_=false, needRead_=false, wantLatest_=true;
    const QString serviceEndpoint_;
#ifdef RESHETO_WITH_SERVICE
    struct ServiceCommand {
        QString path, cancelId;
        bool recursive=false;
        std::optional<service::MonitorOptions> monitor;
        bool monitorStop=false;
    };
    struct ServiceReply {
        std::optional<service::Status> status;
        std::optional<Job> started;
        std::optional<MonitorStatus> monitorStarted;
        std::optional<std::vector<ProcessInfo>> processes;
        QString processesError;
        QString connectionError, commandError;
    };
    std::optional<ServiceCommand> serviceCommand_;
    std::future<ServiceReply> serviceReply_;
    std::chrono::steady_clock::time_point nextServicePoll_;
    QLabel *serviceError_=nullptr;
    QLabel *serviceDiagnostics_=nullptr;
    QPushButton *quarantineResult_=nullptr;
    QPushButton *terminateProcess_=nullptr;
    ReactionPanel *notificationPanel_=nullptr,*quarantinePanel_=nullptr,*journalPanel_=nullptr;
    qint64 serviceUnread_=-1;
    bool serviceReady_=false, serviceCommandRunning_=false;
    bool serviceBusy_=false, serviceJobPending_=false;
    bool serviceScanAvailable_=false,serviceReactionBusy_=false,serviceQuarantineAvailable_=false;
    bool serviceMonitorAvailable_=false,serviceMonitorStopRequested_=false;
    MonitorStatus serviceMonitor_;
    std::vector<ProcessInfo> serviceProcesses_;
    QString serviceProcessesError_;
    struct ProcessActionReply {
        QString jobId,key,error;
        QJsonObject result;
        bool confirmed=false;
    };
    std::future<ProcessActionReply> processAction_;
    bool confirmingProcess_=false;
    void pollService();
    void updateQuarantineAction();
    const Result *selectedProcessDetection() const;
    void requestProcessAction(const QString &jobId,const QString &key,bool confirmed);
    void pollProcessAction();
#endif
    qint64 notifiedMatches_=0;
    int processTick_=0;
    qint64 cursor_=0, knownResults_=-1;
    void probe();
    void tick();
    void start();
    void stopManual();
    void selectManualJob(const QString &id);
    void updateManualProgress(const Job &job,bool busy);
    void loadHistory();
    void resetPage(bool resetCursor=true);
    void readPage();
    void showSummary(const Job &job);
    void startMonitor();
    void stopMonitor();
    void selectMonitorJob(const QString &id,bool files);
    void updateMonitorProgress(const MonitorStatus &status);
    void showProcesses();
    void showDetails();
    void setInputsEnabled(bool enabled);
    QString &selectionForView();
    void selectJob(const QString &id);
    void selectView(int index);
    void notify(const Job &job,qint64 &known,const QString &source);
public:
    explicit MainWindow(const Request &defaults,const QString &behaviorPath={},const QString &processScope={},const QString &watchPath={},const QString &networkRulesPath={},const QString &serviceEndpoint={});
    ~MainWindow() override;
};
}
