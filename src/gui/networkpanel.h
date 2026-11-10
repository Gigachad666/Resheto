#pragma once
#include "network/session.h"
#include <QProcess>
#include <QWidget>
#include <future>

class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTabBar;
class QToolButton;

namespace resheto {
class NetworkPanel : public QWidget {
    Q_OBJECT
    struct Page {
        quint64 generation=0;
        QString id,error,newestJobId;
        QString noticeJobId,noticeText;
        qint64 noticeCount=0;
        std::optional<network::NetworkJob> job;
        std::vector<network::NetworkJob> jobs;
        std::vector<network::Diagnostic> diagnostics;
        network::NetworkFlowPage flows;
        network::NetworkDetectionPage detections;
        std::vector<network::Flow> linkedFlows;
        bool detectionView=false,hasOlderJobs=false;
    };
    struct Detail {
        QString jobId,flowId,error;
        network::NetworkDetectionPage detections;
    };
    network::NetworkSession session_;
    QProcess interfaceProcess_,sampleProcess_;
    QByteArray sampleOutput_;
    QString storage_,selectedId_,workerPath_,samplePath_,lastProgressId_;
    QString selectedFlowId_,copiedBasis_,sampleJobId_,stateJobId_;
    std::vector<quint16> samplePorts_;
    std::optional<network::NetworkJob> latest_;
    std::future<Page> pending_;
    std::future<Detail> detail_;
    Page visible_;
    quint64 generation_=0;
    qint64 offset_=0,jobOffset_=0,total_=0,noticeShown_=0;
    int interfaceSeconds_=0,sampleSeconds_=30;
    bool dirty_=true,wasBusy_=false,stopRequested_=false,sampleSent_=false,sampleClosing_=false,sampleFailed_=false;
    QComboBox *source_,*interfaces_,*jobs_,*filter_,*sort_,*direction_;
    QLineEdit *pcap_,*rules_,*ports_,*search_;
    QSpinBox *duration_;
    QLabel *state_,*summary_,*historyError_,*notice_,*pageLabel_,*sampleState_;
    QLabel *inputLabel_,*durationLabel_,*portsLabel_;
    QPushButton *start_,*stop_,*refresh_,*pcapBrowse_,*rulesBrowse_;
    QPushButton *current_,*older_,*newer_,*previousPage_,*nextPage_,*copy_,*sample_,*sendSample_;
    QTableWidget *table_;
    QTabBar *resultKind_;
    QWidget *detailPane_;
    QPlainTextEdit *details_,*diagnosticText_;
    QToolButton *detailsToggle_,*diagnosticsToggle_;
    void tick();
    void updateControls();
    void setStateText(const QString &text,const QString &jobId={});
    void start();
    void refreshInterfaces();
    void readInterfaces(int exitCode);
    void prepareSample();
    void readSample();
    void finishSample(int exitCode);
    void resetSample(const QString &message={});
    bool samplePrepared() const;
    void sendSample(const QString &kind);
    void requestPage(bool resetOffset=true);
    void loadPage();
    void showPage(Page page);
    void selectRow();
    void loadDetail();
    QString interfaceId() const;
    std::vector<quint16> tcpPorts() const;
public:
    explicit NetworkPanel(const QString &storage,const QString &rulesPath,QWidget *parent=nullptr);
    ~NetworkPanel() override;
    void setStorage(const QString &path);
    bool busy() const { return session_.busy(); }
    void cancel() { session_.cancel(); }
signals:
    void activeChanged();
    void detectionNotice(qint64 count);
};
}
