#include "networkpanel.h"
#include <QAction>
#include <QApplication>
#include <QBoxLayout>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QSplitter>
#include <QTabBar>
#include <QTableWidget>
#include <QTimer>
#include <QToolButton>
#include <algorithm>

namespace resheto {
using namespace network;
namespace {
enum SourceIndex { InterfaceSource, PcapSource, SampleSource };
QString sibling(const QString &name) {
#ifdef Q_OS_WIN
    return QDir(QCoreApplication::applicationDirPath()).filePath(name+".exe");
#else
    return QDir(QCoreApplication::applicationDirPath()).filePath(name);
#endif
}
QString packetTime(qint64 microseconds) {
    return QDateTime::fromMSecsSinceEpoch(microseconds/1000).toUTC().toString(Qt::ISODateWithMs);
}
QString countersText(const NetworkJob &job) {
    const auto &c=job.counters;
    return QStringLiteral("Пакетов %1 · потоков %2 · обнаружений %3").arg(c.packets).arg(job.storedFlows).arg(job.storedDetections);
}
bool hasSpecificError(const NetworkJob &job) {
    return !job.error.isEmpty() && job.error!=networkIncompleteReason();
}
QString detectionText(const Detection &d) {
    const auto data=QString::fromUtf8(QJsonDocument(d.evidence).toJson(QJsonDocument::Indented));
    return QStringLiteral("Правило %1, версия %2. %3\nОснование: %4\n%5").arg(d.ruleId,d.ruleVersion,d.description,d.basis,data);
}
void putRow(QTableWidget *table,int row,const QStringList &values,const QString &id) {
    for(int column=0;column<values.size();++column) {
        auto *item=new QTableWidgetItem(values[column]);
        item->setToolTip(values[column]);
        if(column==0)item->setData(Qt::UserRole,id);
        table->setItem(row,column,item);
    }
}
}
NetworkPanel::NetworkPanel(const QString &storage,const QString &rulesPath,QWidget *parent)
    : QWidget(parent),storage_(storage),workerPath_(sibling("resheto-network-worker")),samplePath_(sibling("resheto-network-sample")) {
    setObjectName("networkPanel");
    auto *body=new QVBoxLayout(this);
    body->setSpacing(4);
    auto *config=new QGridLayout;config->setVerticalSpacing(3);
    body->addLayout(config);
    source_=new QComboBox;source_->setObjectName("networkSource");source_->addItems({QStringLiteral("Сетевой интерфейс"),QStringLiteral("Файл PCAP"),QStringLiteral("Локальный показ")});
    interfaces_=new QComboBox;interfaces_->setObjectName("networkInterface");interfaces_->setEditable(true);interfaces_->lineEdit()->setPlaceholderText(QStringLiteral("Выберите сетевой интерфейс"));
    refresh_=new QPushButton(QStringLiteral("Обновить интерфейсы"));refresh_->setObjectName("networkRefreshInterfaces");
    pcap_=new QLineEdit;pcap_->setObjectName("networkPcap");pcap_->setPlaceholderText(QStringLiteral("Путь к файлу PCAP"));
    pcapBrowse_=new QPushButton(QStringLiteral("Выбрать PCAP…"));
    config->addWidget(new QLabel(QStringLiteral("Источник")),0,0);config->addWidget(source_,0,1);
    inputLabel_=new QLabel;config->addWidget(inputLabel_,0,2);
    config->addWidget(interfaces_,0,3);config->addWidget(refresh_,0,4);
    config->addWidget(pcap_,0,3);config->addWidget(pcapBrowse_,0,4);
    rules_=new QLineEdit(rulesPath.isEmpty()?QStringLiteral("data/network_rules.json"):rulesPath);rules_->setObjectName("networkRules");
    rulesBrowse_=new QPushButton(QStringLiteral("Выбрать…"));
    duration_=new QSpinBox;duration_->setObjectName("networkDuration");duration_->setRange(0,maximumDurationMs/1000);
    duration_->setSpecialValueText(QStringLiteral("До остановки"));duration_->setSuffix(QStringLiteral(" с"));duration_->setToolTip(QStringLiteral("Предельная длительность захвата. Ноль отключает автоостановку."));
    ports_=new QLineEdit;ports_->setObjectName("networkPorts");ports_->setMaxLength(440);ports_->setPlaceholderText(QStringLiteral("Через запятую. Пусто — весь интерфейс"));ports_->setToolTip(QStringLiteral("Пустое поле охватывает весь IPv4/IPv6 выбранного интерфейса"));
    config->addWidget(new QLabel(QStringLiteral("Правила")),1,0);config->addWidget(rules_,1,1,1,3);config->addWidget(rulesBrowse_,1,4);
    durationLabel_=new QLabel(QStringLiteral("Автоостановка"));durationLabel_->setBuddy(duration_);config->addWidget(durationLabel_,2,0);config->addWidget(duration_,2,1,Qt::AlignLeft);
    portsLabel_=new QLabel(QStringLiteral("TCP-порты"));portsLabel_->setBuddy(ports_);config->addWidget(portsLabel_,2,2);config->addWidget(ports_,2,3,1,2);config->setColumnStretch(3,1);
    auto *actions=new QHBoxLayout;body->addLayout(actions);
    start_=new QPushButton;start_->setObjectName("networkStart");stop_=new QPushButton(QStringLiteral("Остановить"));stop_->setObjectName("networkStop");
    sample_=new QPushButton(QStringLiteral("1. Подготовить порты"));sample_->setObjectName("networkPrepareSample");
    sendSample_=new QPushButton(QStringLiteral("3. Отправить трафик"));sendSample_->setObjectName("networkSendSample");
    auto *sampleMenu=new QMenu(sendSample_);sendSample_->setMenu(sampleMenu);
    const std::pair<QString,QString> samples[]={{QStringLiteral("Два обычных соединения"),"normal"},{QStringLiteral("Двадцать разных портов"),"sweep"},{QStringLiteral("Шесть регулярных попыток"),"periodic"}};
    for(const auto &[name,kind]:samples) {
        auto *action=sampleMenu->addAction(name);action->setObjectName("networkSample_"+kind);
        connect(action,&QAction::triggered,this,[this,kind]{sendSample(kind);});
    }
    actions->addWidget(sample_);actions->addWidget(start_);actions->addWidget(sendSample_);actions->addWidget(stop_);actions->addStretch();
    state_=new QLabel;state_->setObjectName("networkState");state_->setWordWrap(true);state_->hide();body->addWidget(state_);
    sampleState_=new QLabel;sampleState_->setObjectName("networkSampleState");sampleState_->setWordWrap(true);sampleState_->hide();body->addWidget(sampleState_);
    notice_=new QLabel;notice_->setObjectName("networkNotice");notice_->setWordWrap(true);notice_->hide();body->addWidget(notice_);
    auto *history=new QHBoxLayout;body->addLayout(history);history->addWidget(new QLabel(QStringLiteral("Результаты задания")));
    jobs_=new QComboBox;jobs_->setObjectName("networkJobs");jobs_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);jobs_->setMinimumContentsLength(25);
    jobs_->setAccessibleName(QStringLiteral("Сетевые задания"));
    newer_=new QPushButton(QStringLiteral("К новым заданиям"));newer_->setObjectName("networkNewerJobs");
    older_=new QPushButton(QStringLiteral("Более ранние задания"));older_->setObjectName("networkOlderJobs");
    current_=new QPushButton;current_->setObjectName("networkCurrent");
    history->addWidget(jobs_,1);history->addWidget(newer_);history->addWidget(older_);history->addWidget(current_);
    summary_=new QLabel;summary_->setObjectName("networkSummary");summary_->setWordWrap(true);summary_->setTextInteractionFlags(Qt::TextSelectableByMouse);body->addWidget(summary_);
    historyError_=new QLabel;historyError_->setObjectName("networkHistoryError");historyError_->setWordWrap(true);historyError_->setTextInteractionFlags(Qt::TextSelectableByMouse);historyError_->hide();body->addWidget(historyError_);
    resultKind_=new QTabBar;resultKind_->setObjectName("networkResultView");resultKind_->setExpanding(false);resultKind_->setAccessibleName(QStringLiteral("Вид сетевых результатов"));
    resultKind_->addTab(QStringLiteral("Трафик"));resultKind_->addTab(QStringLiteral("Обнаружения"));body->addWidget(resultKind_);
    auto *filters=new QHBoxLayout;body->addLayout(filters);
    filter_=new QComboBox;filter_->setObjectName("networkFilter");filter_->addItems({QStringLiteral("Все потоки"),QStringLiteral("Потоки с обнаружениями")});
    search_=new QLineEdit;search_->setObjectName("networkSearch");search_->setMaxLength(4096);search_->setPlaceholderText(QStringLiteral("Адрес, порт, правило или основание"));
    sort_=new QComboBox;sort_->setObjectName("networkSort");sort_->addItems({QStringLiteral("По началу"),QStringLiteral("По окончанию"),QStringLiteral("По соединению"),QStringLiteral("По пакетам")});
    direction_=new QComboBox;direction_->addItems({QStringLiteral("По возрастанию"),QStringLiteral("По убыванию")});
    filters->addWidget(filter_);filters->addWidget(search_,1);filters->addWidget(sort_);filters->addWidget(direction_);
    auto *results=new QSplitter(Qt::Horizontal);results->setChildrenCollapsible(false);body->addWidget(results,1);
    table_=new QTableWidget(0,3);table_->setObjectName("networkResults");table_->setEditTriggers(QAbstractItemView::NoEditTriggers);table_->setSelectionBehavior(QAbstractItemView::SelectRows);table_->setSelectionMode(QAbstractItemView::SingleSelection);table_->setWordWrap(false);table_->horizontalHeader()->setStretchLastSection(true);results->addWidget(table_);
    detailPane_=new QWidget;detailPane_->setMinimumWidth(180);detailPane_->setMaximumWidth(330);results->addWidget(detailPane_);results->setStretchFactor(0,1);
    auto *side=new QVBoxLayout(detailPane_);side->setContentsMargins(0,0,0,0);
    details_=new QPlainTextEdit;details_->setObjectName("networkDetails");details_->setReadOnly(true);details_->setSizePolicy(QSizePolicy::Preferred,QSizePolicy::Ignored);side->addWidget(details_);
    diagnosticText_=new QPlainTextEdit;diagnosticText_->setObjectName("networkDiagnostics");diagnosticText_->setReadOnly(true);diagnosticText_->setSizePolicy(QSizePolicy::Preferred,QSizePolicy::Ignored);side->addWidget(diagnosticText_);
    detailPane_->hide();
    auto *pages=new QHBoxLayout;body->addLayout(pages);pageLabel_=new QLabel;pageLabel_->setObjectName("networkPage");pages->addWidget(pageLabel_);pages->addStretch();
    previousPage_=new QPushButton(QStringLiteral("Предыдущие"));nextPage_=new QPushButton(QStringLiteral("Следующие"));nextPage_->setObjectName("networkNext");copy_=new QPushButton(QStringLiteral("Копировать основание"));copy_->setObjectName("networkCopyBasis");
    pages->addWidget(previousPage_);pages->addWidget(nextPage_);pages->addWidget(copy_);
    detailsToggle_=new QToolButton;detailsToggle_->setObjectName("networkDetailsToggle");detailsToggle_->setText(QStringLiteral("Подробности"));detailsToggle_->setCheckable(true);detailsToggle_->setChecked(true);pages->addWidget(detailsToggle_);
    diagnosticsToggle_=new QToolButton;diagnosticsToggle_->setObjectName("networkDiagnosticsToggle");diagnosticsToggle_->setText(QStringLiteral("Диагностика"));diagnosticsToggle_->setCheckable(true);pages->addWidget(diagnosticsToggle_);

    connect(start_,&QPushButton::clicked,this,&NetworkPanel::start);
    connect(stop_,&QPushButton::clicked,this,[this]{
        stopRequested_=true;session_.cancel();
        if(!sampleJobId_.isEmpty())resetSample(QStringLiteral("Останавливаем локальный захват…"));
        updateControls();
    });
    connect(refresh_,&QPushButton::clicked,this,&NetworkPanel::refreshInterfaces);
    connect(duration_,&QSpinBox::valueChanged,this,[this](int seconds){
        if(source_->currentIndex()==SampleSource)sampleSeconds_=seconds;
        else if(source_->currentIndex()==InterfaceSource)interfaceSeconds_=seconds;
    });
    connect(source_,&QComboBox::currentIndexChanged,this,[this](int source){
        const bool sample=source==SampleSource;
        QSignalBlocker durationSignal(duration_);
        duration_->setMinimum(sample?1:0);
        duration_->setSpecialValueText(sample?QString():QStringLiteral("До остановки"));
        duration_->setValue(sample?sampleSeconds_:interfaceSeconds_);
        if(!busy() && !sample){resetSample();sampleState_->clear();}
        updateControls();
    });
    connect(pcapBrowse_,&QPushButton::clicked,this,[this]{const auto path=QFileDialog::getOpenFileName(this,QStringLiteral("Открыть PCAP"),{},QStringLiteral("PCAP (*.pcap);;Все файлы (*)"));if(!path.isEmpty())pcap_->setText(path);});
    connect(rulesBrowse_,&QPushButton::clicked,this,[this]{const auto path=QFileDialog::getOpenFileName(this,QStringLiteral("Сетевые правила"),{},QStringLiteral("JSON (*.json)"));if(!path.isEmpty())rules_->setText(path);});
    connect(jobs_,&QComboBox::currentIndexChanged,this,[this](int index){if(index>=0){selectedId_=jobs_->itemData(index).toString();requestPage();}});
    connect(current_,&QPushButton::clicked,this,[this]{if(!visible_.newestJobId.isEmpty()){selectedId_=visible_.newestJobId;jobOffset_=0;requestPage();updateControls();}});
    connect(older_,&QPushButton::clicked,this,[this]{jobOffset_+=50;requestPage(false);updateControls();});
    connect(newer_,&QPushButton::clicked,this,[this]{jobOffset_=0;requestPage(false);updateControls();});
    connect(resultKind_,&QTabBar::currentChanged,this,[this]{table_->setRowCount(0);total_=0;pageLabel_->clear();selectRow();requestPage();updateControls();});
    connect(filter_,&QComboBox::currentIndexChanged,this,[this]{requestPage();updateControls();});
    connect(sort_,&QComboBox::currentIndexChanged,this,[this]{requestPage();});
    connect(direction_,&QComboBox::currentIndexChanged,this,[this]{requestPage();});
    auto *searchDelay=new QTimer(this);searchDelay->setSingleShot(true);searchDelay->setInterval(220);
    connect(search_,&QLineEdit::textChanged,searchDelay,qOverload<>(&QTimer::start));connect(searchDelay,&QTimer::timeout,this,[this]{requestPage();});
    connect(previousPage_,&QPushButton::clicked,this,[this]{offset_=qMax<qint64>(0,offset_-200);requestPage(false);});
    connect(nextPage_,&QPushButton::clicked,this,[this]{offset_+=200;requestPage(false);});
    connect(table_,&QTableWidget::itemSelectionChanged,this,&NetworkPanel::selectRow);
    connect(detailsToggle_,&QToolButton::toggled,this,&NetworkPanel::updateControls);
    connect(diagnosticsToggle_,&QToolButton::toggled,this,&NetworkPanel::updateControls);
    connect(copy_,&QPushButton::clicked,this,[this]{if(!copiedBasis_.isEmpty())QApplication::clipboard()->setText(copiedBasis_);});
    connect(sample_,&QPushButton::clicked,this,&NetworkPanel::prepareSample);
    connect(&sampleProcess_,&QProcess::readyReadStandardOutput,this,&NetworkPanel::readSample);
    connect(&sampleProcess_,&QProcess::errorOccurred,this,[this](QProcess::ProcessError error){
        if(error==QProcess::FailedToStart && !sampleClosing_){sampleFailed_=true;resetSample(QStringLiteral("Не удалось запустить локальный помощник: ")+sampleProcess_.errorString());updateControls();}
    });
    connect(&sampleProcess_,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this](int code,QProcess::ExitStatus status){finishSample(status==QProcess::NormalExit?code:-1);});
    connect(&interfaceProcess_,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,[this](int code,QProcess::ExitStatus){readInterfaces(code);});
    connect(&interfaceProcess_,&QProcess::errorOccurred,this,[this]{setStateText(interfaceProcess_.errorString());updateControls();});
    auto *interfaceTimeout=new QTimer(this);interfaceTimeout->setSingleShot(true);interfaceTimeout->setInterval(5000);
    connect(&interfaceProcess_,&QProcess::stateChanged,this,[interfaceTimeout](QProcess::ProcessState state){if(state==QProcess::NotRunning)interfaceTimeout->stop();else interfaceTimeout->start();});
    connect(interfaceTimeout,&QTimer::timeout,this,[this]{interfaceProcess_.kill();});
    for(auto *label:{state_,sampleState_,notice_,summary_,historyError_})label->setTextFormat(Qt::PlainText);
    auto *timer=new QTimer(this);timer->setInterval(150);connect(timer,&QTimer::timeout,this,&NetworkPanel::tick);timer->start();
    updateControls();
}
NetworkPanel::~NetworkPanel() {
    session_.cancel();
    disconnect(&interfaceProcess_,nullptr,this,nullptr);
    disconnect(&sampleProcess_,nullptr,this,nullptr);
    if(interfaceProcess_.state()!=QProcess::NotRunning)interfaceProcess_.kill();
    if(sampleProcess_.state()!=QProcess::NotRunning)sampleProcess_.kill();
}
void NetworkPanel::setStorage(const QString &path) {
    if(path==storage_ || busy())return;
    storage_=path;selectedId_.clear();latest_.reset();lastProgressId_.clear();jobOffset_=0;noticeShown_=0;emit detectionNotice(0);
    visible_=Page{};table_->setRowCount(0);notice_->hide();historyError_->hide();summary_->clear();setStateText({});
    requestPage();
}
QString NetworkPanel::interfaceId() const {
    const int index=interfaces_->currentIndex();
    if(index>=0 && interfaces_->currentText()==interfaces_->itemText(index))return interfaces_->itemData(index).toString();
    return interfaces_->currentText().trimmed();
}
std::vector<quint16> NetworkPanel::tcpPorts() const {
    std::vector<quint16> result;
    if(ports_->text().trimmed().isEmpty())return result;
    for(const auto &part:ports_->text().split(',')) {
        bool ok=false;const auto port=part.trimmed().toUInt(&ok);
        if(!ok || !port || port>65535)throw Error(QStringLiteral("Укажите TCP-порты числами 1..65535 через запятую"));
        result.push_back(static_cast<quint16>(port));
    }
    return result;
}
void NetworkPanel::start() {
    try {
        NetworkRequest request;const int source=source_->currentIndex();
        request.analysis.source=source==PcapSource?"pcap":"live";
        request.analysis.durationMs=source==PcapSource?0:duration_->value()*1000;
        if(source==PcapSource)request.analysis.input=pcap_->text().trimmed();
        else if(source==SampleSource) {
            if(!samplePrepared())throw Error(QStringLiteral("Сначала подготовьте локальные порты"));
            if(!request.analysis.durationMs)throw Error(QStringLiteral("Для локального показа укажите время автоостановки"));
            request.analysis.input="loopback";
            request.analysis.capture.tcpPorts=samplePorts_;
        } else {
            request.analysis.input=interfaceId();
            request.analysis.capture.tcpPorts=tcpPorts();
        }
        request.rulesPath=rules_->text();request.storagePath=storage_;request.workerPath=workerPath_;
        if(!session_.submit(std::move(request)))return;
        wasBusy_=true;stopRequested_=false;notice_->hide();noticeShown_=0;emit detectionNotice(0);
        if(source==SampleSource) {
            sampleJobId_=session_.progress()->id;
            sampleState_->setText(QStringLiteral("Запускаем локальный захват…"));
        }
        setStateText(QStringLiteral("Запускается сетевой анализ…"));emit activeChanged();
    }catch(const Error &error){setStateText(error.message);}
    updateControls();
}
void NetworkPanel::refreshInterfaces() {
    if(interfaceProcess_.state()!=QProcess::NotRunning || busy())return;
    setStateText(QStringLiteral("Чтение списка интерфейсов…"));
    interfaceProcess_.start(workerPath_,{"--interfaces"});updateControls();
}
void NetworkPanel::readInterfaces(int exitCode) {
    const auto output=interfaceProcess_.readAllStandardOutput();
    if(exitCode || output.size()>65536) {
        const auto error=QJsonDocument::fromJson(interfaceProcess_.readAllStandardError()).object()["error"].toString();
        setStateText(error.isEmpty()?QStringLiteral("Не удалось получить список интерфейсов"):error);updateControls();return;
    }
    const auto object=QJsonDocument::fromJson(output).object();
    if(object["format"]!="resheto-network-interfaces-v1" || !object["interfaces"].isArray()) {
        setStateText(QStringLiteral("Сетевой процесс вернул неверный список интерфейсов"));updateControls();return;
    }
    const auto previous=interfaceId();
    interfaces_->clear();
    for(const auto &value:object["interfaces"].toArray()) {
        const auto item=value.toObject();const auto id=item["id"].toString();
        if(id.isEmpty())continue;
        const auto name=item["name"].toString();
        interfaces_->addItem(name.isEmpty()?id:name,id);
    }
    const int index=interfaces_->findData(previous);
    interfaces_->setCurrentIndex(index);
    if(index<0)interfaces_->setEditText(previous);
    setStateText(QStringLiteral("Доступных интерфейсов: %1").arg(interfaces_->count()));updateControls();
}
void NetworkPanel::prepareSample() {
    if(busy() || !sampleJobId_.isEmpty() || source_->currentIndex()!=SampleSource || sampleProcess_.state()!=QProcess::NotRunning)return;
    sampleOutput_.clear();samplePorts_.clear();sampleSent_=false;sampleClosing_=false;sampleFailed_=false;
    sampleState_->setText(QStringLiteral("Подготавливаем собственные порты на 127.0.0.1…"));
    sampleProcess_.start(samplePath_,{"--wait"});updateControls();
}
bool NetworkPanel::samplePrepared() const {
    return samplePorts_.size()==20 && !sampleSent_ && !sampleClosing_ && sampleProcess_.state()==QProcess::Running;
}
void NetworkPanel::resetSample(const QString &message) {
    samplePorts_.clear();sampleOutput_.clear();sampleSent_=false;
    if(!message.isEmpty())sampleState_->setText(message);
    if(sampleProcess_.state()!=QProcess::NotRunning && !sampleClosing_) {
        sampleClosing_=true;sampleProcess_.kill();
    }
}
void NetworkPanel::readSample() {
    const auto output=sampleProcess_.readAllStandardOutput();
    if(sampleClosing_)return;
    sampleOutput_+=output;
    if(sampleOutput_.size()>8192){sampleFailed_=true;resetSample(QStringLiteral("Неверный ответ локального помощника"));if(!sampleJobId_.isEmpty())session_.cancel();return;}
    while(true) {
        const auto newline=sampleOutput_.indexOf('\n');
        if(newline<0)break;
        const auto object=QJsonDocument::fromJson(sampleOutput_.left(newline)).object();sampleOutput_.remove(0,newline+1);
        if(object["type"]=="ready" && object["address"]=="127.0.0.1" && object["ports"].toArray().size()==20 && !busy() && source_->currentIndex()==SampleSource) {
            std::vector<quint16> ports;
            for(const auto &value:object["ports"].toArray()) {
                const int port=value.toInt();if(port<1 || port>65535 || std::find(ports.begin(),ports.end(),port)!=ports.end())break;
                ports.push_back(static_cast<quint16>(port));
            }
            if(ports.size()!=20){sampleFailed_=true;resetSample(QStringLiteral("Локальный помощник сообщил неверные порты"));break;}
            samplePorts_=std::move(ports);
            sampleState_->setText(QStringLiteral("Готовы 20 локальных портов на 127.0.0.1"));
        } else if(object["type"]=="sent")sampleState_->setText(QStringLiteral("Доставлено: %1 соединений на 127.0.0.1").arg(object["connected"].toInt()));
    }
    updateControls();
}
void NetworkPanel::finishSample(int exitCode) {
    readSample();
    const auto diagnostic=QString::fromUtf8(sampleProcess_.readAllStandardError()).trimmed().left(2048);
    if(!sampleClosing_ && exitCode) {
        sampleFailed_=true;
        sampleState_->setText(diagnostic.isEmpty()?QStringLiteral("Локальный помощник завершился с ошибкой"):diagnostic);
        if(!sampleJobId_.isEmpty())session_.cancel();
    }
    sampleClosing_=false;samplePorts_.clear();sampleOutput_.clear();
    updateControls();
}
void NetworkPanel::sendSample(const QString &kind) {
    if(!sendSample_->isEnabled())return;
    const auto command=kind.toLatin1()+'\n';
    if(sampleProcess_.write(command)==command.size()) {
        sampleSent_=true;sampleProcess_.closeWriteChannel();sampleState_->setText(QStringLiteral("Локальные соединения выполняются…"));
    } else sampleState_->setText(QStringLiteral("Не удалось запустить локальные соединения"));
    updateControls();
}
void NetworkPanel::setStateText(const QString &text,const QString &jobId) {
    stateJobId_=jobId;state_->setText(text);
}
void NetworkPanel::updateControls() {
    const bool active=busy(),interface=source_->currentIndex()==InterfaceSource,sample=source_->currentIndex()==SampleSource;
    const bool idle=!active && sampleJobId_.isEmpty();
    inputLabel_->setText(interface?QStringLiteral("Интерфейс"):QStringLiteral("Путь к PCAP"));inputLabel_->setVisible(!sample);
    interfaces_->setVisible(interface);refresh_->setVisible(interface);ports_->setVisible(interface);portsLabel_->setVisible(interface);
    duration_->setVisible(interface || sample);durationLabel_->setVisible(interface || sample);
    pcap_->setVisible(!interface && !sample);pcapBrowse_->setVisible(!interface && !sample);
    for(auto *input:QList<QWidget*>{source_,interfaces_,duration_,ports_,pcap_,pcapBrowse_,rules_,rulesBrowse_})input->setEnabled(idle);
    refresh_->setEnabled(idle && interfaceProcess_.state()==QProcess::NotRunning);
    start_->setText(sample?QStringLiteral("2. Начать захват"):interface?QStringLiteral("Начать захват"):QStringLiteral("Анализировать PCAP"));
    start_->setEnabled(idle && (!sample || samplePrepared()));stop_->setEnabled(active && !stopRequested_);
    const bool summaryShown=!active && latest_ && latest_->state!="running" && visible_.job && visible_.error.isEmpty() &&
        stateJobId_==latest_->id && visible_.job->id==stateJobId_ && !hasSpecificError(*latest_) &&
        visible_.job->state==latest_->state && visible_.job->finished==latest_->finished && visible_.job->error==latest_->error;
    state_->setVisible(!state_->text().isEmpty() && !summaryShown);
    sample_->setVisible(sample);sendSample_->setVisible(sample);sampleState_->setVisible(sample && !sampleState_->text().isEmpty());
    sample_->setEnabled(idle && sampleProcess_.state()==QProcess::NotRunning);
    const bool ready=sample && active && latest_ && latest_->id==sampleJobId_ && latest_->state=="running" && latest_->updated!=latest_->started;
    const bool maySend=ready && samplePrepared() && !stopRequested_;
    if(maySend && !sendSample_->isEnabled())sampleState_->setText(QStringLiteral("Локальный захват запущен"));
    sendSample_->setEnabled(maySend);
    const bool traffic=resultKind_->currentIndex()==0;
    filter_->setVisible(traffic);sort_->setVisible(traffic);direction_->setVisible(traffic);
    const bool showCurrent=!visible_.newestJobId.isEmpty() && visible_.newestJobId!=selectedId_;
    current_->setText(active && latest_ && visible_.newestJobId==latest_->id?QStringLiteral("К запущенному заданию"):QStringLiteral("Показать последний результат"));
    current_->setToolTip(QStringLiteral("Сейчас в истории открыто другое задание"));current_->setVisible(showCurrent);current_->setEnabled(showCurrent);
    const bool historyReady=!dirty_ && !pending_.valid();
    newer_->setVisible(jobOffset_>0);newer_->setEnabled(jobOffset_>0 && historyReady);
    older_->setVisible(visible_.hasOlderJobs);older_->setEnabled(visible_.hasOlderJobs && historyReady);
    previousPage_->setEnabled(historyReady && offset_>0);nextPage_->setEnabled(historyReady && offset_+200<total_);
    copy_->setEnabled(!copiedBasis_.isEmpty());
    const bool selected=table_->currentRow()>=0 && table_->selectionModel()->hasSelection();
    const bool hasDiagnostics=visible_.job.has_value() && visible_.error.isEmpty();
    detailsToggle_->setEnabled(selected);diagnosticsToggle_->setEnabled(hasDiagnostics);
    const bool showDetails=selected && detailsToggle_->isChecked();
    const bool showDiagnostics=hasDiagnostics && diagnosticsToggle_->isChecked();
    details_->setVisible(showDetails);diagnosticText_->setVisible(showDiagnostics);detailPane_->setVisible(showDetails || showDiagnostics);
}
void NetworkPanel::requestPage(bool resetOffset) {
    if(resetOffset)offset_=0;
    ++generation_;dirty_=true;
}
void NetworkPanel::loadPage() {
    if(pending_.valid() || !dirty_)return;
    const auto generation=generation_;
    const auto id=selectedId_,storage=storage_,term=search_->text();
    const auto jobOffset=jobOffset_,offset=offset_;
    const bool detections=resultKind_->currentIndex()==1;
    const NetworkQuery query{term,filter_->currentIndex()==1,direction_->currentIndex()==1,static_cast<NetworkSort>(sort_->currentIndex()),offset,200};
    const auto active=busy()?latest_:std::optional<NetworkJob>{};
    const auto noticeJob=latest_ && latest_->storedDetections>noticeShown_?latest_:std::optional<NetworkJob>{};
    dirty_=false;
    pending_=std::async(std::launch::async,[generation,id,storage,term,jobOffset,offset,detections,query,active,noticeJob]{
        Page page;page.generation=generation;page.id=id;page.detectionView=detections;
        try {
            if(storage.isEmpty() || !QFileInfo::exists(storage))return page;
            NetworkStore store(storage,true);
            if(noticeJob) {
                const auto alerts=store.detections(noticeJob->id,{},{},noticeJob->storedDetections-1,1);
                if(!alerts.rows.empty()) {
                    const auto &last=alerts.rows.front();page.noticeJobId=noticeJob->id;page.noticeCount=noticeJob->storedDetections;
                    page.noticeText=QStringLiteral("Новое обнаружение · %1\n%2").arg(last.ruleId,last.basis);
                }
            }
            page.jobs=store.jobs(jobOffset,51);
            page.hasOlderJobs=page.jobs.size()>50;
            if(page.hasOlderJobs)page.jobs.pop_back();
            if(jobOffset>0) {
                const auto newest=store.jobs(0,1);
                if(!newest.empty())page.newestJobId=newest.front().id;
            } else if(!page.jobs.empty())page.newestJobId=page.jobs.front().id;
            if(page.id.isEmpty() && !page.jobs.empty())page.id=page.jobs.front().id;
            if(page.id.isEmpty())return page;
            page.job=active && active->id==page.id?active:store.getJob(page.id);
            if(!page.job)return page;
            page.diagnostics=store.diagnostics(page.id);
            if(detections) {
                page.detections=store.detections(page.id,{},term,offset);
                for(const auto &d:page.detections.rows) {
                    const auto flow=store.flow(page.id,d.flowId);
                    if(!flow)throw Error(QStringLiteral("В истории отсутствует поток обнаружения"));
                    page.linkedFlows.push_back(*flow);
                }
            } else page.flows=store.flows(page.id,query);
        }catch(const Error &error){page.error=error.message;}
        return page;
    });
}
void NetworkPanel::showPage(Page page) {
    if(latest_ && page.noticeJobId==latest_->id && page.noticeCount>noticeShown_) {
        noticeShown_=page.noticeCount;notice_->setText(page.noticeText);notice_->show();
    }
    const auto oldRow=table_->currentRow();
    const auto oldId=oldRow>=0 && table_->item(oldRow,0)?table_->item(oldRow,0)->data(Qt::UserRole).toString():QString();
    const auto sameSelection=visible_.id==page.id && visible_.detectionView==page.detectionView;
    visible_=std::move(page);
    if(!visible_.error.isEmpty()) {
        historyError_->setText(QStringLiteral("Ошибка сетевой истории: ")+visible_.error);historyError_->show();table_->setRowCount(0);return;
    }
    historyError_->hide();selectedId_=visible_.id;
    {
        QSignalBlocker block(jobs_);jobs_->clear();
        for(const auto &job:visible_.jobs)jobs_->addItem(QStringLiteral("%1 · %2 · %3").arg(job.started,job.source=="pcap"?QStringLiteral("PCAP"):QStringLiteral("Захват"),job.input),job.id);
        if(!selectedId_.isEmpty() && jobs_->findData(selectedId_)<0)jobs_->addItem(QStringLiteral("Выбранное задание"),selectedId_);
        jobs_->setCurrentIndex(jobs_->findData(selectedId_));
    }
    if(visible_.job) {
        const auto &job=*visible_.job;const auto &c=job.counters;
        QString text=networkStateText(job)+" · "+countersText(job);
        if(job.source=="live" && job.state!="running") {
            text+=job.dropsAvailable?QStringLiteral(" · Потери: %1, интерфейс: %2").arg(job.reportedDropped).arg(job.reportedInterfaceDropped)
                                    :QStringLiteral(" · Источник не сообщил потери");
        }
        const auto fullScope=networkScopeText(job);
        summary_->setText(text);
        summary_->setToolTip(fullScope);
        QString diagnostic=hasSpecificError(job)?job.error+"\n\n":QString();
        diagnostic+=fullScope+"\n\n"+QStringLiteral("Вне разбора: %1\nФрагменты: %2\nОбрезано: %3\nПовреждено: %4\nВытеснено потоков: %5\nВытеснено состояний правил: %6\nПакеты вне порядка: %7")
            .arg(c.unsupported).arg(c.fragments).arg(c.truncated).arg(c.malformed).arg(c.flowEvictions).arg(c.ruleEvictions).arg(c.reordered);
        for(const auto &d:visible_.diagnostics)diagnostic+="\n"+d.reason;
        diagnosticText_->setPlainText(diagnostic);
    } else {
        summary_->setText(QStringLiteral("Нет сохранённых сетевых заданий"));summary_->setToolTip({});diagnosticText_->clear();
    }
    const auto &v=visible_;const bool detections=v.detectionView;
    const int count=static_cast<int>(detections?v.detections.rows.size():v.flows.rows.size());
    total_=detections?v.detections.total:v.flows.total;
    {
        QSignalBlocker block(table_);table_->setRowCount(0);table_->setRowCount(count);
        const int columns=detections?4:3;
        if(table_->columnCount()!=columns || !table_->horizontalHeaderItem(0)) {
            table_->setColumnCount(columns);
            const auto common=QStringList{QStringLiteral("Соединение"),QStringLiteral("Время UTC")};
            table_->setHorizontalHeaderLabels(detections?common+QStringList{QStringLiteral("Обнаружение"),QStringLiteral("Основание")}:common+QStringList{QStringLiteral("Пакеты / байты")});
            table_->setColumnWidth(0,235);table_->setColumnWidth(1,166);
            if(detections)table_->setColumnWidth(2,210);
        }
        for(int row=0;row<count;++row) {
            if(detections) {
                const auto &d=v.detections.rows[row];putRow(table_,row,{flowText(v.linkedFlows[row]),packetTime(d.timestampUs),d.description,d.basis},d.id);
            } else {
                const auto &item=v.flows.rows[row];const auto &f=item.flow;
                putRow(table_,row,{flowText(f),packetTime(f.firstUs),QStringLiteral("%1 / %2").arg(f.packetsAToB+f.packetsBToA).arg(static_cast<quint64>(f.bytesAToB)+static_cast<quint64>(f.bytesBToA))},f.id);
            }
            if(sameSelection && table_->item(row,0)->data(Qt::UserRole).toString()==oldId)table_->setCurrentCell(row,0);
        }
    }
    pageLabel_->setText(QStringLiteral("Показано %1–%2 из %3").arg(count?offset_+1:0).arg(count?offset_+count:0).arg(total_));
    selectRow();
}
void NetworkPanel::selectRow() {
    selectedFlowId_.clear();copiedBasis_.clear();details_->hide();
    const int row=table_->currentRow();
    if(row<0 || !table_->selectionModel()->hasSelection()){updateControls();return;}
    if(visible_.detectionView && row<static_cast<int>(visible_.detections.rows.size())) {
        const auto &d=visible_.detections.rows[row];copiedBasis_=d.basis;
        details_->setPlainText(flowText(visible_.linkedFlows[row])+"\n"+packetTime(d.timestampUs)+"\n"+detectionText(d));
    } else if(!visible_.detectionView && row<static_cast<int>(visible_.flows.rows.size())) {
        const auto &item=visible_.flows.rows[row];const auto &f=item.flow;
        details_->setPlainText(QStringLiteral("%1\n%2 – %3 UTC\nA → B: %4 пакетов, %5 байт. B → A: %6 пакетов, %7 байт.").arg(flowText(f),packetTime(f.firstUs),packetTime(f.lastUs)).arg(f.packetsAToB).arg(f.bytesAToB).arg(f.packetsBToA).arg(f.bytesBToA));
        if(item.matches){selectedFlowId_=f.id;loadDetail();}
    }
    updateControls();
}
void NetworkPanel::loadDetail() {
    if(detail_.valid() || selectedFlowId_.isEmpty())return;
    const auto id=visible_.id,flow=selectedFlowId_,storage=storage_;
    detail_=std::async(std::launch::async,[id,flow,storage]{
        Detail detail;detail.jobId=id;detail.flowId=flow;
        try{NetworkStore store(storage,true);detail.detections=store.detections(id,flow);}catch(const Error &error){detail.error=error.message;}
        return detail;
    });
}
void NetworkPanel::tick() {
    using namespace std::chrono_literals;
    const bool active=busy();
    if(const auto job=session_.progress();job && (active || wasBusy_ || job->id==lastProgressId_)) {
        const bool fresh=!latest_ || latest_->id!=job->id;
        const bool changed=fresh || latest_->state!=job->state || latest_->counters.packets!=job->counters.packets || latest_->storedDetections!=job->storedDetections || latest_->storedFlows!=job->storedFlows;
        if(job->storedDetections>(fresh?0:latest_->storedDetections)) {
            notice_->setText(QStringLiteral("Новые обнаружения: %1").arg(job->storedDetections));notice_->show();
            emit detectionNotice(job->storedDetections);dirty_=true;
        }
        const bool ready=!active || job->updated!=job->started;
        if(ready && (fresh || latest_->updated==latest_->started))dirty_=true;
        latest_=job;lastProgressId_=job->id;
        if(active || wasBusy_ || changed)
            setStateText(stopRequested_ && active?QStringLiteral("Остановка запрошена…"):networkStateText(*job)+" · "+countersText(*job)+(hasSpecificError(*job)?"\n"+job->error:QString()),job->id);
        if(ready && selectedId_.isEmpty() && QFileInfo::exists(storage_)){selectedId_=job->id;requestPage();}
        else if(ready && selectedId_==job->id && changed)dirty_=true;
    }
    if(wasBusy_!=active) {
        wasBusy_=active;dirty_=true;
        if(!active && !sampleJobId_.isEmpty()) {
            resetSample(sampleFailed_?QString():QStringLiteral("Порты освобождены"));
            sampleJobId_.clear();
        }
        emit activeChanged();
    }
    if(pending_.valid() && pending_.wait_for(0ms)==std::future_status::ready) {
        auto page=pending_.get();if(page.generation==generation_)showPage(std::move(page));
    }
    if(detail_.valid() && detail_.wait_for(0ms)==std::future_status::ready) {
        const auto detail=detail_.get();
        if(detail.jobId==visible_.id && detail.flowId==selectedFlowId_) {
            if(!detail.error.isEmpty())details_->appendPlainText(detail.error);
            else {
                QStringList bases;for(const auto &d:detail.detections.rows){bases<<d.basis;details_->appendPlainText("\n"+detectionText(d));}
                copiedBasis_=bases.join('\n');
            }
        } else loadDetail();
    }
    loadPage();updateControls();
}
}
