#include "mainwindow.h"
#ifdef RESHETO_WITH_NETWORK
#include "networkpanel.h"
#endif
#include "core/signatures.h"
#include "core/heuristic.h"
#include <QCheckBox>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDialog>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QSplitter>
#include <QTableWidget>
#include <QTimer>
#include <QToolButton>
#include <QUuid>
#include <QVBoxLayout>
#include <QTabWidget>
#include <QPlainTextEdit>
#include <QJsonArray>
#include <QJsonDocument>
#include <QSignalBlocker>

namespace resheto {
namespace {
QString shortSummary(const Job &j) {
    return QStringLiteral("%1; проверено %2; совпадений %3; ошибок %4").arg(stateText(j.state)).arg(j.checked).arg(j.matches).arg(j.errors);
}
QString shownDetectionName(const Result &result) {
    if(result.outcome=="heuristic_match") {
        for(const auto &value:result.details["matched"].toArray()) {
            const auto rule=value.toObject();
            if(rule["id"]==result.ruleId && rule["version"]==result.ruleVersion) {
                const auto description=rule["description"].toString();
                if(!description.isEmpty())return description;
            }
        }
    }
    return detectionName(result);
}
}
MainWindow::MainWindow(const Request &defaults,const QString &behaviorPath,const QString &processScope,const QString &watchPath,[[maybe_unused]] const QString &networkRulesPath) {
    manualHooks_=defaults.hooks;
    setWindowTitle(QStringLiteral("АС Решето")); resize(1100,760);
    auto *central=new QWidget(this); setCentralWidget(central); auto *layout=new QVBoxLayout(central);
    layout->setSpacing(4);
    auto *top=new QHBoxLayout;layout->addLayout(top);
    settingsToggle_=new QToolButton;settingsToggle_->setObjectName("fileSettingsToggle");
    settingsToggle_->setText(QStringLiteral("Параметры проверки и наблюдения"));settingsToggle_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    settingsToggle_->setCheckable(true);settingsToggle_->setArrowType(Qt::RightArrow);top->addWidget(settingsToggle_);
    auto *settingsDialog=new QDialog(this,Qt::Tool);settingsDialog->setObjectName("fileSettingsDialog");
    settingsDialog->setWindowTitle(QStringLiteral("Параметры проверки и наблюдения"));settingsDialog->resize(650,330);
    auto *dialogLayout=new QVBoxLayout(settingsDialog);
    auto *settingsScroll=new QScrollArea;settingsScroll->setObjectName("fileSettings");settingsScroll->setWidgetResizable(true);
    settingsScroll->setFrameShape(QFrame::NoFrame);dialogLayout->addWidget(settingsScroll,1);
    auto *settingsBody=new QWidget;auto *settingsLayout=new QVBoxLayout(settingsBody);settingsLayout->setContentsMargins(0,0,0,0);settingsScroll->setWidget(settingsBody);
    auto *settings=new QGridLayout;settingsLayout->addLayout(settings);
    auto *closeSettings=new QPushButton(QStringLiteral("Закрыть"));dialogLayout->addWidget(closeSettings,0,Qt::AlignRight);
    connect(closeSettings,&QPushButton::clicked,settingsDialog,&QDialog::close);
    connect(settingsDialog,&QDialog::finished,this,[this]{settingsToggle_->setChecked(false);});
    connect(settingsToggle_,&QToolButton::toggled,this,[this,settingsDialog](bool expanded){
        settingsToggle_->setArrowType(expanded?Qt::DownArrow:Qt::RightArrow);
        settingsDialog->setVisible(expanded);
    });
    db_=new QLineEdit(defaults.signaturePath.isEmpty()?QString():absolute(defaults.signaturePath)); db_->setObjectName("database");
    storage_=new QLineEdit(defaults.storagePath.isEmpty()?QString():absolute(defaults.storagePath)); storage_->setObjectName("storage"); historyPath_=storage_->text();
    auto *base=new QPushButton(QStringLiteral("Выбрать…")); auto *heuristicChoose=new QPushButton(QStringLiteral("Выбрать…")); auto *behaviorChoose=new QPushButton(QStringLiteral("Выбрать…"));
    settings->addWidget(new QLabel(QStringLiteral("Сигнатуры")),0,0); settings->addWidget(db_,0,1); settings->addWidget(base,0,2);
    heuristicEnabled_=new QCheckBox(QStringLiteral("Статическая эвристика")); heuristicEnabled_->setObjectName("heuristicEnabled"); heuristicEnabled_->setChecked(!defaults.heuristicPath.isEmpty());
    heuristics_=new QLineEdit(defaults.heuristicPath); heuristics_->setObjectName("heuristics"); settings->addWidget(heuristicEnabled_,1,0); settings->addWidget(heuristics_,1,1); settings->addWidget(heuristicChoose,1,2);
    behavior_=new QLineEdit(behaviorPath); behavior_->setObjectName("behavior"); settings->addWidget(new QLabel(QStringLiteral("Правила поведения")),2,0); settings->addWidget(behavior_,2,1); settings->addWidget(behaviorChoose,2,2);
    top->addWidget(new QLabel(QStringLiteral("Файл истории")));top->addWidget(storage_,1);
    databaseState_=new QLabel; databaseState_->setObjectName("databaseState"); databaseState_->setWordWrap(true); settingsLayout->addWidget(databaseState_);
    auto *manual=new QHBoxLayout; layout->addLayout(manual);
    path_=new QLineEdit(defaults.path.isEmpty()?QString():absolute(defaults.path)); path_->setObjectName("path"); path_->setAccessibleName(QStringLiteral("Путь ручной проверки"));
    auto *file=new QPushButton(QStringLiteral("Файл…")); auto *folder=new QPushButton(QStringLiteral("Каталог…"));
    recursive_=new QCheckBox(QStringLiteral("Подкаталоги")); recursive_->setChecked(defaults.recursive);
    start_=new QPushButton(QStringLiteral("Проверить")); start_->setObjectName("start"); start_->setEnabled(false); stop_=new QPushButton(QStringLiteral("Отменить проверку")); stop_->setObjectName("stop"); stop_->setEnabled(false);
    manual->addWidget(new QLabel(QStringLiteral("Вручную"))); manual->addWidget(path_,1); manual->addWidget(file); manual->addWidget(folder); manual->addWidget(recursive_); manual->addWidget(start_); manual->addWidget(stop_);
    manualState_=new QLabel(QStringLiteral("Ручная проверка не запущена")); manualState_->setObjectName("manualState"); manualState_->setWordWrap(true); layout->addWidget(manualState_);
    progress_=new QProgressBar; progress_->setTextVisible(false); progress_->setRange(0,1); progress_->setValue(0); progress_->setMaximumHeight(6); layout->addWidget(progress_);
    auto *watchSettings=new QGridLayout; settingsLayout->addLayout(watchSettings);
    fileEnabled_=new QCheckBox(QStringLiteral("Наблюдать файлы")); fileEnabled_->setObjectName("fileEnabled"); fileEnabled_->setChecked(true);
    watchPath_=new QLineEdit(watchPath.isEmpty()?defaults.path:watchPath); watchPath_->setObjectName("watchPath"); watchPath_->setPlaceholderText(QStringLiteral("Каталог файлового наблюдения"));
    auto *watchChoose=new QPushButton(QStringLiteral("Каталог…")); watchSettings->addWidget(fileEnabled_,0,0); watchSettings->addWidget(watchPath_,0,1); watchSettings->addWidget(watchChoose,0,2);
    watchRecursive_=new QCheckBox(QStringLiteral("Подкаталоги")); watchRecursive_->setChecked(true); watchRecursive_->setObjectName("watchRecursive"); watchSettings->addWidget(watchRecursive_,0,3);
    processEnabled_=new QCheckBox(QStringLiteral("Наблюдать процессы")); processEnabled_->setObjectName("processEnabled"); processEnabled_->setChecked(!behaviorPath.isEmpty());
    processScope_=new QLineEdit(processScope.isEmpty()?watchPath_->text():processScope); processScope_->setObjectName("processScope"); processScope_->setPlaceholderText(QStringLiteral("Каталог программ для наблюдения"));
    auto *scopeChoose=new QPushButton(QStringLiteral("Каталог…")); watchSettings->addWidget(processEnabled_,1,0); watchSettings->addWidget(processScope_,1,1); watchSettings->addWidget(scopeChoose,1,2);
    processImages_=new QCheckBox(QStringLiteral("Проверять файлы процессов: сигнатуры и включённая эвристика")); processImages_->setObjectName("processImages"); processImages_->setToolTip(QStringLiteral("Проверяет файл по пути образа; связь сохраняется с PID и временем старта. Память процесса не читается.")); watchSettings->addWidget(processImages_,2,0,1,4);
    watch_=new QPushButton(QStringLiteral("Начать наблюдение")); watch_->setObjectName("watch"); watch_->setEnabled(false); watchStop_=new QPushButton(QStringLiteral("Остановить наблюдение")); watchStop_->setObjectName("watchStop"); watchStop_->setEnabled(false);
    auto *watchActions=new QHBoxLayout;layout->addLayout(watchActions);
    monitorState_=new QLabel(QStringLiteral("Наблюдение не запущено")); monitorState_->setObjectName("monitorState"); monitorState_->setWordWrap(true);
    watchActions->addWidget(monitorState_,1);watchActions->addWidget(watch_);watchActions->addWidget(watchStop_);
    historyErrorLabel_=new QLabel; historyErrorLabel_->setObjectName("historyError"); historyErrorLabel_->setWordWrap(true); historyErrorLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse); historyErrorLabel_->hide(); layout->addWidget(historyErrorLabel_);
    notification_=new QLabel; notification_->setObjectName("notification"); notification_->setTextFormat(Qt::PlainText); notification_->setWordWrap(true); notification_->setTextInteractionFlags(Qt::TextSelectableByMouse); notification_->hide(); layout->addWidget(notification_);
    fileHistory_=new QWidget;fileHistory_->setObjectName("fileHistoryControls");layout->addWidget(fileHistory_);
    auto *history=new QHBoxLayout(fileHistory_);history->setContentsMargins(0,0,0,0);history->addWidget(new QLabel(QStringLiteral("Результаты задания")));
    jobs_=new QComboBox; jobs_->setObjectName("jobs"); jobs_->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon); jobs_->setMinimumContentsLength(30); history->addWidget(jobs_,1);
    jobs_->setAccessibleName(QStringLiteral("Файловые и процессные задания"));
    earlier_=new QPushButton(QStringLiteral("Более ранние задания")); earlier_->setObjectName("earlierJobs"); earlier_->hide(); history->addWidget(earlier_);
    newer_=new QPushButton(QStringLiteral("К новым заданиям")); newer_->setObjectName("newerJobs"); newer_->hide(); history->addWidget(newer_);
    currentManual_=new QPushButton(QStringLiteral("Показать проверку")); currentManual_->setObjectName("currentManual"); history->addWidget(currentManual_); currentMonitor_=new QPushButton(QStringLiteral("Показать наблюдение")); currentMonitor_->setObjectName("currentMonitor"); history->addWidget(currentMonitor_);
    summary_=new QLabel(QStringLiteral("Готово к выбору области проверки")); summary_->setObjectName("summary"); summary_->setWordWrap(true); summary_->setTextInteractionFlags(Qt::TextSelectableByMouse); layout->addWidget(summary_);
    auto *resultsArea=new QSplitter(Qt::Horizontal);resultsArea->setChildrenCollapsible(false);layout->addWidget(resultsArea,1);
    tabs_=new QTabWidget; tabs_->setObjectName("resultTabs"); resultsArea->addWidget(tabs_);
    for(int i=0;i<3;++i) {
        auto *page=new QWidget; auto *body=new QVBoxLayout(page); ResultView v;
        if(i==2) {
            body->addWidget(new QLabel(QStringLiteral("Текущие процессы наблюдения")));
            processState_=new QLabel(QStringLiteral("Наблюдение за процессами не запущено")); processState_->setWordWrap(true); body->addWidget(processState_);
            processTable_=new QTableWidget(0,4); processTable_->setObjectName("processes"); processTable_->setHorizontalHeaderLabels({"PID","PPID",QStringLiteral("ID запуска ОС"),QStringLiteral("Файл программы")}); processTable_->setEditTriggers(QAbstractItemView::NoEditTriggers); processTable_->horizontalHeader()->setStretchLastSection(true); processTable_->setMaximumHeight(160); body->addWidget(processTable_); body->addWidget(new QLabel(QStringLiteral("Результаты выбранного задания: файлы процессов и сценарии")));
        }
        auto *filters=new QHBoxLayout; body->addLayout(filters);
        v.filter=new QComboBox; v.filter->addItems({QStringLiteral("Все"),QStringLiteral("Совпадения"),QStringLiteral("Не проверены / неполные")});
        v.search=new QLineEdit; v.search->setPlaceholderText(i==2?QStringLiteral("В результатах: PID, путь, основание или правило"):QStringLiteral("Путь, основание, правило или причина"));
        if(i==2) { processSearch_=v.search; v.search->setPlaceholderText(QStringLiteral("PID, путь, основание или правило")); }
        v.sort=new QComboBox; v.sort->addItems({QStringLiteral("Порядок записи"),QStringLiteral("По пути"),QStringLiteral("По итогу"),QStringLiteral("По обнаружению")}); v.direction=new QComboBox; v.direction->addItems({QStringLiteral("По возрастанию"),QStringLiteral("По убыванию")});
        filters->addWidget(v.filter); filters->addWidget(v.search,1); filters->addWidget(v.sort); filters->addWidget(v.direction);
        v.table=new QTableWidget(0,3); v.table->setHorizontalHeaderLabels({i==2?QStringLiteral("PID / файл"):QStringLiteral("Объект / путь"),QStringLiteral("Итог"),QStringLiteral("Обнаружение")}); v.table->setEditTriggers(QAbstractItemView::NoEditTriggers); v.table->setSelectionBehavior(QAbstractItemView::SelectRows); v.table->setWordWrap(false); v.table->horizontalHeader()->setStretchLastSection(true); v.table->setColumnWidth(0,480); v.table->setColumnWidth(1,260); body->addWidget(v.table);
        const auto suffix=i==0?QString():QString::number(i); v.table->setObjectName(i==0?QStringLiteral("results"):i==1?QStringLiteral("fileResults"):QStringLiteral("processResults")); v.filter->setObjectName("filter"+suffix); v.search->setObjectName("search"+suffix); v.sort->setObjectName("sort"+suffix); v.direction->setObjectName("direction"+suffix);
        v.object=i==0?ResultObject::Manual:i==1?ResultObject::Files:ResultObject::Processes; resultViews_.push_back(v);
        auto changed=[this,i]{if(activeView_==i) { resetPage(); needRead_=true; }}; connect(v.filter,&QComboBox::currentIndexChanged,this,changed); connect(v.sort,&QComboBox::currentIndexChanged,this,changed); connect(v.direction,&QComboBox::currentIndexChanged,this,changed);
        auto *debounce=new QTimer(this); debounce->setSingleShot(true); debounce->setInterval(250); connect(v.search,&QLineEdit::textChanged,debounce,qOverload<>(&QTimer::start)); connect(debounce,&QTimer::timeout,this,changed); connect(v.table,&QTableWidget::itemSelectionChanged,this,[this,i]{if(activeView_==i) showDetails();});
        tabs_->addTab(page,i==0?QStringLiteral("Ручная проверка"):i==1?QStringLiteral("Файловое наблюдение"):QStringLiteral("Процессы"));
    }
#ifdef RESHETO_WITH_NETWORK
    networkPanel_=new NetworkPanel(storage_->text(),networkRulesPath);
    const int networkIndex=tabs_->addTab(networkPanel_,QStringLiteral("Сеть"));
    connect(networkPanel_,&NetworkPanel::activeChanged,this,[this]{setInputsEnabled(true);});
    connect(networkPanel_,&NetworkPanel::detectionNotice,this,[this,networkIndex](qint64 count){tabs_->setTabText(networkIndex,count && tabs_->currentIndex()!=networkIndex?QStringLiteral("Сеть · %1").arg(count):QStringLiteral("Сеть"));});
#endif
    table_=resultViews_[0].table; filter_=resultViews_[0].filter; search_=resultViews_[0].search; sort_=resultViews_[0].sort; direction_=resultViews_[0].direction;
    details_=new QPlainTextEdit;details_->setObjectName("details");details_->setReadOnly(true);details_->setMinimumWidth(180);details_->setMaximumWidth(330);
    resultsArea->addWidget(details_);resultsArea->setStretchFactor(0,1);details_->hide();
    filePages_=new QWidget;filePages_->setObjectName("filePageControls");layout->addWidget(filePages_);
    auto *pages=new QHBoxLayout(filePages_);pages->setContentsMargins(0,0,0,0);pageState_=new QLabel; pages->addWidget(pageState_); pages->addStretch();
    first_=new QPushButton(QStringLiteral("С начала")); next_=new QPushButton(QStringLiteral("Следующие 200")); next_->setObjectName("next"); pages->addWidget(first_); pages->addWidget(next_);
    auto *copyPath=new QPushButton(QStringLiteral("Копировать путь")); copyPath->setObjectName("copyPath"); pages->addWidget(copyPath); auto *copyBasis=new QPushButton(QStringLiteral("Копировать основание")); copyBasis->setObjectName("copyBasis"); pages->addWidget(copyBasis);
    detailsToggle_=new QToolButton;detailsToggle_->setObjectName("fileDetailsToggle");detailsToggle_->setText(QStringLiteral("Подробности"));detailsToggle_->setCheckable(true);detailsToggle_->setChecked(true);detailsToggle_->setEnabled(false);pages->addWidget(detailsToggle_);
    connect(detailsToggle_,&QToolButton::toggled,this,[this]{showDetails();});
    connect(copyPath,&QPushButton::clicked,this,[this]{const int row=table_->currentRow(); if(row>=0 && row<static_cast<int>(visibleRows_.size())) QApplication::clipboard()->setText(visibleRows_[row].path);});
    connect(copyBasis,&QPushButton::clicked,this,[this]{const int row=table_->currentRow(); if(row>=0 && row<static_cast<int>(visibleRows_.size())) { const auto &r=visibleRows_[row]; QString context; if(row<static_cast<int>(visibleEvents_.size()) && visibleEvents_[row]["type"]=="process_image") context=QString::fromUtf8(QJsonDocument(visibleEvents_[row]["details"].toObject()).toJson(QJsonDocument::Indented))+"\n"; QApplication::clipboard()->setText(context+r.basis+(r.details.isEmpty()?QString():"\n"+QString::fromUtf8(QJsonDocument(r.details).toJson(QJsonDocument::Indented)))); }});
    inputs_={db_,storage_,base,heuristicEnabled_,heuristics_,heuristicChoose,behavior_,behaviorChoose}; manualInputs_={path_,recursive_,file,folder}; monitorInputs_={watchPath_,watchChoose,watchRecursive_,fileEnabled_,processEnabled_,processScope_,scopeChoose,processImages_};
    connect(file,&QPushButton::clicked,this,[this]{auto p=QFileDialog::getOpenFileName(this,QStringLiteral("Выберите файл")); if(!p.isEmpty()) path_->setText(p);}); connect(folder,&QPushButton::clicked,this,[this]{auto p=QFileDialog::getExistingDirectory(this,QStringLiteral("Выберите каталог")); if(!p.isEmpty()) path_->setText(p);});
    connect(watchChoose,&QPushButton::clicked,this,[this,settingsDialog]{auto p=QFileDialog::getExistingDirectory(settingsDialog,QStringLiteral("Каталог файлового наблюдения")); if(!p.isEmpty()) watchPath_->setText(p);}); connect(scopeChoose,&QPushButton::clicked,this,[this,settingsDialog]{auto p=QFileDialog::getExistingDirectory(settingsDialog,QStringLiteral("Каталог образов процессов")); if(!p.isEmpty()) processScope_->setText(p);});
    connect(base,&QPushButton::clicked,this,[this,settingsDialog]{auto p=QFileDialog::getOpenFileName(settingsDialog,QStringLiteral("База сигнатур / указатель версии"),{},"SQLite / версии (*.db *.json);;Все файлы (*)"); if(!p.isEmpty()) db_->setText(p);});
    connect(heuristicChoose,&QPushButton::clicked,this,[this,settingsDialog]{auto p=QFileDialog::getOpenFileName(settingsDialog,QStringLiteral("Эвристические правила"),{},"JSON (*.json)"); if(!p.isEmpty()) { heuristics_->setText(p); heuristicEnabled_->setChecked(true); }}); connect(behaviorChoose,&QPushButton::clicked,this,[this,settingsDialog]{auto p=QFileDialog::getOpenFileName(settingsDialog,QStringLiteral("Поведенческие правила"),{},"JSON (*.json)"); if(!p.isEmpty()) behavior_->setText(p);});
    connect(db_,&QLineEdit::textChanged,this,[this]{databaseReady_=false; start_->setEnabled(false); databaseState_->setText(QStringLiteral("Проверка базы…")); probe();}); auto changedHeuristics=[this]{heuristicReady_=false; start_->setEnabled(false); probe();}; connect(heuristicEnabled_,&QCheckBox::toggled,this,changedHeuristics); connect(heuristics_,&QLineEdit::textChanged,this,changedHeuristics);
    connect(start_,&QPushButton::clicked,this,[this]{start();}); connect(stop_,&QPushButton::clicked,this,[this]{controller_.cancel(); stop_->setEnabled(false); manualState_->setText(QStringLiteral("Отмена ручной проверки запрошена…"));}); connect(watch_,&QPushButton::clicked,this,[this]{startMonitor();}); connect(watchStop_,&QPushButton::clicked,this,[this]{monitor_.cancel(); watchStop_->setEnabled(false);});
    connect(storage_,&QLineEdit::editingFinished,this,[this]{loadHistory();}); connect(first_,&QPushButton::clicked,this,[this]{resetPage(); readPage();}); connect(next_,&QPushButton::clicked,this,[this]{resetPage(false); readPage();}); connect(tabs_,&QTabWidget::currentChanged,this,[this](int index){selectView(index);}); connect(processSearch_,&QLineEdit::textChanged,this,[this]{showProcesses();});
    connect(jobs_,&QComboBox::currentIndexChanged,this,[this](int index){if(index>=0) selectJob(jobs_->itemData(index).toString());}); connect(earlier_,&QPushButton::clicked,this,[this]{earlier_->setEnabled(false); jobOffset_+=50; jobsDirty_=true; needRead_=true;});
    connect(newer_,&QPushButton::clicked,this,[this]{newer_->setEnabled(false); jobOffset_=0; jobsDirty_=true; needRead_=true;});
    connect(currentManual_,&QPushButton::clicked,this,[this]{tabs_->setCurrentIndex(0); selectJob(manualJobId_);}); connect(currentMonitor_,&QPushButton::clicked,this,[this]{if(activeView_==0) tabs_->setCurrentIndex(fileEnabled_->isChecked()?1:2); selectJob(monitorJobId_);});
    auto *timer=new QTimer(this); timer->setInterval(150); connect(timer,&QTimer::timeout,this,[this]{tick();}); timer->start(); probe();
}
MainWindow::~MainWindow() {
    controller_.cancel();monitor_.cancel();
#ifdef RESHETO_WITH_NETWORK
    networkPanel_->cancel();
#endif
}
void MainWindow::probe() {
    if(probe_.valid() || running_ || monitorActive_) return;
    probePath_=db_->text(); probeHeuristicPath_=heuristicEnabled_->isChecked()?heuristics_->text():QString(); const auto path=probePath_,heuristic=probeHeuristicPath_;
    probe_=std::async(std::launch::async,[path,heuristic] {
        DatabaseProbe result; if(path.isEmpty()) result.message=QStringLiteral("База не выбрана");
        else try { const auto s=loadSignatures(path); result.signatures=true; result.message=QStringLiteral("Сигнатуры: %1; HASH %2, PATTERN %3").arg(s->version).arg(s->hashCount).arg(s->patternCount); } catch(const Error &e) { result.message=QStringLiteral("Ошибка базы: ")+e.message; }
        if(!heuristic.isEmpty()) try { const auto rules=loadHeuristicRules(heuristic); result.heuristics=true; result.message+=QStringLiteral("; эвристика %1, правил %2").arg(rules->version).arg(rules->entries.size()); } catch(const Error &e) { result.message+=QStringLiteral("\nОшибка эвристики: ")+e.message; } return result;
    });
}
void MainWindow::setInputsEnabled(bool) {
    for(auto *w:inputs_) w->setEnabled(!running_ && !monitorActive_); for(auto *w:manualInputs_) w->setEnabled(!running_); for(auto *w:monitorInputs_) w->setEnabled(!monitorActive_); processImages_->setEnabled(!monitorActive_ && processEnabled_->isChecked());
#ifdef RESHETO_WITH_NETWORK
    if(networkPanel_->busy())storage_->setEnabled(false);
#endif
}
void MainWindow::showProcesses() {
    const auto processes=monitor_.processes(); const auto search=processSearch_->text(); qint64 matching=0; processTable_->setRowCount(0);
    bool numeric=false; const auto wantedPid=search.toULongLong(&numeric);
    if(!monitor_.status().active) { processState_->setText(QStringLiteral("Наблюдение остановлено; результаты сохранены")); return; }
    for(const auto &p:processes) {
        if(!search.isEmpty() && (numeric?p.pid!=wantedPid:!p.image.contains(search,Qt::CaseInsensitive))) continue;
        ++matching; if(processTable_->rowCount()>=200) continue; const int row=processTable_->rowCount(); processTable_->insertRow(row); const QStringList values{QString::number(p.pid),QString::number(p.parentPid),p.startTime,p.image}; for(int c=0;c<4;++c) { auto *item=new QTableWidgetItem(values[c]); item->setToolTip(values[c]); processTable_->setItem(row,c,item); }
    }
    processState_->setText(QStringLiteral("В выбранной области: %1; по поиску: %2; показано: %3").arg(processes.size()).arg(matching).arg(processTable_->rowCount())); processState_->setToolTip(monitor_.status().coverage);
}
void MainWindow::showDetails() {
    if(tabs_->currentIndex()!=activeView_)return;
    const int row=table_->currentRow();const bool selected=row>=0 && row<static_cast<int>(visibleRows_.size());detailsToggle_->setEnabled(selected);
    if(!selected) { details_->hide(); return; } const auto &r=visibleRows_[row]; QString text=outcomeText(r)+"\n";
    if(row<static_cast<int>(visibleEvents_.size()) && !visibleEvents_[row].isEmpty()) {
        const auto event=visibleEvents_[row],e=event["details"].toObject(),p=e["process"].toObject(); const auto operation=e["operation"].toString();
        if(event["type"]=="process_image") text+=QStringLiteral("Проверка файла процесса: PID %1; ID запуска %2\nФайл: %3\n").arg(p["pid"].toString(),p["start_time"].toString(),p["image"].toString());
        else text+=QStringLiteral("Событие: %1; %2\n").arg(operation=="created"?QStringLiteral("создание файла"):operation=="modified"?QStringLiteral("изменение файла"):operation=="child_start"?QStringLiteral("наблюдение дочернего процесса"):operation,e["time"].toString());
    }
    if(r.source=="behavioral") { const auto p=r.details["process"].toObject(); text+=QStringLiteral("Процесс: PID %1; ID запуска %2\n").arg(p["pid"].toString(),p["start_time"].toString()); }
    if(isDetection(r)) {
        text+=QStringLiteral("Обнаружение: %1\nОснование: %2\n").arg(shownDetectionName(r),r.basis);
        if(r.outcome=="heuristic_match") {
            text+=QStringLiteral("Сработавшие правила:\n");
            for(const auto &value:r.details["matched"].toArray()) {
                const auto rule=value.toObject();
                text+=QStringLiteral("• %1 [%2, версия %3]\n").arg(rule["description"].toString(),rule["id"].toString(),rule["version"].toString());
            }
        } else {
            text+=QStringLiteral("Правило: %1, версия %2\n").arg(r.source=="signature"?r.signatureId:r.ruleId,r.source=="signature"?r.signatureVersion:r.ruleVersion);
        }
    }
    text+=QStringLiteral("Полнота: %1; версия базы/набора: %2\n").arg(r.completeness=="full"?QStringLiteral("завершён"):r.completeness=="partial"?QStringLiteral("неполная"):QStringLiteral("не проверен"),r.source=="signature"?r.databaseVersion:r.rulesVersion);
    if(!r.reason.isEmpty()) text+=QStringLiteral("Ошибка / ограничение: %1 [%2]\n").arg(r.reason,r.code);
    if(!r.details.isEmpty()) text+=QStringLiteral("\nТехнические основания:\n")+QString::fromUtf8(QJsonDocument(r.details).toJson(QJsonDocument::Indented));
    details_->setPlainText(text);details_->setVisible(detailsToggle_->isChecked());
}
void MainWindow::selectView(int index) {
    const bool files=index>=0 && index<static_cast<int>(resultViews_.size());
    fileHistory_->setVisible(files);filePages_->setVisible(files);summary_->setVisible(files);
    if(!files) {
        details_->hide();
#ifdef RESHETO_WITH_NETWORK
        if(index==tabs_->indexOf(networkPanel_)){networkPanel_->setStorage(storage_->text());tabs_->setTabText(index,QStringLiteral("Сеть"));}
#endif
        return;
    }
    activeView_=index; auto &v=resultViews_[index]; table_=v.table; filter_=v.filter; search_=v.search; sort_=v.sort; direction_=v.direction; resetPage(); needRead_=true;
}
void MainWindow::selectJob(const QString &id) {
    if(id.isEmpty()) return;
    { QSignalBlocker block(jobs_); int index=jobs_->findData(id);
      if(index<0) { jobs_->addItem(QStringLiteral("Выбрано: ")+id,id); index=jobs_->count()-1; }
      jobs_->setCurrentIndex(index); }
    jobId_=id; knownResults_=-1; wantLatest_=false; selectionRead_=true; resetPage(); needRead_=true;
}
void MainWindow::resetPage(bool resetCursor) { ++generation_; if(resetCursor) { cursor_=0; upperRow_=0; } table_->setRowCount(0); visibleRows_.clear(); visibleEvents_.clear(); pageState_->clear(); details_->hide();detailsToggle_->setEnabled(false); }
void MainWindow::loadHistory() {
#ifdef RESHETO_WITH_NETWORK
    if(networkPanel_->busy())return;
    networkPanel_->setStorage(storage_->text());
#endif
    if(running_ || monitorActive_ || historyPath_==storage_->text()) return;
    historyPath_=storage_->text(); jobId_.clear(); manualJobId_.clear(); monitorJobId_.clear(); stoppedByHistoryError_=false; notifiedMatches_=0; notification_->clear(); notification_->hide();
    historyError_.clear(); historyErrorLabel_->clear(); historyErrorLabel_->hide(); resetPage(); total_=0; wantLatest_=true; selectionRead_=true; needRead_=false; jobsDirty_=true; jobOffset_=0; hasEarlierJobs_=false; { QSignalBlocker block(jobs_); jobs_->clear(); } summary_->setText(QStringLiteral("Чтение истории…"));
}
void MainWindow::start() {
    if(controller_.busy() || (!databaseReady_ && !heuristicReady_) || probe_.valid()) return;
    Request r; r.id=QUuid::createUuid().toString(QUuid::WithoutBraces); r.path=path_->text(); r.signaturePath=db_->text(); r.storagePath=storage_->text(); r.recursive=recursive_->isChecked(); r.hooks=manualHooks_; if(heuristicEnabled_->isChecked()) r.heuristicPath=heuristics_->text();
    if(r.path.trimmed().isEmpty() || r.storagePath.trimmed().isEmpty()) { summary_->setText(QStringLiteral("Укажите путь и хранилище")); return; }
    if(!QFileInfo::exists(r.path)) { summary_->setText(QStringLiteral("Объект проверки не найден: %1. Выберите существующий файл/каталог.").arg(absolute(r.path))); return; }
    try { r.storagePath=Store::preparePath(r.storagePath); storage_->setText(r.storagePath); historyPath_=r.storagePath; } catch(const Error &e) { summary_->setText(e.message); return; }
    if(!controller_.submit(r)) { summary_->setText(QStringLiteral("Очередь задания занята")); return; }
    historyError_.clear(); historyErrorLabel_->clear(); historyErrorLabel_->hide(); stoppedByHistoryError_=false; running_=true; manualJobId_=r.id; manualNotified_=0; tabs_->setCurrentIndex(0); selectJob(r.id); needRead_=false; jobsDirty_=true; jobOffset_=0;
    progress_->setRange(0,0); manualState_->setText(QStringLiteral("Начинаем ручную проверку…")); summary_->setText(QStringLiteral("Начинаем проверку; общий объём пока неизвестен")); setInputsEnabled(false); start_->setEnabled(false); stop_->setEnabled(true);
}
void MainWindow::startMonitor() {
    if(monitorActive_ || probe_.valid()) return;
    if(fileEnabled_->isChecked() && !QFileInfo(watchPath_->text()).isDir()) { summary_->setText(QStringLiteral("Для файлового наблюдения выберите существующий каталог")); return; }
    if(processEnabled_->isChecked() && !QFileInfo(processScope_->text()).isDir()) { summary_->setText(QStringLiteral("Выберите существующий каталог образов процессов")); return; }
    MonitorRequest r; r.id=QUuid::createUuid().toString(QUuid::WithoutBraces); r.directory=watchPath_->text(); r.files=fileEnabled_->isChecked(); r.signaturePath=db_->text(); r.storagePath=storage_->text(); r.recursive=watchRecursive_->isChecked(); if(heuristicEnabled_->isChecked()) r.heuristicPath=heuristics_->text();
    r.processes=processEnabled_->isChecked(); r.scanProcessImages=r.processes && processImages_->isChecked(); r.behaviorPath=behavior_->text(); r.processImageDirectory=processScope_->text();
    try { r.storagePath=Store::preparePath(r.storagePath); if(!monitor_.start(r)) return; storage_->setText(r.storagePath); historyPath_=r.storagePath; } catch(const Error &e) { summary_->setText(e.message); return; }
    historyError_.clear(); historyErrorLabel_->clear(); historyErrorLabel_->hide(); stoppedByHistoryError_=false; monitorActive_=true; monitorJobId_=r.id; monitorNotified_=0; tabs_->setCurrentIndex(r.files?1:2); selectJob(r.id); needRead_=false; jobsDirty_=true; jobOffset_=0; setInputsEnabled(false); watch_->setEnabled(false); watchStop_->setEnabled(true); monitorState_->setText(QStringLiteral("Запускаем наблюдение…"));
}
void MainWindow::notify(const Job &j,qint64 &known,const QString &source) { if(j.matches>known) { known=j.matches; notification_->setText(QStringLiteral("%1: %2 — %3").arg(source,j.detectionPath,j.detectionName)); notification_->show(); } }
void MainWindow::showSummary(const Job &j) {
    const auto state=stoppedByHistoryError_?QStringLiteral("Остановка запрошена из-за ошибки чтения истории; %1").arg(stateText(j.state)):stateText(j.state);
    summary_->setText(QStringLiteral("%1. Проверено: %2; совпадений: %3; ошибок: %4; пропусков: %5. %6\nЗадание: %7").arg(state).arg(j.checked).arg(j.matches).arg(j.errors).arg(j.skipped).arg(j.error,j.id));
}
void MainWindow::readPage() {
    if(view_.valid()) return;
    const auto storage=storage_->text(),id=jobId_; const auto after=cursor_; const bool latest=wantLatest_,readJob=selectionRead_,readJobs=jobsDirty_; const auto jobOffset=jobOffset_;
    const bool live=(running_ && (id==manualJobId_ || id==controller_.progress().id)) || (monitorActive_ && id==monitorJobId_); const bool listOnly=table_->rowCount()>=200; const int limit=qMax(1,200-table_->rowCount()); if(listOnly && !readJobs) return;
    ResultQuery query; query.offset=after; query.limit=limit; query.upperRow=upperRow_; query.filter=static_cast<ResultFilter>(filter_->currentIndex()); query.sort=static_cast<ResultSort>(sort_->currentIndex()); query.text=search_->text(); query.object=resultViews_[activeView_].object; query.descending=direction_->currentIndex()==1; const auto generation=generation_;
    wantLatest_=false; selectionRead_=false; jobsDirty_=false; needRead_=false;
    view_=std::async(std::launch::async,[storage,id,after,latest,readJob,readJobs,live,jobOffset,query,generation,listOnly] {
        ViewPage page; page.jobId=id; page.cursor=after; page.generation=generation; page.listOnly=listOnly; page.listed=readJobs;
        try {
            if(!QFileInfo::exists(storage) && (latest || id.isEmpty())) return page;
            Store store(storage,true);
            if(readJobs) {
                page.jobs=store.jobs(jobOffset,51);
                page.hasEarlierJobs=page.jobs.size()>50;
                if(page.hasEarlierJobs)page.jobs.pop_back();
            }
            if(latest) { page.job=store.latest(); if(page.job) page.jobId=page.job->id; }
            else if(readJob && !id.isEmpty()) { page.job=store.getJob(id,!live); if(!page.job) throw Error(QStringLiteral("Задание отсутствует в истории: ")+id); }
            if(!page.jobId.isEmpty() && !listOnly) { auto result=store.query(page.jobId,query); page.rows=std::move(result.rows); page.cursor=after+static_cast<qint64>(page.rows.size()); page.total=result.total; page.upperRow=result.upperRow;
                for(const auto &r:page.rows) { const auto e=store.observation(page.jobId,r.eventId); if(!r.eventId.isEmpty() && !e) throw Error(QStringLiteral("Отсутствует связанное событие результата: ")+r.eventId); page.rowEvents.push_back(e.value_or(QJsonObject())); }
            }
        } catch(const Error &e) { page.error=e.message; } return page;
    });
}
void MainWindow::tick() {
    using namespace std::chrono_literals;
    if(probe_.valid() && probe_.wait_for(0ms)==std::future_status::ready) {
        const auto status=probe_.get();
        if(probePath_==db_->text() && probeHeuristicPath_==(heuristicEnabled_->isChecked()?heuristics_->text():QString())) {
            databaseReady_=status.signatures;heuristicReady_=status.heuristics;databaseState_->setText(status.message);
            const bool error=(!probePath_.isEmpty() && !databaseReady_) || (!probeHeuristicPath_.isEmpty() && !heuristicReady_);
            settingsToggle_->setText(error?QStringLiteral("Параметры · ошибка загрузки"):QStringLiteral("Параметры проверки и наблюдения"));
            settingsToggle_->setToolTip(status.message);
        } else probe();
    }
    if(view_.valid() && view_.wait_for(0ms)==std::future_status::ready) {
        auto page=view_.get();
        if(page.generation!=generation_) { needRead_=true; selectionRead_=true; jobsDirty_=true; if(jobId_.isEmpty()) wantLatest_=true; }
        else if(!page.error.isEmpty()) { if(historyError_.isEmpty()) historyError_=QStringLiteral("Ошибка чтения хранилища: ")+page.error; historyErrorLabel_->setText(historyError_); historyErrorLabel_->show(); if(running_ || monitorActive_) { stoppedByHistoryError_=true; controller_.cancel(); monitor_.cancel(); stop_->setEnabled(false); watchStop_->setEnabled(false); } }
        else {
            if(page.listed) { QSignalBlocker block(jobs_); jobs_->clear(); for(const auto &j:page.jobs) { const auto label=QStringLiteral("%1 · %2 · %3 · %4").arg(j.started,j.source=="monitor"?QStringLiteral("Наблюдение"):QStringLiteral("Вручную"),stateText(j.state),j.path); jobs_->addItem(label,j.id); } if(!page.jobId.isEmpty() && jobs_->findData(page.jobId)<0) jobs_->addItem(QStringLiteral("Выбрано: ")+page.jobId,page.jobId); jobs_->setCurrentIndex(jobs_->findData(page.jobId)); hasEarlierJobs_=page.hasEarlierJobs; }
            if(page.job) { jobId_=page.jobId; showSummary(*page.job); knownResults_=page.job->results; if(page.job->source=="monitor" && tabs_->currentIndex()==0 && page.rows.empty()) { tabs_->setCurrentIndex(1); needRead_=true; } }
            else if(page.jobId.isEmpty()) summary_->setText(QStringLiteral("Нет сохранённых заданий"));
            if(!page.listOnly && page.jobId==jobId_ && page.generation==generation_) {
                cursor_=page.cursor; total_=page.total; upperRow_=page.upperRow; size_t eventIndex=0;
                for(const auto &r:page.rows) { const int row=table_->rowCount(); table_->insertRow(row); visibleRows_.push_back(r); visibleEvents_.push_back(eventIndex<page.rowEvents.size()?page.rowEvents[eventIndex]:QJsonObject()); ++eventIndex;
                    const auto process=r.source=="behavioral"?r.details["process"].toObject():visibleEvents_.back()["details"].toObject()["process"].toObject();
                    const auto object=activeView_==2 && !process["pid"].toString().isEmpty()?QStringLiteral("PID %1 — %2").arg(process["pid"].toString(),r.path):r.path;
                    const QStringList values{object,outcomeText(r),shownDetectionName(r)}; for(int c=0;c<3;++c) { auto *item=new QTableWidgetItem(values[c]); item->setToolTip(c==0?r.path:c==2?r.basis:values[c]); table_->setItem(row,c,item); } }
                const int rows=table_->rowCount();
                pageState_->setText(QStringLiteral("Показано %1–%2 из %3").arg(rows?cursor_-rows+1:0).arg(rows?cursor_:0).arg(total_));
            }
        }
    }
    if(running_) {
        const auto j=controller_.progress(); if(!j.id.isEmpty() && (manualJobId_.isEmpty() || j.id==manualJobId_)) { manualState_->setText(QStringLiteral("Ручная проверка: ")+shortSummary(j)+(stoppedByHistoryError_?QStringLiteral("; остановка из-за ошибки чтения истории"):QString())); notify(j,manualNotified_,QStringLiteral("Ручная проверка")); if(j.id==jobId_) { showSummary(j); if(j.results!=knownResults_) { knownResults_=j.results; resetPage(); needRead_=true; } } }
        if(!controller_.busy()) { running_=false; progress_->setRange(0,1); progress_->setValue(1); stop_->setEnabled(false); jobsDirty_=true; if(j.id==jobId_) { resetPage(); needRead_=true; selectionRead_=true; } }
    }
    if(monitorActive_) {
        const auto s=monitor_.status(); monitorState_->setText(QStringLiteral("Наблюдение: %1. %2\nСобытия файлов: %3; процессов: %4; результатов проверки файлов процессов: %5; очередь: %6; потерь: %7%8").arg(monitorStateText(s.state),s.coverage.section(';',0,2)).arg(s.fileEvents).arg(s.processEvents).arg(s.processImages).arg(s.queued).arg(s.lost).arg(s.reason.isEmpty()?QString():"\n"+s.reason)); monitorState_->setToolTip(s.coverage);
        if(!s.job.id.isEmpty()) { notify(s.job,monitorNotified_,QStringLiteral("Наблюдение")); if(s.job.id==jobId_) { showSummary(s.job); if(s.job.results!=knownResults_) { knownResults_=s.job.results; resetPage(); needRead_=true; } } }
        if(++processTick_%6==0) showProcesses(); if(!s.active) { monitorActive_=false; watchStop_->setEnabled(false); jobsDirty_=true; if(s.job.id==jobId_) { resetPage(); needRead_=true; selectionRead_=true; } showProcesses(); }
    }
    const bool selectedPending=(running_ && jobId_==manualJobId_ && controller_.progress().id!=manualJobId_) || (monitorActive_ && jobId_==monitorJobId_ && monitor_.status().job.id.isEmpty());
    if(!view_.valid() && !selectedPending && (wantLatest_ || (historyError_.isEmpty() && (jobsDirty_ || (needRead_ && table_->rowCount()<200))))) readPage();
    setInputsEnabled(true); start_->setEnabled(!running_ && !probe_.valid() && (monitorActive_ || !view_.valid()) && (databaseReady_ || heuristicReady_)); watch_->setEnabled(!monitorActive_ && !probe_.valid() && (running_ || !view_.valid()) && (fileEnabled_->isChecked() || processEnabled_->isChecked()) && (databaseReady_ || heuristicReady_ || (processEnabled_->isChecked() && !behavior_->text().isEmpty())));
    next_->setEnabled(!view_.valid() && !jobId_.isEmpty() && cursor_<total_); first_->setEnabled(!view_.valid() && !jobId_.isEmpty()); currentManual_->setEnabled(!manualJobId_.isEmpty()); currentMonitor_->setEnabled(!monitorJobId_.isEmpty());
    earlier_->setVisible(hasEarlierJobs_);earlier_->setEnabled(hasEarlierJobs_ && !jobsDirty_ && !view_.valid());
    newer_->setVisible(jobOffset_>0);newer_->setEnabled(jobOffset_>0 && !jobsDirty_ && !view_.valid());
}
}
