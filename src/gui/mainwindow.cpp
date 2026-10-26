#include "mainwindow.h"
#include "core/database.h"
#include "core/signatures.h"
#include <QCheckBox>
#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCloseEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QGridLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>

namespace resheto {
MainWindow::MainWindow(const Request &defaults) {
    setWindowTitle(QStringLiteral("АС Решето — сигнатурное сканирование")); resize(1100,680);
    auto *central=new QWidget(this); setCentralWidget(central); auto *layout=new QVBoxLayout(central);
    auto *title=new QLabel(QStringLiteral("АС Решето")); title->setStyleSheet("font-size:24px; font-weight:600"); layout->addWidget(title);
    layout->addWidget(new QLabel(QStringLiteral("Ручная проверка файлов по локальным сигнатурам")));
    auto *grid=new QGridLayout; layout->addLayout(grid);
    path_=new QLineEdit(defaults.path.isEmpty()?QString():absolute(defaults.path)); path_->setObjectName("path"); path_->setAccessibleName(QStringLiteral("Путь проверки"));
    path_->setPlaceholderText(QStringLiteral("Файл или каталог, который нужно проверить"));
    db_=new QLineEdit(defaults.signaturePath.isEmpty()?QString():absolute(defaults.signaturePath)); db_->setObjectName("database"); db_->setAccessibleName(QStringLiteral("База сигнатур"));
    db_->setPlaceholderText(QStringLiteral("Одна база правил: current.json либо signatures.db"));
    storage_=new QLineEdit(defaults.storagePath.isEmpty()?QString():absolute(defaults.storagePath)); storage_->setObjectName("storage"); storage_->setAccessibleName(QStringLiteral("Хранилище результатов"));
    storage_->setToolTip(QStringLiteral("Здесь сохраняются результаты, а не сигнатуры. Новый файл и его каталог будут созданы при запуске проверки."));
    auto *file=new QPushButton(QStringLiteral("Файл…")); auto *folder=new QPushButton(QStringLiteral("Каталог…")); auto *base=new QPushButton(QStringLiteral("Выбрать…"));
    grid->addWidget(new QLabel(QStringLiteral("Объект")),0,0); grid->addWidget(path_,0,1); grid->addWidget(file,0,2); grid->addWidget(folder,0,3);
    grid->addWidget(new QLabel(QStringLiteral("Сигнатуры")),1,0); grid->addWidget(db_,1,1,1,2); grid->addWidget(base,1,3);
    grid->addWidget(new QLabel(QStringLiteral("История проверок")),2,0); grid->addWidget(storage_,2,1,1,3);
    auto *hint=new QLabel(QStringLiteral("Сигнатуры — правила поиска; история — ваши результаты. Для задания выбирается одна база сигнатур."));
    hint->setWordWrap(true); grid->addWidget(hint,3,0,1,4);
    databaseState_=new QLabel(QStringLiteral("База не выбрана")); databaseState_->setObjectName("databaseState"); databaseState_->setWordWrap(true); layout->addWidget(databaseState_);
    auto *actions=new QHBoxLayout; layout->addLayout(actions);
    recursive_=new QCheckBox(QStringLiteral("Включая подкаталоги")); recursive_->setChecked(defaults.recursive); actions->addWidget(recursive_);
    actions->addStretch(); start_=new QPushButton(QStringLiteral("Начать")); stop_=new QPushButton(QStringLiteral("Остановить")); last_=new QPushButton(QStringLiteral("Последнее задание"));
    start_->setObjectName("start"); stop_->setObjectName("stop"); last_->setObjectName("last");
    actions->addWidget(start_); actions->addWidget(stop_); actions->addWidget(last_); start_->setEnabled(false); stop_->setEnabled(false);
    progress_=new QProgressBar; progress_->setTextVisible(false); progress_->setRange(0,1); progress_->setValue(0); layout->addWidget(progress_);
    summary_=new QLabel(QStringLiteral("Готово к выбору области проверки")); summary_->setObjectName("summary"); summary_->setWordWrap(true); summary_->setTextInteractionFlags(Qt::TextSelectableByMouse); layout->addWidget(summary_);
    historyErrorLabel_=new QLabel; historyErrorLabel_->setObjectName("historyError"); historyErrorLabel_->setWordWrap(true);
    historyErrorLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse); historyErrorLabel_->hide(); layout->addWidget(historyErrorLabel_);
    auto *filters=new QHBoxLayout; layout->addLayout(filters);
    filter_=new QComboBox; filter_->setObjectName("filter"); filter_->addItems({QStringLiteral("Все"),QStringLiteral("Совпадения"),QStringLiteral("Не проверены")});
    search_=new QLineEdit; search_->setObjectName("search"); search_->setPlaceholderText(QStringLiteral("Часть пути (с учётом регистра)"));
    sort_=new QComboBox; sort_->setObjectName("sort"); sort_->addItems({QStringLiteral("Порядок записи"),QStringLiteral("По пути"),QStringLiteral("По итогу"),QStringLiteral("По сигнатуре")});
    direction_=new QComboBox; direction_->setObjectName("direction"); direction_->addItems({QStringLiteral("По возрастанию"),QStringLiteral("По убыванию")});
    filters->addWidget(filter_); filters->addWidget(search_,1); filters->addWidget(sort_); filters->addWidget(direction_);
    table_=new QTableWidget(0,4); table_->setObjectName("results"); table_->setHorizontalHeaderLabels({QStringLiteral("Путь"),QStringLiteral("Итог"),QStringLiteral("Сигнатура / основание"),QStringLiteral("Причина / код")});
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers); table_->setSelectionBehavior(QAbstractItemView::SelectRows); table_->setWordWrap(false);
    table_->horizontalHeader()->setStretchLastSection(true); table_->setColumnWidth(0,330); table_->setColumnWidth(1,210); table_->setColumnWidth(2,260); layout->addWidget(table_,1);
    auto *pages=new QHBoxLayout; layout->addLayout(pages); pageState_=new QLabel; pages->addWidget(pageState_); pages->addStretch();
    first_=new QPushButton(QStringLiteral("С начала")); next_=new QPushButton(QStringLiteral("Следующие 200")); next_->setObjectName("next"); pages->addWidget(first_); pages->addWidget(next_);
    auto *copyPath=new QPushButton(QStringLiteral("Копировать путь")); copyPath->setObjectName("copyPath"); pages->addWidget(copyPath);
    auto *copyBasis=new QPushButton(QStringLiteral("Копировать основание")); copyBasis->setObjectName("copyBasis"); pages->addWidget(copyBasis);
    connect(copyPath,&QPushButton::clicked,this,[this]{const int row=table_->currentRow(); if(row>=0 && row<static_cast<int>(visibleRows_.size())) QApplication::clipboard()->setText(visibleRows_[row].path);});
    connect(copyBasis,&QPushButton::clicked,this,[this]{const int row=table_->currentRow(); if(row>=0 && row<static_cast<int>(visibleRows_.size())) QApplication::clipboard()->setText(visibleRows_[row].basis);});
    auto changed=[this]{resetPage(); needRead_=true;};
    connect(filter_,&QComboBox::currentIndexChanged,this,changed); connect(sort_,&QComboBox::currentIndexChanged,this,changed); connect(direction_,&QComboBox::currentIndexChanged,this,changed);
    auto *debounce=new QTimer(this); debounce->setSingleShot(true); debounce->setInterval(250);
    connect(search_,&QLineEdit::textChanged,debounce,qOverload<>(&QTimer::start)); connect(debounce,&QTimer::timeout,this,changed);
    layout->addWidget(new QLabel(QStringLiteral("Отсутствие совпадений не доказывает безопасность файла. Ссылки и специальные файлы пропускаются.")));
    inputs_={path_,db_,storage_,recursive_,file,folder,base};
    connect(file,&QPushButton::clicked,this,[this]{auto p=QFileDialog::getOpenFileName(this,QStringLiteral("Выберите файл")); if(!p.isEmpty()) path_->setText(p);});
    connect(folder,&QPushButton::clicked,this,[this]{auto p=QFileDialog::getExistingDirectory(this,QStringLiteral("Выберите каталог")); if(!p.isEmpty()) path_->setText(p);});
    connect(base,&QPushButton::clicked,this,[this]{auto p=QFileDialog::getOpenFileName(this,QStringLiteral("База сигнатур / указатель версии"),{},"SQLite / версии (*.db *.json);;Все файлы (*)"); if(!p.isEmpty()) db_->setText(p);});
    connect(db_,&QLineEdit::textChanged,this,[this]{databaseReady_=false; start_->setEnabled(false); databaseState_->setText(QStringLiteral("Проверка базы…")); probe();});
    connect(start_,&QPushButton::clicked,this,[this]{start();});
    connect(stop_,&QPushButton::clicked,this,[this]{controller_.cancel(); stop_->setEnabled(false); summary_->setText(QStringLiteral("Отмена запрошена; сохраняем завершённые результаты…"));});
    connect(last_,&QPushButton::clicked,this,[this]{jobId_.clear(); stoppedByHistoryError_=false; resetPage(); wantLatest_=true;});
    connect(first_,&QPushButton::clicked,this,[this]{resetPage(); readPage();});
    connect(next_,&QPushButton::clicked,this,[this]{resetPage(false); readPage();});
    auto *timer=new QTimer(this); timer->setInterval(150); connect(timer,&QTimer::timeout,this,[this]{tick();}); timer->start();
    probe();
}
MainWindow::~MainWindow() { controller_.cancel(); }
void MainWindow::probe() {
    if(probe_.valid() || running_) return;
    probePath_=db_->text(); const auto path=probePath_;
    if(path.isEmpty()) { databaseState_->setText(QStringLiteral("База не выбрана")); return; }
    probe_=std::async(std::launch::async,[path] {
        try { const auto s=loadSignatures(path);
            const auto purpose=s->purpose=="working"?QStringLiteral("Рабочая"):s->purpose=="test"?QStringLiteral("Тестовая"):s->purpose=="synthetic"?QStringLiteral("Синтетическая"):QStringLiteral("Пользовательская");
            return QStringLiteral("Готова: %1; %2; HASH %3, PATTERN %4.\nИсточник: %5\nБаза: %6. Контрольная сумма проверена.").arg(s->version,purpose).arg(s->hashCount).arg(s->patternCount).arg(s->source,s->path); }
        catch(const Error &e) { return QStringLiteral("Ошибка базы: ")+e.message; }
    });
}
void MainWindow::resetPage(bool resetCursor) {
    ++generation_;
    if(resetCursor) { cursor_=0; upperRow_=0; }
    table_->setRowCount(0); visibleRows_.clear(); pageState_->clear();
}
void MainWindow::start() {
    if(controller_.busy() || !databaseReady_ || view_.valid() || probe_.valid()) return;
    Request r; r.id=QUuid::createUuid().toString(QUuid::WithoutBraces); r.path=path_->text(); r.signaturePath=db_->text(); r.storagePath=storage_->text(); r.recursive=recursive_->isChecked();
    if(r.path.trimmed().isEmpty() || r.storagePath.trimmed().isEmpty()) { summary_->setText(QStringLiteral("Укажите путь и хранилище")); return; }
    if(!QFileInfo::exists(r.path)) {
        summary_->setText(QStringLiteral("Объект проверки не найден: %1. Выберите существующий файл/каталог. Если это контрольные данные, сначала выполните их подготовку.").arg(absolute(r.path))); return;
    }
    try { r.storagePath=Store::preparePath(r.storagePath); storage_->setText(r.storagePath); }
    catch(const Error &e) { summary_->setText(e.message); return; }
    if(!controller_.submit(r)) { summary_->setText(QStringLiteral("Очередь задания занята")); return; }
    historyError_.clear(); historyErrorLabel_->clear(); historyErrorLabel_->hide(); stoppedByHistoryError_=false;
    jobId_=r.id; resetPage(); knownResults_=-1; running_=true; wantLatest_=false; needRead_=false;
    progress_->setRange(0,0); summary_->setText(QStringLiteral("Начинаем проверку; общий объём пока неизвестен"));
    for(auto *w:inputs_) w->setEnabled(false);
    start_->setEnabled(false); stop_->setEnabled(true); last_->setEnabled(false);
}
void MainWindow::showSummary(const Job &j) {
    const auto state=stoppedByHistoryError_ ?
        (j.state=="running" ? QStringLiteral("Остановка из-за ошибки чтения истории") : QStringLiteral("Остановка запрошена из-за ошибки чтения истории; состояние задания: %1").arg(stateText(j.state))) : stateText(j.state);
    summary_->setText(QStringLiteral("%1. Проверено: %2; совпадений: %3; ошибок: %4; пропусков: %5. %6\nЗадание: %7; база: %8")
        .arg(state).arg(j.checked).arg(j.matches).arg(j.errors).arg(j.skipped).arg(j.error,j.id,j.databaseVersion)
        +(j.detectionPath.isEmpty()?QString():QStringLiteral("\nПоследнее совпадение: %1 — %2").arg(j.detectionPath,j.detectionName)));
}
void MainWindow::readPage() {
    if(view_.valid()) return;
    const auto storage=storage_->text(), id=jobId_; const auto after=cursor_; const bool latest=wantLatest_;
    const int limit=200-table_->rowCount(); if(limit<=0) return;
    ResultQuery query; query.offset=after; query.limit=limit; query.upperRow=upperRow_;
    query.filter=static_cast<ResultFilter>(filter_->currentIndex()); query.sort=static_cast<ResultSort>(sort_->currentIndex());
    query.path=search_->text(); query.descending=direction_->currentIndex()==1; const auto generation=generation_;
    wantLatest_=false; needRead_=false;
    view_=std::async(std::launch::async,[storage,id,after,latest,query,generation] {
        ViewPage page; page.jobId=id; page.cursor=after; page.generation=generation;
        try {
            if(latest && !QFileInfo::exists(storage)) return page;
            Store store(storage,true);
            if(latest) { page.job=store.latest(); if(page.job) page.jobId=page.job->id; }
            if(!page.jobId.isEmpty()) { auto result=store.query(page.jobId,query); page.rows=std::move(result.rows); page.cursor=after+static_cast<qint64>(page.rows.size()); page.total=result.total; page.upperRow=result.upperRow; }
        } catch(const Error &e) { page.error=e.message; }
        return page;
    });
}
void MainWindow::tick() {
    using namespace std::chrono_literals;
    if(probe_.valid() && probe_.wait_for(0ms)==std::future_status::ready) {
        const auto status=probe_.get();
        if(probePath_==db_->text()) { databaseReady_=status.startsWith(QStringLiteral("Готова:")); databaseState_->setText(status); }
        else probe();
    }
    if(view_.valid() && view_.wait_for(0ms)==std::future_status::ready) {
        auto page=view_.get();
        if(page.generation!=generation_) { needRead_=true; if(jobId_.isEmpty()) wantLatest_=true; }
        else if(!page.error.isEmpty()) {
            if(historyError_.isEmpty()) historyError_=QStringLiteral("Ошибка чтения хранилища: ")+page.error;
            historyErrorLabel_->setText(historyError_); historyErrorLabel_->show();
            if(running_) { stoppedByHistoryError_=true; controller_.cancel(); stop_->setEnabled(false); }
        }
        else {
            if(page.job) { jobId_=page.jobId; showSummary(*page.job); }
            if(page.jobId==jobId_) {
                cursor_=page.cursor;
                total_=page.total; upperRow_=page.upperRow;
                for(const auto &r:page.rows) {
                    if(table_->rowCount()>=200) { needRead_=true; break; }
                    const int row=table_->rowCount(); table_->insertRow(row);
                    visibleRows_.push_back(r);
                    const QStringList values={r.path,outcomeText(r),r.signatureName.isEmpty()?r.basis:r.signatureName+"; "+r.basis,r.reason+(r.code.isEmpty()?QString():" ["+r.code+"]")};
                    for(int c=0;c<4;++c) { auto *item=new QTableWidgetItem(values[c]); item->setToolTip(values[c]); table_->setItem(row,c,item); }
                }
                pageState_->setText(QStringLiteral("На странице: %1; по запросу: %2; показано до %3").arg(table_->rowCount()).arg(total_).arg(cursor_));
            }
        }
    }
    if(running_) {
        const auto j=controller_.progress();
        if(j.id==jobId_) {
            showSummary(j);
            if(j.results!=knownResults_) { knownResults_=j.results; resetPage(); needRead_=true; }
        }
        if(!controller_.busy()) {
            running_=false; progress_->setRange(0,1); progress_->setValue(1); stop_->setEnabled(false); last_->setEnabled(true);
            for(auto *w:inputs_) w->setEnabled(true);
            resetPage(); needRead_=true;
        }
    }
    if(!view_.valid() && (wantLatest_ || (historyError_.isEmpty() && needRead_ && table_->rowCount()<200))) readPage();
    start_->setEnabled(!running_ && !view_.valid() && !probe_.valid() && databaseReady_);
    next_->setEnabled(!running_ && !view_.valid() && !jobId_.isEmpty() && cursor_<total_);
    first_->setEnabled(!view_.valid() && !jobId_.isEmpty());
    last_->setEnabled(!running_ && !view_.valid());
}
}
