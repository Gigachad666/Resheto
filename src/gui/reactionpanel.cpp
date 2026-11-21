#include "reactionpanel.h"
#include <QFileDialog>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QShowEvent>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace resheto {
namespace {
constexpr int pageSize=50;

QString reactionStateText(const QString &state) {
    if(state=="preparing")return QStringLiteral("Подготовка");
    if(state=="stored")return QStringLiteral("В карантине");
    if(state=="restoring")return QStringLiteral("Восстановление");
    if(state=="restored")return QStringLiteral("Восстановлен");
    if(state=="deleting")return QStringLiteral("Удаление");
    if(state=="deleted")return QStringLiteral("Удалён");
    if(state=="failed")return QStringLiteral("Ошибка");
    if(state=="interrupted")return QStringLiteral("Прервано");
    if(state=="ok" || state=="completed")return QStringLiteral("Выполнено");
    if(state=="cancelled")return QStringLiteral("Отменено");
    if(state=="running")return QStringLiteral("Выполняется");
    if(state=="refused")return QStringLiteral("Отклонено");
    if(state=="pending")return QStringLiteral("Ожидается подтверждение ОС");
    if(state=="requested")return QStringLiteral("Запрошено");
    return state;
}

QString eventText(const QString &action) {
    if(action=="job_started")return QStringLiteral("Начало проверки");
    if(action=="job_finished")return QStringLiteral("Окончание проверки");
    if(action=="detection")return QStringLiteral("Обнаружение");
    if(action=="file_error")return QStringLiteral("Ошибка проверки");
    if(action=="skipped")return QStringLiteral("Пропуск");
    if(action=="quarantine")return QStringLiteral("Помещение в карантин");
    if(action=="restore")return QStringLiteral("Восстановление");
    if(action=="delete")return QStringLiteral("Удаление");
    if(action=="terminate_process")return QStringLiteral("Завершение процесса");
    if(action=="service_started")return QStringLiteral("Запуск службы");
    if(action=="diagnostic")return QStringLiteral("Ошибка компонента");
    if(action=="recovery")return QStringLiteral("Прерванная операция");
    return action;
}

QString sourceText(const QString &source) {
    if(source=="manual")return QStringLiteral("Ручная проверка");
    if(source=="monitor" || source=="files" || source=="file_monitor")return QStringLiteral("Файловое наблюдение");
    if(source=="processes" || source=="process_monitor" || source=="behavioral")return QStringLiteral("Процессы");
    if(source=="network")return QStringLiteral("Сеть");
    if(source=="signature")return QStringLiteral("Сигнатуры");
    if(source=="heuristic")return QStringLiteral("Эвристика");
    if(source=="service")return QStringLiteral("Служба");
    return source;
}
}

ReactionPanel::ReactionPanel(QString endpoint,View view,QWidget *parent)
    :QWidget(parent),endpoint_(std::move(endpoint)),view_(view) {
    auto *layout=new QVBoxLayout(this);
    auto *toolbar=new QHBoxLayout;
    refresh_=new QPushButton(QStringLiteral("Обновить"));
    toolbar->addWidget(refresh_);
    if(view==View::Notifications) {
        primary_=new QPushButton(QStringLiteral("К результату"));
        primary_->setObjectName("notificationOpenResult");
        secondary_=new QPushButton(QStringLiteral("Отметить просмотренным"));
        connect(primary_,&QPushButton::clicked,this,[this]{
            const auto row=selection();
            if(!row.isEmpty())emit openResult(row);
        });
        connect(secondary_,&QPushButton::clicked,this,[this]{
            const auto id=selection()["id"].toString();
            if(!id.isEmpty())perform([id](const service::Client &client){return client.acknowledgeNotification(id);},true);
        });
    } else if(view==View::Quarantine) {
        primary_=new QPushButton(QStringLiteral("Восстановить"));
        primary_->setObjectName("restoreQuarantine");
        secondary_=new QPushButton(QStringLiteral("Восстановить как…"));
        remove_=new QPushButton(QStringLiteral("Удалить"));
        connect(primary_,&QPushButton::clicked,this,[this]{restore(false);});
        connect(secondary_,&QPushButton::clicked,this,[this]{restore(true);});
        connect(remove_,&QPushButton::clicked,this,&ReactionPanel::removeSelected);
    } else {
        search_=new QLineEdit;
        search_->setPlaceholderText(QStringLiteral("Поиск по журналу"));
        connect(search_,&QLineEdit::returnPressed,this,[this]{offset_=0;reload();});
        toolbar->addWidget(search_,1);
    }
    for(auto *button:{primary_,secondary_,remove_})if(button)toolbar->addWidget(button);
    toolbar->addStretch();
    layout->addLayout(toolbar);

    table_=new QTableWidget;
    table_->setObjectName("reactionEntries");
    const auto headers=view==View::Notifications
        ? QStringList{QStringLiteral("Время UTC"),QStringLiteral("Состояние"),QStringLiteral("Источник"),QStringLiteral("Объект"),QStringLiteral("Обнаружение"),QStringLiteral("Основание")}
        : view==View::Quarantine
        ? QStringList{QStringLiteral("Время UTC"),QStringLiteral("Исходный путь"),QStringLiteral("Состояние"),QStringLiteral("Размер"),QStringLiteral("SHA-256"),QStringLiteral("Подробности")}
        : QStringList{QStringLiteral("Время UTC"),QStringLiteral("Источник"),QStringLiteral("Событие"),QStringLiteral("Объект"),QStringLiteral("Результат"),QStringLiteral("Причина")};
    table_->setColumnCount(static_cast<int>(headers.size()));
    table_->setHorizontalHeaderLabels(headers);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    connect(table_,&QTableWidget::itemSelectionChanged,this,&ReactionPanel::updateButtons);
    layout->addWidget(table_);

    message_=new QLabel;
    message_->setTextFormat(Qt::PlainText);
    message_->setWordWrap(true);
    message_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    message_->hide();
    layout->addWidget(message_);
    auto *navigation=new QHBoxLayout;
    page_=new QLabel;
    previous_=new QPushButton(QStringLiteral("Назад"));
    next_=new QPushButton(QStringLiteral("Далее"));
    navigation->addWidget(page_);
    navigation->addStretch();
    navigation->addWidget(previous_);
    navigation->addWidget(next_);
    layout->addLayout(navigation);
    connect(refresh_,&QPushButton::clicked,this,[this]{offset_=0;reload();});
    connect(previous_,&QPushButton::clicked,this,[this]{offset_=qMax<qint64>(0,offset_-pageSize);reload();});
    connect(next_,&QPushButton::clicked,this,[this]{offset_+=pageSize;reload();});
    auto *timer=new QTimer(this);
    connect(timer,&QTimer::timeout,this,&ReactionPanel::finish);
    timer->start(100);
    updateButtons();
}

void ReactionPanel::showEvent(QShowEvent *event) {
    QWidget::showEvent(event);
    reload();
}

void ReactionPanel::setConnected(bool connected) {
    if(connected_==connected)return;
    connected_=connected;
    updateButtons();
    if(connected_ && isVisible())reload();
}

void ReactionPanel::notificationsChanged() {
    if(isVisible())reload();
}

QJsonObject ReactionPanel::selection() const {
    const int row=table_->currentRow();
    return row>=0 && row<rows_.size()?rows_.at(row).toObject():QJsonObject{};
}

void ReactionPanel::updateButtons() {
    const bool ready=connected_ && !task_.valid();
    const auto row=selection();
    const bool selected=ready && !row.isEmpty();
    const bool restorable=selected && (row["state"]=="stored" || row["state"]=="interrupted");
    refresh_->setEnabled(ready);
    previous_->setEnabled(ready && offset_>=pageSize);
    next_->setEnabled(ready && offset_+pageSize<total_);
    if(primary_)primary_->setEnabled(view_==View::Notifications?selected:restorable);
    if(secondary_)secondary_->setEnabled(view_==View::Notifications?selected && !row["acknowledged"].toBool():restorable);
    if(remove_)remove_->setEnabled(selected && (row["state"]=="stored" || row["state"]=="restored"));
}

void ReactionPanel::perform(std::function<QJsonObject(const service::Client &)> request,bool operation) {
    if(!connected_ || task_.valid())return;
    operation_=operation;
    if(operation_) {
        message_->setText(QStringLiteral("Служба выполняет операцию…"));
        message_->show();
    }
    task_=std::async(std::launch::async,[endpoint=endpoint_,request=std::move(request)]{
        try {return Reply{request(service::Client(endpoint)),{}};}
        catch(const Error &error) {return Reply{{},error.message};}
        catch(const std::exception &error) {return Reply{{},QString::fromUtf8(error.what())};}
    });
    updateButtons();
}

void ReactionPanel::reload() {
    if(task_.valid()) {
        refreshPending_=true;
        return;
    }
    const auto text=search_?search_->text():QString();
    perform([view=view_,offset=offset_,text](const service::Client &client){
        if(view==View::Notifications)return client.notifications(offset,pageSize);
        if(view==View::Quarantine)return client.quarantineItems(offset,pageSize);
        return client.journal(offset,pageSize,text);
    },false);
}

void ReactionPanel::showPage(const QJsonObject &page) {
    rows_=page["rows"].toArray();
    total_=page["total"].toString().toLongLong();
    if(rows_.isEmpty() && offset_>0) {
        offset_=0;
        refreshPending_=true;
        return;
    }
    table_->setRowCount(0);
    table_->setRowCount(static_cast<int>(rows_.size()));
    for(int i=0;i<rows_.size();++i) {
        const auto row=rows_.at(i).toObject();
        QStringList values;
        if(view_==View::Notifications) {
            values={row["time"].toString(),row["acknowledged"].toBool()?QStringLiteral("Просмотрено"):QStringLiteral("Новое"),
                    sourceText(row["view"].toString()),row["path"].toString(),row["name"].toString(),row["basis"].toString()};
        } else if(view_==View::Quarantine) {
            QString details=row["detection_name"].toString()+"\n"+row["basis"].toString()+"\n"+row["reason"].toString();
            if(!row["target_path"].toString().isEmpty())details.append("\n"+row["target_path"].toString());
            values={row["created"].toString(),row["original_path"].toString(),reactionStateText(row["state"].toString()),
                    row["size"].toString(),row["sha256"].toString(),details.trimmed()};
        } else {
            values={row["time"].toString(),sourceText(row["source"].toString()),eventText(row["action"].toString()),row["object"].toString(),
                    reactionStateText(row["outcome"].toString()),row["reason"].toString()};
        }
        for(int c=0;c<values.size();++c) {
            auto *item=new QTableWidgetItem(values.at(c));
            item->setToolTip(values.at(c));
            table_->setItem(i,c,item);
        }
    }
    page_->setText(rows_.isEmpty()?QStringLiteral("Записей нет"):QStringLiteral("%1–%2 из %3").arg(offset_+1).arg(offset_+rows_.size()).arg(total_));
}

void ReactionPanel::finish() {
    using namespace std::chrono_literals;
    if(!task_.valid() || task_.wait_for(0ms)!=std::future_status::ready)return;
    const auto reply=task_.get();
    if(!reply.error.isEmpty()) {
        message_->setText(reply.error);
        message_->show();
    } else if(operation_) {
        const auto state=reply.data["state"].toString();
        message_->setText(state.isEmpty()?QStringLiteral("Уведомление отмечено"):reactionStateText(state));
        const auto reason=reply.data["reason"].toString();
        if(!reason.isEmpty())message_->setText(message_->text()+". "+reason);
        message_->show();
    } else {
        showPage(reply.data);
    }
    const bool needsRefresh=refreshPending_ || operation_;
    refreshPending_=false;
    operation_=false;
    updateButtons();
    if(needsRefresh)reload();
}

bool ReactionPanel::isolate(Result result) {
    if(!connected_ || task_.valid())return false;
    if(QMessageBox::question(this,QStringLiteral("Поместить в карантин"),
        QStringLiteral("Поместить файл в карантин и убрать его из исходного каталога?\n%1").arg(result.path),
        QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return false;
    if(!connected_ || task_.valid())return false;
    const auto key=service::resultKey(result);
    perform([job=result.jobId,key](const service::Client &client){return client.quarantine(job,key);},true);
    return true;
}

void ReactionPanel::restore(bool choosePath) {
    const auto row=selection();
    if(row["state"]!="stored" && row["state"]!="interrupted")return;
    const auto id=row["id"].toString(),original=row["original_path"].toString();
    QString target;
    if(choosePath) {
        target=QFileDialog::getSaveFileName(this,QStringLiteral("Куда восстановить файл"),original,{},nullptr,QFileDialog::DontConfirmOverwrite);
        if(target.isEmpty())return;
    }
    if(QMessageBox::question(this,QStringLiteral("Восстановить файл"),
        QStringLiteral("Восстановить файл в %1?").arg(target.isEmpty()?original:target),
        QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    perform([id,target](const service::Client &client){return client.restoreQuarantine(id,target);},true);
}

void ReactionPanel::removeSelected() {
    const auto row=selection();
    if(row["state"]!="stored" && row["state"]!="restored")return;
    if(QMessageBox::question(this,QStringLiteral("Удалить из карантина"),
        QStringLiteral("Удалить сохранённый файл без возможности восстановления?\n%1").arg(row["original_path"].toString()),
        QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
    const auto id=row["id"].toString();
    perform([id](const service::Client &client){return client.deleteQuarantine(id);},true);
}
}
