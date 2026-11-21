#pragma once

#include "service/client.h"
#include <QJsonArray>
#include <QWidget>
#include <functional>
#include <future>

class QLabel;
class QLineEdit;
class QTableWidget;
class QPushButton;

namespace resheto {

class ReactionPanel : public QWidget {
    Q_OBJECT
public:
    enum class View { Notifications, Quarantine, Journal };
    ReactionPanel(QString endpoint,View view,QWidget *parent=nullptr);
    void setConnected(bool connected);
    bool isolate(Result result);
    void notificationsChanged();

signals:
    void openResult(const QJsonObject &notification);

protected:
    void showEvent(QShowEvent *event) override;

private:
    struct Reply {
        QJsonObject data;
        QString error;
    };
    const QString endpoint_;
    const View view_;
    QLabel *message_,*page_;
    QTableWidget *table_;
    QLineEdit *search_=nullptr;
    QPushButton *refresh_,*previous_,*next_,*primary_=nullptr,*secondary_=nullptr,*remove_=nullptr;
    QJsonArray rows_;
    std::future<Reply> task_;
    qint64 offset_=0,total_=0;
    bool connected_=false, operation_=false, refreshPending_=false;
    QJsonObject selection() const;
    void reload();
    void finish();
    void updateButtons();
    void showPage(const QJsonObject &page);
    void perform(std::function<QJsonObject(const service::Client &)> request,bool operation);
    void restore(bool choosePath);
    void removeSelected();
};

}
