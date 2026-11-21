#include "server.h"
#include "client.h"
#include "diagnostics.h"
#include "notifications.h"
#include "protocol.h"
#include "monitor_protocol.h"
#include "quarantine.h"
#include "process_reaction.h"
#ifdef RESHETO_SERVICE_NETWORK
#include "network_service.h"
#endif
#include <core/controller.h>
#include <core/file_access.h>
#include <core/heuristic.h>
#include <core/signatures.h>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QLocalServer>
#include <QLocalSocket>
#include <QLockFile>
#include <QPointer>
#include <QSet>
#include <QTextStream>
#include <QTimer>
#include <QUuid>
#include <chrono>
#include <future>
#ifdef Q_OS_WIN
#include "windows_service.h"
#include <windows.h>
#elif defined(Q_OS_LINUX)
#include <QFile>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace resheto::service {
namespace {
constexpr int maxClients=8;
constexpr int connectionLifetimeMs=5000;

class InvalidRequest : public Error {
public:
    using Error::Error;
};

void check(bool valid,const QString &message) {
    if(!valid)throw InvalidRequest(message);
}

void fields(const QJsonObject &request,std::initializer_list<const char *> names) {
    check(request.size()==2+static_cast<qsizetype>(names.size()),QStringLiteral("Некорректные поля команды службы"));
    for(const auto name:names)check(request.contains(name),QStringLiteral("Отсутствует поле команды: ")+QString::fromLatin1(name));
}

QString text(const QJsonValue &value,qsizetype max) {
    const auto string=value.toString();
    check(value.isString() && !string.trimmed().isEmpty() && string.size()<=max && !string.contains(QChar(u'\0')),
          QStringLiteral("Некорректное строковое поле команды службы"));
    return string;
}

QString optionalText(const QJsonValue &value,qsizetype max) {
    check(value.isString() && value.toString().size()<=max && !value.toString().contains(QChar(u'\0')),
          QStringLiteral("Некорректное строковое поле команды службы"));
    return value.toString();
}

int pageSize(const QJsonValue &value) {
    const int size=value.toInt(-1);
    check(value.isDouble() && value.toDouble()==size && size>=1 && size<=protocol::pageLimit,
          QStringLiteral("Размер страницы должен быть от 1 до 200"));
    return size;
}

bool boolean(const QJsonValue &value) {
    check(value.isBool(),QStringLiteral("Ожидалось логическое поле команды службы"));
    return value.toBool();
}

QJsonValue jobValue(const std::optional<Job> &job) {
    return job?QJsonValue(job->json()):QJsonValue(QJsonValue::Null);
}

QJsonObject failure(const char *code,const QString &message) {
    return {{"version",protocol::version},{"ok",false},{"code",QString::fromLatin1(code)},{"message",message.left(8192)}};
}

bool sameFile(const QString &left,const QString &right) {
    std::error_code error;
    return left==right || std::filesystem::equivalent(nativePath(left),nativePath(right),error);
}

#ifdef Q_OS_WIN
bool isLocalPeer(const QLocalSocket &socket) {
    // Qt ограничивает доступ SID пользователя. NETWORK исключаем отдельно
    // после первого чтения из именованного канала.
    const auto pipe=reinterpret_cast<HANDLE>(socket.socketDescriptor());
    if(!ImpersonateNamedPipeClient(pipe))return false;
    HANDLE token=nullptr;
    const auto opened=OpenThreadToken(GetCurrentThread(),TOKEN_QUERY,TRUE,&token);
    if(!RevertToSelf())std::terminate();
    if(!opened)return false;
    const std::unique_ptr<void,decltype(&CloseHandle)> tokenHandle(token,CloseHandle);

    DWORD size=0;
    if(GetTokenInformation(token,TokenGroups,nullptr,0,&size) || GetLastError()!=ERROR_INSUFFICIENT_BUFFER || size>65536)
        return false;
    std::vector<unsigned char> buffer(size);
    if(!GetTokenInformation(token,TokenGroups,buffer.data(),size,&size))return false;
    const auto *groups=reinterpret_cast<const TOKEN_GROUPS *>(buffer.data());
    for(DWORD index=0;index<groups->GroupCount;++index)
        if(IsWellKnownSid(groups->Groups[index].Sid,WinNetworkSid))return false;
    return true;
}
#endif

Request prepare(Request defaults) {
    if(defaults.storagePath.trimmed().isEmpty())
        throw Error(QStringLiteral("Укажите файл истории через --storage или storage в настройках"));
    defaults.storagePath=absolute(defaults.storagePath);
    if(!defaults.signaturePath.isEmpty()) {
        defaults.signaturePath=absolute(defaults.signaturePath);
        std::shared_ptr<const Snapshot> snapshot;
        try {snapshot=loadSignatures(defaults.signaturePath);}
        catch(const Error &) {} // Причина появится в самодиагностике.
        if(sameFile(defaults.storagePath,defaults.signaturePath) || (snapshot && sameFile(defaults.storagePath,snapshot->path)))
            throw Error(QStringLiteral("База сигнатур и история должны быть разными файлами"));
    }
    if(!defaults.heuristicPath.isEmpty()) {
        defaults.heuristicPath=absolute(defaults.heuristicPath);
        if(sameFile(defaults.storagePath,defaults.heuristicPath))
            throw Error(QStringLiteral("Эвристические правила и история должны быть разными файлами"));
    }
    return defaults;
}

class Server {
    Request defaults_;
    // Задания закрывают SQLite до освобождения блокировки файла истории.
    std::unique_ptr<QLockFile> storageLock_;
    Controller controller_;
    MonitorRuntime monitor_;
    std::optional<MonitorOptions> monitorOptions_;
    std::optional<Job> submitted_;
    std::optional<Job> monitorSubmitted_;
    QSet<QLocalSocket *> clients_;
    QLocalServer socket_;
    QJsonObject diagnostics_;
    std::unique_ptr<Notifications> notifications_;
    QTimer reactionPoll_;
    std::future<QJsonObject> reaction_;
    QPointer<QLocalSocket> reactionClient_;
    QString historyFailure_;
    QString reportedJob_;
    QString reportedMonitor_;
#ifdef RESHETO_SERVICE_NETWORK
    std::unique_ptr<NetworkService> network_;
    QString networkStartupError_;
#endif

    void report(const QString &component,const QString &reason) {
        if(!diagnostics_["history"].toString().isEmpty()) {
            logSystemError(component+QStringLiteral(" — ")+reason);
            return;
        }
        try {
            Store history(defaults_.storagePath,true);
            Quarantine(defaults_.storagePath).diagnostic(component,reason);
        }
        catch(const Error &) {logSystemError(component+QStringLiteral(" — ")+reason);}
    }

    MonitorStatus monitorStatus() {
        auto current=monitor_.status();
        // start() принимает задание раньше, чем поток сохранит первую строку истории.
        if(current.active && current.job.id.isEmpty() && monitorSubmitted_)current.job=*monitorSubmitted_;
        return current;
    }

    Status status() {
        Status result;
        result.busy=controller_.busy();
        result.storagePath=defaults_.storagePath;
        result.signaturePath=defaults_.signaturePath;
        result.heuristicPath=defaults_.heuristicPath;
        result.reactionBusy=reaction_.valid();
        result.diagnostics=diagnostics_;
        result.monitor=monitorStatus();
        result.monitorOptions=monitorOptions_;
        if(!result.monitor.active && !result.monitor.job.error.isEmpty() && reportedMonitor_!=result.monitor.job.id) {
            reportedMonitor_=result.monitor.job.id;
            report(QStringLiteral("Файловое и процессное наблюдение"),result.monitor.job.error);
        }
        if(notifications_) {
            try {result.unreadNotifications=notifications_->unreadCount();}
            catch(const Error &error) {
                result.diagnostics["notifications"]=error.message;
                if(historyFailure_!=error.message) {
                    historyFailure_=error.message;
                    report(QStringLiteral("Уведомления"),error.message);
                }
            }
            if(!result.diagnostics.contains("notifications"))historyFailure_.clear();
        }
        if(submitted_) {
            auto progress=controller_.progress();
            if(progress.id==submitted_->id) {
                if(!result.busy && !progress.error.isEmpty() && reportedJob_!=progress.id) {
                    reportedJob_=progress.id;
                    report(QStringLiteral("Ручная проверка"),progress.error);
                }
                result.job=std::move(progress);
            }
        }
        return result;
    }

    QJsonObject dispatch(const QJsonObject &request) {
        check(request["version"].isDouble() && request["version"].toDouble()==protocol::version,
              QStringLiteral("Неподдерживаемая версия протокола службы"));
        const auto command=text(request["command"],32);
        if(command=="status") {
            fields(request,{});
            const auto current=status();
            return {{"busy",current.busy},{"job",jobValue(current.job)},{"storage_path",current.storagePath},
                    {"signature_path",current.signaturePath},{"heuristic_path",current.heuristicPath},
                    {"diagnostics",current.diagnostics},{"unread_notifications",QString::number(current.unreadNotifications)},
                    {"reaction_busy",current.reactionBusy},{"monitor",protocol::encodeMonitorStatus(current.monitor)},
                    {"monitor_options",current.monitorOptions?QJsonValue(protocol::encodeMonitorOptions(*current.monitorOptions)):QJsonValue(QJsonValue::Null)}};
        }
        if(command=="start_scan") {
            fields(request,{"path","recursive"});
            const auto path=text(request["path"],4096);
            check(QDir::isAbsolutePath(path) && QFileInfo(path).isNativePath(),QStringLiteral("Службе нужен абсолютный путь к файлу или каталогу"));
            if(!diagnostics_["history"].toString().isEmpty())throw Error(diagnostics_["history"].toString());
            if(reaction_.valid())throw Error(QStringLiteral("Дождитесь завершения операции карантина"));
            if(!(diagnostics_["signatures"].toString().isEmpty() && !defaults_.signaturePath.isEmpty()) &&
               !(diagnostics_["heuristics"].toString().isEmpty() && !defaults_.heuristicPath.isEmpty()))
                throw Error(QStringLiteral("Нет доступного анализатора. Проверьте настройки службы."));
            auto scan=defaults_;
            scan.path=path;
            scan.recursive=boolean(request["recursive"]);
            scan.id=QUuid::createUuid().toString(QUuid::WithoutBraces);
            scan.cancel=std::make_shared<std::atomic_bool>(false);
            scan.recordDetectionDigest=true;
            Job pending;
            pending.id=scan.id;
            pending.path=scan.path;
            pending.started=now();
            if(!scan.heuristicPath.isEmpty())pending.formatVersion=2;
            if(controller_.busy() || !controller_.submit(std::move(scan)))
                throw Error(QStringLiteral("В службе уже выполняется ручное задание"));
            submitted_=pending;
            return pending.json();
        }
        if(command=="cancel") {
            fields(request,{"job_id"});
            const auto id=text(request["job_id"],256);
            const bool accepted=submitted_ && id==submitted_->id && controller_.busy();
            if(accepted)controller_.cancel();
            return {{"accepted",accepted}};
        }
        if(command=="start_monitor") {
            fields(request,{"options"});
            check(request["options"].isObject(),QStringLiteral("Ожидались параметры наблюдения"));
            const auto options=protocol::decodeMonitorOptions(request["options"].toObject());
            if(!diagnostics_["history"].toString().isEmpty())throw Error(diagnostics_["history"].toString());
            if(monitor_.status().active)throw Error(QStringLiteral("В службе уже выполняется файловое и процессное наблюдение"));
            MonitorRequest monitor;
            monitor.directory=options.directory;monitor.processImageDirectory=options.processImageDirectory;monitor.behaviorPath=options.behaviorPath;
            monitor.recursive=options.recursive;monitor.files=options.files;monitor.processes=options.processes;monitor.scanProcessImages=options.scanProcessImages;
            monitor.signaturePath=defaults_.signaturePath;monitor.heuristicPath=defaults_.heuristicPath;monitor.storagePath=defaults_.storagePath;
            monitor.id=QUuid::createUuid().toString(QUuid::WithoutBraces);monitor.recordDetectionDigest=true;
            Job pending;pending.formatVersion=2;pending.source="monitor";pending.id=monitor.id;pending.path=monitor.directory.isEmpty()?QStringLiteral("processes"):monitor.directory;pending.started=now();
            if(!monitor_.start(std::move(monitor)))throw Error(QStringLiteral("В службе уже выполняется наблюдение"));
            monitorOptions_=options;
            monitorSubmitted_=pending;
            return protocol::encodeMonitorStatus(monitorStatus());
        }
        if(command=="monitor_status") {
            fields(request,{});
            return protocol::encodeMonitorStatus(monitorStatus());
        }
        if(command=="cancel_monitor") {
            fields(request,{"job_id"});
            const auto id=text(request["job_id"],256);const auto current=monitorStatus();
            const bool accepted=current.active && current.job.id==id;
            if(accepted)monitor_.cancel();
            return {{"accepted",accepted}};
        }
        if(command=="monitor_processes") {
            fields(request,{"job_id"});
            const auto id=text(request["job_id"],256);const auto current=monitorStatus();
            if(current.job.id!=id)throw Error(QStringLiteral("Задание наблюдения сменилось; повторите запрос процессов"));
            QJsonArray processes;
            if(current.active)for(const auto &process:monitor_.processes())processes.push_back(process.json());
            return {{"job_id",id},{"processes",processes}};
        }
        if(command=="jobs") {
            fields(request,{"offset","limit"});
            const auto limit=pageSize(request["limit"]);
            const auto offset=protocol::counter(request["offset"]);
            Store history(defaults_.storagePath,true);
            QJsonArray jobs;
            for(const auto &job:history.jobs(offset,limit))jobs.append(job.json());
            return {{"jobs",jobs}};
        }
        if(command=="get_job") {
            fields(request,{"job_id","recover_running"});
            const auto id=text(request["job_id"],256);
            const auto observing=monitorStatus();
            const bool ownMonitor=observing.active && observing.job.id==id;
            const bool recover=boolean(request["recover_running"]) && !(submitted_ && id==submitted_->id && controller_.busy()) && !ownMonitor;
            Store history(defaults_.storagePath,true);
            auto job=history.getJob(id,recover);
            if(!job && ownMonitor)job=observing.job;
            return {{"job",jobValue(job)}};
        }
        if(command=="query") {
            fields(request,{"job_id","query"});
            const auto id=text(request["job_id"],256);
            check(request["query"].isObject(),QStringLiteral("Ожидался JSON параметров страницы"));
            const auto query=protocol::decodeQuery(request["query"].toObject());
            Store history(defaults_.storagePath,true);
            const auto page=history.query(id,query);
            QJsonArray rows;
            for(const auto &row:page.rows)rows.append(row.json());
            return {{"rows",rows},{"total",QString::number(page.total)},{"upper_row",QString::number(page.upperRow)}};
        }
        if(command=="observation") {
            fields(request,{"job_id","event_id"});
            const auto id=text(request["job_id"],256),eventId=text(request["event_id"],256);
            Store history(defaults_.storagePath,true);
            const auto event=history.observation(id,eventId);
            return {{"event",event?QJsonValue(*event):QJsonValue(QJsonValue::Null)}};
        }
        if(command=="notifications" || command=="quarantine_items" || command=="journal") {
            if(command=="journal")fields(request,{"offset","limit","text"});
            else fields(request,{"offset","limit"});
            const auto limit=pageSize(request["limit"]);
            const auto offset=protocol::counter(request["offset"]);
            if(!diagnostics_["history"].toString().isEmpty())throw Error(diagnostics_["history"].toString());
            if(command=="journal")
                return Quarantine(defaults_.storagePath).journal(offset,limit,optionalText(request["text"],4096));
            if(command=="quarantine_items")return Quarantine(defaults_.storagePath).items(offset,limit);
            if(!notifications_)throw Error(QStringLiteral("Хранилище уведомлений недоступно"));
            return notifications_->page(offset,limit);
        }
        if(command=="acknowledge_notification") {
            fields(request,{"id"});
            const auto id=text(request["id"],160);
            if(!notifications_)throw Error(QStringLiteral("Хранилище уведомлений недоступно"));
            return notifications_->acknowledge(id);
        }
#ifdef RESHETO_SERVICE_NETWORK
        if(command.startsWith("network_")) {
            if(network_)return network_->dispatch(command,request);
            const auto reason=networkStartupError_.isEmpty()?diagnostics_["history"].toString():networkStartupError_;
            if(command=="network_status") {
                fields(request,{});
                return {{"busy",false},{"rules",""},{"error",reason},{"job",QJsonValue::Null}};
            }
            throw Error(reason);
        }
#endif
        throw InvalidRequest(QStringLiteral("Неизвестная команда службы"));
    }

    void startReaction(QLocalSocket &client,const QJsonObject &request) {
        const auto command=request["command"].toString();
        const bool process=command=="inspect_process" || command=="terminate_process";
        QString id,argument;
        if(command=="quarantine" || process) {
            fields(request,{"job_id","result_key"});
            id=text(request["job_id"],256);
            argument=text(request["result_key"],64);
        } else if(command=="restore_quarantine") {
            fields(request,{"id","alternative"});
            id=text(request["id"],64);
            argument=optionalText(request["alternative"],4096);
        } else {
            fields(request,{"id"});
            id=text(request["id"],64);
        }
        if(!diagnostics_["history"].toString().isEmpty())throw Error(diagnostics_["history"].toString());
        if(!process && !diagnostics_["quarantine"].toString().isEmpty())throw Error(diagnostics_["quarantine"].toString());
        if(reaction_.valid())throw Error(QStringLiteral("Дождитесь завершения текущего действия"));
        if(!process && controller_.busy())throw Error(QStringLiteral("Дождитесь завершения ручной проверки"));
        reaction_=std::async(std::launch::async,[storage=defaults_.storagePath,command,id,argument,process]{
            try {
                if(process)return QJsonObject{{"version",protocol::version},{"ok",true},
                                              {"result",reactToProcess(storage,id,argument,command=="terminate_process")}};
                Quarantine quarantine(storage);
                auto result=command=="quarantine"?quarantine.take(id,argument):
                            command=="restore_quarantine"?quarantine.restore(id,argument):quarantine.erase(id);
                return QJsonObject{{"version",protocol::version},{"ok",true},{"result",result}};
            } catch(const Error &error) {return failure("command_failed",error.message);}
            catch(const std::exception &) {return failure("internal_error",QStringLiteral("Не удалось выполнить операцию карантина"));}
        });
        reactionClient_=&client;
        reactionPoll_.start();
    }

    void send(QLocalSocket &client,const QJsonObject &reply) {
        QByteArray bytes;
        try { bytes=protocol::frame(reply,protocol::replyLimit); }
        catch(const Error &error) { bytes=protocol::frame(failure("reply_too_large",error.message),protocol::replyLimit); }
        if(client.write(bytes)!=bytes.size())client.abort();
        else client.disconnectFromServer();
    }

    void receive(QLocalSocket &client,QByteArray &buffer) {
        if(client.state()!=QLocalSocket::ConnectedState)return;
        const auto bytes=client.read(protocol::requestLimit+protocol::headerSize-buffer.size());
        if(bytes.isEmpty())return;
#ifdef Q_OS_WIN
        if(buffer.isEmpty() && !isLocalPeer(client)){client.abort();return;}
#endif
        buffer+=bytes;
        std::optional<QJsonObject> request;
        try { request=protocol::readFrame(buffer,protocol::requestLimit); }
        catch(const Error &error) { send(client,failure("invalid_frame",error.message));return; }
        if(!request)return;

        QJsonObject reply;
        try {
            const auto command=(*request)["command"].toString();
            if(command=="quarantine" || command=="restore_quarantine" || command=="delete_quarantine" ||
               command=="inspect_process" || command=="terminate_process") {
                check((*request)["version"].isDouble() && (*request)["version"].toDouble()==protocol::version,
                      QStringLiteral("Неподдерживаемая версия протокола службы"));
                startReaction(client,*request);
                return;
            }
            reply={{"version",protocol::version},{"ok",true},{"result",dispatch(*request)}};
        }
        catch(const InvalidRequest &error) { reply=failure("invalid_request",error.message); }
        catch(const Error &error) { reply=failure("command_failed",error.message); }
        catch(const std::exception &) { reply=failure("internal_error",QStringLiteral("Не удалось выполнить команду службы")); }
        send(client,reply);
    }

    void acceptClients() {
        while(auto *client=socket_.nextPendingConnection()) {
            if(clients_.size()>=maxClients || client->state()!=QLocalSocket::ConnectedState) {
                client->abort();
                client->deleteLater();
                continue;
            }
            clients_.insert(client);
            client->setReadBufferSize(protocol::requestLimit+protocol::headerSize);
            QObject::connect(client,&QLocalSocket::disconnected,&socket_,[this,client]{
                clients_.remove(client);
                client->deleteLater();
            });
            QTimer::singleShot(connectionLifetimeMs,client,[this,client]{if(reactionClient_!=client)client->abort();});
            auto buffer=std::make_shared<QByteArray>();
            QObject::connect(client,&QLocalSocket::readyRead,client,[this,client,buffer]{receive(*client,*buffer);});
            if(client->bytesAvailable())receive(*client,*buffer);
        }
    }

public:
    explicit Server(Request defaults,[[maybe_unused]] const QString &networkRulesPath):defaults_(prepare(std::move(defaults))) {
        diagnostics_=diagnose(defaults_);
        QString historyError;
        try {
            defaults_.storagePath=Store::preparePath(defaults_.storagePath);
            const QFileInfo storage(defaults_.storagePath);
            const auto canonical=storage.exists()?storage.canonicalFilePath():
                QFileInfo(storage.absolutePath()).canonicalFilePath()+"/"+storage.fileName();
            storageLock_=std::make_unique<QLockFile>(canonical+".service.lock");
            storageLock_->setStaleLockTime(0);
            if(!storageLock_->tryLock(0))throw Error(QStringLiteral("Файл истории занят другой службой или недоступен для записи"));
            Store history(defaults_.storagePath);
        } catch(const Error &error) {historyError=error.message;}
        diagnostics_["history"]=historyError;
        if(historyError.isEmpty()) {
            try {Quarantine quarantine(defaults_.storagePath,true);}
            catch(const Error &error) {diagnostics_["quarantine"]=error.message;}
#ifdef RESHETO_SERVICE_NETWORK
            try {network_=std::make_unique<NetworkService>(defaults_.storagePath,networkRulesPath);}
            catch(const Error &error) {networkStartupError_=error.message; diagnostics_["network"]=error.message;}
#endif
            try {notifications_=std::make_unique<Notifications>(defaults_.storagePath
#ifdef RESHETO_SERVICE_NETWORK
                    ,network_!=nullptr
#endif
                );}
            catch(const Error &error) {diagnostics_["notifications"]=error.message;}
        }
        const auto reportIfFailed=[&](const char *key,const QString &component) {
            const auto reason=diagnostics_[key].toString();
            if(!reason.isEmpty())report(component,reason);
        };
        if(!historyError.isEmpty())reportIfFailed("history",QStringLiteral("История"));
        if(!defaults_.signaturePath.isEmpty())reportIfFailed("signatures",QStringLiteral("Сигнатуры"));
        reportIfFailed("heuristics",QStringLiteral("Статическая эвристика"));
        reportIfFailed("quarantine",QStringLiteral("Карантин"));
        reportIfFailed("notifications",QStringLiteral("Уведомления"));
        reportIfFailed("network",QStringLiteral("Сеть"));

        reactionPoll_.setInterval(50);
        QObject::connect(&reactionPoll_,&QTimer::timeout,&socket_,[this]{
            using namespace std::chrono_literals;
            if(reaction_.wait_for(0ms)!=std::future_status::ready)return;
            const auto reply=reaction_.get();
            reactionPoll_.stop();
            if(reactionClient_)send(*reactionClient_,reply);
            reactionClient_.clear();
        });
    }
    void listen(const QString &endpoint) {
        socket_.setSocketOptions(QLocalServer::UserAccessOption);
        socket_.setMaxPendingConnections(maxClients);
        QObject::connect(&socket_,&QLocalServer::newConnection,&socket_,[this]{acceptClients();});
        if(!socket_.listen(endpoint))throw Error(QStringLiteral("Не удалось открыть локальный адрес службы: ")+socket_.errorString());
    }
};
}

int serve(const QString &endpoint,Request defaults,const QString &networkRulesPath) {
    if(!protocol::validEndpoint(endpoint))throw Error(QStringLiteral("Имя службы: 1–64 латинские буквы, цифры, дефис или подчёркивание"));
    // На Windows второму серверу на том же имени может достаться другой экземпляр канала.
#ifdef Q_OS_WIN
    const auto key=endpoint.toLower();
#else
    const auto &key=endpoint;
#endif
    const auto digest=QCryptographicHash::hash(key.toUtf8(),QCryptographicHash::Sha256).toHex();
    QLockFile lock(QDir::temp().filePath("resheto-service-"+QString::fromLatin1(digest)+".lock"));
    lock.setStaleLockTime(0);
    if(!lock.tryLock(0))throw Error(QStringLiteral("Локальное имя службы уже занято или его нельзя заблокировать"));
    {
        QLocalSocket other;
        other.connectToServer(endpoint);
        if(other.state()==QLocalSocket::ConnectedState || other.waitForConnected(350))
            throw Error(QStringLiteral("Локальное имя службы уже используется"));
#ifdef Q_OS_LINUX
        if(other.error()==QLocalSocket::ConnectionRefusedError || other.error()==QLocalSocket::ServerNotFoundError) {
            // Блокировка имени уже взята. Удаляем только сокет текущего пользователя после отказа подключения.
            const auto path=QFile::encodeName(QDir::temp().filePath(endpoint));
            struct stat info{};
            if(::lstat(path.constData(),&info)==0 && S_ISSOCK(info.st_mode) && info.st_uid==::geteuid()) {
                if(::unlink(path.constData())!=0)throw Error(QStringLiteral("Не удалось освободить сокет прерванной службы"));
            } else if(other.error()!=QLocalSocket::ServerNotFoundError) {
                throw Error(QStringLiteral("Локальное имя службы недоступно: ")+other.errorString());
            }
        } else
#endif
        if(other.error()!=QLocalSocket::ServerNotFoundError)
            throw Error(QStringLiteral("Локальное имя службы недоступно: ")+other.errorString());
    }
    Server server(std::move(defaults),networkRulesPath);
    server.listen(endpoint);
#ifdef Q_OS_WIN
    scmReady();
#endif
    QTextStream(stdout)<<QStringLiteral("READY ")<<endpoint<<Qt::endl;
    return QCoreApplication::exec();
}
}
