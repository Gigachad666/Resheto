#include "process_reaction.h"
#include "client.h"
#include "diagnostics.h"
#include "monitor_protocol.h"
#include "quarantine.h"
#include <QDir>
#include <QRegularExpression>
#include <QScopeGuard>
#include <limits>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#elif defined(Q_OS_LINUX)
#include <cerrno>
#include <csignal>
#include <poll.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#endif

namespace resheto::service {
namespace {
constexpr quint64 minimumAgeSeconds=5;
constexpr int exitWaitMs=1500;

struct Target {
    ProcessInfo process;
    QString basis;
};

struct Decision {
    QString code,reason;
    bool ready() const { return code=="ready"; }
};

Decision ended() {
    return {"exited",QStringLiteral("Процесс уже завершился")};
}

Decision inaccessible() {
    return {"unavailable",QStringLiteral("Процесс завершился или недоступен текущей учётной записи")};
}

Decision changed() {
    return {"identity_changed",QStringLiteral("Идентификатор запуска или путь процесса изменился")};
}

Decision ageDecision(quint64 seconds) {
    if(seconds>=minimumAgeSeconds)return {"ready",{}};
    return {"too_young",QStringLiteral("Завершение доступно через %1 с после запуска процесса").arg(minimumAgeSeconds)};
}

std::optional<Target> selectedTarget(const QString &storage,const QString &jobId,const QString &key,bool verifyHistory) {
    static const QRegularExpression digest(QStringLiteral("\\A[0-9a-f]{64}\\z"));
    if(!digest.match(key).hasMatch())return {};
    Store history(storage,true);
    if(verifyHistory && !history.getJob(jobId,false))return {};
    ResultQuery query;
    query.filter=ResultFilter::Matches;
    query.object=ResultObject::Processes;
    std::optional<Target> target;
    while(true) {
        const auto page=history.query(jobId,query);
        for(const auto &row:page.rows) {
            if(resultKey(row)!=key)continue;
            if(target)throw Error(QStringLiteral("Обнаружение связано с неоднозначным результатом"));
            if(row.outcome=="behavioral_match") {
                target=Target{protocol::decodeProcess(row.details["process"].toObject()),row.basis};
            } else {
                const auto event=history.observation(jobId,row.eventId);
                if(!event || (*event)["type"]!="process_image" || (*event)["source"]!="process_monitor" ||
                   (*event)["object"]!=row.path || (*event)["details"].toObject()["operation"]!="image_file")return {};
                const auto process=protocol::decodeProcess((*event)["details"].toObject()["process"].toObject());
                if(process.image!=row.path)return {};
                target=Target{process,row.basis};
            }
        }
        query.offset+=static_cast<qint64>(page.rows.size());
        if(page.rows.empty() || query.offset>=page.total)break;
        query.upperRow=page.upperRow;
    }
    return target;
}

#ifdef Q_OS_WIN
quint64 ticks(const FILETIME &time) { return (quint64(time.dwHighDateTime)<<32)|time.dwLowDateTime; }

QByteArray tokenUser(HANDLE process) {
    HANDLE token=nullptr;
    if(!OpenProcessToken(process,TOKEN_QUERY,&token))return {};
    const auto close=qScopeGuard([&]{CloseHandle(token);});
    DWORD length=0;
    GetTokenInformation(token,TokenUser,nullptr,0,&length);
    if(length==0 || length>65536)return {};
    QByteArray buffer(static_cast<qsizetype>(length),Qt::Uninitialized);
    if(!GetTokenInformation(token,TokenUser,buffer.data(),length,&length))return {};
    // SID хранится внутри буфера, указатель TokenUser не переживает копирование.
    const auto sid=reinterpret_cast<const TOKEN_USER *>(buffer.constData())->User.Sid;
    return QByteArray(reinterpret_cast<const char *>(sid),static_cast<qsizetype>(GetLengthSid(sid)));
}

class HeldProcess {
    HANDLE handle_=nullptr;
public:
    ~HeldProcess(){if(handle_)CloseHandle(handle_);}
    Decision inspect(const ProcessInfo &process) {
        if(process.pid<=4 || process.pid>MAXDWORD || process.pid==GetCurrentProcessId())
            return {"protected",QStringLiteral("Завершение этого процесса недоступно")};
        handle_=OpenProcess(PROCESS_TERMINATE|PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,static_cast<DWORD>(process.pid));
        if(!handle_)return GetLastError()==ERROR_INVALID_PARAMETER?ended():inaccessible();
        const auto wait=WaitForSingleObject(handle_,0);
        if(wait==WAIT_OBJECT_0)return ended();
        if(wait!=WAIT_TIMEOUT)return inaccessible();
        BOOL critical=FALSE;
        if(!IsProcessCritical(handle_,&critical) || critical)
            return {"protected",QStringLiteral("ОС не разрешает завершить этот процесс")};
        FILETIME created{},exited{},kernel{},user{},current{};
        std::wstring name(32768,L'\0');
        DWORD size=static_cast<DWORD>(name.size());
        if(!GetProcessTimes(handle_,&created,&exited,&kernel,&user) || !QueryFullProcessImageNameW(handle_,0,name.data(),&size))
            return inaccessible();
        const auto image=QDir::cleanPath(QDir::fromNativeSeparators(QString::fromWCharArray(name.data(),size)));
        if(QString::number(ticks(created))!=process.startTime || image.compare(process.image,Qt::CaseInsensitive)!=0)return changed();
        const auto owner=tokenUser(handle_),ours=tokenUser(GetCurrentProcess());
        if(owner.isEmpty() || ours.isEmpty() || owner!=ours)
            return {"different_owner",QStringLiteral("Процесс принадлежит другой учётной записи или владелец недоступен")};
        GetSystemTimeAsFileTime(&current);
        const auto createdTicks=ticks(created),currentTicks=ticks(current);
        return ageDecision(currentTicks>=createdTicks?(currentTicks-createdTicks)/10000000:0);
    }
    Decision terminate() const {
        if(WaitForSingleObject(handle_,0)==WAIT_OBJECT_0)return ended();
        if(!TerminateProcess(handle_,1)) {
            const auto error=GetLastError();
            if(WaitForSingleObject(handle_,0)==WAIT_OBJECT_0)return ended();
            return {"failed",QStringLiteral("ОС отказала в завершении процесса, код Windows %1").arg(error)};
        }
        if(WaitForSingleObject(handle_,exitWaitMs)==WAIT_OBJECT_0)return {"completed",{}};
        return {"pending",QStringLiteral("Команда принята. ОС пока не подтвердила выход процесса")};
    }
};
#elif defined(Q_OS_LINUX) && defined(SYS_pidfd_open) && defined(SYS_pidfd_send_signal)
class HeldProcess {
    int fd_=-1;
    int waitForExit(int timeout) const {
        pollfd process{fd_,POLLIN,0};
        const auto result=::poll(&process,1,timeout);
        if(result>0 && (process.revents&(POLLIN|POLLHUP)))return 1;
        return result==0?0:-1;
    }
public:
    ~HeldProcess(){if(fd_>=0)::close(fd_);}
    Decision inspect(const ProcessInfo &process) {
        if(process.pid<=1 || process.pid>static_cast<quint64>(std::numeric_limits<pid_t>::max()) ||
           process.pid==static_cast<quint64>(::getpid()))return {"protected",QStringLiteral("Завершение этого процесса недоступно")};
        fd_=static_cast<int>(::syscall(SYS_pidfd_open,static_cast<pid_t>(process.pid),0));
        if(fd_<0) {
            if(errno==ESRCH)return ended();
            if(errno==ENOSYS)return {"unsupported",QStringLiteral("Ядро Linux не поддерживает pidfd")};
            return inaccessible();
        }
        const int wait=waitForExit(0);
        if(wait>0)return ended();
        if(wait<0)return inaccessible();
        if(!processIdentityError(process).isEmpty())return waitForExit(0)>0?ended():changed();
        const auto directory=QStringLiteral("/proc/%1").arg(process.pid).toLatin1();
        struct stat info{};
        if(::stat(directory.constData(),&info)!=0)return inaccessible();
        if(info.st_uid!=::geteuid())return {"different_owner",QStringLiteral("Процесс принадлежит другой учётной записи")};
        const auto frequency=::sysconf(_SC_CLK_TCK);
        timespec current{};
        if(frequency<=0 || ::clock_gettime(CLOCK_BOOTTIME,&current)!=0)return inaccessible();
        const auto nowTicks=static_cast<quint64>(current.tv_sec)*static_cast<quint64>(frequency)+
            static_cast<quint64>(current.tv_nsec)*static_cast<quint64>(frequency)/1000000000;
        const auto start=process.startTime.toULongLong();
        return ageDecision(nowTicks>=start?(nowTicks-start)/static_cast<quint64>(frequency):0);
    }
    Decision terminate() const {
        if(waitForExit(0)>0)return ended();
        if(::syscall(SYS_pidfd_send_signal,fd_,SIGKILL,nullptr,0)!=0) {
            if(errno==ESRCH)return ended();
            return {"failed",QStringLiteral("ОС отказала в завершении процесса, код Linux %1").arg(errno)};
        }
        if(waitForExit(exitWaitMs)>0)return {"completed",{}};
        return {"pending",QStringLiteral("Команда принята. ОС пока не подтвердила выход процесса")};
    }
};
#else
class HeldProcess {
public:
    Decision inspect(const ProcessInfo &) {return {"unsupported",QStringLiteral("Безопасное завершение процессов недоступно на этой сборке")};}
    Decision terminate() const {return {"failed",QStringLiteral("Завершение процесса недоступно")};}
};
#endif
}

QJsonObject reactToProcess(const QString &storage,const QString &jobId,const QString &key,bool confirm) {
    const auto target=selectedTarget(storage,jobId,key,confirm);
    if(!target)throw Error(QStringLiteral("Требуется сохранённое обнаружение, связанное с конкретным процессом"));
    const auto pid=QString::number(target->process.pid);
    HeldProcess held;
    auto decision=held.inspect(target->process);
    if(confirm) {
        Database journal(storage,false);
        const auto context=QStringLiteral("PID %1, запуск %2").arg(pid,target->process.startTime);
        if(decision.ready()) {
            recordReaction(journal,"terminate_process",target->process.image,jobId,{},"requested",context+". "+target->basis);
            decision=held.terminate();
        }
        const auto outcome=decision.code=="completed" || decision.code=="pending" || decision.code=="failed"
            ?decision.code:QStringLiteral("refused");
        try {
            recordReaction(journal,"terminate_process",target->process.image,jobId,{},outcome,
                           context+(decision.reason.isEmpty()?QString():". "+decision.reason));
        } catch(const Error &error) {
            logSystemError(QStringLiteral("Завершение процесса %1, %2. Итог %3. %4")
                .arg(target->process.image,context,outcome,error.message));
            if(!decision.reason.isEmpty())decision.reason+=". ";
            decision.reason+=QStringLiteral("Запись результата в SQLite не удалась. Подробности в диагностике службы");
        }
    }
    return {{"code",decision.code},{"eligible",decision.ready()},{"reason",decision.reason},
            {"pid",pid},{"path",target->process.image},{"basis",target->basis}};
}
}
