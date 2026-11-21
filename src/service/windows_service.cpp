#include "windows_service.h"
#include "diagnostics.h"
#include <windows.h>
#include <atomic>
#include <mutex>
#include <QTextStream>

namespace resheto::service {
namespace {
void reportFailure(const QString &operation,DWORD error) {
    logSystemError(QStringLiteral("Windows SCM. %1. Код Windows %2.").arg(operation).arg(error));
}

struct Host {
    int argc;
    char **argv;
    int (*entry)(int,char **);
    int exitCode=2;
    SERVICE_STATUS_HANDLE handle=nullptr;
    std::mutex mutex;
    std::atomic_bool stop=false;

    bool report(DWORD state) const {
        SERVICE_STATUS status{};
        status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;
        status.dwCurrentState=state;
        if(state==SERVICE_START_PENDING || state==SERVICE_STOP_PENDING) {
            status.dwCheckPoint=1;
            status.dwWaitHint=30000;
        }
        if(state==SERVICE_RUNNING)status.dwControlsAccepted=SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
        if(state==SERVICE_STOPPED && exitCode!=0) {
            status.dwWin32ExitCode=ERROR_SERVICE_SPECIFIC_ERROR;
            status.dwServiceSpecificExitCode=static_cast<DWORD>(exitCode);
        }
        if(SetServiceStatus(handle,&status))return true;
        const auto error=GetLastError();
        reportFailure(QStringLiteral("Не удалось передать состояние %1").arg(state),error);
        return false;
    }
};
Host *host=nullptr;

DWORD WINAPI control(DWORD code,DWORD,void *,void *context) {
    auto &service=*static_cast<Host *>(context);
    if(code==SERVICE_CONTROL_STOP || code==SERVICE_CONTROL_SHUTDOWN) {
        std::lock_guard lock(service.mutex);
        if(!service.stop.exchange(true))service.report(SERVICE_STOP_PENDING);
        return NO_ERROR;
    }
    return code==SERVICE_CONTROL_INTERROGATE?NO_ERROR:ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI start(DWORD count,wchar_t **arguments) {
    auto &service=*host;
    if(!count || !arguments) {
        logSystemError(QStringLiteral("Windows SCM не передал имя запускаемой службы"));
        return;
    }
    service.handle=RegisterServiceCtrlHandlerExW(arguments[0],control,&service);
    if(!service.handle) {
        const auto error=GetLastError();
        reportFailure(QStringLiteral("Не удалось зарегистрировать обработчик команд"),error);
        return;
    }
    if(!service.report(SERVICE_START_PENDING)) {
        service.report(SERVICE_STOPPED);
        return;
    }
    try {service.exitCode=service.entry(service.argc,service.argv);}
    catch(...) {logSystemError(QStringLiteral("Аварийное завершение службы Windows"));}
    std::lock_guard lock(service.mutex);
    service.report(SERVICE_STOPPED);
}
}

int runUnderScm(int argc,char **argv,int (*entry)(int,char **)) {
    Host service{argc,argv,entry};
    host=&service;
    wchar_t name[]=L"Resheto";
    SERVICE_TABLE_ENTRYW table[]={{name,start},{nullptr,nullptr}};
    const bool dispatched=StartServiceCtrlDispatcherW(table);
    if(!dispatched) {
        const auto error=GetLastError();
        QTextStream(stderr)<<QStringLiteral("Не удалось запустить службу через SCM, код Windows %1.").arg(error)<<Qt::endl;
    }
    host=nullptr;
    return service.exitCode;
}

bool scmStopRequested() {
    return host && host->stop.load();
}

bool runningUnderScm() {
    return host!=nullptr;
}

void scmReady() {
    if(!host)return;
    std::lock_guard lock(host->mutex);
    if(!host->stop.load() && !host->report(SERVICE_RUNNING))
        throw Error(QStringLiteral("Диспетчер Windows не подтвердил запуск службы"));
}
}
