#include "diagnostics.h"
#include <core/database.h>
#include <core/heuristic.h>
#include <core/signatures.h>
#include <QDebug>
#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <syslog.h>
#endif

namespace resheto::service {
QJsonObject diagnose(const Request &request,const QString &quarantineError) {
    QJsonObject report{{"history",""},{"signatures",""},{"heuristics",""},{"quarantine",quarantineError}};
    try {Store history(request.storagePath,true);}
    catch(const Error &error) {report["history"]=error.message;}
    if(!request.signaturePath.isEmpty()) {
        try {loadSignatures(request.signaturePath);}
        catch(const Error &error) {report["signatures"]=error.message;}
    } else {
        report["signatures"]=QStringLiteral("База сигнатур не задана");
    }
    if(!request.heuristicPath.isEmpty()) {
        try {loadHeuristicRules(request.heuristicPath);}
        catch(const Error &error) {report["heuristics"]=error.message;}
    }
    return report;
}

void logSystemError(const QString &message) {
    qWarning().noquote()<<message;
#ifdef Q_OS_WIN
    if(const auto source=RegisterEventSourceW(nullptr,L"Resheto")) {
        const auto text=message.left(4096).toStdWString();
        const wchar_t *strings[]={text.c_str()};
        ReportEventW(source,EVENTLOG_ERROR_TYPE,0,1,nullptr,1,0,strings,nullptr);
        DeregisterEventSource(source);
    }
#else
    openlog("resheto-service",LOG_PID,LOG_USER);
    syslog(LOG_ERR,"%s",message.left(4096).toUtf8().constData());
    closelog();
#endif
}
}
