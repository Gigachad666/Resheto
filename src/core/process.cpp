#include "process.h"
#include <QDir>
#include <QFile>
#include <QUuid>
#include <algorithm>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace resheto {
QString ProcessInfo::key() const { return QString::number(pid)+":"+startTime; }
QJsonObject ProcessInfo::json() const { return {{"pid",QString::number(pid)},{"parent_pid",QString::number(parentPid)},{"start_time",startTime},{"image",image}}; }
QJsonObject ProcessEvent::json() const { return {{"id",id},{"operation",operation},{"time",time},{"source",source},{"monotonic_ms",QString::number(monotonicMs)},{"process",process.json()},{"parent",parent.json()}}; }
QString processIdentityError(const ProcessInfo &process) {
    ProcessInfo current; current.pid=process.pid;
#ifdef _WIN32
    if(process.pid>MAXDWORD) return QStringLiteral("PID вне диапазона ОС");
    const HANDLE handle=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,static_cast<DWORD>(process.pid));
    if(!handle) return QStringLiteral("Процесс завершился либо его сведения недоступны");
    FILETIME created{},exited{},kernel{},user{}; wchar_t path[32768]; DWORD length=32768;
    const bool running=WaitForSingleObject(handle,0)==WAIT_TIMEOUT;
    const bool ok=running && GetProcessTimes(handle,&created,&exited,&kernel,&user) && QueryFullProcessImageNameW(handle,0,path,&length);
    CloseHandle(handle);
    if(!ok) return QStringLiteral("Не удалось повторно подтвердить процесс");
    current.startTime=QString::number((quint64(created.dwHighDateTime)<<32)|created.dwLowDateTime);
    current.image=QDir::cleanPath(QDir::fromNativeSeparators(QString::fromWCharArray(path,static_cast<int>(length))));
    const bool sameImage=current.image.compare(process.image,Qt::CaseInsensitive)==0;
#else
    const auto base=QStringLiteral("/proc/%1").arg(process.pid); QFile stat(base+"/stat");
    if(!stat.open(QIODevice::ReadOnly)) return QStringLiteral("Процесс завершился либо его сведения недоступны");
    const auto bytes=stat.read(8192); const auto close=bytes.lastIndexOf(')');
    const auto fields=close<0?QList<QByteArray>():bytes.mid(close+2).simplified().split(' ');
    if(fields.size()<=19) return QStringLiteral("Не удалось повторно прочитать идентичность процесса");
    bool ok=false; const auto start=fields[19].toULongLong(&ok);
    if(!ok || !start) return QStringLiteral("Некорректная идентичность процесса");
    current.startTime=QString::number(start); current.image=QFile::symLinkTarget(base+"/exe");
    const bool sameImage=current.image==process.image;
#endif
    if(current.startTime!=process.startTime || !sameImage) return QStringLiteral("PID или путь образа уже относится к другому состоянию процесса");
    return {};
}
ProcessSnapshot processSnapshot() {
    ProcessSnapshot out; int unavailable=0;
#ifdef _WIN32
    const HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE) { out.available=false; out.complete=false; out.reason=QStringLiteral("Не удалось получить системный снимок процессов: %1").arg(GetLastError()); return out; }
    PROCESSENTRY32W entry{}; entry.dwSize=sizeof(entry);
    if(!Process32FirstW(snapshot,&entry)) { CloseHandle(snapshot); out.available=false; out.complete=false; out.reason=QStringLiteral("Не удалось прочитать системный снимок процессов"); return out; }
    do {
        if(entry.th32ProcessID==0) continue;
        HANDLE handle=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);
        if(!handle) { ++unavailable; continue; }
        FILETIME created{},exited{},kernel{},user{}; wchar_t path[32768]; DWORD length=32768;
        if(GetProcessTimes(handle,&created,&exited,&kernel,&user) && QueryFullProcessImageNameW(handle,0,path,&length)) {
            ProcessInfo p; p.pid=entry.th32ProcessID; p.parentPid=entry.th32ParentProcessID;
            p.startTime=QString::number((quint64(created.dwHighDateTime)<<32)|created.dwLowDateTime);
            p.image=QDir::cleanPath(QDir::fromNativeSeparators(QString::fromWCharArray(path,static_cast<int>(length))));
            out.processes.push_back(std::move(p));
        } else ++unavailable;
        CloseHandle(handle);
        if(out.processes.size()>=4096) { out.complete=false; break; }
    } while(Process32NextW(snapshot,&entry));
    CloseHandle(snapshot);
#else
    QDir proc("/proc");
    if(!proc.exists()) { out.available=false; out.complete=false; out.reason=QStringLiteral("procfs недоступен"); return out; }
    const auto names=proc.entryList(QDir::Dirs|QDir::NoDotAndDotDot,QDir::Name);
    auto stat=[](const QString &path) {
        QFile f(path); if(!f.open(QIODevice::ReadOnly)) return QByteArray(); return f.read(8192);
    };
    auto parse=[](const QByteArray &bytes,ProcessInfo &p) {
        const auto close=bytes.lastIndexOf(')'); if(close<0) return false;
        const auto fields=bytes.mid(close+2).simplified().split(' '); if(fields.size()<=19) return false;
        bool a=false,b=false; p.parentPid=fields[1].toULongLong(&a); const auto start=fields[19].toULongLong(&b);
        if(!a || !b || !start) return false; p.startTime=QString::number(start); return true;
    };
    for(const auto &name:names) {
        bool numeric=false; const auto pid=name.toULongLong(&numeric); if(!numeric || !pid) continue;
        const auto base=proc.filePath(name); ProcessInfo p; p.pid=pid;
        if(!parse(stat(base+"/stat"),p)) { ++unavailable; continue; }
        p.image=QFile::symLinkTarget(base+"/exe");
        ProcessInfo again; if(p.image.isEmpty() || !parse(stat(base+"/stat"),again) || p.startTime!=again.startTime) { ++unavailable; continue; }
        out.processes.push_back(std::move(p));
        if(out.processes.size()>=4096) { out.complete=false; break; }
    }
#endif
    if(unavailable) { out.complete=false; out.reason=QStringLiteral("Нет достоверных метаданных для %1 процессов (права/завершение/неприменимость)").arg(unavailable); }
    if(out.processes.size()>=4096) out.reason=QStringLiteral("Достигнут предел снимка 4096 процессов");
    std::sort(out.processes.begin(),out.processes.end(),[](const ProcessInfo &a,const ProcessInfo &b){return a.pid<b.pid;});
    return out;
}
std::vector<ProcessEvent> ProcessTracker::update(const ProcessSnapshot &snapshot,qint64 tick) {
    std::vector<ProcessEvent> out;
    if(!snapshot.available) { reset(); return out; }
    if(snapshot.processes.size()>4096) { reset(); lost_=true; return out; }
    QHash<quint64,ProcessInfo> current;
    for(const auto &p:snapshot.processes) {
        bool valid=false; const auto start=p.startTime.toULongLong(&valid);
        if(!p.pid || !valid || !start || current.contains(p.pid)) { reset(); lost_=true; return out; }
        current.insert(p.pid,p);
    }
    int additional=0; for(const auto &p:snapshot.processes) if(!seen_.contains(p.key())) ++additional;
    if(seen_.size()+additional>8192) { reset(); lost_=true; }
    if(initialized_) {
        for(const auto &p:snapshot.processes) {
            const auto previous=previous_.constFind(p.pid);
            if((previous!=previous_.cend() && previous->startTime==p.startTime) || seen_.contains(p.key())) continue;
            ProcessEvent e; e.id=QUuid::createUuid().toString(QUuid::WithoutBraces); e.operation="observed_start";
            e.time=now(); e.monotonicMs=tick; e.source="process_snapshot"; e.process=p;
            const auto parent=current.constFind(p.parentPid);
            // Существующий PPID может уже принадлежать новому процессу. Сверяем время старта.
            bool childOk=false,parentOk=false; const auto childTime=p.startTime.toULongLong(&childOk);
            if(parent!=current.cend()) {
                const auto parentTime=parent->startTime.toULongLong(&parentOk);
                if(childOk && parentOk && parentTime<=childTime && parent->pid!=p.pid) { e.parent=*parent; e.operation="child_start"; }
            }
            out.push_back(std::move(e));
        }
        for(auto p=previous_.cbegin();p!=previous_.cend();++p) {
            const auto found=current.constFind(p.key());
            if(found!=current.cend() && found->startTime==p->startTime) continue;
            ProcessEvent e; e.id=QUuid::createUuid().toString(QUuid::WithoutBraces); e.operation="not_observed";
            e.time=now(); e.monotonicMs=tick; e.source="process_snapshot"; e.process=*p; out.push_back(std::move(e));
        }
    }
    for(const auto &p:snapshot.processes) seen_.insert(p.key());
    previous_=std::move(current); initialized_=true; return out;
}
void ProcessTracker::reset() { previous_.clear(); seen_.clear(); initialized_=false; lost_=false; }
}
