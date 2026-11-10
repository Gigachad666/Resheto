#include "private_session.h"
#include "core/file_access.h"
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QUuid>
#include <cstring>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace resheto::network::ipc {
namespace {
void protect(const QString &path,bool directory) {
#ifdef Q_OS_WIN
    HANDLE token=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))throw Error(QStringLiteral("Не удалось получить владельца IPC"));
    DWORD size=0;GetTokenInformation(token,TokenUser,nullptr,0,&size);QByteArray data(static_cast<qsizetype>(size),0);
    const bool read=GetTokenInformation(token,TokenUser,data.data(),size,&size)!=FALSE;CloseHandle(token);
    if(!read)throw Error(QStringLiteral("Не удалось прочитать владельца IPC"));
    LPWSTR sid=nullptr;if(!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(data.data())->User.Sid,&sid))throw Error(QStringLiteral("Не удалось подготовить права IPC"));
    const QString sddl=QStringLiteral("D:P(A;%1;FA;;;%2)").arg(directory?QStringLiteral("OICI"):QString(),QString::fromWCharArray(sid));LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(reinterpret_cast<LPCWSTR>(sddl.utf16()),SDDL_REVISION_1,&descriptor,nullptr))throw Error(QStringLiteral("Не удалось создать DACL IPC"));
    const auto native=QDir::toNativeSeparators(path);const bool written=SetFileSecurityW(reinterpret_cast<LPCWSTR>(native.utf16()),DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,descriptor)!=FALSE;LocalFree(descriptor);
    if(!written)throw Error(QStringLiteral("Не удалось ограничить DACL IPC текущим пользователем"));
#else
    const auto bytes=QFile::encodeName(path);if(::chmod(bytes.constData(),directory?0700:0600)!=0)throw Error(QStringLiteral("Не удалось ограничить права IPC текущим пользователем"));
#endif
}
}
PrivateSession::PrivateSession():directory_(QDir::tempPath()+"/resheto-net-XXXXXX") {
    if(!directory_.isValid())throw Error(QStringLiteral("Не удалось создать приватный каталог сетевой сессии"));
    protect(directory_.path(),true);ticket_.endpoint="resheto_net_"+QUuid::createUuid().toString(QUuid::Id128);ticket_.controllerPid=QCoreApplication::applicationPid();
    QByteArray random(32,0);for(int i=0;i<32;i+=4){const auto value=QRandomGenerator::system()->generate();memcpy(random.data()+i,&value,4);}ticket_.token=QString::fromLatin1(random.toHex());path_=directory_.filePath("session.json");
    QFile file(path_);if(!file.open(QIODevice::WriteOnly|QIODevice::NewOnly))throw Error(QStringLiteral("Не удалось создать описание сетевой сессии"));protect(path_,false);
    const auto bytes=QJsonDocument(QJsonObject{{"format","resheto-private-network-v1"},{"endpoint",ticket_.endpoint},{"token",ticket_.token},{"controller_pid",QString::number(ticket_.controllerPid)},{"created_ms",QString::number(QDateTime::currentMSecsSinceEpoch())}}).toJson(QJsonDocument::Compact);
    if(file.write(bytes)!=bytes.size() || !file.flush())throw Error(QStringLiteral("Не удалось записать описание сетевой сессии"));
}
SessionTicket readSessionTicket(const QString &path) {
    ReadFile file(path);
#ifndef Q_OS_WIN
    struct stat info{};if(::lstat(QFile::encodeName(path).constData(),&info)!=0 || !S_ISREG(info.st_mode) || info.st_uid!=::geteuid() || (info.st_mode&077)!=0)throw Error(QStringLiteral("Файл сетевой сессии доступен другим пользователям"));
#endif
    const auto bytes=file.read(4097);if(bytes.size()>4096)throw Error(QStringLiteral("Описание сетевой сессии превышает предел 4096 байт"));
    if(bytes.size()!=file.size() || !file.unchanged())throw Error(QStringLiteral("Описание сетевой сессии изменилось или прочитано не полностью"));
    QJsonParseError error;const auto document=QJsonDocument::fromJson(bytes,&error);if(error.error!=QJsonParseError::NoError || !document.isObject())throw Error(QStringLiteral("Повреждена сетевая сессия"));const auto object=document.object();
    SessionTicket ticket;ticket.endpoint=object["endpoint"].toString();ticket.token=object["token"].toString();bool goodPid=false,goodTime=false;ticket.controllerPid=object["controller_pid"].toString().toLongLong(&goodPid);const auto created=object["created_ms"].toString().toLongLong(&goodTime);
    if(object["format"]!="resheto-private-network-v1" || !QRegularExpression("^resheto_net_[0-9a-f]{32}$").match(ticket.endpoint).hasMatch() || !QRegularExpression("^[0-9a-f]{64}$").match(ticket.token).hasMatch() || !goodPid || ticket.controllerPid<=0 || !goodTime || created>QDateTime::currentMSecsSinceEpoch()+1000 || QDateTime::currentMSecsSinceEpoch()-created>60000)throw Error(QStringLiteral("Сетевая сессия недействительна или устарела"));
    return ticket;
}
}
