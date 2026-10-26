#include "import.h"
#include "database.h"
#include "signatures.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QLockFile>
#include <QRegularExpression>
#include <QSaveFile>
#include <QTemporaryDir>
#include <QUuid>
namespace resheto {
static void check(bool ok,const QString &why) { if(!ok) throw Error(QStringLiteral("Импорт: ")+why); }
static QByteArray hashFile(const QString &path) {
    QFile f(path); check(QFileInfo(path).isFile() && f.open(QIODevice::ReadOnly) && f.size()<=128*1024*1024,QStringLiteral("исходный файл недоступен/больше 128 МиБ")); QCryptographicHash h(QCryptographicHash::Sha256);
    check(h.addData(&f),QStringLiteral("чтение исходного снимка")); return h.result().toHex();
}
static QJsonObject readJson(const QString &path) {
    QFile f(path); check(f.open(QIODevice::ReadOnly) && f.size()<=1024*1024,QStringLiteral("чтение JSON: ")+path);
    QJsonParseError e; auto d=QJsonDocument::fromJson(f.readAll(),&e); check(e.error==QJsonParseError::NoError && d.isObject(),QStringLiteral("формат JSON")); return d.object();
}
static void saveJson(const QString &path,const QJsonObject &o) {
    QSaveFile f(path); const auto bytes=QJsonDocument(o).toJson();
    check(f.open(QIODevice::WriteOnly) && f.write(bytes)==bytes.size() && f.commit(),QStringLiteral("публикация: ")+path+" "+f.errorString());
}
static QString versionPath(const QString &root,const QString &relative) {
    check(QRegularExpression("^versions/[a-zA-Z0-9-]+/signatures[.]db$").match(relative).hasMatch(),QStringLiteral("путь версии"));
    const auto path=QDir(root).absoluteFilePath(relative);
    const auto canonical=QFileInfo(path).canonicalFilePath();
    check(!canonical.isEmpty() && canonical.startsWith(QFileInfo(root).canonicalFilePath()+"/"),QStringLiteral("версия вне каталога поставки"));
    return path;
}
QString resolveSignaturePath(const QString &path) {
    if(!path.endsWith(".json",Qt::CaseInsensitive)) return absolute(path);
    const auto o=readJson(path);
    check(o["format"].toString()=="resheto-selection-v1",QStringLiteral("формат указателя"));
    return versionPath(QFileInfo(path).absolutePath(),o["database"].toString());
}
static void select(const QString &root,const QString &relative) {
    loadSignatures(versionPath(root,relative));
    QString previous; const auto current=root+"/current.json";
    if(QFileInfo::exists(current)) {
        const auto o=readJson(current); check(o["format"]=="resheto-selection-v1",QStringLiteral("прежний указатель повреждён"));
        previous=o["database"].toString(); versionPath(root,previous);
    }
    saveJson(current,{{"format","resheto-selection-v1"},{"database",relative},{"previous",previous}});
}
void activateVersion(const QString &repository,const QString &relative) {
    const auto root=absolute(repository); QLockFile lock(root+"/import.lock");
    check(lock.tryLock(0),QStringLiteral("другая публикация уже выполняется")); select(root,relative);
}
QJsonObject importSnapshot(const ImportRequest &r) {
    check(r.format=="sha256-lines" || r.format=="clamav-hsb",QStringLiteral("неподдерживаемый формат"));
    check(!r.version.trimmed().isEmpty() && r.version.size()<=256,QStringLiteral("версия"));
    for(const auto &key:{"source_url","source_revision","license","attribution","acquired_utc","source_sha256"})
        check(r.provenance[key].isString() && !r.provenance[key].toString().trimmed().isEmpty(),QStringLiteral("нет происхождения: ")+key);
    const auto sourceHash=hashFile(r.input);
    check(sourceHash==r.provenance["source_sha256"].toString().toLatin1(),QStringLiteral("контрольная сумма исходного снимка"));
    const auto root=absolute(r.repository);
    check(QDir().mkpath(root+"/versions"),QStringLiteral("создание каталога поставки"));
    QLockFile lock(root+"/import.lock"); check(lock.tryLock(0),QStringLiteral("другая публикация уже выполняется"));
    QTemporaryDir staging(root+"/prepare-XXXXXX"); check(staging.isValid(),QStringLiteral("временный каталог недоступен"));
    const auto dbPath=staging.path()+"/signatures.db";
    // Источник включён в каталог версии: происхождение каждой строки остаётся проверяемым офлайн.
    check(QFile::copy(r.input,staging.path()+"/source.txt"),QStringLiteral("копирование исходного снимка"));
    check(hashFile(staging.path()+"/source.txt")==sourceHash,QStringLiteral("снимок изменился при копировании"));
    qint64 lines=0,accepted=0,duplicates=0,unsupported=0,excluded=0;
    {
        Database db(dbPath,false); db.transaction();
        db.exec("PRAGMA user_version=1"); db.exec("PRAGMA application_id=1381189441");
        db.exec("CREATE TABLE metadata(version TEXT NOT NULL)"); db.exec("INSERT INTO metadata VALUES(?)",{r.version});
        db.exec("CREATE TABLE database_info(purpose TEXT NOT NULL,source TEXT NOT NULL)");
        db.exec("INSERT INTO database_info VALUES('working',?)",{r.provenance["source_url"].toString()});
        db.exec("CREATE TABLE signatures(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,version TEXT NOT NULL,enabled INTEGER NOT NULL,algorithm TEXT,mask TEXT,offset INTEGER,min_size INTEGER,max_size INTEGER)");
        db.exec("CREATE TABLE provenance(signature_id TEXT PRIMARY KEY,source_line INTEGER NOT NULL,source_value TEXT NOT NULL)");
        QFile input(staging.path()+"/source.txt"); check(input.open(QIODevice::ReadOnly) && input.size()<=128*1024*1024,QStringLiteral("исходный файл недоступен/больше 128 МиБ"));
        QHash<QByteArray,QByteArray> seen;
        while(!input.atEnd()) {
            const auto raw=input.readLine(4098); ++lines;
            check(raw.size()<=4096,QStringLiteral("слишком длинная строка %1").arg(lines));
            auto line=raw.trimmed(); if(line.isEmpty() || line.startsWith('#')) continue;
            auto fields=line.split(':'); QByteArray digest,name,size;
            if(r.format=="sha256-lines") { check(fields.size()==1,QStringLiteral("формат строки %1").arg(lines)); digest=line; name="Known-malicious-hash"; }
            else {
                check(fields.size()>=3 && fields.size()<=5,QStringLiteral("формат HSB строки %1").arg(lines));
                digest=fields[0]; size=fields[1]; name=fields[2];
                check(!size.isEmpty(),QStringLiteral("пустой размер HSB"));
                for(int i=3;i<fields.size();++i) { bool ok=false; const auto level=fields[i].toUInt(&ok); check(ok && level<=255,QStringLiteral("functional level HSB")); }
                check(!name.isEmpty() && name.size()<=256 && QRegularExpression("^[A-Za-z0-9_.-]+$").match(QString::fromLatin1(name)).hasMatch(),QStringLiteral("имя HSB"));
            }
            check(QRegularExpression("^[0-9a-fA-F]+$").match(QString::fromLatin1(digest)).hasMatch(),QStringLiteral("неверный hex строки %1").arg(lines));
            check(digest.size()==32 || digest.size()==40 || digest.size()==64,QStringLiteral("неизвестный алгоритм/длина строки %1").arg(lines));
            QVariant fileSize;
            if(!size.isEmpty() && size!="*") {
                bool ok=false; auto n=size.toLongLong(&ok); check(ok && n>=0 && QRegularExpression("^[0-9]+$").match(QString::fromLatin1(size)).hasMatch(),QStringLiteral("размер строки %1").arg(lines)); fileSize=n;
            }
            if(digest.size()!=64) { ++unsupported; continue; }
            const auto lowerName=name.toLower();
            if(lowerName.contains("test") || lowerName.contains("eicar") || lowerName.contains("pua")) { ++excluded; continue; }
            digest=digest.toLower(); const auto normalized=size+":"+name;
            if(seen.contains(digest)) { check(seen.value(digest)==normalized,QStringLiteral("конфликт SHA-256 строки %1").arg(lines)); ++duplicates; continue; }
            seen.insert(digest,normalized); check(++accepted<=MaxSignatures,QStringLiteral("лимит записей"));
            const auto id=QStringLiteral("sha256-")+QString::fromLatin1(digest);
            db.exec("INSERT INTO signatures VALUES(?,?,'HASH',?,?,1,'SHA-256',NULL,NULL,?,?)",{id,QString::fromUtf8(name),QString::fromLatin1(digest),r.version,fileSize,fileSize});
            db.exec("INSERT INTO provenance VALUES(?,?,?)",{id,lines,QString::fromUtf8(line)});
        }
        check(input.error()==QFileDevice::NoError,QStringLiteral("ошибка чтения снимка")); check(accepted>0,QStringLiteral("нет принятых SHA-256")); db.commit();
    }
    writeManifest(dbPath); const auto snapshot=loadSignatures(dbPath);
    auto report=r.provenance; report["format"]="resheto-release-v1"; report["importer"]="resheto-import/1"; report["input_format"]=r.format;
    report["version"]=r.version; report["created_utc"]=now(); report["database_sha256"]=snapshot->checksum;
    report["lines"]=QString::number(lines); report["hash"]=QString::number(accepted); report["pattern"]="0"; report["disabled"]="0";
    report["duplicates"]=QString::number(duplicates); report["unsupported_algorithms"]=QString::number(unsupported); report["excluded_test_pua"]=QString::number(excluded);
    saveJson(staging.path()+"/manifest.json",report);
    if(r.beforePublish) r.beforePublish();
    const auto id=QUuid::createUuid().toString(QUuid::WithoutBraces); const auto relative="versions/"+id+"/signatures.db";
    check(QDir().rename(staging.path(),root+"/versions/"+id),QStringLiteral("публикация каталога версии")); staging.setAutoRemove(false);
    select(root,relative); report["database"]=relative; return report;
}
}
