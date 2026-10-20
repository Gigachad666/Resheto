#include "signatures.h"
#include "database.h"
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <limits>

namespace resheto {
static QByteArray fileHash(const QString &path) {
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)) throw Error(QStringLiteral("Не открыть базу: ")+f.errorString());
    QCryptographicHash h(QCryptographicHash::Sha256);
    while(!f.atEnd()) {
        auto b=f.read(65536);
        if(b.isEmpty() && f.error()!=QFileDevice::NoError) throw Error(QStringLiteral("Ошибка чтения базы"));
        h.addData(b);
    }
    return h.result().toHex();
}
void writeManifest(const QString &path) {
    QSaveFile f(path+".sha256");
    if(!f.open(QIODevice::WriteOnly) || f.write(fileHash(path)+"\n")!=65 || !f.commit()) throw Error(QStringLiteral("Не сохранить manifest"));
}
static void require(bool ok,const QString &what) { if(!ok) throw Error(QStringLiteral("Некорректная база сигнатур: ")+what); }
static QByteArray hex(const QString &s) {
    require(!s.isEmpty() && s.size()%2==0 && QRegularExpression("^[0-9a-fA-F]+$").match(s).hasMatch(),QStringLiteral("ожидается непустая строка hex"));
    return QByteArray::fromHex(s.toLatin1());
}
static std::optional<qint64> number(const QVariant &v) {
    if(v.isNull()) return {};
    bool ok=false; auto n=v.toString().toLongLong(&ok);
    require(ok && n>=0,QStringLiteral("offset/size должен быть целым 0..INT64_MAX")); return n;
}
std::shared_ptr<const Snapshot> loadSignatures(const QString &path) {
    const auto file=absolute(path);
    require(!QFileInfo::exists(file+"-wal") && !QFileInfo::exists(file+"-journal"),QStringLiteral("база имеет активный WAL/journal; завершите запись и подготовьте manifest"));
    require(QFileInfo(file).isFile() && QFileInfo(file).size()<=64*1024*1024,QStringLiteral("база отсутствует либо больше 64 МиБ"));
    QFile manifest(file+".sha256");
    require(manifest.open(QIODevice::ReadOnly) && manifest.size()<=128,QStringLiteral("нет manifest .sha256"));
    const auto expected=manifest.readAll().trimmed().toLower();
    require(QRegularExpression("^[0-9a-f]{64}$").match(QString::fromLatin1(expected)).hasMatch(),QStringLiteral("формат manifest"));
    const auto before=fileHash(file);
    require(before==expected,QStringLiteral("контрольная сумма"));
    auto snap=std::make_shared<Snapshot>(); snap->path=file; snap->checksum=QString::fromLatin1(before);
    {
        Database db(file,true); db.transaction();
        auto v=db.exec("PRAGMA user_version"); require(v.next() && v.value(0).toInt()==1,QStringLiteral("версия схемы"));
        auto app=db.exec("PRAGMA application_id"); require(app.next() && app.value(0).toInt()==1381189441,QStringLiteral("application_id"));
        auto integrity=db.exec("PRAGMA quick_check"); require(integrity.next() && integrity.value(0).toString()=="ok",QStringLiteral("повреждение SQLite"));
        auto meta=db.exec("SELECT version FROM metadata");
        require(meta.next(),QStringLiteral("нет версии базы")); snap->version=meta.value(0).toString();
        require(!snap->version.trimmed().isEmpty() && snap->version.size()<=256 && !meta.next(),QStringLiteral("версия базы"));
        auto q=db.exec("SELECT id,name,kind,value,version,enabled,algorithm,mask,offset,min_size,max_size FROM signatures ORDER BY id COLLATE BINARY");
        QSet<QString> ids; qsizetype total=0; int count=0;
        while(q.next()) {
            require(++count<=MaxSignatures,QStringLiteral("слишком много записей"));
            Signature s; s.id=q.value(0).toString(); s.name=q.value(1).toString(); s.kind=q.value(2).toString(); s.version=q.value(4).toString();
            require(!s.id.trimmed().isEmpty() && s.id.size()<=256 && !ids.contains(s.id),QStringLiteral("пустой/повторный id")); ids.insert(s.id);
            require(!s.name.trimmed().isEmpty() && s.name.size()<=256 && !s.version.trimmed().isEmpty() && s.version.size()<=256,QStringLiteral("name/version"));
            const QString enabled=q.value(5).toString(); require(enabled=="0" || enabled=="1",QStringLiteral("enabled"));
            s.value=hex(q.value(3).toString());
            s.offset=number(q.value(8)); s.minSize=number(q.value(9)); s.maxSize=number(q.value(10));
            require(!s.minSize || !s.maxSize || *s.minSize<=*s.maxSize,QStringLiteral("min_size > max_size"));
            if(s.kind=="HASH") {
                require(s.value.size()==32 && q.value(6).toString()=="SHA-256",QStringLiteral("digest/algorithm"));
                require(q.value(7).isNull() && !s.offset,QStringLiteral("маска/offset для HASH"));
            } else if(s.kind=="PATTERN") {
                require(s.value.size()<=MaxPattern && q.value(6).isNull(),QStringLiteral("длина PATTERN/algorithm"));
                if(!q.value(7).isNull()) {
                    const auto mask=q.value(7).toString();
                    require(mask.size()==s.value.size() && QRegularExpression("^[01]+$").match(mask).hasMatch() && mask.contains('1'),QStringLiteral("маска"));
                    s.mask=mask.toLatin1();
                }
                require(!s.offset || *s.offset<=std::numeric_limits<qint64>::max()-s.value.size(),QStringLiteral("переполнение offset"));
            } else require(false,QStringLiteral("неизвестный kind"));
            total+=s.value.size()+s.mask.size(); require(total<=MaxSignatureBytes,QStringLiteral("суммарная длина сигнатур"));
            if(enabled=="1") {
                if(s.kind=="PATTERN") snap->maxPattern=qMax(snap->maxPattern,s.value.size());
                snap->entries.push_back(std::move(s));
            }
        }
        require(!snap->entries.empty(),QStringLiteral("нет активных сигнатур")); db.commit();
    }
    require(fileHash(file)==before,QStringLiteral("база изменилась при загрузке"));
    return snap;
}
void createSignatures(const QString &input,const QString &path) {
    require(!QFileInfo::exists(path) && !QFileInfo::exists(path+".sha256"),QStringLiteral("выходной файл уже существует"));
    QFile source(input); require(source.open(QIODevice::ReadOnly) && source.size()<=32*1024*1024,QStringLiteral("JSON недоступен/слишком большой"));
    QJsonParseError err; auto doc=QJsonDocument::fromJson(source.readAll(),&err);
    require(err.error==QJsonParseError::NoError && doc.isObject() && doc.object()["signatures"].isArray(),QStringLiteral("JSON"));
    {
        Database db(path,false); db.transaction();
        db.exec("PRAGMA user_version=1");
        db.exec("PRAGMA application_id=1381189441");
        db.exec("CREATE TABLE metadata(version TEXT NOT NULL)");
        db.exec("INSERT INTO metadata VALUES(?)",{doc.object()["version"].toString()});
        db.exec("CREATE TABLE signatures(id TEXT PRIMARY KEY,name TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,version TEXT NOT NULL,enabled INTEGER NOT NULL,algorithm TEXT,mask TEXT,offset INTEGER,min_size INTEGER,max_size INTEGER)");
        for(const auto &v:doc.object()["signatures"].toArray()) {
            require(v.isObject(),QStringLiteral("запись JSON")); const auto o=v.toObject();
            for(const auto *key:{"offset","min_size","max_size"}) {
                if(!o[key].isUndefined() && !o[key].isNull()) {
                    require(o[key].isString() && QRegularExpression("^[0-9]+$").match(o[key].toString()).hasMatch(),QStringLiteral("offset/size в JSON задаются десятичными строками"));
                    number(o[key].toVariant());
                }
            }
            auto nullable=[&](const char *key)->QVariant { return o[key].isUndefined() || o[key].isNull() ? QVariant() : o[key].toVariant(); };
            db.exec("INSERT INTO signatures VALUES(?,?,?,?,?,?,?,?,?,?,?)",{o["id"].toVariant(),o["name"].toVariant(),o["kind"].toVariant(),o["value"].toVariant(),o["version"].toVariant(),o["enabled"].toVariant(),nullable("algorithm"),nullable("mask"),nullable("offset"),nullable("min_size"),nullable("max_size")});
        }
        db.commit();
    }
    writeManifest(path);
    loadSignatures(path); // Повторная проверка точно тем же валидатором, что используется сканером.
}
}
