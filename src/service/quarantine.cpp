#include "quarantine.h"
#include "quarantine_file.h"
#include "protocol.h"
#include <core/file_access.h>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSqlError>
#include <QScopeGuard>
#include <QUuid>

namespace resheto::service {
namespace {
const QByteArray magic="RESHETO-QUARANTINE-1\n";
const QStringList states{"preparing","stored","restoring","restored","deleting","deleted","failed","interrupted"};

void require(bool good,const QString &message) {
    if(!good)throw Error(message);
}
QString encode(const QJsonObject &object) {
    return QString::fromUtf8(QJsonDocument(object).toJson(QJsonDocument::Compact));
}
QJsonObject decode(const QVariant &value) {
    QJsonParseError error;
    const auto document=QJsonDocument::fromJson(value.toByteArray(),&error);
    require(error.error==QJsonParseError::NoError && document.isObject(),QStringLiteral("Повреждены метаданные карантина"));
    return document.object();
}
bool digest(const QString &value) {
    static const QRegularExpression pattern("\\A[0-9a-f]{64}\\z");
    return pattern.match(value).hasMatch();
}
bool identifier(const QString &value) {
    const QUuid id(value);
    return !id.isNull() && id.toString(QUuid::WithoutBraces)==value;
}
QString checkedId(const QString &id) {
    require(identifier(id),QStringLiteral("Некорректный идентификатор карантина"));
    return id;
}
void bounds(qint64 offset,int limit) {
    require(offset>=0 && limit>=1 && limit<=protocol::pageLimit,QStringLiteral("Некорректные границы страницы карантина или журнала"));
}
QJsonObject publicItem(QJsonObject item) {
    for(const auto *key:{"blob_identity","stage_path","restore_temporary","restored_identity"})item.remove(key);
    return item;
}
QByteArray transform(QByteArray bytes) {
    for(auto &byte:bytes)byte=static_cast<char>(static_cast<unsigned char>(byte)^0xa5);
    return bytes;
}
void write(QFile &file,const QByteArray &bytes) {
    require(file.write(bytes)==bytes.size(),QStringLiteral("Не удалось записать файл карантина: ")+file.errorString());
}

QString pack(HeldFile &source,const QString &path,const QString &expected) {
    QFile output(path);
    require(output.open(QIODevice::WriteOnly|QIODevice::NewOnly),QStringLiteral("Не удалось создать упаковку карантина: ")+output.errorString());
    auto cleanup=qScopeGuard([&]{output.close();output.remove();});
    protectPrivateFile(path);
    write(output,magic);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 size=0;
    for(auto bytes=source.read();!bytes.isEmpty();bytes=source.read()) {
        size+=bytes.size();
        require(size<=quarantineFileLimit,QStringLiteral("Файл вырос во время помещения в карантин"));
        hash.addData(bytes);
        write(output,transform(std::move(bytes)));
    }
    const auto actual=QString::fromLatin1(hash.result().toHex());
    require(source.unchanged() && size==source.size() && actual==expected,QStringLiteral("Файл изменился после обнаружения. Повторите проверку"));
    durableFlush(output);
    cleanup.dismiss();
    return actual;
}

void unpack(HeldFile &blob,const QString &expected,qint64 expectedSize,QFile *output=nullptr) {
    blob.rewind();
    QCryptographicHash hash(QCryptographicHash::Sha256);
    qint64 total=0;
    bool first=true;
    for(auto bytes=blob.read();!bytes.isEmpty();bytes=blob.read()) {
        if(first) {
            require(bytes.startsWith(magic),QStringLiteral("Некорректный формат упаковки карантина"));
            bytes.remove(0,magic.size());
            first=false;
        }
        auto plain=transform(std::move(bytes));
        total+=plain.size();
        require(total<=expectedSize,QStringLiteral("Изменён размер упаковки карантина"));
        hash.addData(plain);
        if(output)write(*output,plain);
    }
    require(!first && blob.unchanged() && total==expectedSize && QString::fromLatin1(hash.result().toHex())==expected,
            QStringLiteral("Контрольная сумма карантина не совпадает. Действие остановлено"));
}

bool within(const QString &path,const QString &directory) {
#ifdef Q_OS_WIN
    return path.compare(directory,Qt::CaseInsensitive)==0 || path.startsWith(directory+"/",Qt::CaseInsensitive);
#else
    return path==directory || path.startsWith(directory+"/");
#endif
}
}

Quarantine::Quarantine(const QString &storage,bool initialize):storage_(absolute(storage)),directory_(storage_+".quarantine"),db_(storage_,false) {
    db_.exec("PRAGMA synchronous=FULL");
    if(!initialize)return;
    db_.exec("CREATE TABLE IF NOT EXISTS service_quarantine_meta(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL)");
    db_.exec("INSERT OR IGNORE INTO service_quarantine_meta VALUES(1,1)");
    auto version=db_.exec("SELECT id,version FROM service_quarantine_meta");
    require(version.next() && version.value(0).toInt()==1 && version.value(1).toInt()==1 && !version.next(),QStringLiteral("Неизвестная версия карантина"));
    db_.exec("CREATE TABLE IF NOT EXISTS service_quarantine(id TEXT PRIMARY KEY,job_id TEXT NOT NULL,result_key TEXT NOT NULL,state TEXT NOT NULL,data TEXT NOT NULL)");
    db_.exec("CREATE TABLE IF NOT EXISTS service_actions(id INTEGER PRIMARY KEY AUTOINCREMENT,time TEXT NOT NULL,action TEXT NOT NULL,object TEXT NOT NULL,job_id TEXT NOT NULL,item_id TEXT NOT NULL,outcome TEXT NOT NULL,reason TEXT NOT NULL)");
    db_.exec("CREATE INDEX IF NOT EXISTS service_quarantine_result ON service_quarantine(job_id,result_key)");
    preparePrivateDirectory(directory_,true);
    recover();
    record("service_started",storage_,{},{},"completed");
}

void Quarantine::diagnostic(const QString &component,const QString &reason) {
    record("diagnostic",component,{},{},"failed",reason);
}

void Quarantine::record(const QString &action,const QString &object,const QString &jobId,const QString &itemId,const QString &outcome,const QString &reason) {
    recordReaction(db_,action,object,jobId,itemId,outcome,reason);
}

void recordReaction(Database &db,const QString &action,const QString &object,const QString &jobId,const QString &itemId,
                    const QString &outcome,const QString &reason) {
    auto value=[](const QString &string){return string.isNull()?QStringLiteral(""):string;};
    db.exec("INSERT INTO service_actions(time,action,object,job_id,item_id,outcome,reason) VALUES(?,?,?,?,?,?,?)",
             {now(),action,value(object),value(jobId),value(itemId),outcome,value(reason)});
}

QJsonObject Quarantine::item(const QString &id) {
    checkedId(id);
    auto query=db_.exec("SELECT job_id,result_key,state,data FROM service_quarantine WHERE id=?",{id});
    require(query.next(),QStringLiteral("Запись карантина не найдена"));
    auto object=decode(query.value(3));
    require(object["id"]==id && object["job_id"]==query.value(0).toString() && object["result_key"]==query.value(1).toString() &&
            object["state"]==query.value(2).toString() && states.contains(object["state"].toString()) &&
            digest(object["result_key"].toString()) && digest(object["sha256"].toString()) &&
            QDir::isAbsolutePath(object["original_path"].toString()) && protocol::counter(object["size"])<=quarantineFileLimit,
            QStringLiteral("Противоречивые метаданные карантина"));
    for(const auto *key:{"created","updated","target_path","reason","blob_identity","stage_path","restore_temporary","restored_identity"})
        require(object[key].isString(),QStringLiteral("Неполные метаданные карантина"));
    return object;
}

void Quarantine::update(const QString &id,const QString &state,const QString &reason) {
    auto object=item(id);
    object["state"]=state;
    object["reason"]=reason.isNull()?QStringLiteral(""):reason;
    object["updated"]=now();
    db_.exec("UPDATE service_quarantine SET state=?,data=? WHERE id=?",{state,encode(object),id});
}

void Quarantine::recover() {
    auto rows=db_.exec("SELECT id FROM service_quarantine WHERE state IN ('preparing','restoring','deleting')");
    QStringList ids;
    while(rows.next())ids.append(rows.value(0).toString());
    rows.finish();
    for(const auto &id:ids) {
        auto object=item(id);
        auto reason=QStringLiteral("Операция прервана. Исходный объект и упаковка автоматически не удаляются");
        if(!object["stage_path"].toString().isEmpty())reason+=QStringLiteral(". Промежуточный путь: ")+object["stage_path"].toString();
        if(!object["restore_temporary"].toString().isEmpty())reason+=QStringLiteral(". Временный файл восстановления: ")+object["restore_temporary"].toString();
        update(id,"interrupted",reason);
        record("recovery",object["original_path"].toString(),object["job_id"].toString(),id,"interrupted",reason);
    }
}

QJsonObject Quarantine::take(const QString &jobId,const QString &key) {
    QString id,original;
    bool durable=false,registered=false;
    try {
        preparePrivateDirectory(directory_);
        require(digest(key),QStringLiteral("Некорректный ключ результата обнаружения"));
        Store history(storage_,true);
        require(history.getJob(jobId).has_value(),QStringLiteral("Задание обнаружения отсутствует"));
        auto rows=db_.exec("SELECT r.data FROM detections d JOIN results r ON r.row_id=d.result_id AND r.job_id=d.job_id WHERE d.job_id=?",{jobId},true);
        std::optional<Result> detection;
        while(rows.next()) {
            const auto candidate=Result::fromJson(decode(rows.value(0)));
            if(resultKey(candidate)==key) {
                require(!detection,QStringLiteral("Результат обнаружения неоднозначен"));
                detection=candidate;
            }
        }
        if(rows.lastError().isValid())throw Error(rows.lastError().text());
        rows.finish();
        require(detection && detection->jobId==jobId && isDetection(*detection) && detection->source!="behavioral" && !detection->identity.isEmpty(),
                QStringLiteral("Карантин доступен для сохранённого файлового обнаружения"));
        require(digest(detection->sha256),QStringLiteral("У старого результата нет SHA-256. Повторите проверку файла"));
        original=absolute(detection->path);
        require(!within(original,directory_) && !within(original,storage_) &&
                !(original.startsWith(storage_+"-",Qt::CaseInsensitive)) && !within(original,storage_+".service.lock"),
                QStringLiteral("Служебные данные нельзя поместить в карантин"));
        auto duplicate=db_.exec("SELECT id FROM service_quarantine WHERE job_id=? AND result_key=? AND state IN ('preparing','stored','restoring','deleting','interrupted')",{jobId,key});
        require(!duplicate.next(),QStringLiteral("Это обнаружение уже связано с действующей записью карантина"));
        duplicate.finish();
        HeldFile source(original);
        require(source.identity()==detection->identity && source.size()==detection->size,
                QStringLiteral("Файл подменён после обнаружения. Повторите проверку"));
        id=QUuid::createUuid().toString(QUuid::WithoutBraces);
        const auto stage=stagingPath(original,id);
        const auto stamp=now();
        QJsonObject object{{"id",id},{"job_id",jobId},{"result_key",key},{"original_path",original},{"sha256",detection->sha256},
                           {"basis",detection->basis},{"detection_name",detectionName(*detection)},
                           {"size",QString::number(source.size())},{"state","preparing"},{"created",stamp},{"updated",stamp},
                           {"target_path",""},{"reason",""},{"blob_identity",""},{"stage_path",stage},
                           {"restore_temporary",""},{"restored_identity",""}};
        db_.exec("BEGIN IMMEDIATE");
        try {
            db_.exec("INSERT INTO service_quarantine(id,job_id,result_key,state,data) VALUES(?,?,?,?,?)",{id,jobId,key,"preparing",encode(object)});
            record("quarantine",original,jobId,id,"requested");
            db_.commit();
        } catch(...) {db_.rollback();throw;}
        registered=true;
        const auto temporary=directory_+"/"+id+".part",blobPath=directory_+"/"+id+".bin";
        pack(source,temporary,detection->sha256);
        publishNew(temporary,blobPath);
        {
            HeldFile blob(blobPath,quarantineFileLimit+magic.size());
            unpack(blob,detection->sha256,source.size());
            object["blob_identity"]=blob.identity();
        }
        db_.exec("UPDATE service_quarantine SET data=? WHERE id=?",{encode(object),id});
        durable=true;
        source.removeVerified(stage,detection->sha256);
        update(id,"stored");
        record("quarantine",original,jobId,id,"completed");
        return publicItem(item(id));
    } catch(const Error &error) {
        if(registered)update(id,durable?"interrupted":"failed",error.message);
        record("quarantine",original,jobId,id,"failed",error.message);
        throw;
    }
}

QJsonObject Quarantine::items(qint64 offset,int limit) {
    bounds(offset,limit);
    auto count=db_.exec("SELECT count(*) FROM service_quarantine");
    require(count.next(),QStringLiteral("Не удалось прочитать количество записей карантина"));
    const auto total=count.value(0).toString();
    auto query=db_.exec("SELECT id FROM service_quarantine ORDER BY rowid DESC LIMIT ? OFFSET ?",{limit,offset});
    QStringList ids;
    while(query.next())ids.append(query.value(0).toString());
    query.finish();
    QJsonArray rows;
    for(const auto &id:ids)rows.append(publicItem(item(id)));
    return {{"rows",rows},{"total",total}};
}

QJsonObject Quarantine::restore(const QString &id,const QString &alternative) {
    QString target,jobId;
    bool started=false;
    try {
        preparePrivateDirectory(directory_);
        auto object=item(id);
        jobId=object["job_id"].toString();
        require(object["state"]=="stored" || object["state"]=="interrupted",QStringLiteral("Запись недоступна для восстановления"));
        target=alternative.isEmpty()?object["original_path"].toString():alternative;
        require(QDir::isAbsolutePath(target) && !target.contains(QChar(u'\0')),QStringLiteral("Укажите абсолютный путь восстановления"));
        target=absolute(target);
        require(!within(target,directory_) && target!=storage_ && !QFileInfo::exists(target) && !isLinkOrReparse(target),
                QStringLiteral("Путь восстановления занят или относится к служебным данным. Выберите другой путь"));
        require(QFileInfo(QFileInfo(target).absolutePath()).isDir(),QStringLiteral("Родительский каталог восстановления отсутствует"));
        HeldFile blob(directory_+"/"+checkedId(id)+".bin",quarantineFileLimit+magic.size());
        require(blob.identity()==object["blob_identity"].toString(),QStringLiteral("Упаковка карантина подменена"));
        unpack(blob,object["sha256"].toString(),protocol::counter(object["size"]));
        const auto temporary=QFileInfo(target).absolutePath()+"/.resheto-restore-"+id+".part";
        object["target_path"]=target;
        object["restore_temporary"]=temporary;
        db_.exec("UPDATE service_quarantine SET data=? WHERE id=?",{encode(object),id});
        update(id,"restoring");
        record("restore",target,jobId,id,"requested");
        started=true;
        QFile output(temporary);
        require(output.open(QIODevice::WriteOnly|QIODevice::NewOnly),QStringLiteral("Не удалось создать новый временный файл восстановления"));
        protectPrivateFile(temporary);
        unpack(blob,object["sha256"].toString(),protocol::counter(object["size"]),&output);
        durableFlush(output);
        output.close();
        publishNew(temporary,target);
        {
            HeldFile restored(target);
            object=item(id);
            object["restored_identity"]=restored.identity();
            db_.exec("UPDATE service_quarantine SET data=? WHERE id=?",{encode(object),id});
        }
        update(id,"restored");
        record("restore",target,jobId,id,"completed");
        return publicItem(item(id));
    } catch(const Error &error) {
        if(started)update(id,"interrupted",error.message);
        record("restore",target,jobId,id,"failed",error.message);
        throw;
    }
}

QJsonObject Quarantine::erase(const QString &id) {
    QString jobId,original;
    bool started=false;
    try {
        preparePrivateDirectory(directory_);
        auto object=item(id);
        jobId=object["job_id"].toString();
        original=object["original_path"].toString();
        require(object["state"]=="stored" || object["state"]=="restored" || object["state"]=="interrupted",
                QStringLiteral("Запись недоступна для удаления из карантина"));
        HeldFile blob(directory_+"/"+checkedId(id)+".bin",quarantineFileLimit+magic.size());
        require(blob.identity()==object["blob_identity"].toString(),QStringLiteral("Упаковка карантина подменена"));
        unpack(blob,object["sha256"].toString(),protocol::counter(object["size"]));
        object["stage_path"]=stagingPath(directory_+"/"+id+".bin",id);
        db_.exec("UPDATE service_quarantine SET data=? WHERE id=?",{encode(object),id});
        update(id,"deleting");
        record("delete",original,jobId,id,"requested");
        started=true;
        // Для POSIX промежуточная сверка относится к упакованным байтам.
        blob.rewind();
        QCryptographicHash packedHash(QCryptographicHash::Sha256);
        for(auto bytes=blob.read();!bytes.isEmpty();bytes=blob.read())packedHash.addData(bytes);
        blob.removeVerified(object["stage_path"].toString(),QString::fromLatin1(packedHash.result().toHex()));
        update(id,"deleted");
        record("delete",original,jobId,id,"completed");
        return publicItem(item(id));
    } catch(const Error &error) {
        if(started)update(id,"interrupted",error.message);
        record("delete",original,jobId,id,"failed",error.message);
        throw;
    }
}

QJsonObject Quarantine::journal(qint64 offset,int limit,const QString &text) {
    bounds(offset,limit);
    require(text.size()<=4096,QStringLiteral("Текст поиска журнала слишком длинный"));
    auto unionSql=QStringLiteral("SELECT 'service-'||id AS id,time,'service' AS source,action,object,job_id,item_id,outcome,reason FROM service_actions "
        "UNION ALL SELECT 'core-'||id,time,source,type,object,job_id,'' AS item_id,code AS outcome,"
        "CASE WHEN json_valid(details) THEN coalesce(json_extract(details,'$.reason'),json_extract(details,'$.basis'),'') ELSE '' END AS reason FROM events");
    auto schema=db_.exec("SELECT 1 FROM sqlite_master WHERE type='table' AND name='network_meta'");
    if(schema.next())unionSql+=QStringLiteral(
        " UNION ALL SELECT 'network-start-'||id,started,'network','job_started',json_extract(data,'$.input'),id,'','running','' FROM network_jobs"
        " UNION ALL SELECT 'network-finish-'||id,json_extract(data,'$.finished'),'network','job_finished',json_extract(data,'$.input'),id,'',"
        "json_extract(data,'$.state'),json_extract(data,'$.error') FROM network_jobs WHERE json_extract(data,'$.finished')<>''"
        " UNION ALL SELECT 'network-detection-'||d.job_id||'-'||d.id,strftime('%Y-%m-%dT%H:%M:%fZ',d.time_us/1000000.0,'unixepoch'),"
        "'network','detection',f.endpoint,d.job_id,d.flow_id,d.rule_id,d.basis FROM network_detections d "
        "JOIN network_flows f ON f.job_id=d.job_id AND f.id=d.flow_id"
        " UNION ALL SELECT 'network-diagnostic-'||d.job_id||'-'||d.code,json_extract(j.data,'$.updated'),'network','diagnostic',"
        "json_extract(j.data,'$.input'),d.job_id,'',d.code,d.reason FROM network_diagnostics d JOIN network_jobs j ON j.id=d.job_id");
    schema.finish();
    const auto where=QStringLiteral(" WHERE instr(lower(source||' '||action||' '||object||' '||job_id||' '||item_id||' '||outcome||' '||reason),lower(?))>0");
    auto count=db_.exec("SELECT count(*) FROM ("+unionSql+")"+where,{text.isNull()?QStringLiteral(""):text});
    require(count.next(),QStringLiteral("Не удалось прочитать количество записей журнала"));
    const auto total=count.value(0).toString();
    auto query=db_.exec("SELECT id,time,source,action,object,job_id,item_id,outcome,reason FROM ("+unionSql+")"+where+" ORDER BY time DESC,id DESC LIMIT ? OFFSET ?",
                        {text.isNull()?QStringLiteral(""):text,limit,offset});
    QJsonArray rows;
    while(query.next()) {
        QJsonObject row;
        const QStringList keys{"id","time","source","action","object","job_id","item_id","outcome","reason"};
        for(int index=0;index<keys.size();++index)row[keys[index]]=query.value(index).toString();
        rows.append(row);
    }
    if(query.lastError().isValid())throw Error(query.lastError().text());
    return {{"rows",rows},{"total",total}};
}
}
