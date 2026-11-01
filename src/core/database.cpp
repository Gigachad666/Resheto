#include "database.h"
#include <QJsonDocument>
#include <QDir>
#include <QFileInfo>
#include <QSqlError>
#include <QUuid>
#include <mutex>
#include <QDateTime>
#include <QRegularExpression>

namespace resheto {
Database::Database(const QString &path, bool ro) : name_(QUuid::createUuid().toString()) {
    if(path!=":memory:") {
        const auto parent=QFileInfo(absolute(path)).absolutePath();
        if(!QDir(parent).exists()) throw Error(QStringLiteral("Каталог базы данных не существует: %1. Путь к базе: %2").arg(parent,absolute(path)));
    }
    db_=QSqlDatabase::addDatabase("QSQLITE",name_);
    db_.setDatabaseName(path);
    db_.setConnectOptions(ro ? "QSQLITE_OPEN_READONLY;QSQLITE_BUSY_TIMEOUT=3000" : "QSQLITE_BUSY_TIMEOUT=3000");
    if(!db_.open()) {
        const auto message=db_.lastError().text();
        db_=QSqlDatabase(); QSqlDatabase::removeDatabase(name_);
        throw Error(QStringLiteral("SQLite: не удалось открыть базу %1. Проверьте путь и права доступа. Техническая причина: %2").arg(path,message));
    }
}
Database::~Database() { db_.close(); db_=QSqlDatabase(); QSqlDatabase::removeDatabase(name_); }
QSqlQuery Database::exec(const QString &sql, const QVariantList &args,bool forwardOnly) {
    QSqlQuery q(db_);
    q.setForwardOnly(forwardOnly);
    if(!q.prepare(sql)) throw Error(QStringLiteral("SQLite: ")+q.lastError().text());
    for(const auto &v:args) q.addBindValue(v);
    if(!q.exec()) throw Error(QStringLiteral("SQLite: ")+q.lastError().text());
    return q;
}
void Database::transaction() { if(!db_.transaction()) throw Error(db_.lastError().text()); }
void Database::commit() { if(!db_.commit()) throw Error(db_.lastError().text()); }
void Database::rollback() { db_.rollback(); }
static QString encode(const QJsonObject &o) { return QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact)); }
static QString sqlText(const QString &s) { return s.isNull()?QStringLiteral(""):s; }
static QJsonObject decode(const QVariant &value) {
    QJsonParseError error; const auto doc=QJsonDocument::fromJson(value.toByteArray(),&error);
    if(error.error!=QJsonParseError::NoError || !doc.isObject()) throw Error(QStringLiteral("Ожидается корректный JSON-объект"));
    return doc.object();
}
QString Store::preparePath(const QString &path) {
    if(path.trimmed().isEmpty()) throw Error(QStringLiteral("Укажите файл истории результатов"));
    const auto file=absolute(path);
    if(QFileInfo(file).isDir()) throw Error(QStringLiteral("В поле истории нужен файл SQLite, а не каталог: %1").arg(file));
    const auto parent=QFileInfo(file).absolutePath();
    if(!QDir().mkpath(parent)) throw Error(QStringLiteral("Не удалось создать каталог истории: %1. Проверьте путь и права записи.").arg(parent));
    return file;
}
static std::mutex storeSchemaMutex;
Store::Store(const QString &path,bool readOnly) : Store(path,readOnly,std::unique_lock<std::mutex>(storeSchemaMutex)) {}
Store::Store(const QString &path,bool readOnly,std::unique_lock<std::mutex> schemaLock) : db_(path,readOnly) {
    // Только подготовка/миграция схемы; дальнейшие задания используют свои соединения.
    Q_UNUSED(schemaLock);
    db_.exec("PRAGMA foreign_keys=ON");
    auto v=db_.exec("PRAGMA user_version"); v.next(); const int version=v.value(0).toInt();
    if(version<0 || version>3) throw Error(QStringLiteral("Несовместимая схема хранилища"));
    auto app=db_.exec("PRAGMA application_id"); app.next(); const auto application=app.value(0).toInt();
    if(version!=0 && application!=1381189442) throw Error(QStringLiteral("Это не хранилище результатов Решето"));
    if(version>=1) {
        db_.exec("SELECT id,started,data FROM jobs LIMIT 0");
        db_.exec("SELECT row_id,job_id,data FROM results LIMIT 0");
        db_.exec("SELECT id,job_id,result_id,source,time,signature_id,signature_version,basis FROM detections LIMIT 0");
        db_.exec("SELECT id,time,type,source,object,code,job_id FROM events LIMIT 0");
        if(version>=2) db_.exec("SELECT rule_id,rule_version,details FROM detections LIMIT 0");
        else if(!readOnly) {
            db_.transaction();
            try {
                db_.exec("ALTER TABLE detections ADD COLUMN rule_id TEXT NOT NULL DEFAULT ''");
                db_.exec("ALTER TABLE detections ADD COLUMN rule_version TEXT NOT NULL DEFAULT ''");
                db_.exec("ALTER TABLE detections ADD COLUMN details TEXT NOT NULL DEFAULT '{}'");
                db_.exec("PRAGMA user_version=2"); db_.commit();
            } catch(...) { db_.rollback(); throw; }
        }
        if(version==3) db_.exec("SELECT details FROM events LIMIT 0");
        else if(!readOnly) {
            db_.transaction();
            try { db_.exec("ALTER TABLE events ADD COLUMN details TEXT NOT NULL DEFAULT '{}'"); db_.exec("PRAGMA user_version=3"); db_.commit(); }
            catch(...) { db_.rollback(); throw; }
        }
        return;
    }
    if(readOnly) throw Error(QStringLiteral("Хранилище не инициализировано"));
    if(version==0) {
        auto tables=db_.exec("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"); tables.next();
        if(tables.value(0).toInt()!=0) throw Error(QStringLiteral("Нельзя инициализировать чужую базу SQLite"));
    }
    db_.transaction();
    try {
        db_.exec("CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, started TEXT NOT NULL, data TEXT NOT NULL)");
        db_.exec("CREATE TABLE IF NOT EXISTS results(row_id INTEGER PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), data TEXT NOT NULL)");
        db_.exec("CREATE INDEX IF NOT EXISTS results_job ON results(job_id,row_id)");
        db_.exec("CREATE TABLE IF NOT EXISTS detections(id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id), result_id INTEGER NOT NULL REFERENCES results(row_id), source TEXT NOT NULL, time TEXT NOT NULL, signature_id TEXT NOT NULL, signature_version TEXT NOT NULL, basis TEXT NOT NULL, rule_id TEXT NOT NULL DEFAULT '', rule_version TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '{}')");
        db_.exec("CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, time TEXT NOT NULL, type TEXT NOT NULL, source TEXT NOT NULL, object TEXT NOT NULL, code TEXT NOT NULL, job_id TEXT NOT NULL REFERENCES jobs(id), details TEXT NOT NULL DEFAULT '{}')");
        db_.exec("PRAGMA user_version=3"); db_.exec("PRAGMA application_id=1381189442"); db_.commit();
    } catch(...) { db_.rollback(); throw; }
}
void Store::event(const QString &job,const QString &type,const QString &object,const QString &code,const QString &source,const QJsonObject &details) {
    db_.exec("INSERT INTO events(time,type,source,object,code,job_id,details) VALUES(?,?,?,?,?,?,?)",{now(),type,source,object,sqlText(code),job,encode(details)});
}
void Store::recordObservation(const QString &job,const QString &source,const QString &type,const QString &object,const QJsonObject &details) {
    if(job.isEmpty() || source.isEmpty() || type.isEmpty() || object.isEmpty()) throw Error(QStringLiteral("Неполное наблюдение"));
    db_.transaction(); try { event(job,type,object,QStringLiteral(""),source,details); db_.commit(); } catch(...) { db_.rollback(); throw; }
}
std::vector<QJsonObject> Store::observations(const QString &job,qint64 after,int limit) {
    if(after<0 || limit<1 || limit>1000) throw Error(QStringLiteral("Некорректные границы событий"));
    auto schema=db_.exec("PRAGMA user_version"); schema.next(); if(schema.value(0).toInt()<3) return {};
    auto q=db_.exec("SELECT id,time,type,source,object,code,details FROM events WHERE job_id=? AND id>? ORDER BY id LIMIT ?",{job,after,limit});
    std::vector<QJsonObject> out;
    while(q.next()) out.push_back(QJsonObject{{"row_id",q.value(0).toString()},{"time",q.value(1).toString()},{"type",q.value(2).toString()},{"source",q.value(3).toString()},{"object",q.value(4).toString()},{"code",q.value(5).toString()},{"details",decode(q.value(6))}});
    if(q.lastError().isValid()) throw Error(q.lastError().text()); return out;
}
std::optional<QJsonObject> Store::observation(const QString &job,const QString &id) {
    if(id.isEmpty()) return {};
    auto schema=db_.exec("PRAGMA user_version"); schema.next(); if(schema.value(0).toInt()<3) return {};
    auto q=db_.exec("SELECT time,type,source,object,details FROM events WHERE job_id=? AND json_extract(details,'$.id')=? ORDER BY id LIMIT 1",{job,id});
    if(!q.next()) { if(q.lastError().isValid()) throw Error(q.lastError().text()); return {}; }
    return QJsonObject{{"time",q.value(0).toString()},{"type",q.value(1).toString()},{"source",q.value(2).toString()},{"object",q.value(3).toString()},{"details",decode(q.value(4))}};
}
void Store::start(const Job &j) {
    db_.transaction();
    try { db_.exec("INSERT INTO jobs VALUES(?,?,?)",{j.id,j.started,encode(j.json())}); event(j.id,"job_started",j.path,"running"); db_.commit(); }
    catch(...) { db_.rollback(); throw; }
}
void Store::append(const Result &r,const Job &j) {
    db_.transaction();
    try {
        auto q=db_.exec("INSERT INTO results(job_id,data) VALUES(?,?)",{r.jobId,encode(r.json())});
        if(isDetection(r)) {
            db_.exec("INSERT INTO detections(id,job_id,result_id,source,time,signature_id,signature_version,basis,rule_id,rule_version,details) VALUES(?,?,?,?,?,?,?,?,?,?,?)",{QUuid::createUuid().toString(QUuid::WithoutBraces),r.jobId,q.lastInsertId(),r.source,r.time,sqlText(r.signatureId),sqlText(r.signatureVersion),r.basis,sqlText(r.ruleId),sqlText(r.ruleVersion),encode(r.details)});
            event(r.jobId,"detection",r.path,r.source=="signature"?r.signatureId:r.ruleId,r.source);
        } else if(r.outcome=="not_checked" || r.completeness=="partial") event(r.jobId,r.skipped ? "skipped" : "file_error",r.path,r.code,r.source);
        db_.exec("UPDATE jobs SET data=? WHERE id=?",{encode(j.json()),j.id}); db_.commit();
    } catch(...) { db_.rollback(); throw; }
}
void Store::finish(const Job &j) {
    db_.transaction();
    try { db_.exec("UPDATE jobs SET data=? WHERE id=?",{encode(j.json()),j.id}); event(j.id,"job_finished",j.path,j.state); db_.commit(); }
    catch(...) { db_.rollback(); throw; }
}
std::optional<Job> Store::latest() {
    auto q=db_.exec("SELECT id FROM jobs ORDER BY rowid DESC LIMIT 1");
    if(!q.next()) { if(q.lastError().isValid()) throw Error(QStringLiteral("Ошибка чтения хранилища: ")+q.lastError().text()); return {}; }
    const auto id=q.value(0).toString(); q.finish(); return getJob(id);
}
std::vector<Job> Store::jobs(qint64 offset,int limit) {
    if(offset<0 || limit<1 || limit>200) throw Error(QStringLiteral("Некорректные границы списка заданий"));
    auto q=db_.exec("SELECT id,started,data FROM jobs ORDER BY rowid DESC LIMIT ? OFFSET ?",{limit,offset});
    std::vector<Job> out;
    while(q.next()) {
        auto j=Job::fromJson(decode(q.value(2)));
        if(j.id!=q.value(0).toString() || j.started!=q.value(1).toString()) throw Error(QStringLiteral("JSON задания не соответствует строке jobs"));
        out.push_back(std::move(j));
    }
    if(q.lastError().isValid()) throw Error(q.lastError().text()); return out;
}
std::optional<Job> Store::getJob(const QString &id,bool recoverRunning) {
    db_.transaction();
    try {
        std::optional<Job> result;
        {
            auto q=db_.exec("SELECT id,started,data FROM jobs WHERE id=?",{id});
            if(q.next()) {
                Job j=Job::fromJson(decode(q.value(2)));
                if(j.id!=q.value(0).toString() || j.started!=q.value(1).toString()) throw Error(QStringLiteral("JSON задания не соответствует строке jobs"));
                auto rows=db_.exec("SELECT row_id,data FROM results WHERE job_id=? ORDER BY row_id",{j.id},true);
                auto schema=db_.exec("PRAGMA user_version"); schema.next(); const int version=schema.value(0).toInt(); schema.finish();
                qint64 count=0,checked=0,matches=0,errors=0,skipped=0; QString lastPath,lastName;
                while(rows.next()) {
                    const auto r=Result::fromJson(decode(rows.value(1)));
                    if(r.jobId!=j.id || r.databaseVersion!=j.databaseVersion || (j.formatVersion==2 && r.rulesVersion!=(r.source=="behavioral"?j.behaviorVersion:j.rulesVersion))) throw Error(QStringLiteral("Результат не соответствует заданию/версии базы"));
                    ++count;
                    auto detection=db_.exec("SELECT source,time,signature_id,signature_version,basis FROM detections WHERE job_id=? AND result_id=?",{j.id,rows.value(0)});
                    if(isDetection(r)) {
                        if(!detection.next() || detection.value(0).toString()!=r.source || detection.value(1).toString()!=r.time || detection.value(2).toString()!=r.signatureId || detection.value(3).toString()!=r.signatureVersion || detection.value(4).toString()!=r.basis)
                            throw Error(QStringLiteral("Запись обнаружения не соответствует результату"));
                        if(detection.next()) throw Error(QStringLiteral("Повторная запись обнаружения результата"));
                    } else if(detection.next()) throw Error(QStringLiteral("Ложная запись обнаружения без совпадения"));
                    if(detection.lastError().isValid()) throw Error(detection.lastError().text());
                    if(isDetection(r) && version>=2) {
                        auto rule=db_.exec("SELECT rule_id,rule_version,details FROM detections WHERE job_id=? AND result_id=?",{j.id,rows.value(0)}); rule.next();
                        if(rule.value(0).toString()!=r.ruleId || rule.value(1).toString()!=r.ruleVersion || decode(rule.value(2))!=r.details) throw Error(QStringLiteral("Основания обнаружения не соответствуют результату"));
                    }
                    if(!r.eventId.isEmpty()) {
                        const auto linked=observation(j.id,r.eventId);
                        if(!linked) throw Error(QStringLiteral("Отсутствует связанное событие результата"));
                        if((*linked)["type"]=="process_image") {
                            const auto d=(*linked)["details"].toObject(),p=d["process"].toObject();
                            auto positive=[](const QJsonValue &v) { bool ok=false; return v.isString() && QRegularExpression("^[0-9]+$").match(v.toString()).hasMatch() && v.toString().toULongLong(&ok)>0 && ok; };
                            bool parentOk=false; const auto parent=p["parent_pid"].toString().toULongLong(&parentOk); Q_UNUSED(parent);
                            if(!positive(p["pid"]) || !positive(p["start_time"]) || !parentOk || !p["parent_pid"].isString() || p["image"]!=r.path || (*linked)["object"]!=r.path || (*linked)["source"]!="process_monitor" || d["id"]!=r.eventId || d["operation"]!="image_file" || d["coverage"]!="image_file_by_path" || !QDateTime::fromString(d["time"].toString(),Qt::ISODateWithMs).isValid())
                                throw Error(QStringLiteral("Некорректная связь результата с файлом процесса"));
                        }
                    }
                    if(r.skipped) ++skipped;
                    else if(r.outcome=="not_checked") { if(r.code!="cancelled") ++errors; }
                    else { ++checked; if(r.completeness=="partial") ++errors; if(isDetection(r)) { ++matches; lastPath=r.path; lastName=detectionName(r); } }
                }
                if(rows.lastError().isValid()) throw Error(rows.lastError().text());
                auto detectionCount=db_.exec("SELECT count(*) FROM detections WHERE job_id=?",{j.id}); detectionCount.next();
                if(detectionCount.value(0).toLongLong()!=matches) throw Error(QStringLiteral("Количество обнаружений не соответствует результатам"));
                if(count!=j.results || checked!=j.checked || matches!=j.matches || errors!=j.errors || skipped!=j.skipped || lastPath!=j.detectionPath || lastName!=j.detectionName)
                    throw Error(QStringLiteral("Сводка задания не соответствует сохранённым результатам"));
                result=std::move(j);
            }
            if(q.lastError().isValid()) throw Error(q.lastError().text());
        }
        db_.commit();
        if(recoverRunning && result && result->state=="running") { result->state="failed"; result->error=QStringLiteral("Задание не завершено: выполнение прервано или ещё продолжается"); }
        return result;
    } catch(const Error &e) { db_.rollback(); throw Error(QStringLiteral("Ошибка чтения хранилища: ")+e.message); }
}
std::vector<Result> Store::page(const QString &id,qint64 after,int limit) {
    if(limit<1 || limit>1000) throw Error(QStringLiteral("Размер страницы вне диапазона 1..1000"));
    try {
        auto q=db_.exec("SELECT row_id,data FROM results WHERE job_id=? AND row_id>? ORDER BY row_id LIMIT ?",{id,after,limit});
        std::vector<Result> out; qint64 cursor=after;
        while(q.next()) {
            cursor=q.value(0).toLongLong(); auto r=Result::fromJson(decode(q.value(1)));
            if(r.jobId!=id) throw Error(QStringLiteral("Результат не соответствует job_id строки results"));
            out.push_back(std::move(r));
        }
        if(q.lastError().isValid()) throw Error(q.lastError().text());
        lastRow_=cursor; return out;
    } catch(const Error &e) { throw Error(QStringLiteral("Ошибка чтения хранилища: ")+e.message); }
}
ResultPage Store::query(const QString &id,const ResultQuery &request) {
    if(request.limit<1 || request.limit>1000 || request.offset<0 || request.upperRow<0) throw Error(QStringLiteral("Некорректные границы страницы"));
    db_.transaction();
    try {
        ResultPage page; page.upperRow=request.upperRow;
        if(!page.upperRow) { auto q=db_.exec("SELECT coalesce(max(row_id),0) FROM results WHERE job_id=?",{id}); q.next(); page.upperRow=q.value(0).toLongLong(); }
        QString where="job_id=? AND row_id<=?"; QVariantList args{id,page.upperRow};
        auto schema=db_.exec("PRAGMA user_version"); schema.next(); const bool eventDetails=schema.value(0).toInt()>=3; schema.finish();
        const QString process=eventDetails?QString("(json_extract(data,'$.analysis_source')='behavioral' OR EXISTS(SELECT 1 FROM events e WHERE e.job_id=results.job_id AND e.type='process_image' AND json_extract(e.details,'$.id')=json_extract(results.data,'$.event_id')))"):QString("0");
        if(request.object==ResultObject::Processes) where+=" AND "+process;
        else if(request.object==ResultObject::Files) where+=" AND NOT coalesce("+process+",0) AND coalesce(json_extract(data,'$.event_id'),'')<>''";
        else if(request.object==ResultObject::Manual) where+=" AND coalesce(json_extract(data,'$.event_id'),'')='' AND NOT coalesce("+process+",0)";
        else if(request.object!=ResultObject::All) throw Error(QStringLiteral("Неизвестный тип объектов"));
        if(request.filter==ResultFilter::Matches) where+=" AND json_extract(data,'$.outcome') IN ('signature_match','heuristic_match','behavioral_match')";
        else if(request.filter==ResultFilter::NotChecked) where+=" AND (json_extract(data,'$.outcome')='not_checked' OR json_extract(data,'$.completeness')='partial')";
        else if(request.filter!=ResultFilter::All) throw Error(QStringLiteral("Неизвестный фильтр"));
        if(!request.path.isEmpty()) { where+=" AND instr(json_extract(data,'$.path'),?)>0"; args.push_back(request.path); }
        if(!request.text.isEmpty()) {
            where+=" AND (instr(lower(json_extract(data,'$.path')),lower(?))>0 OR instr(lower(coalesce(json_extract(data,'$.basis'),'')||' '||coalesce(json_extract(data,'$.signature_name'),'')||' '||coalesce(json_extract(data,'$.rule_name'),'')||' '||coalesce(json_extract(data,'$.rule_id'),'')||' '||coalesce(json_extract(data,'$.signature_id'),'')||' '||coalesce(json_extract(data,'$.reason'),'')),lower(?))>0";
            args.push_back(request.text); args.push_back(request.text);
            if(eventDetails) { where+=" OR EXISTS(SELECT 1 FROM events e WHERE e.job_id=results.job_id AND json_extract(e.details,'$.id')=json_extract(results.data,'$.event_id') AND (instr(json_extract(e.details,'$.process.pid'),?)>0 OR instr(json_extract(e.details,'$.parent.pid'),?)>0))"; args.push_back(request.text); args.push_back(request.text); }
            where+=")";
        }
        QString key;
        switch(request.sort) {
        case ResultSort::Insertion: key="row_id"; break;
        case ResultSort::Path: key="json_extract(data,'$.path') COLLATE BINARY"; break;
        case ResultSort::Outcome: key="json_extract(data,'$.outcome') COLLATE BINARY"; break;
        case ResultSort::Signature: key="coalesce(nullif(json_extract(data,'$.signature_name'),''),json_extract(data,'$.rule_name'),'') COLLATE BINARY"; break;
        default: throw Error(QStringLiteral("Неизвестная сортировка"));
        }
        { auto q=db_.exec("SELECT count(*) FROM results WHERE "+where,args); q.next(); page.total=q.value(0).toLongLong(); }
        args.push_back(request.limit); args.push_back(request.offset);
        const auto direction=request.descending?QString(" DESC"):QString(" ASC");
        auto q=db_.exec("SELECT data FROM results WHERE "+where+" ORDER BY "+key+direction+",row_id"+direction+" LIMIT ? OFFSET ?",args,true);
        while(q.next()) { auto r=Result::fromJson(decode(q.value(0))); if(r.jobId!=id) throw Error(QStringLiteral("Результат не соответствует заданию")); page.rows.push_back(std::move(r)); }
        if(q.lastError().isValid()) throw Error(q.lastError().text()); q.finish(); db_.commit(); return page;
    } catch(const Error &e) { db_.rollback(); throw Error(QStringLiteral("Ошибка чтения хранилища: ")+e.message); }
}
}
