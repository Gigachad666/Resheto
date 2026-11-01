#pragma once
#include "model.h"
#include <QSqlDatabase>
#include <QSqlQuery>
#include <mutex>

namespace resheto {
enum class ResultFilter { All, Matches, NotChecked };
enum class ResultSort { Insertion, Path, Outcome, Signature };
enum class ResultObject { All, Manual, Files, Processes };
struct ResultQuery {
    ResultFilter filter=ResultFilter::All;
    ResultSort sort=ResultSort::Insertion;
    QString path;
    bool descending=false;
    qint64 offset=0, upperRow=0;
    int limit=200;
    QString text; // Путь, основание, правило либо PID связанного процессного события.
    ResultObject object=ResultObject::All;
};
struct ResultPage { std::vector<Result> rows; qint64 total=0, upperRow=0; };
class Database {
    QString name_;
    QSqlDatabase db_;
public:
    Database(const QString &path, bool readOnly);
    ~Database();
    Database(const Database &) = delete;
    Database &operator=(const Database &) = delete;
    QSqlQuery exec(const QString &sql, const QVariantList &args = {}, bool forwardOnly = false);
    void transaction();
    void commit();
    void rollback();
};
class Store {
    Database db_;
public:
    // Явная подготовка выбранного пользователем пути: создаёт только родительский каталог.
    static QString preparePath(const QString &path);
    explicit Store(const QString &path, bool readOnly = false);
    void start(const Job &job);
    void append(const Result &result, const Job &progress);
    void finish(const Job &job);
    void recordObservation(const QString &jobId,const QString &source,const QString &type,const QString &object,const QJsonObject &details);
    std::vector<QJsonObject> observations(const QString &jobId,qint64 afterRow=0,int limit=200);
    std::optional<QJsonObject> observation(const QString &jobId,const QString &eventId);
    std::optional<Job> latest();
    std::optional<Job> getJob(const QString &id,bool recoverRunning=true);
    std::vector<Job> jobs(qint64 offset=0,int limit=50);
    // Постраничное чтение: GUI и CLI не загружают весь журнал в память.
    std::vector<Result> page(const QString &jobId, qint64 afterRow, int limit = 200);
    ResultPage query(const QString &jobId,const ResultQuery &query);
    qint64 lastRow() const { return lastRow_; }
private:
    Store(const QString &path,bool readOnly,std::unique_lock<std::mutex> schemaLock);
    qint64 lastRow_ = 0;
    void event(const QString &job, const QString &type, const QString &object, const QString &code,const QString &source="signature",const QJsonObject &details={});
};
}
