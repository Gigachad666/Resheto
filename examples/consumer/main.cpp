#include <core/api.h>
#include <QCoreApplication>
#include <QTextStream>
using namespace resheto;
static void require(bool ok) { if(!ok) throw Error(QStringLiteral("Проверка внешнего потребителя не выполнена")); }
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    if(argc!=5) { QTextStream(stderr)<<"consumer <database> <positive-file> <negative-file> <new-storage>\n"; return 2; }
    try {
        Request r; r.signaturePath=app.arguments()[1]; r.storagePath=app.arguments()[4]; r.path=app.arguments()[2];
        bool progress=false; const auto positive=runJob(r,[&](const Job &){progress=true;});
        require(progress && positive.matches==1 && positive.exitCode()==1);
        r.path=app.arguments()[3]; const auto negative=runJob(r); require(negative.checked==1 && negative.exitCode()==0);
        r.path=app.arguments()[2]+".missing"; require(runJob(r).exitCode()==2);
        r.path=app.arguments()[2]; *r.cancel=true; const auto cancelled=runJob(r); require(cancelled.exitCode()==3);
        { Store history(r.storagePath,true); require(history.latest()->id==cancelled.id); }
        { Store reopened(r.storagePath,true); const auto rows=reopened.page(positive.id,0); require(rows.size()==1 && rows[0].outcome=="signature_match" && !rows[0].basis.isEmpty()); }
        QTextStream(stdout)<<QStringLiteral("Внешний потребитель: обнаружение, отсутствие совпадений, ошибка, отмена и повторное чтение — успешно\n");
        return 0;
    } catch(const Error &e) { QTextStream(stderr)<<e.message<<Qt::endl; return 2; }
}
