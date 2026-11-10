#include "network/session.h"
#include <QCoreApplication>
int main(int argc,char **argv){QCoreApplication app(argc,argv);auto arguments=app.arguments();arguments.removeFirst();return resheto::network::networkWorkerMain(arguments);}
