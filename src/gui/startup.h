#pragma once

#include "core/model.h"

class QCommandLineParser;
class QDir;

namespace resheto {
struct GuiStartup {
    Request request;
    QString behaviorPath;
    QString processScope;
    QString watchPath;
    QString networkRules;
};

void addGuiOptions(QCommandLineParser &parser,const QDir &executableDir,const QDir &workingDir);
GuiStartup guiStartup(const QCommandLineParser &parser,const QDir &localDataDir);
}
