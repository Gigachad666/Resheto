#pragma once

#include <core/model.h>

namespace resheto::service {

struct Settings {
    QString endpoint;
    Request scan;
    QString networkRulesPath;
};

Settings loadSettings(const QString &path);

}
