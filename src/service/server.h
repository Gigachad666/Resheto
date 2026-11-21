#pragma once
#include <core/model.h>

namespace resheto::service {
int serve(const QString &endpoint,Request defaults,const QString &networkRulesPath={});
}
