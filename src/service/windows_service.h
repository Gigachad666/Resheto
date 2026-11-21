#pragma once

namespace resheto::service {
int runUnderScm(int argc,char **argv,int (*entry)(int,char **));
bool scmStopRequested();
bool runningUnderScm();
void scmReady();
}
