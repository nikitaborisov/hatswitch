#ifndef LOG_H_
#define LOG_H_

#include <sys/types.h>
#include <unistd.h>
#include <cstdio>

using namespace std;

void LOG(FILE* fp, char* msg);

#endif /* LOG_H_ */
