#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include "log.h"

using namespace std;

void LOG(FILE* fp, char* msg)
{
	fprintf(fp, "%s\n", msg);
}
