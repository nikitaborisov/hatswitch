#ifndef R_H_
#define R_H_

#include <sys/types.h>
#include <unistd.h>

#define MAX_BUFFER_SIZE 4096

double calculateCorrelation(const double* x, const double* y, int n);

#endif /* R_H_ */
