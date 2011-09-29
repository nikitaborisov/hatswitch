#ifndef THREAD_H_
#define THREAD_H_

#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>

int createThread(pthread_t* thread, void* (*threadFunction)(void*), void* arg, int detachState);
int setThreadAsyncCancel();

int createMutex(pthread_mutex_t* mutex);
int createSemaphore(sem_t* semaphore);

#endif /* THREAD_H_ */
