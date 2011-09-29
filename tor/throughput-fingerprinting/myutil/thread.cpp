#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <pthread.h>
#include <semaphore.h>
#include "thread.h"

using namespace std;

/* Create a thread. */
int createThread(pthread_t* thread, void* (*threadFunction)(void*), void* arg, int detachState)
{
	int res;

	pthread_attr_t thread_attr;

	res = pthread_attr_init(&thread_attr);

	if(res != 0)
	{
		perror("[createThread] Thread attribute creation failed. Terminating process.\n");
		exit(2);
	}

	res = pthread_attr_setdetachstate(&thread_attr, detachState);
	if(res != 0)
	{
		perror("[createThread] Setting detachstate thread attribute failed. Terminating process.\n");
		exit(2);
	}

	res = pthread_create(thread, &thread_attr, threadFunction, arg);
	if(res != 0)
	{
		perror("[createThread] Thread init failed. Terminating process.\n");
		exit(2);
	}

	(void)pthread_attr_destroy(&thread_attr);

	return res;
}

/* Enables asynchronous cancellation of a thread. */
int setThreadAsyncCancel()
{
	int res, oldVal;

	res = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldVal);
	if(res != 0)
	{
		perror("[setThreadAsyncCancel] Call to pthread_setcancelstate failed. Terminating process.\n");
		exit(2);
	}

	res = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldVal);
	if(res != 0)
	{
		perror("[setThreadAsyncCancel] Call to pthread_setcanceltype failed. Terminating process.\n");
		exit(2);
	}

	return res;
}

/* Create a mutex. */
int createMutex(pthread_mutex_t* mutex)
{
	int res;

	res = pthread_mutex_init(mutex, NULL);

	if(res != 0)
	{
		perror("[createMutex] Mutex init failed. Terminating process.\n");
		exit(2);
	}

	return res;
}

/* Create a semaphore. */
int createSemaphore(sem_t* semaphore)
{
	int res;

	res = sem_init(semaphore, 0, 0);

	if(res != 0)
	{
		perror("[createSemaphore] Semaphore init failed. Terminating process.\n");
		exit(2);
	}

	return res;
}
