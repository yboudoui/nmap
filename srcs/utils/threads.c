#include "utils/threads.h"
#include <stdlib.h>
#include <pthread.h>

t_error threads_pool(size_t count, void *(*user_routine)(void *),  void *user_data)
{
    t_error     error = 0;
    pthread_t	*threads = calloc(count, sizeof(pthread_t));
    if (threads == NULL) {
        return (err_wrap(&error, 1, "unable to allocat threads"));
    }

    for(size_t i = 0; i < count; i++) {
        pthread_create(&threads[i], NULL, user_routine, user_data);
    }
    for(size_t i = 0; i < count; i++) {
		pthread_join(threads[i], NULL);
    }
    free(threads);
    return (error);
}