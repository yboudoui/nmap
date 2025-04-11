#include "pool/pool.h"

static void* routine(void *data)
{
    struct s_addr src = {0};
    t_task      task = {};
    while (get_next_task(&task, data))
    {
        send_raw_packet(src, task);
        // print_task(task);
    }
    return (NULL);
}

bool pool(t_arguments *args, t_fp_callback user_callback, void *user_data)
{
    if (!args || !user_callback)
    {
        return (false);
    }
    t_state pool_state = {
        .args = args
    };
    size_t threads_count = args->speedup;
    pthread_t	*threads = calloc(threads_count, sizeof(pthread_t));
    if (threads == NULL)
    {
        return (false);
    }
    for(size_t i = 0; i < threads_count; i++)
    {
        pthread_create(&threads[i], NULL, routine, &pool_state);
    }
    user_callback(user_data);
    for(size_t i = 0; i < threads_count; i++)
    {
		pthread_join(threads[i], NULL);
    }
    return (free(threads), true);
}