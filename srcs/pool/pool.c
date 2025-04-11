
static void* routine(void *data) {
    t_task      task = {};
    while (get_next_task(&task, data))
    {
        print_task(task);
    }
    return (NULL);
}

bool pool(t_arguments *args, t_fp_callback callback) {
    if (!args || !callback) {
        return (false);
    }
    t_state pool_state = {
        .args = args
    };
    size_t threads_count = args->speedup;
    pthread_t	*threads = calloc(threads_count, sizeof(pthread_t));
    if (threads == NULL) {
        return (false);
    }
    for(size_t i = 0; i < threads_count; i++) {
        pthread_create(&threads[i], NULL, routine, &pool_state);
    }
    callback();
    for(size_t i = 0; i < threads_count; i++) {
		pthread_join(threads[i], NULL);
    }

    return (free(threads), true);
}