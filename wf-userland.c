#include <stdbool.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include "wf-userland.h"


#define die(...) do { fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE); } while(0)

static pthread_t wf_patch_thread;
static pthread_cond_t wf_cond_initiate;
static pthread_cond_t wf_cond_all_threads_migrated; // local quiesence
static pthread_barrier_t wf_global_barrier;

static struct wf_configuration wf_config;

static void wf_initiate_patching(void);

static void wf_sigpatch_handler(int sig) {
    pthread_cond_signal(&wf_cond_initiate);
    printf("signal\n");
}

static int wf_config_get(char * name, int default_value) {
    char *env = getenv(name);
    if (!env) return default_value;
    char *ptr;
    long ret;
    ret = strtol(env, &ptr, 10);
    if (!ptr || *ptr != '\0') die("invalid env config %s: %s", name, env);
    return (int) ret;
}

// Returns the a timestamp in miliseconds. The first call zeroes the clock
static double wf_timestamp(void) { // returns 0 seconds first time called
    static struct timespec ts0;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    if (!ts0.tv_sec) ts0 = ts;
    return (ts.tv_sec - ts0.tv_sec)*1000. + (ts.tv_nsec - ts0.tv_nsec) / 1000000.;
}


static void* wf_patch_thread_entry(void *arg) {
    (void)arg;
    { // Initialize Signals
        struct sigaction act;
        sigemptyset (&act.sa_mask);
        act.sa_flags = 0;
        act.sa_handler = wf_sigpatch_handler;
        if (sigaction(SIGPATCH, &act, NULL) != 0) {
            perror("sigaction");
        }
    }

    pthread_mutex_t wf_mutex;
    pthread_mutex_init(&wf_mutex, NULL);

    pthread_mutex_lock(&wf_mutex);
    while (true) {
        // Wait for signal, or do periodic tests
        int wait = wf_config_get("WF_CYCLIC", -1);
        if (wait == -1) {
            pthread_cond_wait(&wf_cond_initiate, &wf_mutex);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += wait;
            pthread_cond_timedwait(&wf_cond_initiate, &wf_mutex, &ts);
        }

        wf_initiate_patching();
    }
    return NULL;
}

typedef enum {
    IDLE,
    GLOBAL_QUIESENCE,
    LOCAL_QUIESENCE,
} wf_state_t;

static volatile wf_state_t wf_state;

static volatile int wf_remaining_threads;
static volatile int wf_target_generation;
static __thread int wf_current_generation;


typedef struct {
    double timestamp;
    char *name;
    unsigned int threads;
} time_thread_point_t;

static time_thread_point_t *wf_timepoints;
volatile unsigned int wf_timepoints_idx;

int wf_timepoint(char *name, unsigned int threads) {
    assert (wf_timepoints != NULL);

    int idx = __atomic_fetch_add(&wf_timepoints_idx, 1, __ATOMIC_SEQ_CST);
    time_thread_point_t x = {
        .timestamp = wf_timestamp(),
        .name = name,
        .threads = threads,
    };
    wf_timepoints[idx] = x;

    return idx;
}


static void wf_initiate_patching(void) {
    double wf_time_start = wf_timestamp();
    
    bool global = wf_config_get("WF_GLOBAL", 1);

    int threads = wf_config.thread_count(global);

    wf_timepoints = malloc(sizeof(time_thread_point_t) *  threads);
    wf_timepoints_idx = 0;

    wf_state = IDLE;

    if (global) {
        pthread_barrier_init(&wf_global_barrier, NULL, threads + 1);

        ////////////////////////////////////////////////////////////////
        // Now we reach global quiesence with our application
        wf_state = GLOBAL_QUIESENCE;

        // Some Applications need a trigger to reach global quiesence
        if (wf_config.trigger_global_quiesence)
            wf_config.trigger_global_quiesence();

        pthread_barrier_wait(&wf_global_barrier);
        ////////////////////////////////////////////////////////////////
        double wf_time_global_quiesence = wf_timestamp();

        for (unsigned int i = 0; i < threads; i++){
            printf(">>> %s %.2f (%d threads)\n",
                   wf_timepoints[i].name,
                   wf_timepoints[i].timestamp - wf_time_start,
                   wf_timepoints[i].threads
                );
        }

        printf("reached global_quiesence in %f ms\n",
               wf_time_global_quiesence - wf_time_start
        );

        if (wf_config.patch_applied)
            wf_config.patch_applied();
        ////////////////////////////////////////////////////////////////
        // Let's leave the global quiesence point
        wf_state = IDLE;
        pthread_barrier_wait(&wf_global_barrier);
        ////////////////////////////////////////////////////////////////

        pthread_barrier_destroy(&wf_global_barrier);
    } else {
        ////////////////////////////////////////////////////////////////
        wf_remaining_threads = threads;
        printf("Waiting for %d threads\n", wf_remaining_threads);
        wf_target_generation ++;
        wf_state = LOCAL_QUIESENCE;

        // Some applications require a trigger to reach local quiesence
        if (wf_config.trigger_local_quiesence)
            wf_config.trigger_local_quiesence();

        pthread_mutex_t dummy;
        pthread_mutex_init(&dummy, NULL);
        pthread_mutex_lock(&dummy);
        pthread_cond_wait(&wf_cond_all_threads_migrated, &dummy);
        double wf_time_migrated = wf_timestamp();


        for (unsigned int i = 0; i < threads; i++){
            printf(">>> %s %.2f (%d threads)\n",
                   wf_timepoints[i].name,
                   wf_timepoints[i].timestamp - wf_time_start,
                   wf_timepoints[i].threads
                );
        }

        printf("migrated all threads in  in %f ms\n",
               wf_time_migrated - wf_time_start
            );

        wf_state = IDLE;
    }

    printf("----\n");


    // Must be called in all circumstances as thread count could take
    // a lock.
    if (wf_config.patch_done) {
        wf_config.patch_done();
    }

    free(wf_timepoints);
    wf_timepoints = NULL;
}

void wf_global_quiesence(char *name, unsigned int threads) {
    // every global quiesence point is also an local quiesence point
    if (wf_state == LOCAL_QUIESENCE) {
        wf_local_quiesence(name);
        return;
    }
    if (wf_state == GLOBAL_QUIESENCE) {
        wf_timepoint(name, threads);

        pthread_barrier_wait(&wf_global_barrier);
        pthread_barrier_wait(&wf_global_barrier);
    }
}

void wf_local_quiesence(char *name) {
    if (wf_state == LOCAL_QUIESENCE) {
        if (wf_target_generation != wf_current_generation) {
            wf_current_generation = wf_target_generation;
            int remaining = __atomic_sub_fetch(&wf_remaining_threads, 1, __ATOMIC_SEQ_CST);
            wf_timepoint(name, 1);

            // FIXME: Call wf_migrate();

            if (remaining == 0) {
                pthread_cond_signal(&wf_cond_all_threads_migrated);
            }
        }
    }
}

void wf_init(struct wf_configuration config) {
    // Copy(!) away the configuration that we got from the
    // configuration
    wf_config = config;

    // We start a thread that does all the heavy lifting of address
    // space management
    if ((errno = pthread_create(&wf_patch_thread, NULL,
                                &wf_patch_thread_entry, NULL)) != 0) {
        perror("pthread_create");
    }

    pthread_setname_np(wf_patch_thread, "patcher");
}
