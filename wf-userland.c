#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include "wf-userland.h"


#define die(...) do { fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE); } while(0)

static pthread_t wf_patch_thread;
static pthread_cond_t wf_cond_initiate;
static int wf_global;


static pthread_mutex_t wf_mutex_thread_count;
static volatile int wf_existing_threads;
static volatile int wf_migrated_threads; // migrated or barriered.
static pthread_cond_t wf_cond_from_threads;
static pthread_cond_t wf_cond_to_threads;


static volatile int wf_target_generation;
static __thread int wf_current_generation;

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
static struct timespec wf_ts0;
static void wf_timestamp_reset(void) { // returns 0 seconds first time called
    clock_gettime(CLOCK_REALTIME, &wf_ts0);
}

static double wf_timestamp(void) { // returns 0 seconds first time called
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (ts.tv_sec - wf_ts0.tv_sec)*1000. + (ts.tv_nsec - wf_ts0.tv_nsec) / 1000000.;
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

    pthread_mutex_t __dummy;
    pthread_mutex_init(&__dummy, NULL);

    pthread_mutex_lock(&__dummy);
    while (true) {
        // Wait for signal, or do periodic tests
        int wait = wf_config_get("WF_CYCLIC", -1);
        int bound = wf_config_get("WF_CYCLIC_BOUND", -1);
        if (wait == -1) {
            pthread_cond_wait(&wf_cond_initiate, &__dummy);
        } else {
            // FIXME: We use this for benchmarking
            if (bound > 0 && wf_target_generation >= bound) {
                fprintf(stderr, "Cyclic test was OK\n");
                _exit(0);
            }
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += wait;
            pthread_cond_timedwait(&wf_cond_initiate, &__dummy, &ts);
        }

        wf_initiate_patching();
    }
    return NULL;
}


typedef struct {
    double timestamp;
    char *name;
    unsigned int threads;
} time_thread_point_t;

static time_thread_point_t *wf_timepoints;
volatile unsigned int wf_timepoints_idx;

int wf_timepoint(char *name, unsigned int threads) {
    assert (wf_timepoints != NULL);
    // printf("%s %d\n", name, wf_timestamp());

    int idx = __atomic_fetch_add(&wf_timepoints_idx, 1, __ATOMIC_SEQ_CST);
    time_thread_point_t x = {
        .timestamp = wf_timestamp(),
        .name = name,
        .threads = threads,
    };
    wf_timepoints[idx] = x;

    return idx;
}


static FILE *wf_log_file;
static void wf_log(char *fmt, ...) {
    if (wf_log_file) {
        va_list(args);
        va_start(args, fmt);
        vfprintf(wf_log_file, fmt, args);
        fflush(wf_log_file);
    }
}

static
void wf_timepoint_dump(int wf_time_start, int threads) {
    for (unsigned int i = 0; i < threads; i++){
        wf_log("- [migrated, \"%s\", %.4f, %d]\n",
               wf_timepoints[i].name,
               wf_timepoints[i].timestamp - wf_time_start,
               wf_timepoints[i].threads
           );
    }
}

typedef enum {
    IDLE,
    GLOBAL_QUIESCENCE,
    LOCAL_QUIESCENCE,
} wf_state_t;

static volatile wf_state_t wf_state;

bool wf_transition_ongoing(bool global) {
    if ((global > 0)  && wf_global)
        return wf_migrated_threads != wf_existing_threads;
    if ((global == 0) && !wf_global)
        return wf_migrated_threads != wf_existing_threads;
    return false;
}

static void wf_initiate_patching(void) {
    static int first = 0;
    if (!first) first = 1;
    else wf_log("---\n");
    // Reset the time
    wf_timestamp_reset();
    double wf_time_start = 0.0;

    pthread_mutex_lock(&wf_mutex_thread_count);
    // Retrieve the current number of threads from the application,
    // otherwise, we rely on the thread_birth() and thread_death()
    // library calls.
    if (wf_config.thread_count) {
        int threads = wf_config.thread_count(wf_global);
        wf_existing_threads = threads;
    }

    wf_log("- [apply, %ld.%09ld, %s, %d]\n",
           wf_ts0.tv_sec,
           wf_ts0.tv_nsec,
           wf_global > 0 ? "global" : ( wf_global == 0 ? "local" : "base"),
           wf_existing_threads
        );

    wf_migrated_threads = 0;

    wf_timepoints = malloc(sizeof(time_thread_point_t) *  (wf_existing_threads + 10));
    wf_timepoints_idx = 0;

    wf_state = IDLE;

    if (wf_global > 0) {
        wf_target_generation ++;

        ////////////////////////////////////////////////////////////////
        // Now we reach global quiescence with our application
        wf_state = GLOBAL_QUIESCENCE;

        // Some Applications need a trigger to reach global quiescence
        if (wf_config.trigger_global_quiescence)
            wf_config.trigger_global_quiescence();

        while (wf_migrated_threads < wf_existing_threads)
            pthread_cond_wait(&wf_cond_from_threads, &wf_mutex_thread_count);
        ////////////////////////////////////////////////////////////////
        double wf_time_global_quiescence = wf_timestamp();

        wf_timepoint_dump(wf_time_start, wf_existing_threads);
        wf_log("- [quiescence, %.4f]\n",
               wf_time_global_quiescence - wf_time_start);

        wf_log("- [patched, %.4f]\n",
               wf_timestamp() - wf_time_start);

        if (wf_config.patch_applied)
            wf_config.patch_applied();
        ////////////////////////////////////////////////////////////////
        // Let's leave the global quiescence point
        pthread_cond_broadcast(&wf_cond_to_threads); // Wakeup all sleeping threads
        pthread_mutex_unlock(&wf_mutex_thread_count);
        ////////////////////////////////////////////////////////////////

        fprintf(stderr, "[Global] ");
    } else if (wf_global == 0) {
        // FIXME: Insert Patching

        wf_log("- [patched, %.4f]\n",
               wf_timestamp() - wf_time_start);

        ////////////////////////////////////////////////////////////////
        wf_target_generation ++;
        wf_state = LOCAL_QUIESCENCE;

        // Some applications require a trigger to reach local quiescence
        if (wf_config.trigger_local_quiescence)
            wf_config.trigger_local_quiescence();

        while (wf_migrated_threads < wf_existing_threads)
            pthread_cond_wait(&wf_cond_from_threads, &wf_mutex_thread_count);

        double wf_time_migrated = wf_timestamp();

        wf_timepoint_dump(wf_time_start, wf_existing_threads);

        pthread_mutex_unlock(&wf_mutex_thread_count);
        fprintf(stderr, "[Local] ");
    } else {
        pthread_mutex_unlock(&wf_mutex_thread_count);
        /* WF_GLOBAL < 0 */
        wf_target_generation ++;
        fprintf(stderr, "[No] ");
    }

    wf_state = IDLE;

    double wf_time_end = wf_timestamp();
    wf_log("- [finished, %.4f]\n",
            wf_time_end - wf_time_start
    );

    fprintf(stderr, "Migration %d in %.4f\n",
            wf_target_generation,
            wf_time_end - wf_time_start
        );


    // Must be called in all circumstances as thread count could take
    // a lock.
    if (wf_config.patch_done) {
        wf_config.patch_done();
    }


    free(wf_timepoints);
    wf_timepoints = NULL;
}

void wf_global_quiescence(char *name, unsigned int threads) {
    // every global quiescence point is also an local quiescence point
    if (wf_state == LOCAL_QUIESCENCE) {
        wf_local_quiescence(name);
        return;
    }
    if (wf_state == GLOBAL_QUIESCENCE) {
        wf_timepoint(name, threads);

        pthread_mutex_lock(&wf_mutex_thread_count);
        wf_migrated_threads += 1;
        if (wf_migrated_threads == wf_existing_threads) {
            pthread_cond_signal(&wf_cond_from_threads);
        }
        // BLOCK: Wait for patcher thread to respond
        pthread_cond_wait(&wf_cond_to_threads, &wf_mutex_thread_count);
        pthread_mutex_unlock(&wf_mutex_thread_count);
    }
}

void wf_local_quiescence(char *name) {
    if (wf_state == LOCAL_QUIESCENCE) {
        if (wf_target_generation != wf_current_generation) {
            wf_current_generation = wf_target_generation;
            wf_timepoint(name, 1);

            // FIXME: Call wf_migrate();

            // Wakeup Patcher Threads
            pthread_mutex_lock(&wf_mutex_thread_count);
            wf_migrated_threads += 1;
            if (wf_migrated_threads == wf_existing_threads) {
                pthread_cond_signal(&wf_cond_from_threads);
            }
            // BLOCK: We do not block here
            pthread_mutex_unlock(&wf_mutex_thread_count);
        }
    }
}

void wf_thread_birth(char *name) {
    assert(wf_config.track_threads
           && "You are not allowed to call wf_thread_birth() with track_threads=0");
    pthread_mutex_lock(&wf_mutex_thread_count);
    wf_existing_threads += 1;
    pthread_mutex_unlock(&wf_mutex_thread_count);

    // Birth is a point of Quiesence
    wf_global_quiescence(name, 1);
}

void wf_thread_death(char *name) {
    assert(wf_config.track_threads
           && "You are not allowed to call wf_thread_death() with track_threads=0");
    
    pthread_mutex_lock(&wf_mutex_thread_count);
    wf_existing_threads -= 1;
    // Wakeup pather thread in case we were the last thread.
    if (wf_state == LOCAL_QUIESCENCE || wf_state == GLOBAL_QUIESCENCE){
        if (wf_migrated_threads == wf_existing_threads) {
            pthread_cond_signal(&wf_cond_from_threads);
        }
    }
    pthread_mutex_unlock(&wf_mutex_thread_count);
}

void wf_init(struct wf_configuration config) {
    wf_global = wf_config_get("WF_GLOBAL", 1);

    assert((config.track_threads
            || config.thread_count != NULL)
           && "Either .track_threads or .thread_count must be given");


    // Copy(!) away the configuration that we got from the
    // configuration
    wf_config = config;

    char *logfile = getenv("WF_LOGFILE");
    if (logfile) {
        fprintf(stderr, "opening wf logfile: %s\n", logfile);
        wf_log_file = fopen(logfile, "w+");
    } else {
        wf_log_file = stderr;
    }

    // We start a thread that does all the heavy lifting of address
    // space management
    if ((errno = pthread_create(&wf_patch_thread, NULL,
                                &wf_patch_thread_entry, NULL)) != 0) {
        perror("pthread_create");
    }

    pthread_setname_np(wf_patch_thread, "patcher");
}

