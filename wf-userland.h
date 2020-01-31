#ifndef __WAITFREE_PATCHING_H
#define __WAITFREE_PATCHING_H

#include <signal.h>
#include <stdbool.h>

#define SIGPATCH (SIGRTMIN+0)

/*
 In order to use the wait free patching mechanism, you have to
 initialize and configure the library. This should be done at the beginning of your main function.

 wf_init will install an signal handler for SIGPATCH and spawn a thread
 that will coordinate the applying a patch when the signal was received[1].


 [1] Alternatively, there is the cyclic mode, that triggers pseudo
     migrateions every n seconds.

    WF_CYCLIC=<seconds> ./binary
 */
struct wf_configuration {
    // Returns the number of threads that take part in the global barrier.
    // THIS FUNCTION IS MANDATORY
    int (*thread_count)(bool global);

    // Some applications require some extra triggering to reach global
    // or local quiesence points. With these callbacks the library
    // issues such an application kicking.
    void (*trigger_global_quiesence)();
    void (*trigger_local_quiesence)();

    // OPTIONAL: Is called after patching is done.
    void (*patch_applied)();
    // OPTIONAL: Is called after all threads are migrated
    void (*patch_done)();
};

void wf_init(struct wf_configuration config);

// The current thread has reached a global quiesence point. This
// thread represents more N threads (e.g. 16 pool workers)
// The thread must invoke this repeatedly
void wf_global_quiesence(char * name, unsigned int threads);

// The current thread has reached a local quiesence point.
// The thread must invoke this repeatedly
void wf_local_quiesence(char * name);

#endif
