#ifndef __WAITFREE_PATCHING_H
#define __WAITFREE_PATCHING_H

#include <signal.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif
    
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
    // or local quiescence points. With these callbacks the library
    // issues such an application kicking.
    void (*trigger_global_quiescence)(void);
    void (*trigger_local_quiescence)(void);

    // OPTIONAL: Is called after patching is done.
    void (*patch_applied)(void);
    // OPTIONAL: Is called after all threads are migrated
    void (*patch_done)(void);
};

void wf_init(struct wf_configuration config);

// The current thread has reached a global quiescence point. This
// thread represents N morethreads (e.g. 16 pool workers). However,
// the threads argument is purley for statistics. It does NOT
// decrement the thread count by N but only by 1.
//
// The thread must invoke this repeatedly at every global quiesence
// point.
void wf_global_quiescence(char * name, unsigned int threads);

// The current thread has reached a local quiescence point.
// The thread must invoke this repeatedly
void wf_local_quiescence(char * name);

// Are we currently in the phase of a
bool wf_transition_ongoing(bool global);


// Is a thread (that is counted in thread count), given birth to or
// destroyed during a transition
void wf_thread_birth(void);
void wf_thread_death(void);

#ifdef __cplusplus
}
#endif

#endif
