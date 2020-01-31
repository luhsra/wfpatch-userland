#ifndef __WAITFREE_PATCHING_H
#define __WAITFREE_PATCHING_H

#include <signal.h>
#include <stdbool.h>

#define SIGPATCH (SIGRTMIN+0)

struct wf_configuration {
    int (*thread_count)(bool global);
    // Returns the number of threads that take part in the global barrier
    void (*trigger_global_quiesence)();
    void (*trigger_local_quiesence)();

    // Is called after patching is done.
    void (*patch_applied)();
    // Is called after all threads are migrated
    void (*patch_done)();
};

void wf_init(struct wf_configuration config);

void wf_global_quiesence(char * name, unsigned int threads);
void wf_local_quiesence(char * name);

#endif
