#include "wf-userland.h"
#include <stdio.h>

int foo() {
    stderr = stdout;
}

int main(void) {
    struct wf_configuration config = {0};
    config.track_threads = true;
    wf_init(config);
    wf_thread_birth("main");
    int i = 1000;
    while (1) {
        test0(i, 5);
        sleep(1);
        i += 1000;
        wf_global_quiescence("main", 1);
    }
    return 0;
}
