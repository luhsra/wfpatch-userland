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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>

#include "wf-userland.h"


#define die(...) do { fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE); } while(0)
#define die_perror(m, ...) do { perror(m); fprintf(stderr, __VA_ARGS__); exit(EXIT_FAILURE); } while(0)


////////////////////////////////////////////////////////////////
// Apply Patch
// Magic Names: ehdr, shstr
#define offset_to_ptr(offset) (((void*) (ehdr)) + ((int) (offset)))
#define shdr_from_idx(idx) offset_to_ptr(ehdr->e_shoff + ehdr->e_shentsize * idx);
#define section_name(shdr) (((char*) offset_to_ptr(shstr->sh_offset)) + shdr->sh_name)

void wf_relocate(Elf64_Ehdr *ehdr, void *elf_end, Elf64_Shdr* shdr) {
    // Section Header String table
    Elf64_Shdr *shstr = shdr_from_idx(ehdr->e_shstrndx);
    
    Elf64_Shdr *shdr_symtab = shdr_from_idx(shdr->sh_link);
    Elf64_Sym *symbol_table = offset_to_ptr(shdr_symtab->sh_offset);
    
    Elf64_Shdr *shdr_strtab = shdr_from_idx(shdr_symtab->sh_link);
    char *strtab = offset_to_ptr(shdr_strtab->sh_offset);

    // Which section should be modified
    Elf64_Shdr * shdr_target = shdr_from_idx(shdr->sh_info);

    unsigned  rela_num = shdr->sh_size / shdr->sh_entsize;
    printf("%s: %d relocs in %s\n",
           section_name(shdr),
           rela_num,
           section_name(shdr_target));

    Elf64_Rela * rela = offset_to_ptr(shdr->sh_offset);
    for (unsigned i = 0; i < rela_num; i++) {
        Elf64_Rela * rela = offset_to_ptr(shdr->sh_offset + i * shdr->sh_entsize);

        // Where to modify
        void *reloc_dst = offset_to_ptr(shdr_target->sh_offset + rela->r_offset);

        printf("%p %d ", reloc_dst, ELF64_R_TYPE(rela->r_info));
        
        Elf64_Sym * symbol = &symbol_table[ELF64_R_SYM(rela->r_info)];
        Elf64_Shdr * symbol_section = shdr_from_idx(symbol->st_shndx);
        assert (symbol->st_shndx != 0 && "I hope this catches undefined symbols");

        // What should be written into that place
        uintptr_t reloc_src;
        char *name;
        if (ELF64_ST_TYPE(symbol->st_info) == STT_SECTION) {
            name = section_name(symbol_section);
            reloc_src = (uintptr_t) offset_to_ptr(symbol_section->sh_offset);
            printf("SEC %s", section_name(symbol_section));
        } else {
            reloc_src = (uintptr_t) offset_to_ptr(symbol_section->sh_offset + symbol->st_value);
            printf("SYM %s/%s", section_name(symbol_section), strtab + symbol->st_name);
        }
        unsigned reloc_addend = rela->r_addend;
        printf("+%d => ", rela->r_addend);

        void* loc;
        uint64_t val;
        char size;
        switch (ELF64_R_TYPE(rela->r_info)) {
            case R_X86_64_NONE:
                continue;
            case R_X86_64_PC32:
            case R_X86_64_PLT32:
                loc = reloc_dst;
                val = (uint64_t)((uint32_t)((reloc_src + reloc_addend) - (uintptr_t) reloc_dst));
                size = 4;
                break;
            case R_X86_64_32S:
                loc = reloc_dst;
                val = (uint64_t)((int32_t)reloc_src + reloc_addend);
                size = 4;
                break;
            case R_X86_64_32:
                loc = reloc_dst;
                val = (uint64_t)((uint32_t)reloc_src + reloc_addend);
                size = 4;
                break;
            case R_X86_64_64:
                loc = reloc_dst;
                val = (uint64_t) reloc_src + reloc_addend;
                size = 8;
                break;
            default:
                die("Unsupported relocation %ld for source %s (0x%lx <- 0x%lx)\n",
                    ELF64_R_TYPE(rela->r_info), name, reloc_dst, reloc_src);
        }

        if (loc < (void*) ehdr || loc >= elf_end) {
			die("bad relocation 0x%llx for symbol %s\n", loc, name);
		}

        printf("*%p = 0x%lx [%d]\n", loc, val, size);

        if (size == 4) {
            *(uint32_t *) loc = val;
        } else if (size == 8) {
            *(uint64_t *) loc = val;
        } else
            die("Invalid relocation size");

    }
}

struct kpatch_patch_func {
	unsigned long new_addr;
	unsigned long new_size;
	unsigned long old_addr;
	unsigned long old_size;
	unsigned long sympos;
	char *name;
	char *objname;
};

struct kpatch_relocation {
	unsigned long dest;
	unsigned int type;
	int external;
	long addend;
	char *objname; /* object to which this rela applies to */
	struct kpatch_symbol *ksym;
};

struct kpatch_symbol {
	unsigned long src;
	unsigned long sympos;
	unsigned char bind, type;
	char *name;
	char *objname; /* object to which this sym belongs */
};

struct kpatch_patch_dynrela {
	unsigned long dest;
	unsigned long src;
	unsigned long type;
	unsigned long sympos;
	char *name;
	char *objname;
	int external;
	long addend;
};

struct kpatch_pre_patch_callback {
	int (*callback)(void *obj);
	char *objname;
};
struct kpatch_post_patch_callback {
	void (*callback)(void *obj);
	char *objname;
};
struct kpatch_pre_unpatch_callback {
	void (*callback)(void *obj);
	char *objname;
};
struct kpatch_post_unpatch_callback {
	void (*callback)(void *obj);
	char *objname;
};

void wf_load_patch(char *filename) {
    int fd = open(filename, O_RDONLY);
    if (!fd) die_perror("open", "Could not open patch file: %s", filename);

    // Mapt the whole file
    struct stat size;
    if (fstat(fd, &size) == -1) die_perror("fstat", "Could not determine size: %s", filename);

    void *elf_start = mmap(NULL, size.st_size, PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (elf_start == MAP_FAILED) die("mmap", "Could not map patch: %s", filename);
    void *elf_end = elf_start + size.st_size;


    // 1. Find Tables
    Elf64_Ehdr *ehdr = elf_start;

	if (strncmp((const char *)ehdr->e_ident, "\177ELF", 4) != 0) {
		die("Patch is not an ELF file");
	}
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        die("Patch is not an 64-Bit ELF");
    }
    Elf64_Shdr *shstr = shdr_from_idx(ehdr->e_shstrndx);


    // Extract all related sections from patch file
    Elf64_Shdr *kpatch_strings = NULL, *kpatch_funcs = NULL, *kpatch_relocations = NULL, *kpatch_symbols=NULL;

    for (unsigned i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr * shdr = shdr_from_idx(i);

        // Name of section
        char *name = section_name(shdr);

        // Perform relocations
        if (shdr->sh_type == SHT_RELA) {
            wf_relocate(ehdr, elf_end, shdr);
        }

        if (strcmp(name, ".kpatch.strings") == 0)
            kpatch_strings = shdr;
        else if (strcmp(name, ".kpatch.funcs") == 0)
            kpatch_funcs = shdr;
        else if (strcmp(name, ".kpatch.relocations") == 0)
            kpatch_relocations = shdr;
        else if (strcmp(name, ".kpatch.symbols") == 0)
            kpatch_symbols = shdr;
    }

    // Iterate over all symbols
    
    printf("%d sections\n", ehdr->e_shnum);

    // Extract arrays
    struct kpatch_patch_func *funcs = offset_to_ptr(kpatch_funcs->sh_offset);
    int funcs_count = kpatch_funcs->sh_size / sizeof(struct kpatch_patch_func);
    assert(funcs_count * sizeof(struct kpatch_patch_func) == kpatch_funcs->sh_size);

    struct kpatch_symbol *symbols = offset_to_ptr(kpatch_symbols->sh_offset);
    int symbols_count = kpatch_symbols->sh_size / sizeof(struct kpatch_symbol);
    assert(symbols_count * sizeof(struct kpatch_symbol) == kpatch_symbols->sh_size);

    struct kpatch_relocation *relocations = offset_to_ptr(kpatch_relocations->sh_offset);
    int relocations_count = kpatch_relocations->sh_size / sizeof(struct kpatch_relocation);
    assert(relocations_count * sizeof(struct kpatch_relocation) == kpatch_relocations->sh_size);

    for (unsigned f = 0; f < funcs_count; f++) {
        printf("kpatch_func: name:%s objname:%s new: %p\n",
               funcs[f].name, funcs[f].objname, funcs[f].new_addr);


        for (unsigned r = 0; r < relocations_count; r++) {
            if (!(funcs[f].new_addr <= relocations[r].dest
                  && relocations[r].dest <= (funcs[f].new_addr + funcs[f].new_size)))
                continue;
            printf("  kpatch_relocation: name:%s/%s objname:%s type=%d, external=%d, *%p = ...\n",
                   relocations[r].ksym->objname, relocations[r].ksym->name,
                   relocations[r].objname, relocations[r].type, relocations[r].external, relocations[r].dest);


            // Fixme OLD section

            relocations[r].dest = 0;
        }
    }

    /* for (unsigned i = 0; i < symbols_count; i++) { */
    /*     printf("kpatch_symbol: name:%s objname:%s %p\n", */
    /*            symbols[i].name, symbols[i].objname, symbols[i].src); */
    /*     // Fixme OLD section */
    /* } */

    for (unsigned r = 0; r < relocations_count; r++) {
        if (relocations[r].dest == 0) continue; // already handled

        printf("kpatch_relocation: name:%s/%s objname:%s type=%d, external=%d, *%p = ... (SHOULD NOT HAPPEN)\n",
               relocations[r].ksym->objname, relocations[r].ksym->name,
               relocations[r].objname, relocations[r].type, relocations[r].external, relocations[r].dest);
        // Fixme OLD section
    }

    exit(0);
}



////////////////////////////////////////////////////////////////
// Patching Thread and API

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

    wf_load_patch("patch.o");

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

