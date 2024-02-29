#include <getopt.h>  // getopt, optarg
#include <stdlib.h>  // exit, atoi, malloc, free
#include <stdio.h>   // printf, fprintf, stderr, fopen, fclose, FILE
#include <limits.h>  // ULONG_MAX
#include <string.h>  // strcmp, strerror
#include <errno.h>   // errno

/* fast base-2 integer logarithm */
#define INT_LOG2(x) (31 - __builtin_clz(x))
#define NOT_POWER2(x) (__builtin_clz(x) + __builtin_ctz(x) != 31)

/* tag_bits = ADDRESS_LENGTH - set_bits - block_bits */
#define ADDRESS_LENGTH 64

/**
 * Print program usage (no need to modify).
 */
static void print_usage() {
    printf("Usage: csim [-hv] -S <num> -K <num> -B <num> -p <policy> -t <file>\n");
    printf("Options:\n");
    printf("  -h           Print this help message.\n");
    printf("  -v           Optional verbose flag.\n");
    printf("  -S <num>     Number of sets.           (must be > 0)\n");
    printf("  -K <num>     Number of lines per set.  (must be > 0)\n");
    printf("  -B <num>     Number of bytes per line. (must be > 0)\n");
    printf("  -p <policy>  Eviction policy. (one of 'FIFO', 'LRU')\n");
    printf("  -t <file>    Trace file.\n\n");
    printf("Examples:\n");
    printf("$ ./csim    -S 16  -K 1 -B 16 -p LRU -t traces/yi2.trace\n");
    printf("$ ./csim -v -S 256 -K 2 -B 16 -p LRU -t traces/yi2.trace\n");
}

/* Parameters set by command-line args (no need to modify) */
int verbose = 0;   // print trace if 1
int S = 0;         // number of sets
int K = 0;         // lines per set
int B = 0;         // bytes per line

typedef enum { FIFO = 1, LRU = 2 } Policy;
Policy policy;     // 0 (undefined) by default

FILE *trace_fp = NULL;

/**
 * Parse input arguments and set verbose, S, K, B, policy, trace_fp.
 *
 * TODO: Finish implementation
 */
static void parse_arguments(int argc, char **argv) {
    char c;
    while ((c = getopt(argc, argv, "S:K:B:p:t:vh")) != -1) {
        switch(c) {
            case 'S':
                S = atoi(optarg);
                if (NOT_POWER2(S)) {
                    fprintf(stderr, "ERROR: S must be a power of 2\n");
                    exit(1);
                }
                break;
            case 'K':
                K = atoi(optarg);
                break;
            case 'B':
                B = atoi(optarg);
                break;
            case 'p':
                if (!strcmp(optarg, "FIFO")) {
                    policy = FIFO;
                }
                else if (!strcmp(optarg, "LRU"))
                {
                    policy = LRU;
                }
                break;
            case 't':
                trace_fp = fopen(optarg, "r");  // Open the file for reading
    
                if (!trace_fp) {
                    fprintf(stderr, "ERROR: %s: %s\n", optarg, strerror(errno));
                    exit(1);
                }
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
                // TODO
                exit(0);
            default:
                print_usage();
                exit(1);
        }
    }

    /* Make sure that all required command line args were specified and valid */
    if (S <= 0 || K <= 0 || B <= 0 || policy == 0 || !trace_fp) {
        printf("ERROR: Negative or missing command line arguments\n");
        print_usage();
        if (trace_fp) {
            fclose(trace_fp);
        }
        exit(1);
    }

    /* Other setup if needed */
}

/**
 * Cache data structures
 * TODO: Define your own!
 */

typedef struct {
    char valid;
    unsigned long int tag;     // Tag bits for identifying the memory address
    unsigned long last; // For LRU
} CacheLine;

typedef struct {
    CacheLine* lines;  // Array of cache lines
} CacheSet;

typedef struct {
    int num_sets;     // Number of cache sets
    int lines_per_set;  // Number of lines per set
    int block_size;   // Number of bytes per line
    CacheSet** sets;   // Array of cache sets
} Cache;

Cache *cache = NULL;

unsigned long counter = 0;

/**
 * Allocate cache data structures.
 *
 * This function dynamically allocates (with malloc) data structures for each of
 * the `S` sets and `K` lines per set.
 *
 * TODO: Implement
 */
static void allocate_cache() {

    cache = malloc(sizeof(Cache));
    if (cache == NULL) {
        fprintf(stderr, "Cache allocation failed.\n");
        exit(1);
    }

    cache->num_sets = S;    
    cache->lines_per_set = K;     
    cache->block_size = B;
    cache->sets = malloc(S * sizeof(CacheSet));

    if (cache->sets == NULL) {
        fprintf(stderr, "Sets allocation failed.\n");
        exit(1);
    }

    for (int i = 0; i < S; i++) {
        CacheSet *set = malloc(sizeof(CacheSet));
        set->lines = malloc(sizeof(CacheLine) * K);

        for(int j=0; j < K; j++)
        {
            set->lines[j].valid = 0;
            set->lines[j].tag = 0;
            set->lines[j].last = INT_MAX;
        }
        cache->sets[i] = set;
    }

}

/**
 * Deallocate cache data structures.
 *
 * This function deallocates (with free) the cache data structures of each
 * set and line.
 *
 * TODO: Implement
 */
static void free_cache() {
    if (cache == NULL) {
        return;
    }

    if (cache->sets != NULL) 
    {
        for (int i = 0; i < S; ++i) 
        {
            if (cache->sets[i] != NULL) 
            {
                free(cache->sets[i]->lines);
                cache->sets[i]->lines = NULL;

                free(cache->sets[i]);
                cache->sets[i] = NULL;
            }
        }

        free(cache->sets);
        free(cache);
    }
}

/* Counters used to record cache statistics */
int miss_count     = 0;
int hit_count      = 0;
int eviction_count = 0;

/**
 * Simulate a memory access.
 *
 * If the line is already in the cache, increase `hit_count`; otherwise,
 * increase `miss_count`; increase `eviction_count` if another line must be
 * evicted. This function also updates the metadata used to implement eviction
 * policies (LRU, FIFO).
 *
 * TODO: Implement
 */
static void access_data(unsigned long addr) {
    //printf("Access to %016lx\n", addr);

    int num_offset_bits = INT_LOG2(cache->block_size); // bits required for offset
    int num_set_bits = INT_LOG2(cache->num_sets); // bits required for set

    int set_btn_mask = (1 << num_set_bits) - 1; // mask of all 1s of length of log2(sets)
    int set_index = (addr >> num_offset_bits) & (set_btn_mask); // finding set index we are at
    long unsigned int bits_count = num_offset_bits + num_set_bits;
    long unsigned int tag = addr >> (bits_count);

    CacheSet *curr = cache->sets[set_index];
    int temp = cache->lines_per_set;

    for(int i=0; i < K; i++) {
       //decrement from tempK if spot is valid, later check if tempK equal to 0, aka if every spot is valid
       if (curr->lines[i].valid != 0) {
            temp--;
            if (tag == curr->lines[i].tag) { // check if tag is in set
                hit_count++;
                if (policy == LRU) {
                    counter++;
                    curr->lines[i].last = counter; // update LRU for line we are at
                }

                return;
            }
       }
    }

    miss_count++;

    // case where result not found, but we have to evict
    if (temp == 0) {
        eviction_count++;
        int lru = 0;
        unsigned long lowest = curr->lines[0].last;

        // find lru
        for (int i = 1; i < cache->lines_per_set; i++) {
            if (curr->lines[i].last < lowest) {
                lowest = curr->lines[i].last;
                lru = i;
            }
        }    

        curr->lines[lru].tag = tag;
        curr->lines[lru].valid = 1;

        counter++;
        curr->lines[lru].last = counter;

    }

    else {
        for(int i = 0; i < cache->lines_per_set; i++) {
           if (!curr->lines[i].valid) {
                curr->lines[i].tag = tag;
                curr->lines[i].valid = 1;
                curr->lines[i].last = counter++;
                break;
            }
        }
    }

    // TODO: Print additional information if verbose mode is enabled

}

/**
 * Replay the input trace.
 *
 * This function:
 * - reads lines (e.g., using fgets) from the file handle `trace_fp` (a global variable)
 * - skips lines not starting with ` S`, ` L` or ` M`
 * - parses the memory address (unsigned long, in hex) and len (unsigned int, in decimal)
 *   from each input line
 * - calls `access_data(address)` for each access to a cache line
 *
 * TODO: Implement
 */
static void replay_trace() {
    char buf[100];  // Adjust the size as needed

    while (fgets(buf, sizeof(buf), trace_fp) != NULL) {
        if (buf[0] != ' ' || (buf[1] != 'S' && buf[1] != 'L' && buf[1] != 'M')) {
            continue;
        }

        unsigned long addr;
        unsigned int len;

        if (sscanf(buf + 3, "%lx,%u", &addr, &len) == 2) {
            if (buf[1] == 'L' || buf[1] == 'S') {
                access_data(addr);
            } else if (buf[1] == 'M') {
                access_data(addr);  
                access_data(addr);  
            }

            unsigned long i = addr + 1;
            while (i < addr + len) {
                if (i % cache->block_size == 0) {
                    if (buf[1] == 'M') {
                        access_data(i);  
                        access_data(i);  
                    } else {
                        access_data(i);  
                    }
                }
                i++;
            }
        }
    }
}

/**
 * Print cache statistics (DO NOT MODIFY).
 */
static void print_summary(int hits, int misses, int evictions) {
    printf("hits:%d misses:%d evictions:%d\n", hits, misses, evictions);
}

int main(int argc, char **argv) {
    parse_arguments(argc, argv);  // set global variables used by simulation
    allocate_cache();             // allocate data structures of cache
    replay_trace();               // simulate the trace and update counts
    free_cache();                 // deallocate data structures of cache
    fclose(trace_fp);             // close trace file
    print_summary(hit_count, miss_count, eviction_count);  // print counts
    return 0;
}
