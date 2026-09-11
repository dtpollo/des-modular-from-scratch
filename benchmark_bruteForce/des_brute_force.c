/* Sequential and threaded known-plaintext key search. */

#define _POSIX_C_SOURCE 200809L /* pthreads */

#include "des_brute_force.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "des.h"
#include "des_keyspace.h"

/* Reading the shared flag on every candidate would cost more than the
 * encryption it guards; once per chunk stops the workers soon enough. */
#define STOP_CHECK_INTERVAL 4096

typedef struct {
    const des_keyspace_t *space;
    uint64_t    plaintext;
    uint64_t    ciphertext;
    uint64_t    start;
    uint64_t    end;
    atomic_bool *stop; /* NULL when searching on one thread */
    des_attack_result_t result;
} worker_arg_t;

static void search_range(worker_arg_t *arg)
{
    des_attack_result_t result = { false, 0, 0, 0 };

    for (uint64_t candidate = arg->start; candidate < arg->end; ++candidate) {
        if (arg->stop != NULL
            && (result.candidates_tested % STOP_CHECK_INTERVAL) == 0
            && atomic_load_explicit(arg->stop, memory_order_relaxed)) {
            break;
        }

        const uint64_t key = des_keyspace_key(arg->space, candidate);
        ++result.candidates_tested;

        if (des_encrypt_block(arg->plaintext, key) == arg->ciphertext) {
            result.found     = true;
            result.candidate = candidate;
            result.key       = key;

            if (arg->stop != NULL) {
                atomic_store_explicit(arg->stop, true, memory_order_relaxed);
            }
            break;
        }
    }

    arg->result = result;
}

static void *worker_main(void *raw)
{
    search_range((worker_arg_t *)raw);
    return NULL;
}

des_attack_result_t des_brute_force(const des_keyspace_t *space,
                                    uint64_t plaintext, uint64_t ciphertext,
                                    uint64_t start, uint64_t end)
{
    worker_arg_t arg = {
        space, plaintext, ciphertext, start, end, NULL, { false, 0, 0, 0 }
    };

    search_range(&arg);
    return arg.result;
}

des_attack_result_t des_brute_force_parallel(const des_keyspace_t *space,
                                             uint64_t plaintext, uint64_t ciphertext,
                                             uint64_t start, uint64_t end,
                                             unsigned workers)
{
    if (workers > DES_ATTACK_MAX_WORKERS) {
        workers = DES_ATTACK_MAX_WORKERS;
    }

    if (workers <= 1 || end <= start) {
        return des_brute_force(space, plaintext, ciphertext, start, end);
    }

    pthread_t    threads[DES_ATTACK_MAX_WORKERS];
    worker_arg_t args[DES_ATTACK_MAX_WORKERS];
    atomic_bool  stop = false;

    const uint64_t span      = end - start;
    const uint64_t chunk     = span / workers;
    const uint64_t remainder = span % workers;
    uint64_t next = start;

    for (unsigned i = 0; i < workers; ++i) {
        const uint64_t size = chunk + ((i < remainder) ? 1 : 0);

        args[i].space      = space;
        args[i].plaintext  = plaintext;
        args[i].ciphertext = ciphertext;
        args[i].start      = next;
        args[i].end        = next + size;
        args[i].stop       = &stop;
        args[i].result     = (des_attack_result_t){ false, 0, 0, 0 };

        next += size;
    }

    unsigned created = 0;
    for (unsigned i = 0; i < workers; ++i) {
        if (pthread_create(&threads[created], NULL, worker_main, &args[i]) == 0) {
            ++created;
        } else {
            search_range(&args[i]); /* no thread available: sweep it here */
        }
    }

    for (unsigned i = 0; i < created; ++i) {
        pthread_join(threads[i], NULL);
    }

    des_attack_result_t total = { false, 0, 0, 0 };

    for (unsigned i = 0; i < workers; ++i) {
        total.candidates_tested += args[i].result.candidates_tested;

        if (args[i].result.found && !total.found) {
            total.found     = true;
            total.candidate = args[i].result.candidate;
            total.key       = args[i].result.key;
        }
    }

    return total;
}
