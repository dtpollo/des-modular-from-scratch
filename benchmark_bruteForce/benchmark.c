/*
 * Brute-force benchmark: sequential and parallel key search, throughput,
 * speedup, parallel efficiency, and the extrapolation to the full 2^56
 * effective key space.
 *
 * Usage: benchmark_bruteforce [options]
 *   --bits 16,18,20     key-space widths to measure (n unknown effective bits)
 *   --workers 1,2,4     thread counts; 1 is always measured as the baseline
 *   --repeats 3         runs per timed point, averaged
 *   --target N          candidate holding the key (default: the last one)
 *   --csv path          also write the results as CSV
 *
 * Each n is measured twice, for two different reasons:
 *
 *   Full sweep -- timed against a ciphertext no candidate in the space can
 *   produce, so no worker ever exits early and every thread count tests
 *   exactly 2^n keys. Comparing runs that did equal work is what makes the
 *   speedup and efficiency numbers mean anything; timing a real recovery
 *   instead would compare a full sequential sweep against a parallel run
 *   that stopped early, which flatters the parallel side.
 *
 *   Recovery -- an actual attack against a planted key, reporting where the
 *   key sat and how many candidates were tested before the workers stopped.
 */

#define _POSIX_C_SOURCE 200809L /* clock_gettime, sysconf */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "des.h"
#include "des_api.h"
#include "des_brute_force.h"
#include "des_keyspace.h"

#define MAX_POINTS 16
#define KNOWN_PLAINTEXT UINT64_C(0x0123456789ABCDEF)
#define FIXED_PREFIX    UINT64_C(0x2A5C3E19)

#define FULL_KEY_SPACE   72057594037927936.0 /* 2^56 */
#define SECONDS_PER_YEAR 31557600.0          /* 365.25 days */

typedef struct {
    unsigned    bits[MAX_POINTS];
    unsigned    bit_count;
    unsigned    workers[MAX_POINTS];
    unsigned    worker_count;
    unsigned    repeats;
    uint64_t    target;
    const char *csv_path;
} options_t;

typedef struct {
    double   time_avg;
    double   time_min;
    uint64_t candidates_tested;
    bool     complete; /* swept the whole space with no unexpected match */
} sweep_t;

typedef struct {
    bool     found;
    uint64_t candidate;
    uint64_t candidates_tested;
    double   time;
} recovery_t;

static double monotonic_seconds(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + (double)now.tv_nsec / 1e9;
}

static unsigned online_cores(void)
{
    const long count = sysconf(_SC_NPROCESSORS_ONLN);

    return (count > 0) ? (unsigned)count : 1u;
}

/* Linux only; skipped silently elsewhere. The lab report has to state which
 * machine produced the numbers. */
static void print_cpu_model(void)
{
    FILE *info = fopen("/proc/cpuinfo", "r");
    char line[256];

    if (info == NULL) {
        return;
    }

    while (fgets(line, sizeof line, info) != NULL) {
        if (strncmp(line, "model name", 10) == 0) {
            const char *value = strchr(line, ':');

            if (value != NULL) {
                ++value;
                while (*value == ' ' || *value == '\t') {
                    ++value;
                }
                printf("CPU model:         %s", value);
            }
            break;
        }
    }

    fclose(info);
}

static unsigned parse_list(const char *text, unsigned *out, unsigned max)
{
    unsigned count = 0;
    const char *cursor = text;

    while (*cursor != '\0' && count < max) {
        char *end = NULL;
        const unsigned long value = strtoul(cursor, &end, 10);

        if (end == cursor) {
            break;
        }

        out[count++] = (unsigned)value;
        cursor = (*end == ',') ? end + 1 : end;
    }

    return count;
}

/* Speedup is meaningless without T1, so the baseline is always measured. */
static void ensure_baseline(options_t *options)
{
    for (unsigned i = 0; i < options->worker_count; ++i) {
        if (options->workers[i] == 1) {
            return;
        }
    }

    if (options->worker_count == MAX_POINTS) {
        --options->worker_count;
    }

    for (unsigned i = options->worker_count; i > 0; --i) {
        options->workers[i] = options->workers[i - 1];
    }

    options->workers[0] = 1;
    ++options->worker_count;
}

static bool key_has_odd_parity(uint64_t key)
{
    uint8_t bytes[DES_KEY_BYTES];
    bool valid = false;

    for (int i = DES_KEY_BYTES - 1; i >= 0; --i) {
        bytes[i] = (uint8_t)(key & 0xFFu);
        key >>= 8;
    }

    return des_check_parity(bytes, DES_KEY_BYTES, &valid) == DES_OK && valid;
}

/* Same width, different fixed prefix: the key that produced this ciphertext
 * is outside the space, so no candidate in it can match. */
static uint64_t unmatchable_ciphertext(const des_keyspace_t *space, uint64_t plaintext)
{
    const des_keyspace_t outside = {
        space->unknown_bits, space->fixed_prefix ^ UINT64_C(1)
    };

    return des_encrypt_block(plaintext, des_keyspace_key(&outside, 0));
}

static sweep_t run_sweep(const des_keyspace_t *space, uint64_t plaintext,
                         uint64_t ciphertext, uint64_t size,
                         unsigned workers, unsigned repeats)
{
    sweep_t sweep = { 0.0, 0.0, 0, true };
    double total = 0.0;

    for (unsigned run = 0; run < repeats; ++run) {
        const double started = monotonic_seconds();
        const des_attack_result_t result =
            des_brute_force_parallel(space, plaintext, ciphertext, 0, size, workers);
        const double elapsed = monotonic_seconds() - started;

        if (result.found || result.candidates_tested != size) {
            sweep.complete = false;
        }

        total += elapsed;
        if (run == 0 || elapsed < sweep.time_min) {
            sweep.time_min = elapsed;
        }
        sweep.candidates_tested = result.candidates_tested;
    }

    sweep.time_avg = total / (double)repeats;
    return sweep;
}

static recovery_t run_recovery(const des_keyspace_t *space, uint64_t plaintext,
                               uint64_t ciphertext, uint64_t size, unsigned workers)
{
    const double started = monotonic_seconds();
    const des_attack_result_t result =
        des_brute_force_parallel(space, plaintext, ciphertext, 0, size, workers);
    const double elapsed = monotonic_seconds() - started;

    recovery_t recovery = {
        result.found, result.candidate, result.candidates_tested, elapsed
    };

    return recovery;
}

static void usage(const char *program)
{
    printf("Usage: %s [options]\n", program);
    puts("  --bits 16,18,20   key-space widths to measure");
    puts("  --workers 1,2,4   thread counts (1 is always measured)");
    puts("  --repeats 3       runs per timed point, averaged");
    puts("  --target N        candidate holding the key (default: the last one)");
    puts("  --csv path        also write the results as CSV");
}

int main(int argc, char *argv[])
{
    options_t options = { { 0 }, 0, { 0 }, 0, 3, UINT64_MAX, NULL };

    for (int i = 1; i < argc; ++i) {
        const char *flag  = argv[i];
        const char *value = (i + 1 < argc) ? argv[i + 1] : NULL;

        if (strcmp(flag, "--help") == 0) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        }

        if (value == NULL) {
            fprintf(stderr, "Error: %s needs a value.\n", flag);
            return EXIT_FAILURE;
        }

        if (strcmp(flag, "--bits") == 0) {
            options.bit_count = parse_list(value, options.bits, MAX_POINTS);
        } else if (strcmp(flag, "--workers") == 0) {
            options.worker_count = parse_list(value, options.workers, MAX_POINTS);
        } else if (strcmp(flag, "--repeats") == 0) {
            options.repeats = (unsigned)strtoul(value, NULL, 10);
        } else if (strcmp(flag, "--target") == 0) {
            options.target = strtoull(value, NULL, 10);
        } else if (strcmp(flag, "--csv") == 0) {
            options.csv_path = value;
        } else {
            fprintf(stderr, "Error: unknown option %s\n", flag);
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        ++i;
    }

    const unsigned cores = online_cores();

    if (options.bit_count == 0) {
        options.bits[0] = 16;
        options.bits[1] = 18;
        options.bits[2] = 20;
        options.bit_count = 3;
    }

    if (options.worker_count == 0) {
        for (unsigned workers = 1;
             workers <= cores && options.worker_count < MAX_POINTS;
             workers *= 2) {
            options.workers[options.worker_count++] = workers;
        }
    }

    if (options.repeats == 0) {
        fprintf(stderr, "Error: --repeats must be at least 1.\n");
        return EXIT_FAILURE;
    }

    for (unsigned i = 0; i < options.bit_count; ++i) {
        if (options.bits[i] == 0 || options.bits[i] > DES_KEYSPACE_MAX_BITS) {
            fprintf(stderr, "Error: --bits values must be between 1 and %d.\n",
                    DES_KEYSPACE_MAX_BITS);
            return EXIT_FAILURE;
        }
    }

    ensure_baseline(&options);

    FILE *csv = NULL;
    if (options.csv_path != NULL) {
        csv = fopen(options.csv_path, "w");

        if (csv == NULL) {
            fprintf(stderr, "Error: cannot write %s\n", options.csv_path);
            return EXIT_FAILURE;
        }

        fputs("mode,bits,candidates,workers,repeats,time_avg_s,time_min_s,"
              "keys_tested,keys_per_s,speedup,efficiency\n", csv);
    }

    puts("== DES brute-force benchmark ==\n");
    print_cpu_model();
    printf("Logical cores:     %u\n", cores);
    printf("Repeats per point: %u\n", options.repeats);
    printf("Known plaintext:   %016" PRIX64 "\n", KNOWN_PLAINTEXT);
    puts("Mapping:           candidate -> 56 effective bits -> 64-bit key (odd parity)");

    double best_rate = 0.0;
    int failures = 0;

    for (unsigned b = 0; b < options.bit_count; ++b) {
        const unsigned bits = options.bits[b];
        const uint64_t prefix_mask =
            (UINT64_C(1) << (DES_KEY_BITS_EFFECTIVE - bits)) - 1;
        const des_keyspace_t space = { bits, FIXED_PREFIX & prefix_mask };

        const uint64_t size = des_keyspace_size(&space);
        const uint64_t absent = unmatchable_ciphertext(&space, KNOWN_PLAINTEXT);

        printf("\nn = %u  (%" PRIu64 " candidates, fixed prefix %" PRIX64 ")\n",
               bits, size, space.fixed_prefix);
        puts("  Full sweep, no early exit, so every worker count tests all 2^n keys");
        puts("  Workers    Time [s]     Keys tested        Keys/s   Speedup   Efficiency");

        double baseline = 0.0;

        for (unsigned w = 0; w < options.worker_count; ++w) {
            const unsigned workers = options.workers[w];
            const sweep_t sweep = run_sweep(&space, KNOWN_PLAINTEXT, absent, size,
                                            workers, options.repeats);

            if (!sweep.complete) {
                ++failures;
            }

            const double rate = (sweep.time_avg > 0.0)
                              ? (double)sweep.candidates_tested / sweep.time_avg
                              : 0.0;

            if (workers == 1) {
                baseline = sweep.time_avg;
            }

            const double speedup = (baseline > 0.0 && sweep.time_avg > 0.0)
                                 ? baseline / sweep.time_avg
                                 : 0.0;
            const double efficiency = speedup / (double)workers;

            if (rate > best_rate) {
                best_rate = rate;
            }

            printf("  %7u  %10.4f  %14" PRIu64 "  %12.0f  %8.2f  %11.2f%s\n",
                   workers, sweep.time_avg, sweep.candidates_tested, rate,
                   speedup, efficiency, sweep.complete ? "" : "   [INCOMPLETE SWEEP]");

            if (csv != NULL) {
                fprintf(csv,
                        "sweep,%u,%" PRIu64 ",%u,%u,%.6f,%.6f,%" PRIu64 ",%.0f,%.4f,%.4f\n",
                        bits, size, workers, options.repeats, sweep.time_avg,
                        sweep.time_min, sweep.candidates_tested, rate, speedup, efficiency);
            }
        }

        /* The real attack: a planted key, actually searched for. */
        const uint64_t target = (options.target == UINT64_MAX || options.target >= size)
                              ? size - 1
                              : options.target;
        const uint64_t secret_key = des_keyspace_key(&space, target);
        const uint64_t ciphertext = des_encrypt_block(KNOWN_PLAINTEXT, secret_key);

        printf("  Recovery: key at candidate %" PRIu64 " -> %016" PRIX64
               "  (odd parity: %s)\n",
               target, secret_key, key_has_odd_parity(secret_key) ? "yes" : "NO");

        for (unsigned w = 0; w < options.worker_count; ++w) {
            const unsigned workers = options.workers[w];
            const recovery_t recovery =
                run_recovery(&space, KNOWN_PLAINTEXT, ciphertext, size, workers);

            if (!recovery.found || recovery.candidate != target) {
                ++failures;
            }

            printf("            %2u worker(s): %10.4f s  after %" PRIu64 " candidates%s\n",
                   workers, recovery.time, recovery.candidates_tested,
                   (recovery.found && recovery.candidate == target)
                       ? "" : "   [KEY NOT RECOVERED]");

            if (csv != NULL) {
                const double rate = (recovery.time > 0.0)
                                  ? (double)recovery.candidates_tested / recovery.time
                                  : 0.0;

                fprintf(csv,
                        "recovery,%u,%" PRIu64 ",%u,1,%.6f,%.6f,%" PRIu64 ",%.0f,,\n",
                        bits, size, workers, recovery.time, recovery.time,
                        recovery.candidates_tested, rate);
            }
        }
    }

    if (csv != NULL) {
        fclose(csv);
        printf("\nCSV written to %s\n", options.csv_path);
    }

    printf("\nExtrapolation to the full 2^56 effective key space"
           " (best measured R = %.0f keys/s)\n", best_rate);

    if (best_rate > 0.0) {
        const double t_max = FULL_KEY_SPACE / best_rate;
        const double t_avg = t_max / 2.0;

        printf("  T_max = 2^56 / R = %.3e s = %.3e h = %.3e d = %.3e years\n",
               t_max, t_max / 3600.0, t_max / 86400.0, t_max / SECONDS_PER_YEAR);
        printf("  T_avg = 2^55 / R = %.3e s = %.3e h = %.3e d = %.3e years\n",
               t_avg, t_avg / 3600.0, t_avg / 86400.0, t_avg / SECONDS_PER_YEAR);
    }

    if (failures != 0) {
        fprintf(stderr, "\n%d measurement(s) did not behave as expected.\n", failures);
        return EXIT_FAILURE;
    }

    puts("\nEvery sweep was complete and every recovery found the planted key.");
    return EXIT_SUCCESS;
}
