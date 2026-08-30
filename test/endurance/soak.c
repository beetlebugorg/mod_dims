/*
 * The soak client.
 *
 * It builds requests from a seed, sends them with libcurl, and compares each
 * response against the expected result in the plan. A run lasts hours, so a
 * request holds no memory beyond the slot it ran in.
 *
 *   dims_soak --manifest corpus/manifest.tsv --seconds 10800
 *
 * The exit status is zero when nothing failed.
 *
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "soak.h"

#include <curl/curl.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* How many bytes of a body to keep. A format check reads only the first few. */
#define SOAK_HEAD_BYTES 64

typedef enum {
    SOAK_FAILURE_TRANSPORT = 0,   /* the request did not finish */
    SOAK_FAILURE_STATUS,          /* an image was required and did not arrive */
    SOAK_FAILURE_EMPTY,           /* a 2xx with no body */
    SOAK_FAILURE_NOT_IMAGE,       /* a 2xx whose body is not an image */
    SOAK_FAILURE_SERVED,          /* a refused request was answered anyway */
    SOAK_FAILURE_COUNT
} soak_failure;

static const char *const failure_names[SOAK_FAILURE_COUNT] = {
    "transport", "status", "empty-body", "not-an-image", "served-a-refusal"
};

typedef struct {
    CURL *easy;
    dims_plan plan;
    char *url;
    struct curl_slist *headers;
    unsigned char head[SOAK_HEAD_BYTES];
    size_t head_length;
    size_t body_length;
    int active;
} slot;

typedef struct {
    unsigned long long requests;
    unsigned long long bytes;
    unsigned long long by_endpoint[DIMS_ENDPOINT_COUNT];
    unsigned long long by_expect[3];
    unsigned long long failures[SOAK_FAILURE_COUNT];
    unsigned long long status[6];          /* 1xx..5xx, and one for no status */
    unsigned long long tamper_ok[DIMS_TAMPER_COUNT];
    unsigned long long tamper_refused[DIMS_TAMPER_COUNT];
    unsigned long long unknown_format;
    unsigned long long not_modified;
    double latency_total;
    double latency_max;
} statistics;

static volatile sig_atomic_t stop_now = 0;

static void
on_signal(int signal_number)
{
    (void) signal_number;
    stop_now = 1;
}

static double
now_seconds(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (double) ts.tv_sec + (double) ts.tv_nsec / 1e9;
}

static size_t
on_body(char *data, size_t size, size_t count, void *user)
{
    slot *s = user;
    size_t total = size * count;

    if (s->head_length < SOAK_HEAD_BYTES) {
        size_t room = SOAK_HEAD_BYTES - s->head_length;
        size_t take = (total < room) ? total : room;

        memcpy(s->head + s->head_length, data, take);
        s->head_length += take;
    }

    s->body_length += total;

    return total;
}

/* -- Options -------------------------------------------------------------- */

typedef struct {
    const char *base;
    const char *manifest;
    const char *failures_path;
    long seconds;
    long connections;
    long timeout;
    long report_every;
    long max_failures;
    long dump;
    uint64_t seed;
    dims_world world;
} options;

static void
usage(void)
{
    fprintf(stderr,
        "dims_soak, the mod_dims soak client\n"
        "\n"
        "  --base URL          the service under test (http://dims:8000)\n"
        "  --origin URL        where a source lives (http://origin:8080)\n"
        "  --manifest PATH     the corpus manifest\n"
        "  --overlay URL       the watermark overlay\n"
        "  --client ID         the /dims3/ and /dims4/ client id\n"
        "  --secret VALUE      the client secret\n"
        "  --key VALUE         the /dims5/ signing key\n"
        "  --seconds N         how long to run, 0 for no limit\n"
        "  --connections N     requests in flight\n"
        "  --timeout N         seconds before a request is a failure\n"
        "  --seed N            the generator seed, so a run replays\n"
        "  --report N          seconds between progress lines\n"
        "  --failures PATH     where to write the failing requests\n"
        "  --max-failures N    stop writing after this many\n"
        "  --dump N            print N planned requests and stop\n"
"  --no-eurl           never encrypt the source URL\n"
        "  --eurl-ecb          /dims4/ encrypts with AES-ECB, not AES-GCM\n");
}

/* -- Reporting ------------------------------------------------------------ */

static FILE *failure_file = NULL;
static long failures_written = 0;

/* Writes a JSON string, escaping what the format requires. */
static void
write_json_string(FILE *file, const char *text)
{
    const unsigned char *at;

    fputc('"', file);

    for (at = (const unsigned char *) (text != NULL ? text : ""); *at != '\0'; at++) {
        if (*at == '"' || *at == '\\') {
            fprintf(file, "\\%c", *at);
        } else if (*at < 0x20) {
            fprintf(file, "\\u%04x", *at);
        } else {
            fputc((char) *at, file);
        }
    }

    fputc('"', file);
}

static void
record_failure(const options *o, const slot *s, soak_failure kind,
               long status, const char *detail)
{
    if (failure_file == NULL || failures_written >= o->max_failures) {
        return;
    }

    failures_written++;

    fprintf(failure_file, "{\"seq\":%llu,\"kind\":",
            (unsigned long long) s->plan.seq);
    write_json_string(failure_file, failure_names[kind]);
    fprintf(failure_file, ",\"status\":%ld,\"endpoint\":", status);
    write_json_string(failure_file, dims_endpoint_name(s->plan.endpoint));
    fprintf(failure_file, ",\"tamper\":");
    write_json_string(failure_file, dims_tamper_name(s->plan.tamper));
    fprintf(failure_file, ",\"expect\":");
    write_json_string(failure_file, dims_expect_name(s->plan.expect));
    fprintf(failure_file, ",\"source\":");
    write_json_string(failure_file, s->plan.source);
    fprintf(failure_file, ",\"commands\":");
    write_json_string(failure_file, s->plan.commands);
    fprintf(failure_file, ",\"bytes\":%llu,\"detail\":",
            (unsigned long long) s->body_length);
    write_json_string(failure_file, detail);
    fprintf(failure_file, ",\"url\":");
    write_json_string(failure_file, s->url);
    fprintf(failure_file, "}\n");
    fflush(failure_file);
}

/* -- One completed exchange ------------------------------------------------ */

static void
judge(const options *o, slot *s, CURLcode code, statistics *stats)
{
    long status = 0;
    double total_time = 0.0;
    const char *format;

    curl_easy_getinfo(s->easy, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_getinfo(s->easy, CURLINFO_TOTAL_TIME, &total_time);

    stats->requests++;
    stats->bytes += s->body_length;
    stats->by_endpoint[s->plan.endpoint]++;
    stats->by_expect[s->plan.expect]++;
    stats->latency_total += total_time;
    if (total_time > stats->latency_max) {
        stats->latency_max = total_time;
    }

    if (code != CURLE_OK) {
        stats->failures[SOAK_FAILURE_TRANSPORT]++;
        stats->status[5]++;
        record_failure(o, s, SOAK_FAILURE_TRANSPORT, status,
                       curl_easy_strerror(code));
        return;
    }

    if (status >= 100 && status < 600) {
        stats->status[status / 100 - 1]++;
    } else {
        stats->status[5]++;
    }

    if (status == 304) {
        stats->not_modified++;
    }

    /* The result each mutation got. The report prints these counts for the
     * mutations whose outcome depends on a configuration setting. */
    if (status >= 200 && status < 300) {
        stats->tamper_ok[s->plan.tamper]++;
    } else {
        stats->tamper_refused[s->plan.tamper]++;
    }

    if (s->plan.expect == DIMS_EXPECT_REFUSE) {
        if (status >= 200 && status < 300) {
            stats->failures[SOAK_FAILURE_SERVED]++;
            record_failure(o, s, SOAK_FAILURE_SERVED, status,
                           "the service answered a request it had to refuse");
        }
        return;
    }

    if (s->plan.expect != DIMS_EXPECT_IMAGE) {
        return;
    }

    if (status < 200 || status >= 300) {
        stats->failures[SOAK_FAILURE_STATUS]++;
        record_failure(o, s, SOAK_FAILURE_STATUS, status,
                       "a decodable source and a valid request");
        return;
    }

    if (s->body_length == 0) {
        stats->failures[SOAK_FAILURE_EMPTY]++;
        record_failure(o, s, SOAK_FAILURE_EMPTY, status, "the body is empty");
        return;
    }

    format = dims_body_format(s->head, s->head_length);

    if (format == NULL) {
        /* An HTML page or plain text in place of an image is a failure. A
         * format this client does not read is counted, not failed. */
        if (s->head_length > 0 && (s->head[0] == '<' || s->head[0] == '{' ||
                (s->head[0] >= 0x20 && s->head[0] < 0x7F))) {
            stats->failures[SOAK_FAILURE_NOT_IMAGE]++;
            record_failure(o, s, SOAK_FAILURE_NOT_IMAGE, status,
                           "the body is text, not an image");
        } else {
            stats->unknown_format++;
        }
    }
}

/* -- The pool -------------------------------------------------------------- */

static void
arm(slot *s, const options *o, dims_rng *rng, uint64_t sequence)
{
    size_t length;

    dims_plan_free(&s->plan);
    free(s->url);
    if (s->headers != NULL) {
        curl_slist_free_all(s->headers);
        s->headers = NULL;
    }

    dims_plan_make(&s->plan, &o->world, rng, sequence);

    length = strlen(o->base) + strlen(s->plan.path) + 1;
    s->url = malloc(length);
    snprintf(s->url, length, "%s%s", o->base, s->plan.path);

    s->head_length = 0;
    s->body_length = 0;

    curl_easy_reset(s->easy);
    curl_easy_setopt(s->easy, CURLOPT_URL, s->url);
    curl_easy_setopt(s->easy, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(s->easy, CURLOPT_WRITEDATA, s);
    curl_easy_setopt(s->easy, CURLOPT_PRIVATE, s);
    curl_easy_setopt(s->easy, CURLOPT_TIMEOUT, o->timeout);
    curl_easy_setopt(s->easy, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(s->easy, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(s->easy, CURLOPT_USERAGENT, "dims-soak/1.0");
    curl_easy_setopt(s->easy, CURLOPT_NOSIGNAL, 1L);

    /* Most requests reuse the connection, as a production client does. The
     * rest open a new one, which runs the code a first request reaches. */
    if (dims_rng_chance(rng, 10)) {
        curl_easy_setopt(s->easy, CURLOPT_FRESH_CONNECT, 1L);
    }

    if (s->plan.conditional) {
        s->headers = curl_slist_append(NULL, "If-None-Match: *");
        curl_easy_setopt(s->easy, CURLOPT_HTTPHEADER, s->headers);
    }

    s->active = 1;
}

static void
print_progress(const statistics *stats, double elapsed)
{
    unsigned long long failed = 0;
    int i;

    for (i = 0; i < SOAK_FAILURE_COUNT; i++) {
        failed += stats->failures[i];
    }

    fprintf(stderr,
            "[%6.0fs] %10llu requests  %7.1f/s  2xx %llu  3xx %llu  4xx %llu  "
            "5xx %llu  failures %llu\n",
            elapsed, stats->requests,
            elapsed > 0 ? (double) stats->requests / elapsed : 0.0,
            stats->status[1], stats->status[2], stats->status[3],
            stats->status[4], failed);
    fflush(stderr);
}

static void
print_summary(const statistics *stats, double elapsed, uint64_t seed)
{
    unsigned long long failed = 0;
    int i;

    for (i = 0; i < SOAK_FAILURE_COUNT; i++) {
        failed += stats->failures[i];
    }

    printf("\n");
    printf("soak seed              %llu\n", (unsigned long long) seed);
    printf("soak seconds           %.0f\n", elapsed);
    printf("soak requests          %llu\n", stats->requests);
    printf("soak requests_per_sec  %.1f\n",
           elapsed > 0 ? (double) stats->requests / elapsed : 0.0);
    printf("soak bytes             %llu\n", stats->bytes);
    printf("soak latency_mean_ms   %.1f\n",
           stats->requests > 0
                   ? stats->latency_total / (double) stats->requests * 1000.0
                   : 0.0);
    printf("soak latency_max_ms    %.1f\n", stats->latency_max * 1000.0);
    printf("soak failures          %llu\n", failed);

    for (i = 0; i < SOAK_FAILURE_COUNT; i++) {
        printf("soak failure.%-12s %llu\n", failure_names[i], stats->failures[i]);
    }

    printf("soak status.2xx        %llu\n", stats->status[1]);
    printf("soak status.3xx        %llu\n", stats->status[2]);
    printf("soak status.4xx        %llu\n", stats->status[3]);
    printf("soak status.5xx        %llu\n", stats->status[4]);
    printf("soak status.none       %llu\n", stats->status[5]);
    printf("soak not_modified      %llu\n", stats->not_modified);
    printf("soak unknown_format    %llu\n", stats->unknown_format);

    for (i = 0; i < DIMS_ENDPOINT_COUNT; i++) {
        printf("soak endpoint.%-11s %llu\n",
               dims_endpoint_name((dims_endpoint) i), stats->by_endpoint[i]);
    }

    printf("\n%-20s %12s %12s\n", "mutation", "answered", "refused");
    for (i = 0; i < DIMS_TAMPER_COUNT; i++) {
        if (stats->tamper_ok[i] == 0 && stats->tamper_refused[i] == 0) {
            continue;
        }
        printf("%-20s %12llu %12llu\n", dims_tamper_name((dims_tamper) i),
               stats->tamper_ok[i], stats->tamper_refused[i]);
    }

    fflush(stdout);
}

int
main(int argc, char **argv)
{
    options o;
    dims_corpus corpus;
    dims_rng rng;
    statistics stats;
    CURLM *multi;
    slot *slots;
    double start;
    double last_report;
    uint64_t sequence = 0;
    int running = 0;
    int i;
    int failed_total = 0;

    memset(&o, 0, sizeof(o));
    o.base = "http://dims:8000";
    o.manifest = "corpus/manifest.tsv";
    o.failures_path = NULL;
    o.seconds = 600;
    o.connections = 16;
    o.timeout = 120;
    o.report_every = 30;
    o.max_failures = 2000;
    o.seed = 1;
    o.world.origin = "http://origin:8080";
    o.world.client = "soak";
    o.world.secret = "soaksecret";
    o.world.signing_key = "0123456789abcdef0123456789abcdef";
    o.world.overlay = NULL;
    o.world.use_eurl = 1;

    for (i = 1; i < argc; i++) {
        const char *name = argv[i];
        const char *value = (i + 1 < argc) ? argv[i + 1] : NULL;

        if (strcmp(name, "--no-eurl") == 0) {
            o.world.use_eurl = 0;
            continue;
        }
        if (strcmp(name, "--eurl-ecb") == 0) {
            o.world.eurl_ecb = 1;
            continue;
        }
        if (strcmp(name, "--help") == 0) {
            usage();
            return 0;
        }
        if (value == NULL) {
            usage();
            return 2;
        }

        if (strcmp(name, "--base") == 0) { o.base = value; }
        else if (strcmp(name, "--origin") == 0) { o.world.origin = value; }
        else if (strcmp(name, "--manifest") == 0) { o.manifest = value; }
        else if (strcmp(name, "--overlay") == 0) { o.world.overlay = value; }
        else if (strcmp(name, "--client") == 0) { o.world.client = value; }
        else if (strcmp(name, "--secret") == 0) { o.world.secret = value; }
        else if (strcmp(name, "--key") == 0) { o.world.signing_key = value; }
        else if (strcmp(name, "--seconds") == 0) { o.seconds = atol(value); }
        else if (strcmp(name, "--connections") == 0) { o.connections = atol(value); }
        else if (strcmp(name, "--timeout") == 0) { o.timeout = atol(value); }
        else if (strcmp(name, "--seed") == 0) { o.seed = strtoull(value, NULL, 10); }
        else if (strcmp(name, "--report") == 0) { o.report_every = atol(value); }
        else if (strcmp(name, "--failures") == 0) { o.failures_path = value; }
        else if (strcmp(name, "--max-failures") == 0) { o.max_failures = atol(value); }
        else if (strcmp(name, "--dump") == 0) { o.dump = atol(value); }
        else { usage(); return 2; }

        i++;
    }

    if (!dims_corpus_load(&corpus, o.manifest)) {
        fprintf(stderr, "the manifest at %s did not load: %s\n",
                o.manifest, strerror(errno));
        return 2;
    }

    o.world.corpus = &corpus;

    if (o.world.overlay == NULL) {
        static char overlay[512];

        snprintf(overlay, sizeof(overlay), "%s/%s", o.world.origin,
                 corpus.image_count > 0
                         ? corpus.items[corpus.image[0]].name
                         : corpus.items[0].name);
        o.world.overlay = overlay;
    }

    fprintf(stderr,
            "corpus %zu files: %zu image, %zu reject, %zu either\n",
            corpus.count, corpus.image_count, corpus.reject_count,
            corpus.either_count);
    fprintf(stderr, "seed %llu, %ld connections, %ld seconds\n",
            (unsigned long long) o.seed, o.connections, o.seconds);

    if (o.failures_path != NULL) {
        failure_file = fopen(o.failures_path, "w");
        if (failure_file == NULL) {
            fprintf(stderr, "cannot write %s: %s\n", o.failures_path,
                    strerror(errno));
            return 2;
        }
    }

    if (o.dump > 0) {
        dims_rng rng_dump;
        long n;

        dims_rng_seed(&rng_dump, o.seed);

        for (n = 0; n < o.dump; n++) {
            dims_plan plan;

            dims_plan_make(&plan, &o.world, &rng_dump, (uint64_t) n);
            printf("%-6s %-18s %-6s %s%s\n", dims_endpoint_name(plan.endpoint),
                   dims_tamper_name(plan.tamper), dims_expect_name(plan.expect),
                   o.base, plan.path);
            dims_plan_free(&plan);
        }

        dims_corpus_free(&corpus);
        return 0;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    multi = curl_multi_init();

    dims_rng_seed(&rng, o.seed);
    memset(&stats, 0, sizeof(stats));

    slots = calloc((size_t) o.connections, sizeof(*slots));
    for (i = 0; i < o.connections; i++) {
        slots[i].easy = curl_easy_init();
        arm(&slots[i], &o, &rng, sequence++);
        curl_multi_add_handle(multi, slots[i].easy);
    }

    start = now_seconds();
    last_report = start;

    for (;;) {
        CURLMsg *message;
        int left = 0;
        double elapsed;

        curl_multi_perform(multi, &running);

        while ((message = curl_multi_info_read(multi, &left)) != NULL) {
            slot *s = NULL;

            if (message->msg != CURLMSG_DONE) {
                continue;
            }

            curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, &s);
            if (s == NULL) {
                continue;
            }

            judge(&o, s, message->data.result, &stats);

            curl_multi_remove_handle(multi, s->easy);

            elapsed = now_seconds() - start;

            if (stop_now || (o.seconds > 0 && elapsed >= (double) o.seconds)) {
                s->active = 0;
                continue;
            }

            arm(s, &o, &rng, sequence++);
            curl_multi_add_handle(multi, s->easy);
        }

        elapsed = now_seconds() - start;

        if (elapsed - (last_report - start) >= (double) o.report_every) {
            print_progress(&stats, elapsed);
            last_report = now_seconds();
        }

        if (stop_now || (o.seconds > 0 && elapsed >= (double) o.seconds)) {
            int still = 0;

            for (i = 0; i < o.connections; i++) {
                still += slots[i].active;
            }
            if (still == 0) {
                break;
            }
        }

        if (running > 0) {
            curl_multi_poll(multi, NULL, 0, 200, NULL);
        } else if (stop_now || (o.seconds > 0 && elapsed >= (double) o.seconds)) {
            break;
        }
    }

    print_summary(&stats, now_seconds() - start, o.seed);

    for (i = 0; i < SOAK_FAILURE_COUNT; i++) {
        failed_total += (stats.failures[i] > 0);
    }

    for (i = 0; i < o.connections; i++) {
        curl_multi_remove_handle(multi, slots[i].easy);
        curl_easy_cleanup(slots[i].easy);
        dims_plan_free(&slots[i].plan);
        free(slots[i].url);
        if (slots[i].headers != NULL) {
            curl_slist_free_all(slots[i].headers);
        }
    }

    free(slots);
    curl_multi_cleanup(multi);
    curl_global_cleanup();
    dims_corpus_free(&corpus);

    if (failure_file != NULL) {
        fclose(failure_file);
    }

    return failed_total > 0 ? 1 : 0;
}
