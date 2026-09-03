/*
 * The status endpoint and the counters it reports.
 *
 * Copyright 2009 AOL LLC
 * Copyright 2026 Jeremy Collins
 * SPDX-License-Identifier: Apache-2.0
 */

#include "status.h"
#include "metrics.h"
#include "module.h"

#include <scoreboard.h>

/*
 * The four numbers this endpoint prints, summed from the metrics block. A
 * request counts once, under the endpoint it arrived on.
 */
static apr_uint64_t
count_outcome(int outcome)
{
    apr_uint64_t total = 0;
    int e;

    if (dims_metrics == NULL) {
        return 0;
    }

    for (e = 0; e < DIMS_ENDPOINT_COUNT; e++) {
        total += apr_atomic_read64(&dims_metrics->requests[e][outcome]);
    }

    return total;
}

/* Every outcome apart from success. */
static apr_uint64_t
count_failures(void)
{
    apr_uint64_t total = 0;
    int i;

    for (i = 1; i < DIMS_OUTCOME_COUNT; i++) {
        total += count_outcome(i);
    }

    return total;
}


static void show_time(request_rec *r, apr_interval_time_t tsecs)
{
    int days, hrs, mins, secs;

    secs = (int)(tsecs % 60);
    tsecs /= 60;
    mins = (int)(tsecs % 60);
    tsecs /= 60;
    hrs = (int)(tsecs % 24);
    days = (int)(tsecs / 24);

    ap_rprintf(r, "Uptime: ");

    if (days) ap_rprintf(r, " %d day%s", days, days == 1 ? "" : "s");
    if (hrs) ap_rprintf(r, " %d hour%s", hrs, hrs == 1 ? "" : "s");
    if (mins) ap_rprintf(r, " %d minute%s", mins, mins == 1 ? "" : "s");
    if (secs) ap_rprintf(r, " %d second%s", secs, secs == 1 ? "" : "s");

    ap_rprintf(r, "\n");
}

apr_status_t
dims_status_handler(request_rec *r)
{
    dims_config_rec *config = (dims_config_rec *) ap_get_module_config(
            r->server->module_config, &dims_module);
    apr_time_t uptime;


        ap_set_content_type(r, "text/plain");
        ap_rvputs(r, "ALIVE\n\n", NULL);

        uptime = (apr_uint32_t) apr_time_sec(apr_time_now() -
                ap_scoreboard_image->global->restart_time);

        show_time(r, uptime);

        ap_rprintf(r, "Restart time: %s\n", 
                ap_ht_time(r->pool,
                ap_scoreboard_image->global->restart_time,
                "%A, %d-%b-%Y %H:%M:%S %Z", 0));

        /*
         * The versions name every library a caller would need to pick an
         * exploit, and the shipped configuration exposes this handler with no
         * access control. An operator who cannot restrict the location turns
         * them off instead.
         */
        if (config == NULL || config->status_verbose) {
            ap_rprintf(r, "\nmod_dims version: %s (%s)\n", DIMS_VERSION,
                    DIMS_COMMIT);
            ap_rprintf(r, "ImageMagick version: %s\n", GetMagickVersion(NULL));
            ap_rprintf(r, "libcurl version: %s\n", curl_version());
        }

        ap_rprintf(r, "\nDetails\n-------\n");
        
        ap_rprintf(r, "Successful requests: %" APR_UINT64_T_FMT "\n",
                count_outcome(DIMS_SUCCESS));
        ap_rprintf(r, "Failed requests: %" APR_UINT64_T_FMT "\n\n",
                count_failures());
        ap_rprintf(r, "Download timeouts: %" APR_UINT64_T_FMT "\n",
                count_outcome(DIMS_DOWNLOAD_TIMEOUT));
        ap_rprintf(r, "Imagemagick Timeouts: %" APR_UINT64_T_FMT "\n",
                count_outcome(DIMS_IMAGEMAGICK_TIMEOUT));

        ap_rflush(r);

    return OK;
}
