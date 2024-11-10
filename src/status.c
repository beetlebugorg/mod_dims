
#include <httpd.h>
#include <scoreboard.h>
#include <apr.h>
#include <openssl/sha.h>
#include "mod_dims.h"

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
status_handler(request_rec *r) {
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

    ap_rprintf(r, "\nmod_dims version: %s (%s)\n", MODULE_VERSION, MODULE_RELEASE);
    ap_rprintf(r, "ImageMagick version: %s\n", GetMagickVersion(NULL));
    ap_rprintf(r, "libcurl version: %s\n", curl_version());

    ap_rprintf(r, "\nDetails\n-------\n");
    
    ap_rprintf(r, "Successful requests: %d\n", 
            apr_atomic_read32(&stats->success_count));
    ap_rprintf(r, "Failed requests: %d\n\n", 
            apr_atomic_read32(&stats->failure_count));
    ap_rprintf(r, "Download timeouts: %d\n", 
            apr_atomic_read32(&stats->download_timeout_count));
    ap_rprintf(r, "Imagemagick Timeouts: %d\n", 
            apr_atomic_read32(&stats->imagemagick_timeout_count));

    ap_rflush(r);

    return OK;
}