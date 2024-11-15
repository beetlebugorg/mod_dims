
#include <httpd.h>
#include <scoreboard.h>
#include <apr.h>
#include <openssl/sha.h>
#include "mod_dims.h"

apr_status_t
status_handler(request_rec *r) {
    apr_time_t uptime;

    ap_set_content_type(r, "text/plain");
    ap_rvputs(r, "ALIVE\n\n", NULL);

    uptime = (apr_uint32_t) apr_time_sec(apr_time_now() -
            ap_scoreboard_image->global->restart_time);

    ap_rprintf(r, "Restart time: %s\n", 
            ap_ht_time(r->pool,
            ap_scoreboard_image->global->restart_time,
            "%A, %d-%b-%Y %H:%M:%S %Z", 0));

    ap_rprintf(r, "\nmod_dims version: %s (%s)\n", MODULE_VERSION, MODULE_RELEASE);
    ap_rprintf(r, "ImageMagick version: %s\n", GetMagickVersion(NULL));
    ap_rprintf(r, "libcurl version: %s\n", curl_version());

    ap_rflush(r);

    return OK;
}