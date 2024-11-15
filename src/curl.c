
#include <apr.h>
#include <MagickWand/MagickWand.h>

#include "request.h"
#include "mod_dims.h"
#include "curl.h"

/* Converts a hex character to its integer value */
static char from_hex(char ch) {
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
static char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
static char *url_encode(char *str) {
    char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr) {
        if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~' || *pstr == ':' || *pstr == '/' || *pstr == '?' || *pstr == '=' || *pstr == '&')
            *pbuf++ = *pstr;
        else
            *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

void 
lock_share(CURL *handle, 
           curl_lock_data data, 
           curl_lock_access access, 
           void *userptr)
{
    dims_curl_rec *locks = (dims_curl_rec *) userptr;       

    switch(data) {
        case CURL_LOCK_DATA_DNS:
            apr_thread_mutex_lock(locks->dns_mutex);
            break;
        default:
            apr_thread_mutex_lock(locks->share_mutex);
    }
}

void 
unlock_share(CURL *handle, 
             curl_lock_data data, 
             void *userptr) 
{
    dims_curl_rec *locks = (dims_curl_rec *) userptr;       

    switch(data) {
        case CURL_LOCK_DATA_DNS:
            apr_thread_mutex_unlock(locks->dns_mutex);
            break;
        default:
            apr_thread_mutex_unlock(locks->share_mutex);
    }
}

static int
dims_curl_debug_cb(
    CURL *handle,
    curl_infotype type,
    char *data,
    size_t size,
    void *clientp)
{
    dims_request_rec *d = (dims_request_rec *) clientp;
    switch(type) {
        case CURLINFO_HEADER_OUT:
            ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, d->r, "Curl request header data: %s ", data);
            break;
        default:
            break;
    }

    return 0;
}

/**
 * This callback is called by the libcurl API to write data into memory as it's being downloaded.
 */
size_t
dims_write_image_cb(void *new_data, size_t size, size_t nmemb, void *data)
{
    dims_image_data_t *image = (dims_image_data_t *) data;
    size_t realsize = size * nmemb;

    /* Allocate more memory if needed. */
    if(image->size - image->used <= realsize) {
        image->size = image->size == 0 ? realsize : (image->size + realsize) * 1.25;
        image->data = (char *) realloc(image->data, image->size);
    }

    if (image->data) {
        memcpy(&(image->data[image->used]), new_data, realsize);
        image->used += realsize;
    }

    return realsize;
}

static size_t
dims_write_header_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
    dims_request_rec *d = (dims_request_rec *) data;
    size_t realsize = size * nmemb;
    char *start = (char *) ptr;
    char *header = (char *) ptr;
    char *key = NULL, *value = NULL;

    while(header < (start + realsize)) {
        if(*header == ':') {
            key = apr_pstrndup(d->pool, start, header - start);
            while(*header == ' ') {
                header++;
            }
            value = apr_pstrndup(d->pool, header, start + realsize - header - 2);
            header = start + realsize;
        }
        header++;
    }

    if(key && value && strcmp(key, "Cache-Control") == 0) {
        d->source_image->cache_control = value;

        char *src_header = value;
        char *src_start = src_header;
        int src_len = strlen(src_header);

        // Ex. max-age=3600
        while(src_header < (src_start + src_len)) {
            if(*src_header == '=') {
                src_header++;
                while(*src_header == ' ') {
                    src_header++;
                }

                d->source_image->max_age = atoi(src_header);
            }
            src_header++;
        }
    } else if(key && value && strcmp(key, "Edge-Control") == 0) {
        d->source_image->edge_control = value;
    } else if(key && value && strcmp(key, "Last-Modified") == 0) {
        d->source_image->last_modified = value;
    } else if(key && value && strcmp(key, "ETag") == 0) {
        d->source_image->etag = value;
    }

    return realsize;
}

CURLcode
dims_curl(dims_request_rec *d, const char *url, dims_image_data_t *source_image)
{
    CURL *curl_handle;
    CURLcode code;

    dims_image_data_t image_data;
    image_data.data = NULL;
    image_data.size = 0;
    image_data.used = 0;

    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, dims_write_image_cb);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &image_data);
    curl_easy_setopt(curl_handle, CURLOPT_HEADERFUNCTION, dims_write_header_cb);
    curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *) d);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, d->config->download_timeout);
    curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_DEBUGFUNCTION, dims_curl_debug_cb);
    curl_easy_setopt(curl_handle, CURLOPT_DEBUGDATA, d);

    /* Set the user agent to dims/<version> */
    if (d->config->user_agent_override != NULL) {
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, d->config->user_agent_override);
    } else {
        char *dims_useragent = apr_psprintf(d->r->pool, "mod_dims/%s", MODULE_VERSION);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, dims_useragent);
    }

    /* The curl shared handle allows this process to share DNS cache
     * and prevents the DNS cache from going away after every request.
     */
    void *shared_locks = NULL;
    apr_pool_userdata_get((void *) &shared_locks, DIMS_CURL_SHARED_KEY, d->r->server->process->pool);
    if (shared_locks) {
        dims_curl_rec *locks = (dims_curl_rec *) shared_locks;
        curl_easy_setopt(curl_handle, CURLOPT_SHARE, locks->share);
    }

    code = curl_easy_perform(curl_handle);

    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &source_image->response_code);
    curl_easy_cleanup(curl_handle);

    if (source_image->response_code == 200) {
        source_image->data = apr_pmemdup(d->pool, image_data.data, image_data.used);
        source_image->size = image_data.used;
        source_image->used = image_data.used;
    }

    free(image_data.data);

    return code;
}

static apr_status_t
dims_curl_cleanup(void *data) {
    dims_curl_rec *locks = (dims_curl_rec *) data;

    curl_share_cleanup(locks->share);
    curl_global_cleanup();

    apr_thread_mutex_destroy(locks->share_mutex);
    apr_thread_mutex_destroy(locks->dns_mutex);

    apr_pool_userdata_set(NULL, DIMS_CURL_SHARED_KEY, NULL, locks->s->process->pool);
}

void 
dims_curl_init(apr_pool_t *p, server_rec *s) {
    curl_global_init(CURL_GLOBAL_ALL);

    dims_curl_rec *locks = (dims_curl_rec *) apr_pcalloc(p, sizeof(dims_curl_rec));

    locks->s = s;
    locks->share = curl_share_init(); 

    apr_thread_mutex_create(&locks->share_mutex, APR_THREAD_MUTEX_DEFAULT, p);
    apr_thread_mutex_create(&locks->dns_mutex, APR_THREAD_MUTEX_DEFAULT, p);

    curl_share_setopt(locks->share, CURLSHOPT_LOCKFUNC, lock_share); 
    curl_share_setopt(locks->share, CURLSHOPT_UNLOCKFUNC, unlock_share); 
    curl_share_setopt(locks->share, CURLSHOPT_USERDATA, (void *) locks); 
    curl_share_setopt(locks->share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);

    /* We have to associate our handle/locks with the process->pool otherwise
     * we won't be able to get at it from the remote_fetch_image function.  This
     * pool doesn't seem to go away when the child process goes away so we
     * have to register the clean up method below.
     */
    apr_pool_userdata_set(locks, DIMS_CURL_SHARED_KEY, NULL, s->process->pool);

    /* Register cleanup with the 'p' pool so we can clean up the locks and
     * shared curl handle when this process dies.
     */
    apr_pool_cleanup_register(p, locks, dims_curl_cleanup, dims_curl_cleanup);
}