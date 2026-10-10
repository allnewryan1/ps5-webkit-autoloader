/*
 * HTTP Server - serves the cached frontend files from the generated file
 * registry and handles the /install route (installs the homescreen app once
 * the cache is complete and shuts the server down).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <microhttpd.h>

#include "wkali.h"
#include "http_server.h"
#include "file_registry.h"
#include "inflate.h"
#include "app_installer.h"
#include "webkit_cleaner.h"
#include "simulate_corrupt.h"

/* CORS is intentionally `*`: the installer page is also served from the PC
 * host (manuals.playstation.net over HTTPS), which cross-origin XHRs this
 * on-console server (http://127.0.0.1:18181) for /version and
 * /install. The server binds 127.0.0.1 only and lives for seconds.
 * Do not restrict unless that flow changes. */
#define CORS_ORIGIN "*"

/* Shared flag — set to 0 by a successful /install or /exit, read by the main loop.
 * atomic so the store in a connection thread is visible to the main loop. */
atomic_int http_keep_running = 1;

/* Set to 1 only when /install succeeds so shutdown knows to notify success. */
atomic_int install_completed = 0;

/* Set to 1 by a successful /clear-webkit-data, read by the main loop to
 * re-launch the browser. atomic so the store in a connection thread is
 * visible to the main loop. */
atomic_int webkit_data_cleared = 0;

/* One /install at a time. A duplicate AppCache completion event used to start
 * a second install or report failure while the first was still working. */
static atomic_int install_once = 0;

/* Inflated registry entries, reused across the thread pool. AppCache fetches
 * the chain pages in parallel; inflating each one per request (~9 MB) was
 * enough to run the installer out of memory and leave a half-written cache. */
#define INFLATE_CACHE_SLOTS 16
struct Inflated {
    const FileEntry *entry;
    unsigned char *data;
    size_t size;
};
static struct Inflated inflate_cache[INFLATE_CACHE_SLOTS];
static atomic_flag inflate_lock = ATOMIC_FLAG_INIT;

static void inflate_lock_acquire(void) {
    unsigned spins = 0;
    while (atomic_flag_test_and_set_explicit(&inflate_lock, memory_order_acquire)) {
        if (++spins > 64)
            usleep(1000);
    }
}

static void inflate_lock_release(void) {
    atomic_flag_clear_explicit(&inflate_lock, memory_order_release);
}

/* 0 = served, -1 = out of memory, -2 = inflate error.
 * Compressed hits are persistent for the life of the installer. */
static int open_entry(const FileEntry *entry, void **payload, size_t *payload_size,
                      enum MHD_ResponseMemoryMode *mem_mode) {
    if (!entry->compressed) {
        *payload = (void *)entry->data;
        *payload_size = entry->size;
        *mem_mode = MHD_RESPMEM_PERSISTENT;
        return 0;
    }

    inflate_lock_acquire();
    for (int i = 0; i < INFLATE_CACHE_SLOTS; i++) {
        if (inflate_cache[i].entry == entry) {
            *payload = inflate_cache[i].data;
            *payload_size = inflate_cache[i].size;
            *mem_mode = MHD_RESPMEM_PERSISTENT;
            inflate_lock_release();
            return 0;
        }
    }

    unsigned char *decompressed = malloc(entry->orig_size + 1);
    if (!decompressed) {
        inflate_lock_release();
        return -1;
    }
    unsigned long destlen = entry->orig_size;
    unsigned long sourcelen = entry->size;
    int err = puff(decompressed, &destlen, entry->data, &sourcelen);
    if (err != 0) {
        free(decompressed);
        inflate_lock_release();
        return -2;
    }
    decompressed[destlen] = '\0';

    int slot = -1;
    for (int i = 0; i < INFLATE_CACHE_SLOTS; i++) {
        if (!inflate_cache[i].entry) {
            slot = i;
            break;
        }
    }
    if (slot >= 0) {
        inflate_cache[slot].entry = entry;
        inflate_cache[slot].data = decompressed;
        inflate_cache[slot].size = destlen;
        *mem_mode = MHD_RESPMEM_PERSISTENT;
    } else {
        *mem_mode = MHD_RESPMEM_MUST_FREE;
    }
    *payload = decompressed;
    *payload_size = destlen;
    inflate_lock_release();
    return 0;
}

static struct MHD_Response *plain_response(const char *text) {
    return MHD_create_response_from_buffer(strlen(text), (void *)text, MHD_RESPMEM_PERSISTENT);
}

/* Which chains this request's firmware supports: 1 = Poops, 2 = Relapse, 3 = both.
 * Read from the User-Agent, or a ?fw= argument for desktop testing. Recomputed
 * per request and never stored: a remembered choice was what got wiped
 * mid-download and came back stale in earlier revisions. */
static int supported_chains(struct MHD_Connection *conn) {
    const char *ua = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "User-Agent");
    const char *ps5 = ua ? strstr(ua, "PlayStation 5/") : NULL;
    const char *fw_arg = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "fw");
    float fw = ps5 ? strtof(ps5 + 14, NULL) : (fw_arg ? strtof(fw_arg, NULL) : 0);
    /* A PlayStation UA we could not parse must not be treated as a desktop
     * preview. Guessing both chains there runs an exploit the firmware table
     * does not know and kernel-panics. */
    if (fw == 0) return ps5 ? 0 : 3;
    int poops = fw >= 7 && fw <= 12;
    int relapse = fw >= 7 && fw <= 13.60f && fw != 9.05f && fw != 11.40f;
    return poops | (relapse << 1);
}

static void add_cors_headers(struct MHD_Response *resp) {
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", CORS_ORIGIN);
}

static const FileEntry *registry_lookup(const char *url) {
    if (strcmp(url, ROUTE_INDEX) == 0)
        return file_registry_find(ROUTE_INDEX_HTML);
    return file_registry_find(url);
}

enum MHD_Result http_on_request(void *cls, struct MHD_Connection *conn,
                                const char *url, const char *method,
                                const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {

    (void)cls;
    (void)version;
    (void)upload_data;
    (void)upload_data_size;
    /* Handle CORS Preflight (OPTIONS) */
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *resp =
            MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        add_cors_headers(resp);
        MHD_add_response_header(resp, "Access-Control-Allow-Methods",
                                "GET, OPTIONS");
        MHD_add_response_header(resp, "Access-Control-Allow-Headers",
                                "Content-Type");
        enum MHD_Result ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret;
    }

    /* ── Initial call for a new request ────────────────────── */
    if (*con_cls == NULL) {
        *con_cls = (void *)1;
        return MHD_YES;
    }

    struct MHD_Response *resp = NULL;
    int http_status = MHD_HTTP_OK;
    /* Whether this request may start caching. Decided from the request alone --
     * the query string and the User-Agent -- so nothing is remembered between
     * requests and nothing can be left stale by a later one. The entry page is
     * served without its manifest attribute until the user has been given a
     * choice, because AppCache starts on the attribute and JS runs too late to
     * stop it. Firmware with only one chain needs no question, so it may cache
     * immediately. Both chain pages are always cached once it starts, so the
     * cached bytes do not depend on the choice and never have to be invalidated.
     */
    int chains = supported_chains(conn);
    const char *arg = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "exploit");
    int requested = arg && strcmp(arg, "poops") == 0 ? 1 :
                    arg && strcmp(arg, "relapse") == 0 ? 2 : 0;
    int single_chain = chains == 1 || chains == 2;
    int cache_allowed = chains != 0 && (single_chain || (requested & chains) != 0);
    int entry_page = strcmp(url, ROUTE_INDEX) == 0 || strcmp(url, ROUTE_INDEX_HTML) == 0;

    if (strcmp(url, ROUTE_INSTALL) == 0) {
        /* Called by the installer page once the AppCache is fully cached. The
         * homescreen app is only installed/updated now — never on startup —
         * so a shortcut is never created for a partial cache. On failure the
         * server stays up and the page tells the user to re-run the installer. */
        if (atomic_load(&install_completed)) {
            resp = plain_response("OK");
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_OK;
        } else {
            int expected = 0;
            if (!atomic_compare_exchange_strong(&install_once, &expected, 1)) {
                for (int i = 0; i < 200 && !atomic_load(&install_completed); i++)
                    usleep(50000);
                if (atomic_load(&install_completed)) {
                    resp = plain_response("OK");
                    http_status = MHD_HTTP_OK;
                } else {
                    installer_log("[WKALI] App install still in progress or failed.\n");
                    resp = plain_response("Install failed");
                    http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
                }
                MHD_add_response_header(resp, "Content-Type", "text/plain");
            } else {
                int err = installer_install_app_if_needed();
                if (err == 0) {
                    installer_log("[WKALI] App installed. Stopping server...\n");
                    resp = plain_response("OK");
                    MHD_add_response_header(resp, "Content-Type", "text/plain");
                    http_status = MHD_HTTP_OK;
                    atomic_store(&install_completed, 1);
                    atomic_store(&http_keep_running, 0);
                } else {
                    installer_log("[WKALI] App install failed (%d). Staying up.\n", err);
                    resp = plain_response("Install failed");
                    MHD_add_response_header(resp, "Content-Type", "text/plain");
                    http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
                    /* Let a later retry try again. The previous install is intact. */
                    atomic_store(&install_once, 0);
                }
            }
        }
    } else if (strcmp(url, ROUTE_EXIT) == 0) {
        installer_log("[WKALI] Exit requested by client. Stopping server...\n");
        resp = MHD_create_response_from_buffer(2, (void *)"OK",
                                               MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "text/plain");
        http_status = MHD_HTTP_OK;
        atomic_store(&http_keep_running, 0);
    } else if (strcmp(url, ROUTE_VERSION) == 0) {
        resp = MHD_create_response_from_buffer(strlen(WKAL_FULL_VERSION),
                                               (void *)WKAL_FULL_VERSION,
                                               MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(resp, "Content-Type", "text/plain");
        extern int sceUserServiceGetForegroundUser(int *);
        int uid = -1;
        if (sceUserServiceGetForegroundUser(&uid) == 0 && uid > 0) {
            char uid_hdr[32];
            snprintf(uid_hdr, sizeof(uid_hdr), "%08x", (unsigned int)uid);
            MHD_add_response_header(resp, "X-User-Id", uid_hdr);
        }
    } else if (strcmp(url, "/logs") == 0) {
        const char *pos_str = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "pos");
        size_t pos = 0;
        if (pos_str) pos = (size_t)strtoull(pos_str, NULL, 10);

        char *logs = malloc(16384 + 64);
        if (logs) {
            size_t copied = installer_wait_logs(&pos, logs, 16384);
            /* Append the new pos as an HTTP header so the client knows */
            resp = MHD_create_response_from_buffer(copied, (void *)logs, MHD_RESPMEM_MUST_FREE);
            char pos_hdr[64];
            snprintf(pos_hdr, sizeof(pos_hdr), "%zu", pos);
            MHD_add_response_header(resp, "X-Log-Pos", pos_hdr);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
        } else {
            const char *oom = "500 Internal Server Error\n";
            resp = MHD_create_response_from_buffer(strlen(oom), (void *)oom, MHD_RESPMEM_PERSISTENT);
        }
    } else if (strcmp(url, ROUTE_CLEAR_WEBKIT_DATA) == 0) {
        int err = installer_clear_webkit_data();
        if (err == 0) {
            installer_log("[WKALI] WebKit data cleared successfully. Will re-launch browser.\n");
            simulate_on_clear_success();
            resp = MHD_create_response_from_buffer(2, (void *)"OK",
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_OK;
            atomic_store(&webkit_data_cleared, 1);
        } else {
            installer_log("[WKALI] WebKit data clear failed.\n");
            const char *fail = "Clear failed";
            resp = MHD_create_response_from_buffer(strlen(fail), (void *)fail,
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        const FileEntry *entry = registry_lookup(url);
        if (entry) {
            /* Keep repeated root requests and log polling out of the on-screen
             * log; retain /index.html to show its explicit cache download. */
            if (strcmp(url, ROUTE_INDEX) != 0 && strcmp(url, "/logs") != 0) {
                installer_log("[HTTP] Serving %s (size: %u)\n", url, entry->size);
            }
            void *payload = NULL;
            size_t payload_size = 0;
            enum MHD_ResponseMemoryMode mem_mode = MHD_RESPMEM_PERSISTENT;

            int opened = open_entry(entry, &payload, &payload_size, &mem_mode);
            if (opened != 0) {
                const char *msg = opened == -1 ? "503 Out of Memory\n" : "500 Inflate Error\n";
                resp = MHD_create_response_from_buffer(strlen(msg), (void *)msg,
                                                       MHD_RESPMEM_PERSISTENT);
                MHD_add_response_header(resp, "Content-Type", "text/plain");
                http_status = opened == -1 ? MHD_HTTP_SERVICE_UNAVAILABLE
                                           : MHD_HTTP_INTERNAL_SERVER_ERROR;
                add_cors_headers(resp);
                enum MHD_Result ret = MHD_queue_response(conn, http_status, resp);
                MHD_destroy_response(resp);
                return ret;
            }


            /* Test simulation hook (no-op unless compiled with SIMULATE=1|2) */
            simulate_corrupt_manifest(url, &payload, &payload_size, &mem_mode);

            /* Removing the manifest attribute is what stops AppCache from starting
             * before an exploit has been chosen. */
            if (entry_page && !cache_allowed) {
                char *copy = malloc(payload_size + 64);
                if (!copy) {
                    if (mem_mode == MHD_RESPMEM_MUST_FREE) free(payload);
                    return MHD_NO;
                }
                memcpy(copy, payload, payload_size);
                copy[payload_size] = '\0';
                if (mem_mode == MHD_RESPMEM_MUST_FREE) free(payload);
                payload = copy;
                mem_mode = MHD_RESPMEM_MUST_FREE;
                char *attribute = strstr(copy, " manifest=\"/cache.appcache\"");
                if (attribute) memset(attribute, ' ', strlen(" manifest=\"/cache.appcache\""));
            }

            resp = MHD_create_response_from_buffer(payload_size, payload,
                                                   mem_mode);
            MHD_add_response_header(resp, "Content-Type", entry->content_type);
            if (strcmp(url, ROUTE_CACHE_MANIFEST) == 0 ||
                strstr(entry->content_type, "text/html") != NULL) {
                MHD_add_response_header(resp, "Cache-Control",
                                        "no-cache, must-revalidate");
            }
        } else {
            const char *not_found = "404 Not Found\n";
            resp = MHD_create_response_from_buffer(strlen(not_found),
                                                   (void *)not_found,
                                                   MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(resp, "Content-Type", "text/plain");
            http_status = MHD_HTTP_NOT_FOUND;
        }
    }

    if (!resp)
        return MHD_NO;

    add_cors_headers(resp);
    enum MHD_Result ret = MHD_queue_response(conn, http_status, resp);
    MHD_destroy_response(resp);

    return ret;
}
