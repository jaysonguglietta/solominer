"""Offline C regression tests for the pinned upstream hardening patch.

Only extracted patched functions are compiled. No miner, pool connection, or
network process is started. Set CPUMINER_SOURCE to a clean checkout of the pinned
commit to also test git apply --check; CI should fetch the commit explicitly.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "patches/cpuminer-opt-v26.1-security.patch"
PIN = "b34565bfaca5da9ed894a326e3ba0dfe459550a4"


def patched_fragments() -> str:
    """Read only postimage/context lines, never execute text from the patch."""
    result = []
    in_hunk = False
    for line in PATCH.read_text().splitlines(keepends=True):
        if line.startswith("@@"):
            in_hunk = True
            continue
        if line.startswith("diff --git"):
            in_hunk = False
        if in_hunk and line[:1] in ("+", " "):
            result.append(line[1:])
    return "".join(result)


SOURCE = patched_fragments()


def function(name: str) -> str:
    match = re.search(r"(?m)^(?:static )?(?:inline )?(?:CURLcode|bool|float|char \*|void) ?" + name + r"\(", SOURCE)
    if not match:
        raise AssertionError(f"Complete patched function missing: {name}")
    end = SOURCE.index("\n}\n", match.start()) + 3
    return SOURCE[match.start():end]


macro_start = SOURCE.index("#define CURL_SETOPT_OR_GOTO")
macro_end = SOURCE.index("} while (0)", macro_start) + len("} while (0)")
SETOPT_MACRO = SOURCE[macro_start:macro_end]
BUFFER_CONSTANTS = "\n".join(
    line for line in SOURCE.splitlines()
    if re.match(r"#define (?:RBUFSIZE|RECVSIZE|STRATUM_MAX_BUFFER|STRATUM_FRAME_TIMEOUT)\b", line)
)


HEADERS = r"""
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#define LOG_ERR 1
#define LOG_WARNING 2
#define LOG_DEBUG 3
#define LIBCURL_VERSION_NUM 0x080000
#define CURLE_OK 0
#define CURLE_AGAIN 81
#define CURLE_UNKNOWN_OPTION 48
#define CURL_SOCKET_BAD -1
typedef struct { int unused; } CURL;
typedef int CURLcode;
static bool opt_protocol = false;
#define applog(...) ((void)0)
static int fail_malloc, fail_realloc;
static void *controlled_malloc(size_t n) {
    if (fail_malloc) { fail_malloc = 0; return NULL; }
    return malloc(n);
}
static void *controlled_realloc(void *p, size_t n) {
    if (fail_realloc) { fail_realloc = 0; return NULL; }
    return realloc(p, n);
}
"""


BUFFER_HARNESS = HEADERS + r"""
struct stratum_ctx {
    char *sockbuf;
    size_t sockbuf_size;
    CURL *curl;
    int sock;
};
static int disconnects;
static time_t fake_clock;
static const char *payload;
static size_t payload_length, payload_offset, receive_chunk;
static bool repeat_again;
static time_t controlled_time(time_t *p) {
    if (p) *p = fake_clock;
    return fake_clock;
}
static bool socket_full(int sock, int timeout) {
    (void)sock;
    fake_clock += timeout;
    return true;
}
static void stratum_disconnect(struct stratum_ctx *ctx) {
    disconnects++;
    ctx->curl = NULL;
    if (ctx->sockbuf) ctx->sockbuf[0] = 0;
}
static CURLcode curl_easy_recv(CURL *curl, char *out, size_t cap, size_t *n) {
    assert(curl);
    if (payload_offset == payload_length) {
        *n = 0;
        return repeat_again ? CURLE_AGAIN : CURLE_OK;
    }
    *n = payload_length - payload_offset;
    if (*n > cap) *n = cap;
    if (*n > receive_chunk) *n = receive_chunk;
    memcpy(out, payload + payload_offset, *n);
    payload_offset += *n;
    return CURLE_OK;
}
#define malloc controlled_malloc
#define realloc controlled_realloc
#define time controlled_time
""" + BUFFER_CONSTANTS + "\n" + function("stratum_buffer_append") + function("stratum_recv_line") + r"""
static CURL fake_curl;
static struct stratum_ctx new_context(void) {
    struct stratum_ctx ctx = {0};
    ctx.sockbuf = calloc(RBUFSIZE, 1);
    assert(ctx.sockbuf);
    ctx.sockbuf_size = RBUFSIZE;
    ctx.curl = &fake_curl;
    return ctx;
}
static void input(const char *p, size_t n, size_t chunk, bool again) {
    payload = p; payload_length = n; payload_offset = 0;
    receive_chunk = chunk; repeat_again = again;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    struct stratum_ctx ctx = new_context();
    const char *name = argv[1];
    if (!strcmp(name, "bound")) {
        char *large = calloc(STRATUM_MAX_BUFFER, 1);
        assert(large);
        memset(large, 'a', STRATUM_MAX_BUFFER);
        assert(stratum_buffer_append(&ctx, large, STRATUM_MAX_BUFFER));
        assert(ctx.sockbuf_size == STRATUM_MAX_BUFFER + 1);
        assert(strlen(ctx.sockbuf) == STRATUM_MAX_BUFFER);
        assert(!stratum_buffer_append(&ctx, "x", 1));
        assert(strlen(ctx.sockbuf) == STRATUM_MAX_BUFFER);
        free(large);
    } else if (!strcmp(name, "nul")) {
        const char bad[] = {'a', 0, 'b'};
        assert(!stratum_buffer_append(&ctx, bad, sizeof(bad)));
        assert(ctx.sockbuf[0] == 0);
    } else if (!strcmp(name, "realloc")) {
        char large[RBUFSIZE]; memset(large, 'a', sizeof(large));
        strcpy(ctx.sockbuf, "keep");
        char *original = ctx.sockbuf;
        size_t capacity = ctx.sockbuf_size;
        fail_realloc = 1;
        assert(!stratum_buffer_append(&ctx, large, sizeof(large)));
        assert(ctx.sockbuf == original && ctx.sockbuf_size == capacity);
        assert(!strcmp(ctx.sockbuf, "keep"));
    } else if (!strcmp(name, "fragmented")) {
        input("first\nsecond\n", 13, 2, false);
        char *first = stratum_recv_line(&ctx);
        assert(first && !strcmp(first, "first")); free(first);
        char *second = stratum_recv_line(&ctx);
        assert(second && !strcmp(second, "second")); free(second);
        assert(disconnects == 0 && ctx.sockbuf[0] == 0);
    } else if (!strcmp(name, "empty_frame")) {
        input("\nsecond\n", 8, 8, false);
        char *first = stratum_recv_line(&ctx);
        assert(first && !strcmp(first, "")); free(first);
        char *second = stratum_recv_line(&ctx);
        assert(second && !strcmp(second, "second")); free(second);
        assert(disconnects == 0);
    } else if (!strcmp(name, "truncated")) {
        input("{\"id\":1}", 8, 8, true);
        assert(stratum_recv_line(&ctx) == NULL);
        assert(fake_clock == STRATUM_FRAME_TIMEOUT);
        assert(disconnects == 1 && !ctx.curl && !ctx.sockbuf[0]);
    } else if (!strcmp(name, "oversized")) {
        char *large = calloc(STRATUM_MAX_BUFFER + 2, 1);
        assert(large); memset(large, 'a', STRATUM_MAX_BUFFER + 2);
        input(large, STRATUM_MAX_BUFFER + 2, RECVSIZE, false);
        assert(stratum_recv_line(&ctx) == NULL);
        assert(disconnects == 1 && !ctx.curl && !ctx.sockbuf[0]);
        assert(ctx.sockbuf_size <= STRATUM_MAX_BUFFER + 1);
        free(large);
    } else if (!strcmp(name, "peer_nul")) {
        const char bad[] = {'a', 0, 'b', '\n'};
        input(bad, sizeof(bad), sizeof(bad), false);
        assert(stratum_recv_line(&ctx) == NULL);
        assert(disconnects == 1 && !ctx.curl);
    } else if (!strcmp(name, "peer_realloc")) {
        char large[RBUFSIZE + 10]; memset(large, 'a', sizeof(large));
        input(large, sizeof(large), RECVSIZE, false);
        fail_realloc = 1;
        assert(stratum_recv_line(&ctx) == NULL);
        assert(disconnects == 1 && !ctx.curl && !ctx.sockbuf[0]);
    } else if (!strcmp(name, "frame_malloc")) {
        strcpy(ctx.sockbuf, "valid\n"); fail_malloc = 1;
        assert(stratum_recv_line(&ctx) == NULL);
        assert(disconnects == 1 && !ctx.curl && !ctx.sockbuf[0]);
    } else if (!strcmp(name, "peer_closed")) {
        input(NULL, 0, RECVSIZE, false);
        assert(stratum_recv_line(&ctx) == NULL);
        assert(disconnects == 1 && !ctx.curl);
    } else { assert(!"unknown test"); }
    free(ctx.sockbuf);
    return 0;
}
"""


TLS_HARNESS = HEADERS + r"""
#include <pthread.h>
#define CURLOPT_SSL_VERIFYPEER 1
#define CURLOPT_SSL_VERIFYHOST 2
#define CURLOPT_CAINFO 3
#define CURLOPT_VERBOSE 4
#define CURLOPT_URL 5
#define CURLOPT_FRESH_CONNECT 6
#define CURLOPT_CONNECTTIMEOUT 7
#define CURLOPT_ERRORBUFFER 8
#define CURLOPT_NOSIGNAL 9
#define CURLOPT_TCP_NODELAY 10
#define CURLOPT_PROXY 11
#define CURLOPT_PROXYTYPE 12
#define CURLOPT_HTTPPROXYTUNNEL 13
#define CURLOPT_SOCKOPTFUNCTION 14
#define CURLOPT_CONNECT_ONLY 15
#define CURLINFO_ACTIVESOCKET 16
#define CURL_ERROR_SIZE 256
static char *opt_cert;
static char *opt_proxy;
static int opt_proxy_type;
struct stratum_ctx {
    char *sockbuf, *url, *curl_url;
    size_t sockbuf_size;
    CURL *curl;
    int sock;
    pthread_mutex_t sock_lock;
    char curl_err_str[CURL_ERROR_SIZE];
};
static CURL fake_curl;
static int fail_option, last_option, calls, performs, cleanups, fail_calloc, fail_strdup;
static long peer, hostname;
static const char *ca;
static CURLcode curl_easy_setopt(CURL *curl, int option, ...) {
    assert(curl); calls++; last_option = option;
    if (option == fail_option) return CURLE_UNKNOWN_OPTION;
    va_list args; va_start(args, option);
    if (option == CURLOPT_SSL_VERIFYPEER) peer = va_arg(args, long);
    else if (option == CURLOPT_SSL_VERIFYHOST) hostname = va_arg(args, long);
    else if (option == CURLOPT_CAINFO) ca = va_arg(args, const char *);
    va_end(args);
    return CURLE_OK;
}
static const char *curl_easy_strerror(int rc) { (void)rc; return "mock setup failure"; }
static CURL *curl_easy_init(void) { return &fake_curl; }
static void curl_easy_cleanup(CURL *curl) { assert(curl); cleanups++; }
static int curl_easy_perform(CURL *curl) { assert(curl); performs++; return 0; }
static int curl_easy_getinfo(CURL *curl, int info, int *sock) {
    assert(curl && info == CURLINFO_ACTIVESOCKET); *sock = 3; return 0;
}
static int sockopt_keepalive_cb(void) { return 0; }
static void *controlled_calloc(size_t n, size_t size) {
    if (fail_calloc) { fail_calloc = 0; return NULL; }
    return calloc(n, size);
}
static char *controlled_strdup(const char *s) {
    if (fail_strdup) { fail_strdup = 0; return NULL; }
    return strdup(s);
}
#define malloc controlled_malloc
#define calloc controlled_calloc
#define strdup controlled_strdup
#define RBUFSIZE 2048
static void stratum_disconnect(struct stratum_ctx *sctx);
""" + SETOPT_MACRO + "\n" + function("configure_tls_verification") + function("stratum_connect") + function("stratum_disconnect") + r"""
int main(int argc, char **argv) {
    assert(argc == 2);
    const char *name = argv[1];
    struct stratum_ctx ctx = {0};
    assert(pthread_mutex_init(&ctx.sock_lock, NULL) == 0);
    if (!strcmp(name, "system_ca")) {
        ca = "previous setting";
        assert(configure_tls_verification(&fake_curl) == CURLE_OK);
        assert(peer == 1L && hostname == 2L && !strcmp(ca, "previous setting") && calls == 2);
    } else if (!strcmp(name, "custom_ca")) {
        opt_cert = "/etc/pki/ca-trust/source/anchors/pool.pem";
        assert(configure_tls_verification(&fake_curl) == CURLE_OK);
        assert(peer == 1L && hostname == 2L && ca == opt_cert);
    } else if (!strcmp(name, "fail_peer") || !strcmp(name, "fail_host") || !strcmp(name, "fail_ca")) {
        fail_option = !strcmp(name, "fail_peer") ? 1 : !strcmp(name, "fail_host") ? 2 : 3;
        opt_cert = "/etc/pool.pem";
        assert(configure_tls_verification(&fake_curl) == CURLE_UNKNOWN_OPTION);
        assert(calls == fail_option && last_option == fail_option);
    } else if (!strcmp(name, "connect_tls")) {
        opt_cert = "/etc/pool.pem";
        assert(stratum_connect(&ctx, "STRATUM+SSL://pool.example:443"));
        assert(!strcmp(ctx.curl_url, "https://pool.example:443"));
        assert(peer == 1L && hostname == 2L && ca == opt_cert && performs == 1);
    } else if (!strcmp(name, "connect_tcps")) {
        assert(stratum_connect(&ctx, "stratum+tcps://pool.example:443"));
        assert(!strcmp(ctx.curl_url, "https://pool.example:443"));
    } else if (!strcmp(name, "connect_tcp")) {
        assert(stratum_connect(&ctx, "stratum+tcp://pool.example:3333/ssl://"));
        assert(!strcmp(ctx.curl_url, "http://pool.example:3333/ssl://"));
    } else if (!strcmp(name, "connect_fail_tls")) {
        fail_option = CURLOPT_SSL_VERIFYHOST;
        assert(!stratum_connect(&ctx, "stratum+ssl://pool.example:443"));
        assert(performs == 0 && cleanups == 1 && !ctx.curl && !ctx.sockbuf[0]);
    } else if (!strcmp(name, "connect_fail_other")) {
        fail_option = CURLOPT_CONNECT_ONLY;
        assert(!stratum_connect(&ctx, "stratum+ssl://pool.example:443"));
        assert(performs == 0 && cleanups == 1 && !ctx.curl);
    } else if (!strcmp(name, "connect_calloc")) {
        fail_calloc = 1;
        assert(!stratum_connect(&ctx, "stratum+ssl://pool.example:443"));
        assert(performs == 0 && cleanups == 1 && !ctx.curl && !ctx.sockbuf);
    } else if (!strcmp(name, "connect_malloc")) {
        fail_malloc = 1;
        assert(!stratum_connect(&ctx, "stratum+ssl://pool.example:443"));
        assert(performs == 0 && cleanups == 1 && !ctx.curl);
    } else if (!strcmp(name, "connect_strdup")) {
        fail_strdup = 1;
        assert(!stratum_connect(&ctx, "stratum+ssl://pool.example:443"));
        assert(performs == 0 && cleanups == 1 && !ctx.curl && !ctx.url);
    } else if (!strcmp(name, "invalid_scheme")) {
        assert(!stratum_connect(&ctx, "https://pool.example"));
        assert(performs == 0 && cleanups == 0 && !ctx.curl);
    } else { assert(!"unknown test"); }
    if (ctx.curl) stratum_disconnect(&ctx);
    free(ctx.url); free(ctx.curl_url); free(ctx.sockbuf);
    pthread_mutex_destroy(&ctx.sock_lock);
    return 0;
}
"""


SEND_HARNESS = HEADERS + r"""
#include <sys/select.h>
struct stratum_ctx { CURL *curl; int sock; };
static int controlled_select(int nfds, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv) {
    (void)nfds; (void)r; (void)w; (void)e; (void)tv; return 1;
}
static CURLcode curl_easy_send(CURL *curl, const char *s, size_t len, size_t *n) {
    assert(curl && s && len); *n = len; return CURLE_OK;
}
#define select controlled_select
""" + function("send_line") + r"""
int main(void) {
    CURL curl;
    struct stratum_ctx ctx = { &curl, 0 };
    char frame[] = "share";
    assert(send_line(&ctx, frame));
    assert(frame[5] == '\n');
    return 0;
}
"""


THERMAL_HARNESS = HEADERS + r"""
#include <glob.h>
#include <ctype.h>
#include <errno.h>
#define CPUMINER_HWMON_ROOT @HWMON_ROOT@
""" + function("linux_cpu_sensor_name") + function("linux_cpu_sensor_temperature") + function("linux_cputemp") + r"""
int main(int argc, char **argv) {
    assert(argc == 2);
    int expected = (int)strtol(argv[1], NULL, 10);
    int actual = (int)(linux_cputemp(0) * 1000.0f + 0.5f);
    if (actual != expected) fprintf(stderr, "expected %d millidegrees; got %d\n", expected, actual);
    assert(actual == expected);
    return 0;
}
"""


class UpstreamPatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="solominer-c-regressions-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cc = shlex.split(os.environ.get("CC", "cc"))
        if not cc or not shutil.which(cc[0]):
            raise unittest.SkipTest("C compiler unavailable")
        cls.binaries = {}
        cls.hwmon = Path(cls.tmp.name) / "hwmon"
        thermal = THERMAL_HARNESS.replace("@HWMON_ROOT@", json.dumps(str(cls.hwmon)))
        # Optional sanitizer mode is useful in CI and on Linux. No miner runs.
        extra = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if os.environ.get("SANITIZE") == "1" else []
        for name, harness in (("buffer", BUFFER_HARNESS), ("tls", TLS_HARNESS), ("send", SEND_HARNESS), ("thermal", thermal)):
            cfile = Path(cls.tmp.name) / f"{name}.c"
            binary = Path(cls.tmp.name) / name
            cfile.write_text(harness)
            result = subprocess.run(cc + ["-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-Wno-unused-variable", "-O1", "-g", *extra, str(cfile), "-pthread", "-o", str(binary)], capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(f"{name} C harness did not compile:\n{result.stdout}{result.stderr}")
            cls.binaries[name] = binary

    def run_case(self, harness: str, case: str | None = None):
        command = [str(self.binaries[harness])]
        if case is not None:
            command.append(case)
        result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, f"{harness}/{case}: {result.stdout}{result.stderr}")

    def sensor_fixture(self, devices):
        shutil.rmtree(self.hwmon, ignore_errors=True)
        self.hwmon.mkdir()
        for number, (name, readings) in enumerate(devices):
            directory = self.hwmon / f"hwmon{number + 13}"
            directory.mkdir()
            (directory / "name").write_text(name + "\n")
            for index, reading in enumerate(readings):
                (directory / f"temp{index + 1}_input").write_text(reading)

    def test_thermal_hottest_recognized_cpu_only(self):
        self.sensor_fixture([
            ("nvme", ["120000\n"]),
            ("coretemp", ["42000\n", "90000\n"]),
            ("k10temp", ["75000\n"]),
        ])
        self.run_case("thermal", "90000")

    def test_thermal_missing_sensor(self):
        self.sensor_fixture([])
        self.run_case("thermal", "0")

    def test_thermal_invalid_readings_rejected(self):
        self.sensor_fixture([("coretemp", ["-1\n", "150001\n", "not a number\n", "42000junk\n", "99999999999999999999999999\n", "40000.5\n"])])
        self.run_case("thermal", "0")

    def test_thermal_allowlist_matches_runtime(self):
        names = ("coretemp", "k10temp", "k8temp", "zenpower", "cpu_thermal", "x86_pkg_temp")
        for name in names:
            with self.subTest(name=name):
                self.sensor_fixture([(name, ["55000\n"])])
                self.run_case("thermal", "55000")

    def test_thermal_unrelated_sensor_rejected(self):
        self.sensor_fixture([("nvme", ["100000\n"]), ("acpitz", ["110000\n"]), ("coretemp-evil", ["120000\n"])])
        self.run_case("thermal", "0")

    def test_thermal_name_without_readings(self):
        self.sensor_fixture([("coretemp", [])])
        self.run_case("thermal", "0")

    def test_rpc_and_stratum_use_checked_tls_setup(self):
        for name in ("json_rpc_call", "stratum_connect"):
            # RPC has a different return type and is inspected separately.
            body = function(name) if name == "stratum_connect" else SOURCE[SOURCE.index("json_t *json_rpc_call("):SOURCE.index("/* used to load a remote config */")]
            self.assertIn("rc = configure_tls_verification(curl);", body)
            self.assertNotIn("curl_easy_setopt(", body)
            self.assertLess(body.index("configure_tls_verification(curl)"), body.index("curl_easy_perform(curl)"))
        self.assertIn("*curl_err = rc;", SOURCE)

    def test_send_count_is_real_size_t(self):
        self.assertIn("size_t n = 0;", function("send_line"))
        self.assertNotIn("(size_t *)&n", function("send_line"))
        self.run_case("send")

    def test_apply_to_exact_pinned_source(self):
        upstream = os.environ.get("CPUMINER_SOURCE")
        if not upstream:
            self.skipTest("Set CPUMINER_SOURCE to clean pinned checkout for apply validation")
        revision = subprocess.check_output(["git", "-C", upstream, "rev-parse", "HEAD"], text=True).strip()
        self.assertEqual(revision, PIN)
        result = subprocess.run(["git", "-C", upstream, "apply", "--check", str(PATCH)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


def add_case(harness: str, case: str):
    def test(self):
        self.run_case(harness, case)
    test.__name__ = f"test_{harness}_{case}"
    setattr(UpstreamPatchTests, test.__name__, test)


for case in ("bound", "nul", "realloc", "fragmented", "empty_frame", "truncated", "oversized", "peer_nul", "peer_realloc", "frame_malloc", "peer_closed"):
    add_case("buffer", case)
for case in ("system_ca", "custom_ca", "fail_peer", "fail_host", "fail_ca", "connect_tls", "connect_tcps", "connect_tcp", "connect_fail_tls", "connect_fail_other", "connect_calloc", "connect_malloc", "connect_strdup", "invalid_scheme"):
    add_case("tls", case)


if __name__ == "__main__":
    unittest.main()
