/* relapse-offset-dumper
 *
 * Kernel offset dumper for the Relapse PS5 jailbreak.
 * Extracts all firmware-specific kernel values needed to build an
 * offsets/XX.XX.js file for a new firmware port.
 *
 * Uses active RTM_GET for KASLR retStatic (mirrors exploit.js leakKernelBase),
 * brute-force rodata scanning, sysctl OID probing, and mutex name matching.
 *
 * Build:  export PS5_PAYLOAD_SDK=/path/to/ps5-payload-dev-sdk && make
 * Load via elfldr (port 9021) on a jailbroken console.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

#include <ps5/kernel.h>

#define OUT_DIR   "/data/relapse_dump"
#define REPORT    OUT_DIR "/offsets.txt"
#define LOG_FILE  OUT_DIR "/dumper.log"

/* OID struct field offsets (consistent on PS5) */
#define OID_OFF_KIND        0x14
#define OID_OFF_ARG1        0x18
#define OID_OFF_NUMBER      0x10
#define OID_OFF_NAME        0x28
#define OID_OFF_HANDLER     0x30

#define OID_KIND_ORIGINAL   0x80048002u

/* 11.20 and 11.60 reference RVAs for OID/nodeMutex probing.
 * These are text-base-relative (vaddr - 0xFFFFFFFF80210000). */
struct fw_ref {
    uint64_t oid_a_base;
    uint64_t oid_b_base;
    uint64_t oid_c_base;
    uint64_t node_mutex;
    uint64_t walk_counter;
    uint64_t oid_c_arg1val;
};

static const struct fw_ref REF_1120 = {
    .oid_a_base   = 0x02929E58,
    .oid_b_base   = 0x02929D30,
    .oid_c_base   = 0x02C4CB18,
    .node_mutex   = 0x01AF9F18,
    .walk_counter = 0x03CE3F38,
    .oid_c_arg1val= 0x03CE3F3C,
};

static const struct fw_ref REF_1160 = {
    .oid_a_base   = 0x02929ED0,
    .oid_b_base   = 0x02929DA8,
    .oid_c_base   = 0x02C4CB90,
    .node_mutex   = 0x03B77E20,
    .walk_counter = 0x03CE3F38,
    .oid_c_arg1val= 0x03CE3F3C,
};

/* ------------------------------------------------------------------ */
/* globals                                                             */
/* ------------------------------------------------------------------ */
static FILE *g_log = NULL;
static struct timeval g_start_tv;

/* ------------------------------------------------------------------ */
/* timing                                                              */
/* ------------------------------------------------------------------ */
static unsigned long
elapsed_ms(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return (unsigned long)((now.tv_sec - g_start_tv.tv_sec) * 1000 +
                           (now.tv_usec - g_start_tv.tv_usec) / 1000);
}

/* ------------------------------------------------------------------ */
/* notifications                                                       */
/* ------------------------------------------------------------------ */
typedef struct { char _pad[45]; char message[3075]; } notify_req_t;
int sceKernelSendNotificationRequest(int, notify_req_t *, size_t, int);

static void
notify(const char *fmt, ...) {
    notify_req_t req;
    va_list ap;
    memset(&req, 0, sizeof(req));
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

/* ------------------------------------------------------------------ */
/* logging: writes to both report file AND separate log file           */
/* ------------------------------------------------------------------ */
static void
logmsg(FILE *fp, const char *fmt, ...)
{
    va_list ap;
    char prefix[32];
    unsigned long ms = elapsed_ms();
    snprintf(prefix, sizeof(prefix), "[%lu.%03lus] ",
             ms / 1000, ms % 1000);

    /* write to report */
    va_start(ap, fmt);
    fputs(prefix, fp);
    vfprintf(fp, fmt, ap);
    fflush(fp);
    fsync(fileno(fp));
    va_end(ap);

    /* write to log file */
    if (g_log && g_log != fp) {
        va_start(ap, fmt);
        fputs(prefix, g_log);
        vfprintf(g_log, fmt, ap);
        fflush(g_log);
        fsync(fileno(g_log));
        va_end(ap);
    }
}

static void
logerr(FILE *fp, const char *fmt, ...)
{
    va_list ap;
    char prefix[32];
    unsigned long ms = elapsed_ms();
    snprintf(prefix, sizeof(prefix), "[%lu.%03lus] ERROR: ",
             ms / 1000, ms % 1000);

    va_start(ap, fmt);
    fputs(prefix, fp);
    vfprintf(fp, fmt, ap);
    fflush(fp);
    fsync(fileno(fp));
    va_end(ap);

    if (g_log && g_log != fp) {
        va_start(ap, fmt);
        fputs(prefix, g_log);
        vfprintf(g_log, fmt, ap);
        fflush(g_log);
        fsync(fileno(g_log));
        va_end(ap);
    }
}

/* plain fprintf + fflush + fsync for structured output (no timestamp) */
static void
report(FILE *fp, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    fflush(fp);
    fsync(fileno(fp));
    va_end(ap);
}

/* ------------------------------------------------------------------ */
/* self-cleaning: remove old dumps                                     */
/* ------------------------------------------------------------------ */
static void
clean_old_dumps(void)
{
    DIR *d = opendir(OUT_DIR);
    if (!d) return;

    struct dirent *ent;
    struct stat st;
    char path[512];
    int removed = 0;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "%s/%s", OUT_DIR, ent->d_name);
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode) && unlink(path) == 0)
            removed++;
    }
    closedir(d);
    if (removed > 0)
        notify("Cleaned %d old files", removed);
}

/* ------------------------------------------------------------------ */
/* kernel memory helpers                                               */
/* ------------------------------------------------------------------ */
static int g_kread_errors = 0;

static int
kread(intptr_t kaddr, void *buf, size_t len)
{
    int ret = kernel_copyout(kaddr, buf, len);
    if (ret != 0)
        g_kread_errors++;
    return ret;
}

static uint64_t kread8(intptr_t a) { uint64_t v=0; kread(a,&v,8); return v; }
static uint32_t kread4(intptr_t a) { uint32_t v=0; kread(a,&v,4); return v; }

static int
kread_str(intptr_t kaddr, char *buf, size_t max)
{
    size_t i;
    for (i = 0; i < max - 1; i += 8) {
        if (kread(kaddr + i, buf + i, 8))
            break;
        for (size_t j = 0; j < 8 && (i+j) < max-1; j++)
            if (buf[i+j] == '\0') return 0;
    }
    buf[max-1] = '\0';
    return 0;
}

/* ------------------------------------------------------------------ */
/* rodataProbe: scan for "_aio_submit_cmd" string in kernel rodata     */
/* ------------------------------------------------------------------ */
static intptr_t
scan_rodata_string(intptr_t kbase, FILE *fp)
{
    const char *needle = "_aio_submit_cmd";
    size_t nlen = strlen(needle);

    const size_t START = 0x01000000;
    const size_t END   = 0x01400000;
    const size_t CHUNK = 0x10000;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) {
        logerr(fp, "malloc(%zu) failed for rodata scan\n", CHUNK);
        return 0;
    }

    int chunks_ok = 0, chunks_fail = 0;
    for (size_t off = START; off < END; off += CHUNK - 64) {
        size_t want = CHUNK;
        if (off + want > END) want = END - off;
        if (kread(kbase + off, buf, want)) {
            chunks_fail++;
            continue;
        }
        chunks_ok++;

        for (size_t i = 0; i + nlen + 1 <= want; i++) {
            if (buf[i] == '_' &&
                memcmp(buf + i, needle, nlen) == 0 &&
                buf[i + nlen] == '\0') {
                logmsg(fp, "rodata: found at RVA 0x%lX (primary range, %d chunks ok, %d failed)\n",
                       (unsigned long)(off + i), chunks_ok, chunks_fail);
                free(buf);
                return off + i;
            }
        }
    }

    logmsg(fp, "rodata: not in primary range (0x%lX-0x%lX), %d ok / %d fail. Trying broader...\n",
           (unsigned long)START, (unsigned long)END, chunks_ok, chunks_fail);

    chunks_ok = 0; chunks_fail = 0;
    const size_t START2 = 0x00800000;
    const size_t END2   = 0x01800000;
    for (size_t off = START2; off < END2; off += CHUNK - 64) {
        size_t want = CHUNK;
        if (off + want > END2) want = END2 - off;
        if (kread(kbase + off, buf, want)) {
            chunks_fail++;
            continue;
        }
        chunks_ok++;

        for (size_t i = 0; i + nlen + 1 <= want; i++) {
            if (buf[i] == '_' &&
                memcmp(buf + i, needle, nlen) == 0 &&
                buf[i + nlen] == '\0') {
                logmsg(fp, "rodata: found at RVA 0x%lX (broad range, %d ok, %d fail)\n",
                       (unsigned long)(off + i), chunks_ok, chunks_fail);
                free(buf);
                return off + i;
            }
        }
    }

    logerr(fp, "rodata: NOT FOUND in any range (%d ok, %d fail chunks)\n",
           chunks_ok, chunks_fail);
    free(buf);
    return 0;
}

/* ------------------------------------------------------------------ */
/* OID probing: scan for sysctl_oid structs with kind 0x80048002       */
/* ------------------------------------------------------------------ */
static int
probe_oid_range(intptr_t kbase, intptr_t rva_lo, intptr_t rva_hi,
                const char *label, FILE *fp)
{
    logmsg(fp, "OID: scanning 0x%lX-0x%lX (%s)\n",
           (unsigned long)rva_lo, (unsigned long)rva_hi, label);

    int found = 0;
    int read_errors = 0;
    for (intptr_t off = rva_lo; off <= rva_hi; off += 8) {
        uint32_t kind = kread4(kbase + off + OID_OFF_KIND);
        if (kind == 0 && g_kread_errors > read_errors + 10) {
            logerr(fp, "OID: too many read errors at offset 0x%lX, skipping ahead\n",
                   (unsigned long)off);
            read_errors = g_kread_errors;
            continue;
        }
        if (kind == OID_KIND_ORIGINAL) {
            intptr_t name_ptr = (intptr_t)kread8(kbase + off + OID_OFF_NAME);
            char name[64] = {0};
            if (name_ptr && (name_ptr >> 48) == 0xFFFF)
                kread_str(name_ptr, name, sizeof(name));

            uint32_t oid_num = kread4(kbase + off + OID_OFF_NUMBER);
            intptr_t arg1 = (intptr_t)kread8(kbase + off + OID_OFF_ARG1);
            intptr_t handler = (intptr_t)kread8(kbase + off + OID_OFF_HANDLER);

            report(fp, "    OID at RVA 0x%lX: kind=0x%08X num=%u name=\"%s\""
                   " arg1=0x%lX handler=0x%lX\n",
                   (unsigned long)off, kind, oid_num, name,
                   (unsigned long)arg1, (unsigned long)handler);
            found++;
        }
    }
    logmsg(fp, "OID: %s scan done, found %d entries\n", label, found);
    return found;
}

/* ------------------------------------------------------------------ */
/* Dump a kernel region to file                                        */
/* ------------------------------------------------------------------ */
static size_t
dump_region(intptr_t kaddr, size_t size, const char *path, FILE *fp)
{
    const size_t CHUNK = 0x10000;
    uint8_t *buf = malloc(CHUNK);
    if (!buf) {
        logerr(fp, "dump: malloc failed for %s\n", path);
        return 0;
    }

    FILE *out = fopen(path, "wb");
    if (!out) {
        logerr(fp, "dump: fopen(%s) failed: errno=%d\n", path, errno);
        free(buf);
        return 0;
    }

    size_t written = 0;
    size_t failed = 0;
    size_t total_chunks = (size + CHUNK - 1) / CHUNK;
    for (size_t off = 0; off < size; off += CHUNK) {
        size_t want = CHUNK;
        if (off + want > size) want = size - off;
        if (kread(kaddr + off, buf, want)) {
            memset(buf, 0, want);
            failed += want;
        }
        fwrite(buf, 1, want, out);
        written += want;
    }

    fflush(out);
    fsync(fileno(out));
    fclose(out);
    free(buf);

    logmsg(fp, "dump: %s: %zu bytes written, %zu zero-filled (%zu/%zu chunks)\n",
           path, written, failed, total_chunks - (failed / CHUNK), total_chunks);
    return written;
}

/* ------------------------------------------------------------------ */
/* KASLR retStatic via active RTM_GET (mirrors exploit.js)             */
/* ------------------------------------------------------------------ */

/* rt_msghdr layout constants — from exploit.js leakKernelBase() */
#define RTHDR_SZ   152
#define DST_SALEN  88
#define SA_RLEN(l) ((l) ? (((l) - 1) | 7) + 1 : 8)
#define AUTH_OFF   (RTHDR_SZ + SA_RLEN(DST_SALEN))  /* 240 */
#define RTMSG_LEN  (AUTH_OFF + 256)                  /* 496 */
#define AUTH_IDX   6
#define RET_SLOT   184

static uint64_t
rtmsg2_leak(intptr_t kbase, FILE *fp)
{
    /* 1. Get local interface IP via UDP getsockname trick */
    uint8_t local_ip[4] = {0};
    {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            logerr(fp, "rtmsg2: UDP socket failed, errno=%d\n", errno);
            return 0;
        }
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(53);
        dst.sin_addr.s_addr = inet_addr("8.8.8.8");
        if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            logerr(fp, "rtmsg2: UDP connect failed, errno=%d\n", errno);
            close(s);
            return 0;
        }
        struct sockaddr_in local;
        socklen_t slen = sizeof(local);
        getsockname(s, (struct sockaddr *)&local, &slen);
        close(s);
        memcpy(local_ip, &local.sin_addr, 4);
    }

    logmsg(fp, "rtmsg2: local IP = %d.%d.%d.%d\n",
           local_ip[0], local_ip[1], local_ip[2], local_ip[3]);

    if (!local_ip[0] && !local_ip[1] && !local_ip[2] && !local_ip[3]) {
        logerr(fp, "rtmsg2: no interface has an address\n");
        return 0;
    }

    /* 2. Open PF_ROUTE socket */
    int fd = socket(PF_ROUTE, SOCK_RAW, 0);
    if (fd < 0) {
        logerr(fp, "rtmsg2: socket(PF_ROUTE) failed, errno=%d\n", errno);
        return 0;
    }

    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* 3. Build RTM_GET message — byte-for-byte match with exploit.js */
    uint8_t msg[512];
    memset(msg, 0, sizeof(msg));

    uint16_t mlen = RTMSG_LEN;
    memcpy(msg, &mlen, 2);                    /* rtm_msglen */
    msg[2] = 5;                                /* rtm_version */
    msg[3] = 0x04;                             /* rtm_type = RTM_GET */
    uint32_t tmp32 = 0x41;                     /* RTA_DST | RTA_AUTHOR */
    memcpy(msg + 12, &tmp32, 4);               /* rtm_addrs */
    tmp32 = 0x1234;
    memcpy(msg + 20, &tmp32, 4);               /* rtm_seq */

    msg[RTHDR_SZ + 0] = DST_SALEN;            /* dst: sa_len */
    msg[RTHDR_SZ + 1] = AF_INET;              /* dst: sa_family */
    memcpy(msg + RTHDR_SZ + 4, local_ip, 4);  /* dst: IP at +4 */

    msg[AUTH_OFF + 0] = 255;                   /* author: sa_len */
    msg[AUTH_OFF + 1] = AF_INET6;              /* author: sa_family */

    logmsg(fp, "rtmsg2: sending RTM_GET (dst=%d.%d.%d.%d, len=%d)...\n",
           local_ip[0], local_ip[1], local_ip[2], local_ip[3], RTMSG_LEN);

    /* 4. Send */
    ssize_t wr = write(fd, msg, RTMSG_LEN);
    if (wr < 0) {
        logerr(fp, "rtmsg2: write failed, errno=%d\n", errno);
        close(fd);
        return 0;
    }
    logmsg(fp, "rtmsg2: wrote %zd bytes OK\n", wr);

    /* 5. Read reply — up to 8 attempts like exploit.js */
    uint8_t reply[4096];
    ssize_t rlen = 0;
    for (int att = 0; att < 8 && rlen <= 0; att++) {
        rlen = recvfrom(fd, reply, sizeof(reply), 0x80 /*MSG_DONTWAIT*/,
                        NULL, NULL);
        if (rlen <= 0) {
            logmsg(fp, "rtmsg2: recv attempt %d: n=%zd errno=%d\n",
                   att + 1, rlen, errno);
            sleep(1);
        }
    }

    if (rlen <= 0) {
        logerr(fp, "rtmsg2: no reply after 8 attempts\n");
        close(fd);
        return 0;
    }
    logmsg(fp, "rtmsg2: got %zd byte reply\n", rlen);

    /* 6. Parse — find AUTHOR sockaddr by walking addrs bitmap */
    uint32_t present;
    memcpy(&present, reply + 12, 4);
    logmsg(fp, "rtmsg2: reply rtm_addrs=0x%08X\n", present);

    int cursor = RTHDR_SZ, author = 0;
    for (int i = 0; i < 8; i++) {
        if (!(present & (1 << i))) continue;
        if (cursor + 2 > (int)rlen) break;
        if (i == AUTH_IDX) { author = cursor; break; }
        cursor += SA_RLEN(reply[cursor]);
    }

    if (!author || author + 200 > (int)rlen) {
        logerr(fp, "rtmsg2: no author record (cursor=%d, rlen=%zd)\n",
               author, rlen);
        for (ssize_t i = 0; i + 8 <= rlen; i += 8) {
            uint64_t val;
            memcpy(&val, reply + i, 8);
            if ((val >> 48) == 0xFFFF)
                report(fp, "    [%zd] 0x%lX (RVA 0x%lX)\n",
                       i, (unsigned long)val,
                       (unsigned long)(val - (uint64_t)kbase));
        }
        close(fd);
        return 0;
    }

    logmsg(fp, "rtmsg2: author at reply[%d]\n", author);

    /* 7. Extract leaked kernel return address */
    uint64_t ret_addr;
    memcpy(&ret_addr, reply + author + RET_SLOT, 8);
    logmsg(fp, "rtmsg2: author+%d = 0x%lX\n", RET_SLOT, (unsigned long)ret_addr);

    if ((ret_addr >> 32) != 0xFFFFFFFF) {
        logerr(fp, "rtmsg2: not a kernel address, dumping author area:\n");
        for (int off = 0; off + 8 <= 256 && author + off + 8 <= (int)rlen;
             off += 8) {
            uint64_t val;
            memcpy(&val, reply + author + off, 8);
            if (val)
                report(fp, "    author+%d = 0x%lX\n", off, (unsigned long)val);
        }
        close(fd);
        return 0;
    }

    uint64_t ret_rva = ret_addr - (uint64_t)kbase;
    logmsg(fp, "rtmsg2: retStatic = 0x%lX (ret=0x%lX - kbase=0x%lX)\n",
           (unsigned long)ret_rva, (unsigned long)ret_addr, (unsigned long)kbase);

    if (ret_rva < 0x00A00000 || ret_rva >= 0x01000000)
        logerr(fp, "rtmsg2: WARNING retStatic 0x%lX outside typical .text range\n",
               (unsigned long)ret_rva);

    close(fd);
    return ret_rva;
}

/* ------------------------------------------------------------------ */
/* nodeMutex: scan for the mtx structure                               */
/* ------------------------------------------------------------------ */
static void
scan_nodemutex(intptr_t kbase, FILE *fp)
{
    report(fp, "\n=== nodeMutex scan ===\n");

    const char *target_names[] = {"sysctl lock", "sysctl", NULL};

    intptr_t mtx_name_1120 = (intptr_t)kread8(kbase + REF_1120.node_mutex);
    intptr_t mtx_name_1160 = (intptr_t)kread8(kbase + REF_1160.node_mutex);

    char name1[64] = {0}, name2[64] = {0};
    if (mtx_name_1120) kread_str(mtx_name_1120, name1, sizeof(name1));
    if (mtx_name_1160) kread_str(mtx_name_1160, name2, sizeof(name2));

    logmsg(fp, "nodeMutex: [11.20 ref] 0x%lX -> ptr=0x%lX \"%s\"\n",
           (unsigned long)REF_1120.node_mutex,
           (unsigned long)mtx_name_1120, name1);
    logmsg(fp, "nodeMutex: [11.60 ref] 0x%lX -> ptr=0x%lX \"%s\"\n",
           (unsigned long)REF_1160.node_mutex,
           (unsigned long)mtx_name_1160, name2);

    int found = 0;
    struct { intptr_t lo; intptr_t hi; const char *name; } ranges[] = {
        { 0x01A00000, 0x01C00000, "low range" },
        { 0x03B00000, 0x03C00000, "high range" },
    };

    for (int r = 0; r < 2; r++) {
        logmsg(fp, "nodeMutex: scanning %s 0x%lX-0x%lX...\n",
               ranges[r].name, (unsigned long)ranges[r].lo, (unsigned long)ranges[r].hi);
        int range_found = 0;
        for (intptr_t off = ranges[r].lo; off < ranges[r].hi; off += 8) {
            intptr_t name_ptr = (intptr_t)kread8(kbase + off);
            if (!name_ptr || (name_ptr >> 48) != 0xFFFF) continue;
            char name[32] = {0};
            if (kread_str(name_ptr, name, sizeof(name))) continue;
            for (const char **t = target_names; *t; t++) {
                if (strcmp(name, *t) == 0) {
                    report(fp, "    MTX candidate at 0x%lX: lo_name -> \"%s\"\n",
                           (unsigned long)off, name);
                    range_found++;
                    found++;
                }
            }
        }
        logmsg(fp, "nodeMutex: %s done, %d candidates\n", ranges[r].name, range_found);
    }
    logmsg(fp, "nodeMutex: total %d candidates found\n", found);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
int
main(int argc, char *argv[], char *envp[])
{
    (void)argc; (void)argv; (void)envp;

    gettimeofday(&g_start_tv, NULL);
    notify("[0/7] Relapse Dumper v4d (active RTM_GET)...");

    uint32_t fw = kernel_get_fw_version();
    uint16_t fw_high = (uint16_t)(fw >> 16);
    unsigned fw_dec = ((fw_high >> 12) & 0xF) * 1000 +
                      ((fw_high >>  8) & 0xF) *  100 +
                      ((fw_high >>  4) & 0xF) *   10 +
                       (fw_high        & 0xF);

    /* ---- 0. Self-cleaning ---- */
    mkdir(OUT_DIR, 0777);
    clean_old_dumps();

    /* open log file first */
    g_log = fopen(LOG_FILE, "w");
    if (g_log) {
        fprintf(g_log, "=== Relapse Dumper v4d Log ===\n");
        fprintf(g_log, "FW: %u.%02u (raw 0x%08X)\n\n", fw_dec/100, fw_dec%100, fw);
        fflush(g_log);
        fsync(fileno(g_log));
    }

    FILE *fp = fopen(REPORT, "w");
    if (!fp) {
        notify("FAILED: cannot create " REPORT " errno=%d", errno);
        if (g_log) {
            fprintf(g_log, "FATAL: fopen(%s) failed, errno=%d\n", REPORT, errno);
            fclose(g_log);
        }
        return -1;
    }

    report(fp, "=== Relapse Offset Dumper v4d ===\n");
    report(fp, "Firmware: %u.%02u  (raw 0x%08X)\n\n", fw_dec/100, fw_dec%100, fw);

    /* ---- 1. Kernel base from SDK ---- */
    report(fp, "=== Kernel Base ===\n");
    intptr_t data_base = KERNEL_ADDRESS_DATA_BASE;
    intptr_t text_base = KERNEL_ADDRESS_TEXT_BASE;
    logmsg(fp, "KERNEL_ADDRESS_DATA_BASE = 0x%lX\n", (unsigned long)data_base);
    logmsg(fp, "KERNEL_ADDRESS_TEXT_BASE = 0x%lX\n", (unsigned long)text_base);

    if (!data_base) {
        logerr(fp, "KERNEL_ADDRESS_DATA_BASE is 0 — kernel_init failed?\n");
        fclose(fp);
        if (g_log) fclose(g_log);
        notify("FATAL: DATA_BASE=0. Kernel not initialized.");
        return -1;
    }

    intptr_t kbase = text_base;
    if (!kbase) {
        kbase = data_base - 0x0D30000;
        logmsg(fp, "TEXT_BASE is 0, fallback: DATA_BASE - 0x0D30000 = 0x%lX\n",
               (unsigned long)kbase);
    }

    logmsg(fp, "kernel_text_base = 0x%lX\n", (unsigned long)kbase);
    logmsg(fp, "data-text delta  = 0x%lX\n",
           (unsigned long)(data_base - kbase));
    report(fp, "\n");

    notify("[1/7] Bases OK. Verifying Tier 1...");

    /* ---- 2. Verify with SDK-provided addresses ---- */
    report(fp, "=== Tier 1 Verification ===\n");
    logmsg(fp, "ALLPROC        = 0x%lX\n", (unsigned long)KERNEL_ADDRESS_ALLPROC);
    logmsg(fp, "ROOTVNODE      = 0x%lX\n", (unsigned long)KERNEL_ADDRESS_ROOTVNODE);
    logmsg(fp, "SECURITY_FLAGS = 0x%lX\n", (unsigned long)KERNEL_ADDRESS_SECURITY_FLAGS);

    int pre_errors = g_kread_errors;
    uint64_t allproc_val   = kread8(KERNEL_ADDRESS_ALLPROC);
    uint64_t rootvnode_val = kread8(KERNEL_ADDRESS_ROOTVNODE);
    uint32_t secflags_val  = kread4(KERNEL_ADDRESS_SECURITY_FLAGS);
    int tier1_read_errors = g_kread_errors - pre_errors;

    logmsg(fp, "*allproc        = 0x%lX\n", (unsigned long)allproc_val);
    logmsg(fp, "*rootvnode      = 0x%lX\n", (unsigned long)rootvnode_val);
    logmsg(fp, "*security_flags = 0x%08X\n", secflags_val);

    if (tier1_read_errors > 0)
        logerr(fp, "Tier 1 had %d kread errors!\n", tier1_read_errors);

    int valid = ((allproc_val >> 48) == 0xFFFF) &&
                ((rootvnode_val >> 48) == 0xFFFF);
    logmsg(fp, "Tier 1: %s\n",
           valid ? "PASS (both are kernel pointers)"
                 : "FAIL (unexpected values — wrong FW or broken pipe?)");
    report(fp, "\n");

    if (!valid) {
        notify("[1/7] WARNING: Tier 1 FAILED! Continuing anyway...");
    } else {
        notify("[1/7] Tier 1 PASS. Starting scans...");
    }

    /* RVAs (text-relative) for the SDK addresses */
    report(fp, "Text-relative RVAs:\n");
    report(fp, "  allproc        = 0x%lX\n",
           (unsigned long)(KERNEL_ADDRESS_ALLPROC - kbase));
    report(fp, "  rootvnode      = 0x%lX\n",
           (unsigned long)(KERNEL_ADDRESS_ROOTVNODE - kbase));
    report(fp, "  security_flags = 0x%lX\n",
           (unsigned long)(KERNEL_ADDRESS_SECURITY_FLAGS - kbase));
    report(fp, "\n");

    /* ---- 3. rodataProbe: scan for "_aio_submit_cmd" ---- */
    notify("[2/7] Scanning rodata for _aio_submit_cmd...");
    report(fp, "=== rodataProbe ===\n");
    intptr_t rodata_rva = scan_rodata_string(kbase, fp);
    if (rodata_rva) {
        report(fp, "rodataProbe.rva = 0x%lX\n", (unsigned long)rodata_rva);
        report(fp, "rodataProbe.text = \"_aio_submit_cmd\"\n");
    } else {
        report(fp, "rodataProbe.rva = NOT FOUND\n");
    }
    report(fp, "\n");

    notify("[3/7] rodata %s (kread_errs=%d). rtmsg2 leak...",
           rodata_rva ? "FOUND" : "NOT FOUND", g_kread_errors);

    /* ---- 4. KASLR retStatic via rtmsg2 ---- */
    report(fp, "=== KASLR retStatic ===\n");
    uint64_t ret_static = rtmsg2_leak(kbase, fp);
    if (ret_static) {
        report(fp, "kaslr.retStatic = 0x%lX\n", (unsigned long)ret_static);
        report(fp, "kaslr.retLow16  = 0x%04lX\n",
               (unsigned long)(ret_static & 0xFFFF));
    } else {
        report(fp, "kaslr.retStatic = NOT FOUND\n");
    }
    report(fp, "\n");

    notify("[4/7] retStatic %s. Scanning OIDs...",
           ret_static ? "FOUND" : "NOT FOUND");

    /* ---- 5. OID probing ---- */
    report(fp, "=== Sysctl OID Scan ===\n");

    logmsg(fp, "Reference probes:\n");
    notify("[4/7] OID: reading ref probes...");
    uint32_t ka_1120 = kread4(kbase + REF_1120.oid_a_base + OID_OFF_KIND);
    uint32_t ka_1160 = kread4(kbase + REF_1160.oid_a_base + OID_OFF_KIND);
    logmsg(fp, "  oid.a [11.20 +0x14]: 0x%08X %s\n", ka_1120,
           ka_1120 == OID_KIND_ORIGINAL ? "<-- MATCH" : "(no match)");
    logmsg(fp, "  oid.a [11.60 +0x14]: 0x%08X %s\n", ka_1160,
           ka_1160 == OID_KIND_ORIGINAL ? "<-- MATCH" : "(no match)");

    notify("[4/7] OID: scanning oid.a/b range...");
    int oid_ab = probe_oid_range(kbase,
                    REF_1120.oid_a_base - 0x100,
                    REF_1160.oid_a_base + 0x100,
                    "oid.a/oid.b region", fp);

    notify("[4/7] OID: scanning oid.c range...");
    int oid_c = probe_oid_range(kbase,
                    REF_1120.oid_c_base - 0x100,
                    REF_1160.oid_c_base + 0x100,
                    "oid.c region", fp);

    report(fp, "\nTier 1 data-region values:\n");
    uint64_t wc_val = kread8(kbase + REF_1120.walk_counter);
    uint32_t ca_val = kread4(kbase + REF_1120.oid_c_arg1val);
    report(fp, "  walkCounter  [+0x%lX] value=0x%lX\n",
           (unsigned long)REF_1120.walk_counter, (unsigned long)wc_val);
    report(fp, "  oid.c.arg1Val[+0x%lX] value=0x%08X\n",
           (unsigned long)REF_1120.oid_c_arg1val, ca_val);
    report(fp, "\n");

    notify("[5/7] OIDs: %d in a/b, %d in c. nodeMutex...", oid_ab, oid_c);

    /* ---- 6. nodeMutex ---- */
    notify("[5/7] nodeMutex: reading ref pointers...");
    scan_nodemutex(kbase, fp);
    report(fp, "\n");

    notify("[6/7] nodeMutex done. Starting binary dumps...");

    /* ---- 7. Binary dumps for offline analysis ---- */
    report(fp, "=== Binary Dumps ===\n");
    logmsg(fp, "Starting binary dumps (%lu ms elapsed)...\n", elapsed_ms());

    notify("[6/7] Dump 1/4: 3.8MB @0x2920000...");
    dump_region(kbase + 0x02920000, 0x003B0000,
                OUT_DIR "/kdata_0x2920000.bin", fp);
    notify("[6/7] Dump 1/4 done.");

    notify("[6/7] Dump 2/4: 2MB @0x1A00000...");
    dump_region(kbase + 0x01A00000, 0x00200000,
                OUT_DIR "/kdata_0x1A00000.bin", fp);
    notify("[6/7] Dump 2/4 done.");

    notify("[6/7] Dump 3/4: 1MB @0x3B00000...");
    dump_region(kbase + 0x03B00000, 0x00100000,
                OUT_DIR "/kdata_0x3B00000.bin", fp);
    notify("[6/7] Dump 3/4 done.");

    /* text dump SKIPPED — kbase+0xB40000 causes kernel panic (text segment protected) */

    notify("[6/7] Dump 4/4: 64KB @0x3CE0000...");
    dump_region(kbase + 0x03CE0000, 0x00010000,
                OUT_DIR "/kdata_0x3CE0000.bin", fp);
    notify("[6/7] Dump 4/4 done.");

    /* ---- Done ---- */
    report(fp, "\n=== DONE ===\n");
    logmsg(fp, "All done in %lu ms. Total kread errors: %d\n",
           elapsed_ms(), g_kread_errors);
    report(fp, "Transfer %s/ to your PC via FTP.\n", OUT_DIR);
    report(fp, "offsets.txt = extracted values, dumper.log = detailed log\n");
    report(fp, ".bin files = raw kernel memory for offline analysis\n");

    fclose(fp);
    if (g_log) fclose(g_log);

    notify("[7/7] DONE (FW %u.%02u) %lums, %d errs -> %s",
           fw_dec/100, fw_dec%100, elapsed_ms(), g_kread_errors, OUT_DIR);
    return 0;
}
