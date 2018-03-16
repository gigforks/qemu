#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/option.h"
#include "block/block_int.h"
#include <hiredis.h>

typedef struct zdb_state_t {
    const char *host;
    int port;
    int64_t size;
    redisContext *redis;

} zdb_state_t;

// #define zdb_debug printf
#define zdb_debug(...) ((void)0)

#define ZDB_OPT_HOST "host"
#define ZDB_OPT_PORT "port"
#define ZDB_OPT_SIZE "size"

static QemuOptsList runtime_opts = {
    .name = "zdb",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = ZDB_OPT_HOST,
            .type = QEMU_OPT_STRING,
            .help = "zero-db host",
        },
        {
            .name = ZDB_OPT_PORT,
            .type = QEMU_OPT_NUMBER,
            .help = "zero-db port",
        },
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "size of the virtual disk size",
        },
        { /* end of list */ }
    },
};

typedef enum zdb_command_t {
    ZDB_COMMAND_READ,
    ZDB_COMMAND_WRITE,
    ZDB_COMMAND_FLUSH,

    ZDB_COMMAND_FAILED,

} zdb_command_t;

typedef struct zdb_request_t {
    zdb_command_t command; // requested command

    void *buffer;       // common buffer between qemu and driver
    uint64_t start;     // start sector number
    int sectors;        // number of sectors requested
    uint64_t offset;    // real offset in bytes
    uint64_t length;    // real length in bytes
    QEMUIOVector *qiov;

} zdb_request_t;

typedef struct zdb_aio_cb_t {
    BlockAIOCB common;
    zdb_request_t request;
    zdb_state_t *state;
    int status;

} zdb_aio_cb_t;

static const AIOCBInfo null_aiocb_info = {
    .aiocb_size = sizeof(zdb_aio_cb_t),
};


static void zdb_aio_parse_filename(const char *filename, QDict *options, Error **errp) {
    if(strcmp(filename, "zdb://")) {
        error_setg(errp, "The only allowed filename for this driver is 'zdb://'");
        return;
    }
}

static zdb_request_t zdb_request_new(uint64_t sector_num, int nb_sectors, QEMUIOVector *qiov, zdb_command_t command) {
    zdb_request_t request;

    request.command = command;
    request.start = sector_num;
    request.sectors = nb_sectors;
    request.offset = sector_num * BDRV_SECTOR_SIZE;
    request.length = nb_sectors * BDRV_SECTOR_SIZE;
    request.qiov = qiov;
    request.buffer = NULL;

    zdb_debug("[+] zdb: request: %d\n", request.command);
    zdb_debug("[+] zdb: request: sector %lu -> %d\n", request.start, request.sectors);
    zdb_debug("[+] zdb: request: offset %lu -> %lu\n", request.offset, request.length);

    // only write needs allocation
    if(request.command != ZDB_COMMAND_WRITE)
        return request;

    if(!(request.buffer = malloc(BDRV_SECTOR_SIZE)))
        request.command = ZDB_COMMAND_FAILED;

    return request;
}

static void zdb_request_free(zdb_request_t *request) {
    free(request->buffer);
}

static int zdb_connect(zdb_state_t *state, Error **errp) {
    struct timeval timeout = {5, 0};

    zdb_debug("[+] connecting zero-db server: %s:%d\n", state->host, state->port);

    state->redis = redisConnectWithTimeout(state->host, state->port, timeout);
    if(state->redis == NULL || state->redis->err) {
        const char *error = (state->redis->err) ? state->redis->errstr : "memory error";

        printf("[-] zdb: redis: %s\n", error);
        error_setg(errp, "zero-db [%s:%d]: %s", state->host, state->port, error);
        return 1;
    }

    // ping redis to ensure connection
    redisReply *reply = redisCommand(state->redis, "PING");
    if(strcmp(reply->str, "PONG"))
        fprintf(stderr, "[-] zdb: warning, invalid redis PING response: %s\n", reply->str);

    freeReplyObject(reply);

    zdb_debug("[+] zdb: zero-db connected\n");

    return 0;
}

static int zdb_file_open(BlockDriverState *bs, QDict *options, int flags, Error **errp) {
    QemuOpts *opts;
    zdb_state_t *s = bs->opaque;
    int ret = 0;

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);

    if(!(s->host = qemu_opt_get(opts, ZDB_OPT_HOST)))
        s->host = "localhost";

    s->port = qemu_opt_get_number(opts, ZDB_OPT_PORT, 9900);
    s->size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE, 1 << 30);

    zdb_debug("[+] zdb: host: %s\n", s->host);
    zdb_debug("[+] zdb: port: %d\n", s->port);
    zdb_debug("[+] zdb: size: %lu (%.2f MB)\n", s->size, s->size / (1024 * 1024.0));
    zdb_debug("[+] zdb: sector size: %lld\n", BDRV_SECTOR_SIZE);

    qemu_opts_del(opts);

    ret = zdb_connect(s, errp);

    return ret;
}

static void zdb_close(BlockDriverState *bs) {
    zdb_state_t *s = bs->opaque;

    zdb_debug("[+] zdb: closing\n");
    redisFree(s->redis);
}

static int64_t zdb_getlength(BlockDriverState *bs) {
    zdb_state_t *s = bs->opaque;
    return s->size;
}

static inline int zdb_process_read(zdb_request_t *request, zdb_aio_cb_t *acb, uint64_t offset, uint64_t inside) {
    redisReply *reply;
    char key[64];

    zdb_debug("+++ READ PROCEED SECTOR %lu\n", offset);

    sprintf(key, "%lu", offset);
    reply = redisCommand(acb->state->redis, "GET %b", key, strlen(key));

    if(!reply->str) {
        zdb_debug("[-] zdb: empty response\n");
        qemu_iovec_memset(request->qiov, inside, 0, BDRV_SECTOR_SIZE);
        freeReplyObject(reply);
        return 0;
    }

    if(reply->len != BDRV_SECTOR_SIZE) {
        zdb_debug("[-] zdb: wrong payload size read: %d\n", reply->len);
        qemu_iovec_memset(request->qiov, inside, 0, BDRV_SECTOR_SIZE);
        freeReplyObject(reply);
        return 0;
    }

    qemu_iovec_from_buf(request->qiov, inside, reply->str, BDRV_SECTOR_SIZE);

    return 0;
}

static inline int zdb_process_write(zdb_request_t *request, zdb_aio_cb_t *acb, uint64_t offset, uint64_t inside) {
    redisReply *reply;
    char key[64];

    zdb_debug("+++ WRITE PROCEED SECTOR %lu\n", offset);

    sprintf(key, "%lu", offset);
    qemu_iovec_to_buf(request->qiov, inside, request->buffer, BDRV_SECTOR_SIZE);

    reply = redisCommand(acb->state->redis, "SET %b %b", key, strlen(key), request->buffer, BDRV_SECTOR_SIZE);

    freeReplyObject(reply);

    return 0;
}

static void zdb_bh_cb(void *opaque) {
    zdb_aio_cb_t *acb = opaque;
    zdb_request_t *request = &acb->request;
    uint64_t limit = 0;
    uint64_t inside = 0;

    zdb_debug("[+] zdb: callback: command: %d\n", request->command);
    zdb_debug("[+] zdb: request bytes: %lu -> %lu\n", request->offset, request->offset + request->length);

    switch(request->command) {
        case ZDB_COMMAND_READ:
            limit = request->offset + request->length;

            for(uint64_t offset = request->offset; offset + inside < limit; inside += BDRV_SECTOR_SIZE)
                zdb_process_read(request, acb, offset + inside, inside);
        break;

        case ZDB_COMMAND_WRITE:
            limit = request->offset + request->length;

            for(uint64_t offset = request->offset; offset + inside < limit; inside += BDRV_SECTOR_SIZE)
                zdb_process_write(request, acb, offset + inside, inside);
        break;

        case ZDB_COMMAND_FLUSH:
            //
        break;

        case ZDB_COMMAND_FAILED:
            acb->status = 1;
        break;
    }

    acb->common.cb(acb->common.opaque, acb->status);

    zdb_request_free(request);
    qemu_aio_unref(acb);
}

static inline BlockAIOCB *zdb_aio_common(BlockDriverState *bs, BlockCompletionFunc *cb, void *opaque, zdb_request_t request) {
    zdb_aio_cb_t *acb;
    zdb_state_t *s = bs->opaque;

    acb = qemu_aio_get(&null_aiocb_info, bs, cb, opaque);
    acb->status = 0;
    acb->request = request;
    acb->state = s;

    aio_bh_schedule_oneshot(bdrv_get_aio_context(bs), zdb_bh_cb, acb);

    return &acb->common;
}

static BlockAIOCB *zdb_aio_readv(BlockDriverState *bs, int64_t sector_num, QEMUIOVector *qiov, int nb_sectors, BlockCompletionFunc *cb, void *opaque) {
    zdb_request_t request = zdb_request_new(sector_num, nb_sectors, qiov, ZDB_COMMAND_READ);
    return zdb_aio_common(bs, cb, opaque, request);
}

static BlockAIOCB *zdb_aio_writev(BlockDriverState *bs, int64_t sector_num, QEMUIOVector *qiov, int nb_sectors, BlockCompletionFunc *cb, void *opaque) {
    zdb_request_t request = zdb_request_new(sector_num, nb_sectors, qiov, ZDB_COMMAND_WRITE);
    return zdb_aio_common(bs, cb, opaque, request);
}

static BlockAIOCB *zdb_aio_flush(BlockDriverState *bs, BlockCompletionFunc *cb, void *opaque) {
    zdb_request_t request = zdb_request_new(0, 0, NULL, ZDB_COMMAND_FLUSH);
    return zdb_aio_common(bs, cb, opaque, request);
}

static int zdb_reopen_prepare(BDRVReopenState *reopen_state, BlockReopenQueue *queue, Error **errp) {
    return 0;
}

static void zdb_refresh_filename(BlockDriverState *bs, QDict *opts) {
    QINCREF(opts);
    qdict_del(opts, "filename");

    if(!qdict_size(opts)) {
        snprintf(bs->exact_filename, sizeof(bs->exact_filename), "%s://", bs->drv->format_name);
    }

    qdict_put_str(opts, "driver", bs->drv->format_name);
    bs->full_open_options = opts;
}

static BlockDriver bdrv_zdb_aio = {
    .format_name            = "zdb",
    .protocol_name          = "zdb",
    .instance_size          = sizeof(zdb_state_t),

    .bdrv_file_open         = zdb_file_open,
    .bdrv_parse_filename    = zdb_aio_parse_filename,
    .bdrv_close             = zdb_close,
    .bdrv_getlength         = zdb_getlength,

    .bdrv_aio_readv         = zdb_aio_readv,
    .bdrv_aio_writev        = zdb_aio_writev,
    .bdrv_aio_flush         = zdb_aio_flush,

    .bdrv_reopen_prepare    = zdb_reopen_prepare,
    .bdrv_refresh_filename  = zdb_refresh_filename,

    // .bdrv_co_block_status   = null_co_block_status,
};

static void bdrv_zdb_init(void) {
    bdrv_register(&bdrv_zdb_aio);
}

block_init(bdrv_zdb_init);
