#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "qemu/option.h"
#include "block/block_int.h"
#include <hiredis.h>
#include <math.h>

#if defined(__linux__)
    #include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__)
    #include <sys/endian.h>
#elif defined(__OpenBSD__)
    #include <sys/types.h>
    #define be16toh(x) betoh16(x)
    #define be32toh(x) betoh32(x)
    #define be64toh(x) betoh64(x)
#endif

typedef struct zdb_state_t {
    const char *host;
    const char *socket;
    int port;
    int64_t size;
    redisContext *redis;

} zdb_state_t;

// #define DEBUG

#ifdef DEBUG
    #define zdb_debug printf

    static const char *zdb_commands[] = {
        "ZDB_COMMAND_READ",
        "ZDB_COMMAND_WRITE",
        "ZDB_COMMAND_FLUSH",
        "ZDB_COMMAND_FAILED",
    };

#else
    #define zdb_debug(...) ((void)0)
#endif


#define ZDB_OPT_HOST "host"
#define ZDB_OPT_PORT "port"
#define ZDB_OPT_SIZE "size"
#define ZDB_OPT_SOCKET "socket"

#define ZDB_BLOCKSIZE  4096

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
            .name = ZDB_OPT_SOCKET,
            .type = QEMU_OPT_STRING,
            .help = "zero-db unix socket",
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

    uint64_t first_block;
    uint64_t last_block;

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

    zdb_debug("[+] zdb: request: %s\n", zdb_commands[request.command]);
    zdb_debug("[+] zdb: request: sector %lu + %d\n", request.start, request.sectors);
    zdb_debug("[+] zdb: request: offset %lu -> %lu\n", request.offset, request.length);

    request.first_block = request.offset / ZDB_BLOCKSIZE;
    request.last_block = ceil((request.offset + request.length) / ZDB_BLOCKSIZE);

    zdb_debug("[+] zdb: internal blocks: %lu -> %lu\n", request.first_block, request.last_block);

    // only write needs allocation
    if(request.command != ZDB_COMMAND_WRITE)
        return request;

    if(!(request.buffer = malloc(ZDB_BLOCKSIZE)))
        request.command = ZDB_COMMAND_FAILED;

    return request;
}

static void zdb_request_free(zdb_request_t *request) {
    free(request->buffer);
}

static int zdb_connect(zdb_state_t *state, Error **errp) {
    struct timeval timeout = {5, 0};

    if(state->socket) {
        zdb_debug("[+] connecting zero-db server: %s\n", state->socket);
        state->redis = redisConnectUnix(state->socket);

    } else {
        zdb_debug("[+] connecting zero-db server: %s:%d\n", state->host, state->port);
        state->redis = redisConnectWithTimeout(state->host, state->port, timeout);
    }

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

    s->socket = qemu_opt_get(opts, ZDB_OPT_SOCKET);
    s->port = qemu_opt_get_number(opts, ZDB_OPT_PORT, 9900);
    s->size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE, 1 << 30);

    zdb_debug("[+] zdb: host: %s\n", s->socket ? s->socket : s->host);
    zdb_debug("[+] zdb: port: %d\n", s->port);
    zdb_debug("[+] zdb: size: %lu (%.2f MB)\n", s->size, s->size / (1024 * 1024.0));
    zdb_debug("[+] zdb: blocksize: %d\n", ZDB_BLOCKSIZE);

    // qemu_opts_del(opts);

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

//
// zero-db input/output
//
static inline redisReply *zdb_read_block(zdb_aio_cb_t *acb, uint64_t blockid) {
    uint64_t key = htobe64(blockid);
    return redisCommand(acb->state->redis, "GET %b", &key, sizeof(key));
}

static inline void zdb_free_block(redisReply *reply) {
    freeReplyObject(reply);
}

static inline int zdb_write_block(zdb_aio_cb_t *acb, uint64_t blockid, void *payload) {
    uint64_t key = htobe64(blockid);
    redisReply *reply;

    reply = redisCommand(acb->state->redis, "SET %b %b", &key, sizeof(key), payload, ZDB_BLOCKSIZE);
    // should check reply

    freeReplyObject(reply);

    return 0;
}

//
// qemu input/output
//
static void zdb_bh_cb(void *opaque) {
    zdb_aio_cb_t *acb = opaque;
    zdb_request_t *request = &acb->request;

    zdb_debug("[+] zdb: callback: command: %d\n", request->command);
    zdb_debug("[+] zdb: request bytes: %lu -> %lu\n", request->offset, request->offset + request->length);

    if(request->offset % BDRV_SECTOR_SIZE) {
        printf("WRONG OFFSET %lu\n", request->offset);
        exit(EXIT_FAILURE);
    }

    if(request->length % BDRV_SECTOR_SIZE) {
        printf("WRONG LENGTH %lu\n", request->length);
        exit(EXIT_FAILURE);
    }

    switch(request->command) {
        case ZDB_COMMAND_READ: { // create a new scope for this label

            // see write documentation below, it's the same working process
            // except we don't need to update anything
            uint64_t current = request->offset; // current offset on the whole disk, we need to write
            uint64_t iopos = 0;                 // current position in the iovector
            uint64_t remain = request->length;  // amount of data which remains to write

            for(uint64_t block = request->first_block; block <= request->last_block; block += 1) {
                zdb_debug("[+] zdb: processing read: block %lu\n", block);

                // reading the block, we need it anyway
                redisReply *payload = zdb_read_block(acb, block);

                uint64_t buffer_offset = (current % ZDB_BLOCKSIZE);       // position to the buffer
                uint64_t buffer_length = (ZDB_BLOCKSIZE - buffer_offset); // amount of data to put on the buffer

                if(buffer_length > remain)
                    buffer_length = remain;

                if(payload->str) {
                    // fillin data with the buffer
                    qemu_iovec_from_buf(request->qiov, iopos, payload->str + buffer_offset, buffer_length);

                } else {
                    zdb_debug("[+] zdb: read: key not found, fillin zero\n");
                    // block not found, fillin expected data with zero
                    qemu_iovec_memset(request->qiov, iopos, 0, buffer_length);
                }

                // fillin the iovec with the block
                zdb_free_block(payload);

                // updating reminders
                iopos += buffer_length;
                current += buffer_length;
                remain -= buffer_length;
            }
        } break;

        case ZDB_COMMAND_WRITE: { // create a new scope for this label

            // first_block and last_block contains the real limits on the backend
            // when everything is properly aligned on ZDB_BLOCKSIZE, there is no problem but as soon
            // as the data are not aligned on ZDB_BLOCKSIZE we need to read data from the backend
            // to update this block with only the requested change, and write it back
            //
            // Let assume ZDB_BLOCKSIZE is 4 KB
            // 'Block' means one zerodb block (4 KB), 'Sector' is one QEMU disk sector (512 byte)
            //
            // Here is an original empty comparaison between our backend and disk sector
            // Our backend blocks contains multiple disk sectors
            //
            // ...      ][######################][                      ][          ... Backend 4 KB blocks
            // ... [ ][ ][*][*][*][*][*][*][*][*][ ][ ][ ][ ][ ][ ][ ][ ][ ][ ][ ]  ... QEMU 512 bytes sectors
            //
            //
            // Everything is fine if we request to write 4 KB perfectly aligned on our backend
            //
            // ...      ][                      ][                      ][          ... Backend 4 KB blocks
            // ... [ ][ ][X][X][X][X][X][X][X][X][ ][ ][ ][ ][ ][ ][ ][ ][ ][ ][ ]  ... QEMU 512 bytes sectors
            //
            // It becomes more tricky when it's time to write sectors which are in partial
            // blocks. In this case we need to read this block from the baclend, update the expected
            // portion of the block, then send it back to the backend, the only time this can be
            // skipped is when we fully overwrite a block (the whole 4 KB).
            //
            // ...      ][                      ][                      ][          ... Backend 4 KB blocks
            // ... [ ][ ][ ][ ][ ][X][X][X][X][X][X][X][X][X][X][X][X][X][X][X][ ]  ... QEMU 512 bytes sectors
            //            partial -^              ^- full overwrite       ^- partial
            //
            // ...      ][                      ][                      ][          ... Backend 4 KB blocks
            // ... [ ][ ][ ][X][X][X][X][ ][ ][ ][ ][ ][ ][ ][ ][ ][ ][ ][ ][ ][ ]  ... QEMU 512 bytes sectors
            //
            //
            // the 'request' object contains the first and the last blocks we need, but we don't know
            // yet if we can overwrite it and need to update it
            //
            // For each block to proceed, we need to check if this block will be fully overwritten or not,
            // we achive this by checking if the current write expected is aligned.
            //
            uint64_t current = request->offset; // current offset on the whole disk, we need to write
            uint64_t iopos = 0;                 // current position in the iovector
            uint64_t remain = request->length;  // amount of data which remains to write

            for(uint64_t block = request->first_block; block < request->last_block; block += 1) {
                zdb_debug("[+] zdb: processing write: block %lu, remain: %lu\n", block, remain);

                // checking if sector is aligned with the beginin of the block
                // or if the amount of sectors to write is smaller then the block
                // in theses both case, we need to fetch the block and update it
                if(current % ZDB_BLOCKSIZE || remain < ZDB_BLOCKSIZE) {
                    zdb_debug("[+] zdb: partial write, need to read the block\n");
                    zdb_debug("[+] zdb: begin: %lu, remain: %lu > %lu\n", current % ZDB_BLOCKSIZE, current + ZDB_BLOCKSIZE, remain);

                    uint64_t buffer_offset = (current % ZDB_BLOCKSIZE);       // position to the buffer
                    uint64_t buffer_length = (ZDB_BLOCKSIZE - buffer_offset); // amount of data to put on the buffer

                    printf("Offset: %lu\n", buffer_offset);
                    printf("Length: %lu\n", buffer_length);

                    // fetching the block from the backend
                    redisReply *existing = zdb_read_block(acb, block);

                    if(existing->str) {
                        // key was existing, moving the payload to the buffer
                        memcpy(request->buffer, existing->str, ZDB_BLOCKSIZE);

                    } else {
                        // key not found, we need to start from an empty block
                        memset(request->buffer, 0x00, ZDB_BLOCKSIZE);
                    }

                    // if the buffer length is greater than the remaining amount
                    // of data, we are partialy writing the last block with remaning sectors
                    if(buffer_length > remain)
                        buffer_length = remain;

                    // updating only the requested parts
                    qemu_iovec_to_buf(request->qiov, iopos, request->buffer + buffer_offset, buffer_length);
                    zdb_free_block(existing);

                    // writing the buffer back to the backend
                    zdb_write_block(acb, block, request->buffer);

                    // updating reminders
                    iopos += buffer_length;
                    current += buffer_length;
                    remain -= buffer_length;

                    // proceed to the next block
                    continue;
                }

                // here, we know we can blindly overwrite the full block because
                // the current write offset alignes with the begenin of one block and
                // a full block is not larger than the remaining data
                qemu_iovec_to_buf(request->qiov, iopos, request->buffer, ZDB_BLOCKSIZE);
                zdb_write_block(acb, block, request->buffer);

                iopos += ZDB_BLOCKSIZE;
                current += ZDB_BLOCKSIZE;
                remain -= ZDB_BLOCKSIZE;
            }
        } break;

        case ZDB_COMMAND_FLUSH:
            zdb_debug("[+] zdb: flush request\n");
        break;

        case ZDB_COMMAND_FAILED:
            zdb_debug("[+] zdb: command failed, error\n");
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
