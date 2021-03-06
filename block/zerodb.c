#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/qmp/qnum.h"
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
    const char *namespace;
    const char *password;
    int port;
    int64_t size;
    redisContext *redis;
    uint64_t blocksize;

} zdb_state_t;

typedef struct zdb_backend_t {
    size_t length;
    zdb_state_t **targets;

} zdb_backend_t;

typedef struct zdb_drv_t {
    // read servers available
    // (thin-provisioning)
    zdb_backend_t read;

    // write servers available
    // (active-backup)
    zdb_backend_t write;

    // note: there are always at least
    // one of each, which is the general zdb

} zdb_drv_t;

#define DEBUG

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
#define ZDB_OPT_BLOCKSIZE "blocksize"
#define ZDB_OPT_NAMESPACE "namespace"
#define ZDB_OPT_PASSWORD "password"

// thin-provisioning options
// blocksize needs to match
#define ZDB_OPT_THIN_HOST "thin-host"
#define ZDB_OPT_THIN_PORT "thin-port"
#define ZDB_OPT_THIN_SOCKET "thin-socket"
#define ZDB_OPT_THIN_NAMESPACE "thin-namespace"
#define ZDB_OPT_THIN_PASSWORD "thin-password"

// active-active backup option
// blocksize needs to match
#define ZDB_OPT_BACKUP_HOST "backup-host"
#define ZDB_OPT_BACKUP_PORT "backup-port"
#define ZDB_OPT_BACKUP_SOCKET "backup-socket"
#define ZDB_OPT_BACKUP_NAMESPACE "backup-namespace"
#define ZDB_OPT_BACKUP_PASSWORD "backup-password"

#define ZDB_OPT_PORT_DEFAULT 9900

#define ZDB_DEFAULT_BLOCKSIZE  4096


static QemuOptsList runtime_opts = {
    .name = "zdb",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        // general configuration
        {.name = ZDB_OPT_HOST,      .type = QEMU_OPT_STRING, .help = "zero-db host"},
        {.name = ZDB_OPT_PORT,      .type = QEMU_OPT_NUMBER, .help = "zero-db port"},
        {.name = ZDB_OPT_SOCKET,    .type = QEMU_OPT_STRING, .help = "zero-db unix socket"},
        {.name = BLOCK_OPT_SIZE,    .type = QEMU_OPT_SIZE,   .help = "size of the virtual disk size"},
        {.name = ZDB_OPT_BLOCKSIZE, .type = QEMU_OPT_SIZE,   .help = "internal blocksize aggregation"},
        {.name = ZDB_OPT_NAMESPACE, .type = QEMU_OPT_STRING, .help = "zero-db namespace to use"},
        {.name = ZDB_OPT_PASSWORD,  .type = QEMU_OPT_STRING, .help = "optional zero-db namespace password"},

        // thin provisioning
        {.name = ZDB_OPT_THIN_HOST,      .type = QEMU_OPT_STRING, .help = "thin-provisioning zero-db host"},
        {.name = ZDB_OPT_THIN_PORT,      .type = QEMU_OPT_NUMBER, .help = "thin-provisioning zero-db port"},
        {.name = ZDB_OPT_THIN_SOCKET,    .type = QEMU_OPT_STRING, .help = "thin-provisioning zero-db unix socket"},
        {.name = ZDB_OPT_THIN_NAMESPACE, .type = QEMU_OPT_STRING, .help = "thin-provisioning zero-db namespace"},
        {.name = ZDB_OPT_THIN_PASSWORD,  .type = QEMU_OPT_STRING, .help = "thin-provisioning optional zero-db namespace password"},

        // active-active backup
        {.name = ZDB_OPT_BACKUP_HOST,      .type = QEMU_OPT_STRING, .help = "active-backup zero-db host"},
        {.name = ZDB_OPT_BACKUP_PORT,      .type = QEMU_OPT_NUMBER, .help = "active-backup zero-db port"},
        {.name = ZDB_OPT_BACKUP_SOCKET,    .type = QEMU_OPT_STRING, .help = "active-backup zero-db unix socket"},
        {.name = ZDB_OPT_BACKUP_NAMESPACE, .type = QEMU_OPT_STRING, .help = "active-backup zero-db namespace"},
        {.name = ZDB_OPT_BACKUP_PASSWORD,  .type = QEMU_OPT_STRING, .help = "active-backup optional zero-db namespace password"},

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
    zdb_command_t command;  // requested command
    void *buffer;           // common buffer between qemu and driver
    uint64_t start;         // start sector number
    int sectors;            // number of sectors requested
    uint64_t offset;        // real offset in bytes
    uint64_t length;        // real length in bytes

    uint64_t first_block;   // first block id needed from the backend for this request
    uint64_t last_block;    // last block id needed

    QEMUIOVector *qiov;     // qemu io vector where to read/write data

} zdb_request_t;

typedef struct zdb_aio_cb_t {
    BlockAIOCB common;      // common qemu blockdriver object
    zdb_request_t request;  // copy of the request
    zdb_state_t *state;     // object state
    zdb_drv_t *drv;         // global driver object
    int status;             // return code

} zdb_aio_cb_t;

typedef struct key_value_t {
    char *key;
    char *value;
    const char *remain;

} key_value_t;

static const AIOCBInfo null_aiocb_info = {
    .aiocb_size = sizeof(zdb_aio_cb_t),
};

static key_value_t zdb_next_key_value(const char *input) {
    char *match = NULL;
    size_t length;
    key_value_t kv = {
        .key = NULL,
        .value = NULL,
        .remain = NULL,
    };

    // do we have any key/value pair
    if(!(match = strchr(input, '=')))
        return kv;

    kv.key = strndup(input, match - input);

    length = strlen(input + (match - input) + 1);
    input = match + 1;

    // do we have another option after this one
    if((match = strchr(input, '&')))
        length = match - input;

    kv.value = strndup(input, length);

    // do we have anything remaining after that
    if(length)
        kv.remain = input + length + 1;

    return kv;
}

static void key_value_free(key_value_t *kv) {
    free(kv->key);
    free(kv->value);
}

// filename format:
// zdb://                                    -- all default option
//
// zdb://remote-addr                         -- tcp remote server, default port
// zdb://remote-addr:port                    -- tcp remote server, specific port
// zdb://unix:/tmp/unix.socket               -- unix socket path
// zdb://[socket]?namespace=[namespace]      -- namespace option
//            ...?password=[password]        -- namespace password
//            ...?blocksize=[blocksize]      -- blocksize to use
//
//            -- multiple arguments:
//            ...?namespace=[namespace]&size=[size]
//
// this follow classic uri system: schema://target?arg=val&arg2=val2

static void zdb_aio_parse_filename(const char *filename, QDict *options, Error **errp) {
    const char *str = NULL;
    char *match = NULL, *limits = NULL;
    char *value = NULL;
    size_t length, copy;

    if(strncmp(filename, "zdb://", 6) != 0) {
        error_setg(errp, "Protocol should starts with zdb://'");
        return;
    }

    if((length = strlen(filename)) == 6) {
        // nothing to parse, default option for everything
        return;
    }

    // unix socket
    if(strncmp(filename + 6, "unix:", 4) == 0) {
        str = filename + 11;
        copy = length;

        if((limits = strchr(str, '&')))
            copy = limits - str;

        value = strndup(str, copy);
        qdict_put(options, ZDB_OPT_SOCKET, qstring_from_str(value));

    } else {
        str = filename + 6;
        copy = length;

        // classic tcp path
        if((limits = strchr(str, '&')))
            copy = limits - str;

        value = strndup(str, copy);
        if((match = strchr(value, ':'))) {
            int port = atoi(match + 1);

            if(port == 0)
                port = ZDB_OPT_PORT_DEFAULT;

            qdict_put(options, ZDB_OPT_PORT, qnum_from_int(port));
            *match = '\0';
        }

        if(strlen(value) > 0)
            qdict_put(options, ZDB_OPT_HOST, qstring_from_str(value));
    }

    // no more options
    if(!(match = strchr(str, '?')))
        return;

    str = match + 1;

    // list of supported options
    const char *supported[] = {
        ZDB_OPT_NAMESPACE,
        ZDB_OPT_PASSWORD,
        ZDB_OPT_BLOCKSIZE,
        ZDB_OPT_SIZE,
        ZDB_OPT_THIN_HOST,
        ZDB_OPT_THIN_PORT,
        ZDB_OPT_THIN_SOCKET,
        ZDB_OPT_THIN_NAMESPACE,
        ZDB_OPT_THIN_PASSWORD,
        ZDB_OPT_BACKUP_HOST,
        ZDB_OPT_BACKUP_PORT,
        ZDB_OPT_BACKUP_SOCKET,
        ZDB_OPT_BACKUP_NAMESPACE,
        ZDB_OPT_BACKUP_PASSWORD,
    };

    while(1) {
        int valid = 0;
        key_value_t kv = zdb_next_key_value(str);

        // no key, nothing found, we are done
        if(!kv.key)
            return;

        zdb_debug(">> %s\n", kv.key);

        // testing all keys agains all options we supports
        for(unsigned int i = 0; i < sizeof(supported) / sizeof(char *); i++) {
            if(strcmp(kv.key, supported[i]) == 0) {
                // argument accepted
                qdict_put(options, supported[i], qstring_from_str(kv.value));
                valid = 1;
                break;
            }
        }

        if(!valid)
            error_setg(errp, "Unknown option '%s'", kv.key);

        key_value_free(&kv);

        // nothing left on the string
        if(!kv.remain)
            return;

        str = kv.remain;
    }
}

static int zdb_backend_append(zdb_backend_t *backend, zdb_state_t *state) {
    // add one slot on the list
    backend->length += 1;

    // growing up list
    if(!(backend->targets = (zdb_state_t **) realloc(backend->targets, sizeof(zdb_state_t *) * backend->length)))
        abort();

    // append state to the list
    backend->targets[backend->length - 1] = state;

    return 0;
}

static zdb_state_t *zdb_backend_default_read(zdb_drv_t *drv) {
    return drv->read.targets[0];
}

static zdb_state_t *zdb_backend_default_write(zdb_drv_t *drv) {
    return drv->write.targets[0];
}

static int zdb_connect_tcp(zdb_state_t *state, Error **errp) {
    struct timeval timeout = {5, 0};

    zdb_debug("[+] connecting zero-db server: %s:%d\n", state->host, state->port);
    state->redis = redisConnectWithTimeout(state->host, state->port, timeout);

    if(!state->redis || state->redis->err) {
        const char *error = (state->redis->err) ? state->redis->errstr : "memory error";

        zdb_debug("[-] zdb: hiredis: %s\n", error);

        if(errp)
            error_setg(errp, "zero-db [%s:%d]: %s", state->host, state->port, error);

        return 1;
    }

    return 0;
}

static int zdb_connect_unix(zdb_state_t *state, Error **errp) {
    zdb_debug("[+] connecting zero-db server: %s\n", state->socket);
    state->redis = redisConnectUnix(state->socket);

    if(!state->redis || state->redis->err) {
        const char *error = (state->redis->err) ? state->redis->errstr : "memory error";

        zdb_debug("[-] zdb: hiredis: %s\n", error);

        if(errp)
            error_setg(errp, "zero-db [%s]: %s", state->socket, error);

        return 1;
    }

    return 0;
}

static int zdb_connect(zdb_state_t *state, Error **errp) {
    int value;
    redisReply *reply;

    if(state->socket) {
        if((value = zdb_connect_unix(state, errp)))
            return value;

    } else {
        if((value = zdb_connect_tcp(state, errp)))
            return value;
    }

    // ping redis to ensure connection
    reply = redisCommand(state->redis, "PING");
    if(strcmp(reply->str, "PONG"))
        fprintf(stderr, "[-] zdb: warning, invalid redis PING response: %s\n", reply->str);

    freeReplyObject(reply);

    zdb_debug("[+] zdb: zero-db connected\n");

    if(state->namespace) {
        zdb_debug("[+] zdb: switching to namespace: %s\n", state->namespace);

        if(state->password) {
            // select namespace, without password
            reply = redisCommand(state->redis, "SELECT %s %s", state->namespace, state->password);

        } else {
            // select namespace, with password
            reply = redisCommand(state->redis, "SELECT %s", state->namespace);
        }

        if(reply->type == REDIS_REPLY_ERROR) {
            fprintf(stderr, "[-] zdb: namespace: %s\n", reply->str);
            error_setg(errp, "zero-db [%s]: namespace: %s", state->socket, reply->str);
        }

        freeReplyObject(reply);
    }

    return 0;
}

#if 0
static int zdb_reconnect(zdb_state_t *state) {
    redisFree(state->redis);
    return zdb_connect(state, NULL);
}
#endif

static int zdb_discard(zdb_state_t *state) {
    redisFree(state->redis);
    state->redis = NULL;

    return 0;
}

static void zdb_dump_state(zdb_state_t *s, const char *prefix) {
    zdb_debug("[+] zdb: %s: host: %s\n", prefix, s->socket ? s->socket : s->host);
    zdb_debug("[+] zdb: %s: port: %d\n", prefix, s->port);
    zdb_debug("[+] zdb: %s: size: %lu (%.2f MB)\n", prefix, s->size, s->size / (1024 * 1024.0));
    zdb_debug("[+] zdb: %s: blocksize: %lu\n", prefix, s->blocksize);
    zdb_debug("[+] zdb: %s: namespace: %s\n", prefix, s->namespace ? s->namespace : "(not set)");
    zdb_debug("[+] zdb: %s: password: %s\n", prefix, s->password ? "(hidden)" : "(not set)");
}

static int zdb_file_open(BlockDriverState *bs, QDict *options, int flags, Error **errp) {
    QemuOpts *opts;
    zdb_drv_t *drv = bs->opaque;
    zdb_state_t *s = NULL;
    zdb_state_t *dflt = NULL;
    int ret = 0;

    // setting up original driver to zero
    memset(drv, 0, sizeof(zdb_drv_t));

    // instanciating source zero-db
    if(!(s = (zdb_state_t *) malloc(sizeof(zdb_state_t))))
        abort();

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);

    if(!(s->host = qemu_opt_get(opts, ZDB_OPT_HOST)))
        s->host = "localhost";

    s->socket = qemu_opt_get(opts, ZDB_OPT_SOCKET);
    s->namespace = qemu_opt_get(opts, ZDB_OPT_NAMESPACE);
    s->password = qemu_opt_get(opts, ZDB_OPT_PASSWORD);
    s->port = qemu_opt_get_number(opts, ZDB_OPT_PORT, ZDB_OPT_PORT_DEFAULT);
    s->size = qemu_opt_get_size(opts, BLOCK_OPT_SIZE, 1 << 30);
    s->blocksize = qemu_opt_get_size(opts, ZDB_OPT_BLOCKSIZE, ZDB_DEFAULT_BLOCKSIZE);

    // set default backend
    dflt = s;

    // qemu_opts_del(opts);
    zdb_dump_state(s, "source");
    ret = zdb_connect(s, errp);

    // push this state on backend
    // we always have at least one read/write source
    zdb_backend_append(&drv->read, s);
    zdb_backend_append(&drv->write, s);

    // parsing backup
    if(qemu_opt_get(opts, ZDB_OPT_BACKUP_SOCKET) || qemu_opt_get(opts, ZDB_OPT_BACKUP_HOST)) {
        if(!(s = (zdb_state_t *) malloc(sizeof(zdb_state_t))))
            abort();

        if(!(s->host = qemu_opt_get(opts, ZDB_OPT_BACKUP_HOST)))
            s->host = "localhost";

        s->socket = qemu_opt_get(opts, ZDB_OPT_BACKUP_SOCKET);
        s->namespace = qemu_opt_get(opts, ZDB_OPT_BACKUP_NAMESPACE);
        s->password = qemu_opt_get(opts, ZDB_OPT_BACKUP_PASSWORD);
        s->port = qemu_opt_get_number(opts, ZDB_OPT_BACKUP_PORT, ZDB_OPT_PORT_DEFAULT);
        s->size = dflt->size;
        s->blocksize = dflt->blocksize;

        zdb_dump_state(s, "backup");
        ret = zdb_connect(s, errp);

        // active backup is used as duplicate write
        // we add it in read queue, since master can dies
        // if master dies, we need to use the backup as fallback
        zdb_backend_append(&drv->write, s);
        zdb_backend_append(&drv->read, s);
    }

    // parsing thin and backup options
    //
    // parsing thin-provisioning after backup
    // like this we can chain backup and provisioning:
    //   -> Checking on db1
    //   -> Checking on db2
    //   -> Checking on provisioning
    //
    // This is needed in case of redudancy lost
    if(qemu_opt_get(opts, ZDB_OPT_THIN_SOCKET) || qemu_opt_get(opts, ZDB_OPT_THIN_HOST)) {
        if(!(s = (zdb_state_t *) malloc(sizeof(zdb_state_t))))
            abort();

        if(!(s->host = qemu_opt_get(opts, ZDB_OPT_THIN_HOST)))
            s->host = "localhost";

        s->socket = qemu_opt_get(opts, ZDB_OPT_THIN_SOCKET);
        s->namespace = qemu_opt_get(opts, ZDB_OPT_THIN_NAMESPACE);
        s->password = qemu_opt_get(opts, ZDB_OPT_THIN_PASSWORD);
        s->port = qemu_opt_get_number(opts, ZDB_OPT_THIN_PORT, ZDB_OPT_PORT_DEFAULT);
        s->size = dflt->size;
        s->blocksize = dflt->blocksize;

        zdb_dump_state(s, "thinprov");
        ret = zdb_connect(s, errp);

        // thin-provisioning is used as fallback read
        zdb_backend_append(&drv->read, s);
    }


    zdb_debug("[+] zdb backend:\n");
    zdb_debug("[+]   - read: %lu servers\n", drv->read.length);
    zdb_debug("[+]   - write: %lu servers\n", drv->write.length);

    return ret;
}

static void zdb_close(BlockDriverState *bs) {
    zdb_drv_t *drv = bs->opaque;

    for(size_t i = 0; i < drv->read.length; i++) {
        zdb_state_t *s = drv->read.targets[i];

        zdb_debug("[+] zdb: closing read: %lu\n", i);
        redisFree(s->redis);
        s->redis = NULL;
    }


    for(size_t i = 0; i < drv->write.length; i++) {
        zdb_state_t *s = drv->write.targets[i];

        // skip already closed redis
        if(!s->redis)
            continue;

        zdb_debug("[+] zdb: closing write: %lu\n", i);
        redisFree(s->redis);
        s->redis = NULL;
    }
}

static int64_t zdb_getlength(BlockDriverState *bs) {
    zdb_drv_t *drv = bs->opaque;
    zdb_state_t *s = zdb_backend_default_read(drv);
    return s->size;
}

//
// zero-db request
//
static zdb_request_t zdb_request_new(zdb_state_t *state, uint64_t sector, int sectors, QEMUIOVector *qiov, zdb_command_t command) {
    zdb_request_t request;

    request.command = command;
    request.start = sector;
    request.sectors = sectors;
    request.offset = sector * BDRV_SECTOR_SIZE;
    request.length = sectors * BDRV_SECTOR_SIZE;
    request.qiov = qiov;
    request.buffer = NULL;

    zdb_debug("[+] zdb: request: %s\n", zdb_commands[request.command]);
    zdb_debug("[+] zdb: request: sector %lu + %d\n", request.start, request.sectors);
    zdb_debug("[+] zdb: request: offset %lu -> %lu\n", request.offset, request.length);

    request.first_block = request.offset / state->blocksize;
    request.last_block = ceil((request.offset + request.length) / (double) state->blocksize);

    // we use a loop from the first block to the last block on the write
    // if we only touch a single block, the loop won't do anything
    // in this special case, we force the last block to be at least one later
    if(request.last_block == request.first_block)
        request.last_block += 1;

    zdb_debug("[+] zdb: internal blocks: %lu -> %lu\n", request.first_block, request.last_block);

    // only write needs allocation
    if(request.command != ZDB_COMMAND_WRITE)
        return request;

    if(!(request.buffer = malloc(state->blocksize)))
        request.command = ZDB_COMMAND_FAILED;

    return request;
}

static void zdb_request_free(zdb_request_t *request) {
    free(request->buffer);
}

//
// zero-db input/output
//

// declaration used because of circular calls
static inline redisReply *zdb_read_block(zdb_aio_cb_t *acb, uint64_t blockid);
static inline int zdb_write_block(zdb_aio_cb_t *acb, uint64_t blockid, void *payload);

static inline redisReply *zdb_read_block_issue(zdb_aio_cb_t *acb, uint64_t blockid) {
    // skipping reconnection for now
    #if 0
    // if reconnect works, retry
    if(zdb_reconnect(acb->state) == 0)
        return zdb_read_block(acb, blockid);
    #endif

    acb->status = -EBUSY;
    return NULL;
}

static inline redisReply *zdb_read_block(zdb_aio_cb_t *acb, uint64_t blockid) {
    uint64_t key = htobe64(blockid);
    zdb_state_t *state = NULL;
    redisReply *reply = NULL;

    // iterating over read backends
    for(size_t i = 0; i < acb->drv->read.length; i++) {
        zdb_debug("[+] zdb_read_block: trying backend id: %lu\n", i);
        state = acb->drv->read.targets[i];

        // ensure previous reply (if any) is discarded
        if(reply) {
            freeReplyObject(reply);
            reply = NULL;
        }

        // does the connection is still alive
        if(!state->redis) {
            zdb_debug("[-] zdb_read_block: connection died\n");
            acb->status = -EIO;
            continue;
        }

        // performing request
        if(!(reply = redisCommand(state->redis, "GET %b", &key, sizeof(key)))) {
            zdb_debug("[-] zdb: read: cannot perform request: %s\n", state->redis->errstr);
            zdb_read_block_issue(acb, blockid);
            continue;
        }

        // reply exists but length is not expected blocksize
        // this block is corrupted or not what we expected
        if(reply->len > 0 && reply->len != state->blocksize) {
            zdb_debug("[-] zdb: read: wrong blocksize read (%u, expected %lu)\n", reply->len, state->blocksize);
            acb->status = -EIO;
            continue;
        }

        // key was not found, let's check the
        // next backend, if there is no more backend
        // this one will be returned
        if(!reply->str) {
            zdb_debug("[-] zdb: read: not found, looking next backend\n");
            continue;
        }

        acb->status = 0;
        return reply;
    }

    zdb_debug("[+] zdb: read: block read (acb status: %d)\n", acb->status);

    return reply;
}

static inline void zdb_free_block(redisReply *reply) {
    freeReplyObject(reply);
}

static inline int zdb_write_block(zdb_aio_cb_t *acb, uint64_t blockid, void *payload) {
    uint64_t key = htobe64(blockid);
    zdb_state_t *state = NULL;
    redisReply *reply;

    for(size_t i = 0; i < acb->drv->write.length; i++) {
        zdb_debug("[+] zdb_write_block: using backend id: %lu\n", i);
        state = acb->drv->write.targets[i];

        if(!state->redis) {
            zdb_debug("[-] zdb_write_block: closed backend: %lu\n", i);

            if(i > 0 && acb->status == 0)
                continue;

            acb->status = -EIO;
            continue;
        }

        if(!(reply = redisCommand(state->redis, "SET %b %b", &key, sizeof(key), payload, state->blocksize))) {
            zdb_debug("[-] zdb: write: cannot perform request: %s\n", state->redis->errstr);

            // disable auto-reconnection for now
            #if 0
            // if reconnect works, retry
            if(zdb_reconnect(state) == 0) {
                zdb_write_block(acb, blockid, payload);
                continue;
            }
            #endif

            // set state as disconnected
            zdb_debug("[+] === WARNING\n");
            zdb_debug("[-] BACKEND DEAD. ENTERING DEGRADED MODE.\n");
            zdb_debug("[+] === WARNING\n");
            zdb_discard(state);

            // degraded mode but previous write succeed,
            // we are still alive
            if(i > 0 && acb->status == 0)
                continue;

            acb->status = -EBUSY;
            continue;
        }

        if(reply->type != REDIS_REPLY_STRING && reply->type != REDIS_REPLY_NIL) {
            zdb_debug("[-] zdb: reply type: %d\n", reply->type);
            zdb_debug("[-] zdb: write: wrong response type from server\n");

            if(i > 0 && acb->status == 0)
                continue;

            acb->status = -EIO;
            continue;
        }

        acb->status = 0;
        freeReplyObject(reply);
    }

    return acb->status;
}

//
// qemu input/output
//
static void zdb_bh_cb(void *opaque) {
    zdb_aio_cb_t *acb = opaque;
    zdb_request_t *request = &acb->request;
    uint64_t blocksize = acb->state->blocksize;

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

            for(uint64_t block = request->first_block; block < request->last_block; block += 1) {
                zdb_debug("[+] zdb: processing read: block %lu, remain %lu\n", block, remain);

                // reading the block, we need it anyway
                redisReply *payload = zdb_read_block(acb, block);
                if(!payload) {
                    // acb->status = -EIO;
                    goto final;
                }

                uint64_t buffer_offset = (current % blocksize);       // position to the buffer
                uint64_t buffer_length = (blocksize - buffer_offset); // amount of data to put on the buffer

                zdb_debug("[+] zdb: read: partial offset: %lu\n", buffer_offset);
                zdb_debug("[+] zdb: read: partial length: %lu\n", buffer_length);

                if(buffer_length > remain)
                    buffer_length = remain;

                zdb_debug("[+] zdb: read: partial length corrected: %lu\n", buffer_length);

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
                if(current % acb->state->blocksize || remain < acb->state->blocksize) {
                    zdb_debug("[+] zdb: partial write, need to read the block\n");
                    zdb_debug("[+] zdb: begin: %lu, remain: %lu in %lu block\n", current % blocksize, remain, current + blocksize);

                    uint64_t buffer_offset = (current % blocksize);       // position to the buffer
                    uint64_t buffer_length = (blocksize - buffer_offset); // amount of data to put on the buffer

                    zdb_debug("[+] zdb: write: partial offset: %lu\n", buffer_offset);
                    zdb_debug("[+] zdb: write: partial length: %lu\n", buffer_length);

                    // fetching the block from the backend
                    redisReply *existing = zdb_read_block(acb, block);
                    if(!existing) {
                        // if existing is not set, block was not correctly read
                        // acb->status = -EIO;
                        goto final;
                    }

                    if(existing->str) {
                        // key was existing, moving the payload to the buffer
                        memcpy(request->buffer, existing->str, blocksize);

                    } else {
                        // key not found, we need to start from an empty block
                        memset(request->buffer, 0x00, blocksize);
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
                qemu_iovec_to_buf(request->qiov, iopos, request->buffer, blocksize);
                zdb_write_block(acb, block, request->buffer);

                iopos += blocksize;
                current += blocksize;
                remain -= blocksize;
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

final:
    acb->common.cb(acb->common.opaque, acb->status);

    zdb_request_free(request);
    qemu_aio_unref(acb);
}

static inline BlockAIOCB *zdb_aio_common(BlockDriverState *bs, BlockCompletionFunc *cb, void *opaque, zdb_request_t request) {
    zdb_aio_cb_t *acb;
    zdb_drv_t *drv = bs->opaque;
    zdb_state_t *s = zdb_backend_default_read(drv);

    acb = qemu_aio_get(&null_aiocb_info, bs, cb, opaque);
    acb->status = 0;
    acb->request = request;
    acb->state = s;
    acb->drv = drv;

    aio_bh_schedule_oneshot(bdrv_get_aio_context(bs), zdb_bh_cb, acb);

    return &acb->common;
}

static BlockAIOCB *zdb_aio_readv(BlockDriverState *bs, int64_t sector, QEMUIOVector *qiov, int sectors, BlockCompletionFunc *cb, void *opaque) {
    zdb_drv_t *drv = bs->opaque;
    zdb_state_t *s = zdb_backend_default_read(drv);
    zdb_request_t request = zdb_request_new(s, sector, sectors, qiov, ZDB_COMMAND_READ);
    return zdb_aio_common(bs, cb, opaque, request);
}

static BlockAIOCB *zdb_aio_writev(BlockDriverState *bs, int64_t sector, QEMUIOVector *qiov, int sectors, BlockCompletionFunc *cb, void *opaque) {
    zdb_drv_t *drv = bs->opaque;
    zdb_state_t *s = zdb_backend_default_write(drv);
    zdb_request_t request = zdb_request_new(s, sector, sectors, qiov, ZDB_COMMAND_WRITE);
    return zdb_aio_common(bs, cb, opaque, request);
}

static BlockAIOCB *zdb_aio_flush(BlockDriverState *bs, BlockCompletionFunc *cb, void *opaque) {
    zdb_drv_t *drv = bs->opaque;
    zdb_state_t *s = zdb_backend_default_write(drv);
    zdb_request_t request = zdb_request_new(s, 0, 0, NULL, ZDB_COMMAND_FLUSH);
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

static int coroutine_fn zdb_co_create(BlockdevCreateOptions *create_options, Error **errp) {
    zdb_debug("[+] zdb: image creation in early stage\n");
    return 0;
}

static int coroutine_fn zdb_co_create_opts(const char *filename, QemuOpts *opts, Error **errp) {
    zdb_debug("[+] zdb: image creation in early stage\n");
    return 0;
}

static QemuOptsList zdb_create_opts = {
    .name = "zdb-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(zdb_create_opts.head),
    .desc = {
        {/* end if list */}
    }
};

static BlockDriver bdrv_zdb_aio = {
    .format_name            = "zdb",
    .protocol_name          = "zdb",
    .instance_size          = sizeof(zdb_drv_t),

    .bdrv_file_open         = zdb_file_open,
    .bdrv_parse_filename    = zdb_aio_parse_filename,
    .bdrv_close             = zdb_close,
    .bdrv_getlength         = zdb_getlength,

    .bdrv_aio_readv         = zdb_aio_readv,
    .bdrv_aio_writev        = zdb_aio_writev,
    .bdrv_aio_flush         = zdb_aio_flush,

    .bdrv_reopen_prepare    = zdb_reopen_prepare,
    .bdrv_refresh_filename  = zdb_refresh_filename,

    .bdrv_co_create         = zdb_co_create,
    .create_opts            = &zdb_create_opts,
    .bdrv_co_create_opts    = zdb_co_create_opts,

    .bdrv_has_zero_init     = bdrv_has_zero_init_1,
};

static void bdrv_zdb_init(void) {
    bdrv_register(&bdrv_zdb_aio);
}

block_init(bdrv_zdb_init);
