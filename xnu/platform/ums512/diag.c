#include "platform.h"
#define UMS512_LOG_MAGIC 0x394d5852u
void ums512_log_init(struct ums512_log *log) {
    *log = (struct ums512_log){.magic = UMS512_LOG_MAGIC, .version = 1};
}
int ums512_log_put(struct ums512_log *log, uint8_t c) {
    if (!log || log->magic != UMS512_LOG_MAGIC || log->version != 1 ||
        log->head >= 256 || log->count > 256) return UMS512_INVALID;
    log->bytes[log->head] = c;
    log->head = (log->head + 1) % 256;
    if (log->count < 256) ++log->count;
    return UMS512_OK;
}
