#ifndef _CDRA_H
#define _CDRA_H

#include <linux/mutex.h>

struct cdra_state
{
    struct kobject *object;
    int sd;
#if 0
    struct sockaddr_in udpworkeraddr;
    struct sockaddr_in optitrackaddr;
    struct hosten     *optitrackhost;
#endif
#if 0
    struct cdra_adapter *adapter;
    int (*register_set)(struct cdra_state *state, u8 page, u8 offset, const u16 *values, u8 num_values);
    int (*register_get)(struct cdra_state *state, u8 page, u8 offset, u16 *values, u8 num_values);
    int (*register_set_byte)(struct cdra_state *state, u8 page, u8 offset, u16 value);
    u16 (*register_get_byte)(struct cdra_state *state, u8 page, u8 offset);
    int (*register_modify)(struct cdra_state *state, u8 page, u8 offset, u16 clearbits, u16 setbits);
#endif
};

#if 0
struct cdra_adapter {
    void *client;
    struct device *dev;
    struct mutex lock;

    int (*read)(struct cdra_adapter *state, u16 address, char *buffer, size_t length); 
    int (*write)(struct cdra_adapter *state, u16 address, const char *buffer, size_t length); 
};

int cdra_probe(struct cdra_adapter *state);
int cdra_remove(struct cdra_adapter *state);
#endif

#endif /* _CDRA_H */
