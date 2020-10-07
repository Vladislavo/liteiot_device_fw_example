#ifndef __DEVICE_CONTROL_H__
#define __DEVICE_CONTROL_H__

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

void device_control_packet_encode(
    const uint8_t operation, 
    const uint8_t args_len,
    const uint8_t *args,
    uint8_t *packet_len,
    uint8_t *packet);

uint8_t device_control_packet_decode(
    uint8_t *operation, 
    uint8_t *args_len,
    uint8_t *args,
    const uint8_t packet_len,
    const uint8_t *packet);

#ifdef __cplusplus
}
#endif

#endif // __DEVICE_CONTROL_H__