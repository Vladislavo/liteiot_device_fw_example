#include <device_control.h>

void device_control_packet_encode(
    const uint8_t operation, 
    const uint8_t args_len,
    const uint8_t *args,
    uint8_t *packet_len,
    uint8_t *packet) 
{
    *packet_len = 0;

    packet[*packet_len] = operation;
    (*packet_len)++;

    packet[*packet_len] = args_len;
    (*packet_len)++;

    memcpy(&packet[*packet_len], args, args_len);
    *packet_len += args_len;
}

uint8_t device_control_packet_decode(
    uint8_t *operation, 
    uint8_t *args_len,
    uint8_t *args,
    const uint8_t packet_len,
    const uint8_t *packet) 
{
    uint8_t p_len = 0;
    
    *operation = packet[p_len];
    p_len++;

    *args_len = packet[p_len];
    p_len++;

    memcpy(args, &packet[p_len], *args_len);
    p_len += *args_len;

    return packet_len == p_len;
}