#include <Arduino.h>
#include <WiFi.h>

#include "gateway_protocol.h"
#include "device_control.h"

#include <Time.h>

#include "driver/periph_ctrl.h"

#define BAUDRATE                            115200

#define WIFI_SSID                           "ISRcomunicaciones*34*"
#define WIFI_PASSWORD                       "52dq4yk9"

#define GATEWAY_IP_ADDRESS                  IPAddress(51,254,120,244)
#define GATEWAY_PORT                        54445
#define GATEWAY_APP_KEY                     "49f4d289"
#define GATEWAY_DEV_ID                      2
#define SECURE                              1 // encrypted payload

#define TIME_ZONE                           2 // +2 Madrid
#define TIME_REQUEST_RETRIES                3//50
#define DATA_SEND_RETRIES_MAX               3//50

#define GET_DATA                            0
#define SET_SAMPLING_PERIOD                 1
#define DEV_REBOOT                          2

#define DEFAULT_SAMPLE_PERIOD               60000 // 1min

#define TIME_DRIFT_INFO


typedef struct {
    uint32_t sample_period; // 1 min default
} dev_conf_t;

typedef struct {
    uint32_t utc;
    int16_t data;
} sensor_data_t;

WiFiUDP clientUDP;

hw_timer_t *timer = NULL;
volatile uint8_t sample_flag = 1;

void IRAM_ATTR on_timer();

// get time from the gateway
time_t gateway_protocol_get_time(void);
// send STAT message (ACK, NACK)
void gateway_protocol_send_stat(gateway_protocol_stat_t stat);
// encode sensors data for sending (martialize)
void  gateway_protocol_send_data_payload_encode (
    const sensor_data_t *sensor_data, 
    uint8_t *payload, 
    uint8_t *payload_length);
// request pending message from the gateway
void gateway_protocol_req_pend(void);
// send sensors data
gateway_protocol_stat_t send_sensor_data(const sensor_data_t *sensor_data);

uint8_t send_udp_datagram (
    const IPAddress ip, 
    const uint16_t port, 
    const uint8_t *packet, 
    const uint8_t packet_length);

// util
void print_array_hex(uint8_t *array, uint8_t array_length, const char *sep);

sensor_data_t sensor_data;
dev_conf_t dev_conf;
gateway_protocol_stat_t g_stat = GATEWAY_PROTOCOL_STAT_NACK;

// key for AES encryption pasted from the platform
uint8_t secure_key[GATEWAY_PROTOCOL_SECURE_KEY_SIZE] = { 0x73, 0x60, 0xe4, 0x5e, 0x09, 0xa0, 0x5e, 0xab, 0xb1, 0x69, 0xdf, 0x1f, 0x8c, 0x80, 0x72, 0xd5 };


void setup() {
    Serial.begin(BAUDRATE);
    
    periph_module_reset(PERIPH_WIFI_MODULE);
    WiFi.disconnect(true);
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    WiFi.setSleep(false);
    uint8_t cnt = 20;
    while (WiFi.status() != WL_CONNECTED && cnt) {
        delay(500);
        Serial.print(".");
        cnt--;
    }
    if (!cnt) {
        ESP_LOGE(TAG, "WiFi not connected -> restart!");
        periph_module_reset(PERIPH_WIFI_MODULE);
        ESP.restart();
    }

    ESP_LOGD(TAG, "WiFi connected");
    // Serial.println("IP address set: ");
    // Serial.println(WiFi.localIP()); //print LAN IP

    clientUDP.begin(GATEWAY_PORT);

    gateway_protocol_init((uint8_t *)GATEWAY_APP_KEY, GATEWAY_DEV_ID, secure_key, SECURE);

    setSyncProvider(gateway_protocol_get_time);
    setSyncInterval(300);

    dev_conf.sample_period = DEFAULT_SAMPLE_PERIOD;
    timer = timerBegin(0, 80, true);
    timerAttachInterrupt(timer, &on_timer, true);
    timerAlarmWrite(timer, dev_conf.sample_period*1000, true);
    timerAlarmEnable(timer);
}

void loop() {
    if (sample_flag) {
        sensor_data.data = random(0, INT16_MAX);
        
        g_stat = send_sensor_data(&sensor_data);
        
        if (g_stat == GATEWAY_PROTOCOL_STAT_ACK) {
            ESP_LOGD(TAG, "ACK received");
        } else if (g_stat == GATEWAY_PROTOCOL_STAT_ACK_PEND) {
            ESP_LOGD(TAG, "ACK_PEND received");
            gateway_protocol_req_pend();
        } else {
            ESP_LOGD(TAG, "NACK %02X", g_stat);
        }
        sample_flag = 0;
    }
}

time_t gateway_protocol_get_time() {
    uint32_t utc = 0;
    uint8_t buf[50];
    uint8_t buf_len = 0, payload_len = 0;
    uint8_t retries = 0;

    do {
        gateway_protocol_packet_encode(
                                GATEWAY_PROTOCOL_PACKET_TYPE_TIME_REQ,
                                0, buf,
                                &buf_len, buf);

        if (send_udp_datagram(GATEWAY_IP_ADDRESS, GATEWAY_PORT, buf, buf_len)) {
            ESP_LOGD(TAG, "Time request complete!");
        } else {
            ESP_LOGE(TAG, "Time request failed!");
        }
        
        uint32_t wait_ms = millis() + 1000;
        while(!clientUDP.parsePacket() && wait_ms > millis()) {}
        if ((buf_len = clientUDP.read((unsigned char *)buf, sizeof(buf)))) {
            gateway_protocol_packet_type_t p_type;
            if (gateway_protocol_packet_decode(
                &p_type,
                &payload_len, buf,
                buf_len, buf))
            {
                if (p_type == GATEWAY_PROTOCOL_PACKET_TYPE_TIME_SEND &&
                    payload_len == sizeof(uint32_t)) 
                {
                    memcpy(&utc, buf, sizeof(uint32_t));

                    struct timeval now = { .tv_sec = utc };
                    settimeofday(&now, NULL);

                    setTime(utc);
                } else {
                    ESP_LOGE(TAG, "time content decode error : %02X, %d", p_type, payload_len);
                }
            } else {
                ESP_LOGE(TAG, "time pck decode error");
            }
        } else {
            ESP_LOGE(TAG, "no time response");
            delay(20);
        }
    } while (utc == 0 && retries++ < TIME_REQUEST_RETRIES);

    return (time_t) utc;
}

void gateway_protocol_send_stat(gateway_protocol_stat_t stat) {
    uint8_t buffer[32];
    uint8_t buffer_length = 0;

    gateway_protocol_packet_encode (
        GATEWAY_PROTOCOL_PACKET_TYPE_STAT,
        1, (uint8_t *)&stat,
        &buffer_length, buffer);

    send_udp_datagram(GATEWAY_IP_ADDRESS, GATEWAY_PORT, buffer, buffer_length);
}

void  gateway_protocol_send_data_payload_encode (
    const sensor_data_t *sensor_data, 
    uint8_t *payload, 
    uint8_t *payload_length) 
{
    *payload_length = 0;

    memcpy(&payload[*payload_length], &sensor_data->utc, sizeof(sensor_data->utc));
    (*payload_length) += sizeof(sensor_data->utc);

    memcpy(&payload[*payload_length], &sensor_data->data, sizeof(sensor_data->data));
    (*payload_length) += sizeof(sensor_data->data);
}

void gateway_protocol_req_pend() {
    uint8_t buffer[GATEWAY_PROTOCOL_MAX_PACKET_SIZE];
    uint8_t buffer_length = 0;
    uint8_t payload[GATEWAY_PROTOCOL_MAX_PACKET_SIZE];
    uint8_t payload_length = 0;

    gateway_protocol_packet_encode(
        GATEWAY_PROTOCOL_PACKET_TYPE_PEND_REQ,
        0, buffer,
        &buffer_length, buffer);

    send_udp_datagram(GATEWAY_IP_ADDRESS, GATEWAY_PORT, buffer, buffer_length);
    
    uint32_t wait_ms = millis() + 1000;
    while(!clientUDP.parsePacket() && wait_ms > millis()) {}
    if ((buffer_length = clientUDP.read(buffer, sizeof(buffer)))) {
        gateway_protocol_packet_type_t p_type;
        if (gateway_protocol_packet_decode(
            &p_type,
            &payload_length, payload,
            buffer_length, buffer))
        {
            if (p_type == GATEWAY_PROTOCOL_PACKET_TYPE_PEND_SEND) {
                ESP_LOGD(TAG, "PEND SEND received");
                print_array_hex(payload, payload_length, " : ");

                uint8_t op, arg_len, args[32];

                device_control_packet_decode(&op, &arg_len, args, payload_length, payload);

                ESP_LOGD(TAG, "PEND SEND decoded op = %d, arg_len = %d, args : ", op, arg_len);
                print_array_hex(args, arg_len, " : ");

                if (op == GET_DATA) {
                    // extra data_send
                    gateway_protocol_send_stat(GATEWAY_PROTOCOL_STAT_ACK);
                    // assign extra data send
                    sample_flag = 1;
                } else if (op == SET_SAMPLING_PERIOD) {
                    uint32_t samp_period;
                    // if (arg_len == sizeof(samp_period)) {
                        samp_period = atoi((char *)args);
                        // memcpy(&samp_period, args, sizeof(samp_period));
                        dev_conf.sample_period = samp_period;

                        timerEnd(timer);
                        timer = timerBegin(0, 80, true);
                        timerAttachInterrupt(timer, &on_timer, true);
                        timerAlarmWrite(timer, dev_conf.sample_period*1000, true);
                        timerAlarmEnable(timer);

                        ESP_LOGD(TAG, "sampling period set to %lu from %s", dev_conf.sample_period, args);

                        gateway_protocol_send_stat(GATEWAY_PROTOCOL_STAT_ACK);
                    // } else {
                    //     ESP_LOGE(TAG, "arg_len error %d != 4", arg_len);
                    //     gateway_protocol_send_stat(GATEWAY_PROTOCOL_STAT_NACK);
                    // }
                } else if (op == DEV_REBOOT) {
                    ESP_LOGD(TAG, "going to restart...");
                    gateway_protocol_send_stat(GATEWAY_PROTOCOL_STAT_ACK);
                    periph_module_reset(PERIPH_WIFI_MODULE);
                    ESP.restart();
                    // see peripherals reset
                } else {
                    // error unknown op
                    ESP_LOGE(TAG, "UNKNOWN OPERATION");
                    gateway_protocol_send_stat(GATEWAY_PROTOCOL_STAT_NACK);
                }
            }
        }
    } else {
        ESP_LOGD(TAG, "NO PEND SEND received");
    }
}

gateway_protocol_stat_t send_sensor_data(const sensor_data_t *sensor_data) {
    gateway_protocol_stat_t g_stat = GATEWAY_PROTOCOL_STAT_NACK;
    uint8_t data_send_retries = DATA_SEND_RETRIES_MAX;
    uint8_t received_ack = 0;
    uint8_t buffer[GATEWAY_PROTOCOL_MAX_PACKET_SIZE];
    uint8_t buffer_length = 0;
    uint8_t payload[GATEWAY_PROTOCOL_MAX_PACKET_SIZE];
    uint8_t payload_length = 0;

    gateway_protocol_send_data_payload_encode(sensor_data, payload, &payload_length);
    
    do {
        gateway_protocol_packet_encode(
            GATEWAY_PROTOCOL_PACKET_TYPE_DATA_SEND,
            payload_length, payload,
            &buffer_length, buffer);

        ESP_LOGD(TAG, "sending %d bytes...", buffer_length);
    
        if (send_udp_datagram(GATEWAY_IP_ADDRESS, GATEWAY_PORT, buffer, buffer_length)) {
            ESP_LOGD(TAG, "data send done!");
        } else {
            ESP_LOGD(TAG, "data send error");
        }
    
        uint32_t wait_ms = millis() + 1000;
        while(!clientUDP.parsePacket() && wait_ms > millis()) {}
        if ((buffer_length = clientUDP.read((unsigned char *)buffer, sizeof(buffer)))) {
            gateway_protocol_packet_type_t p_type;
            if (gateway_protocol_packet_decode(
                &p_type,
                &payload_length, payload,
                buffer_length, buffer)) 
            {
                ESP_LOGD(TAG, "ack resoponse DECR: ", payload_length);
                print_array_hex(payload, payload_length, " : ");
                if (p_type == GATEWAY_PROTOCOL_PACKET_TYPE_STAT &&
                    payload_length == 1)
                {
                    g_stat = (gateway_protocol_stat_t) payload[0];
                    received_ack = 1;
                    ESP_LOGD(TAG, "STAT RECEIVED %02X", g_stat);
                } else {
                    ESP_LOGD(TAG, "STAT content error p_type = %02X, buf = %02X", p_type, payload[0]);
                }
            } else {
                ESP_LOGD(TAG, "STAT packet decode error");
            }
        } else {
            ESP_LOGD(TAG, "NO STAT RECEIVED");
            delay(20);
        }
    } while (!received_ack && --data_send_retries);

    return g_stat;
}

void print_array_hex(uint8_t *array, uint8_t array_length, const char *sep) {
    #if CORE_DEBUG_LEVEL >= ARDUHAL_LOG_LEVEL_DEBUG
    for(uint8_t i = 0; i < array_length-1; i++) {
        Serial.printf("%02X%s", array[i], sep);
    }
    Serial.printf("%02X\r\n", array[array_length-1]);
    #endif
}

uint8_t send_udp_datagram (
    const IPAddress ip, 
    const uint16_t port, 
    const uint8_t *packet, 
    const uint8_t packet_length) 
{
    clientUDP.beginPacket(GATEWAY_IP_ADDRESS, GATEWAY_PORT);
    clientUDP.write(packet, packet_length);

    return clientUDP.endPacket();
}

void IRAM_ATTR on_timer() {
    sample_flag = 1;
}