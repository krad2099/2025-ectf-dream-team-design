/**
 * @file    decoder.c
 * @author  Samuel Meyers
 * @brief   eCTF Decoder Example Design Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "simple_uart.h"
#include "simple_crypto.h"
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/aes.h>

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
#define FLASH_FIRST_BOOT 0xDEADBEEF
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

#pragma pack(push, 1)
typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;
#pragma pack(pop)

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot;
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

flash_entry_t decoder_status;

typedef enum {
    LIST_MSG = 1,
    DECODE_MSG = 2,
    SUBSCRIBE_MSG = 3
} msg_type_t;

int is_subscribed(channel_id_t channel) {
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
            return 1;
        }
    }
    return 0;
}

int list_channels() {
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;
    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[resp.n_channels] = decoder_status.subscribed_channels[i];
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);
    write_packet(LIST_MSG, &resp, len);
    return 0;
}

int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Cannot subscribe to emergency channel\n");
        return -1;
    }

    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
            decoder_status.subscribed_channels[i] = (channel_status_t){
                .active = true,
                .id = update->channel,
                .start_timestamp = update->start_timestamp,
                .end_timestamp = update->end_timestamp
            };
            break;
        }
    }

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    uint8_t decrypted_data[FRAME_SIZE];
    uint8_t key[16] = {0};
    
    if (!is_subscribed(new_frame->channel)) {
        STATUS_LED_GREEN();
        print_error("Receiving unsubscribed channel data\n");
        return -1;
    }

    int ret = decrypt_sym(new_frame->data, FRAME_SIZE, key, decrypted_data);
    if (ret != 0) {
        STATUS_LED_RED();
        print_error("Decryption failed\n");
        return -1;
    }

    write_packet(DECODE_MSG, decrypted_data, FRAME_SIZE);
    return 0;
}

void init() {
    flash_simple_init();
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        decoder_status.first_boot = FLASH_FIRST_BOOT;
        memset(decoder_status.subscribed_channels, 0, sizeof(decoder_status.subscribed_channels));
        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }
}

int main(void) {
    uint8_t uart_buf[100];
    msg_type_t cmd;
    uint16_t pkt_len;
    
    init();
    print_debug("Decoder Booted!\n");

    while (1) {
        STATUS_LED_GREEN();
        if (read_packet(&cmd, uart_buf, &pkt_len) < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        switch (cmd) {
            case LIST_MSG:
                list_channels();
                break;
            case DECODE_MSG:
                STATUS_LED_PURPLE();
                decode(pkt_len, (frame_packet_t *)uart_buf);
                break;
            case SUBSCRIBE_MSG:
                STATUS_LED_YELLOW();
                update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
                break;
            default:
                STATUS_LED_ERROR();
                print_error("Invalid Command\n");
                break;
        }
    }
}


