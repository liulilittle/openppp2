#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*openppp2_ios_packet_release)(void* packet_context);
typedef int (*openppp2_ios_packet_writer)(
    const void* packet,
    int         packet_size,
    void*       packet_context,
    openppp2_ios_packet_release packet_release,
    void*       user_data);
typedef int (*openppp2_ios_http_post_fn)(const char* url, const void* body, int body_len, void* user_data);

typedef void (*openppp2_ios_p2p_receive_fn)(
    void*          receive_context,
    int            status,
    const uint8_t* source_address,
    int            source_address_size,
    uint16_t       source_port,
    const void*    packet,
    int            packet_size);
typedef int (*openppp2_ios_p2p_ready_fn)(void* user_data);
typedef void* (*openppp2_ios_p2p_create_fn)(
    openppp2_ios_p2p_receive_fn receive,
    void*                       receive_context,
    void*                       user_data);
typedef int (*openppp2_ios_p2p_start_fn)(void* handle);
typedef int (*openppp2_ios_p2p_send_fn)(
    void*          handle,
    const uint8_t* destination_address,
    int            destination_address_size,
    uint16_t       destination_port,
    const void*    packet,
    int            packet_size);
typedef void (*openppp2_ios_p2p_close_fn)(void* handle);

/**
 * Provider-owned UDP transport callbacks for PacketTunnel P2P.
 *
 * close() must synchronously stop delivery and must not access receive_context
 * after it returns. All callbacks are required; incomplete tables fail closed.
 */
typedef struct openppp2_ios_p2p_datagram_provider
{
    openppp2_ios_p2p_ready_fn  ready;
    openppp2_ios_p2p_create_fn create;
    openppp2_ios_p2p_start_fn  start;
    openppp2_ios_p2p_send_fn   send;
    openppp2_ios_p2p_close_fn  close;
} openppp2_ios_p2p_datagram_provider;

typedef struct openppp2_ios_tunnel_options
{
    int         mux;
    int         vnet;
    int         lwip;
    int         block_quic;
    int         static_mode;
    const char* ip;
    const char* mask;
    const char* bypass_ip_list;
    const char* dns_rules_list;
    const char* root_path;
    int         packet_logging;
    const char* dns1;
    const char* dns2;
} openppp2_ios_tunnel_options;

typedef struct openppp2_ios_tap openppp2_ios_tap;

const char* openppp2_ios_version(void);

openppp2_ios_tap* openppp2_ios_tap_create(
    openppp2_ios_packet_writer writer,
    void*                      user_data);

int openppp2_ios_tap_set_p2p_datagram_provider(
    openppp2_ios_tap*                           tap,
    const openppp2_ios_p2p_datagram_provider* provider,
    void*                                       user_data);

void openppp2_ios_tap_clear_p2p_datagram_provider(openppp2_ios_tap* tap);

void openppp2_ios_tap_destroy(openppp2_ios_tap* tap);

int openppp2_ios_tap_start(
    openppp2_ios_tap*                  tap,
    const char*                        configuration_json,
    const openppp2_ios_tunnel_options* options);

int openppp2_ios_tap_stop(openppp2_ios_tap* tap, int stop_reason);

int openppp2_ios_tap_input(
    openppp2_ios_tap* tap,
    const void*       packet,
    int               packet_size);

int openppp2_ios_tap_get_link_state(openppp2_ios_tap* tap);

int openppp2_ios_tap_get_runtime_snapshot(
    openppp2_ios_tap* tap,
    char*             buffer,
    int               buffer_size);

int openppp2_ios_tap_get_start_stage(
    openppp2_ios_tap* tap,
    char*             buffer,
    int               buffer_size);

const char* openppp2_ios_last_error_text(void);

int openppp2_ios_last_error_code(void);

void openppp2_ios_set_telemetry_http_post(
    openppp2_ios_http_post_fn fn,
    void*                      user_data);

void openppp2_ios_set_telemetry_resource_attribute(
    const char* key,
    const char* value);

void openppp2_ios_clear_telemetry_resource_attributes(void);

#ifdef __cplusplus
}
#endif
