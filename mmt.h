#pragma once
#include "config.h"
#include <epan/packet.h>
#include <epan/epan.h>
#include <stdio.h>
#include <epan/proto.h>

#define MMT_PORT 52001
#define MMT_V_FLAGS		    0xC0
#define MMT_C_FLAG		    0x20
#define MMT_FEC_FLAGS		    0x18
#define MMT_RP1_FLAG		    0x04
#define MMT_RP2_FLAG		    0x8000
#define MMT_X1_FLAG		    0x02
#define MMT_X2_FLAG		    0x04
#define MMT_RG1_FLAG		    0x01
#define MMT_RG2_FLAG		    0x02
#define MMT_RES_FLAGS		    0xC0
#define MMT_TYPE1_FLAGS		    0x3F
#define MMT_FRAG_IND                0xC0
#define MMT_RES_FI                  0x3C
#define MMT_H                       0x2
#define MMT_A                       0x1
#define MMT_PACKET_TYPE             0x0F
#define MMT_TYPE2_FLAGS		    0x0F
#define MMT_Q_FLAG		    0x01
#define MMT_F_FLAG		    0x80
#define MMT_E_FLAG		    0x40
#define MMT_B_FLAG		    0x20
#define MMT_I_FLAG		    0x10
#define MMT_TYPE_BITRATE_FLAGS      0x6000
#define MMT_DELAY_SENSITIV_FLAGS    0x1C00
#define MMT_TX_PRIORITY_FLAGS       0x0038
#define MMT_FLOW_LABEL_FLAGS        0x007F

static int proto_mmt = -1;
static int hf_mmt_V_flags = -1;
static int hf_mmt_C_flag = -1;
static int hf_mmt_FEC_flags = -1;
static int hf_mmt_r1_flag = -1;
static int hf_mmt_r2_flag = -1;
static int hf_mmt_X1_flag = -1;
static int hf_mmt_X2_flag = -1;
static int hf_mmt_R1_flag = -1;
static int hf_mmt_R2_flag = -1;
static int hf_mmt_RES_flags = -1;
static int hf_mmt_type1_flags = -1;
static int hf_mmt_f_i = -1;
static int hf_mmt_res = -1;
static int hf_mmt_H_flag = -1;
static int hf_mmt_A_flag = -1;
static int hf_mmt_frag_count = -1;
static int hf_mmt_packet_type = -1;
static int hf_mmt_signal_payload = -1;
static int hf_mmt_MSG_length = -1;
static int hf_mmt_type2_flags = -1;
static int hf_mmt_packet_id = -1;
static int hf_mmt_timestamp = -1;
static int hf_mmt_packet_seqno = -1;
static int hf_mmt_packet_counter = -1;
static int hf_mmt_header_extension = -1;
static int hf_mmt_extension_header = -1;
static int hf_mmt_type_extension_header;
static int hf_mmt_length_extension_header;
static int hf_mmt_payload_data = -1;
static int hf_mmt_source_FEC_payload_ID = -1;
static int hf_mmt_Q_flag = -1;
static int hf_mmt_F_flag = -1;
static int hf_mmt_E_flag = -1;
static int hf_mmt_B_flag = -1;
static int hf_mmt_I_flag = -1;
static int hf_mmt_type_bitrate_flags = -1;
static int hf_mmt_delay_sensitiv_flags = -1;
static int hf_mmt_tx_priority_flags = -1;
static int hf_mmt_flow_label_flags = -1;
static int hf_mmt_delay = -1;
static int hf_mmt_text = -1;
static int hf_mmt_payload_length = -1;
static int hf_mmt_timestamp_sec = -1;
static int hf_mmt_timestamp_nsec = -1;
static int hf_mmt_ntp = -1;
static int ett_mmt = -1;
static int hf_mmt_ntp_delta = -1;
static int hf_mmt_table_id = -1;

static const value_string fectypenames[] = {
	{ 0, "MMTP packet without source_FEC_payload_ID field" },
	{ 1, "MMTP packet with source_FEC_payload_ID field" },
	{ 2, "MMTP packet for repair symbol(s) for FEC Payload Mode 0 (FEC repair packet)" },
	{ 3, "MMTP packet for repair symbol(s) for FEC Payload Mode 1 (FEC repair packet)" }
};

static const value_string bitratetypenames[] = {
	{ 0, "Constant Bit Rate (CBR)" },
	{ 1, "Non-Constant Bit Rate (nCBR)" },
	{ 2, "Reserved" },
	{ 3, "Reserved" },
	{ 4, "Reserved" },
	{ 5, "Reserved" }
};

static const value_string delaytypenames[] = {
	{ 7, "Conversational Service (~100ms)" },
	{ 6, "Live-streaming Service (~1sec)" },
	{ 5, "Delay-sensitive Interactive Service (~2sec)" },
	{ 4, "Interactive Service (~5sec)" },
	{ 3, "Streaming Service (~10sec)" },
	{ 2, "Non-realtime" },
	{ 1, "Reserved" },
	{ 0, "Reserved" }
};

static const value_string datatypenames1[] = {
	{ 0, "MPU" },
	{ 1, "generic object" },
	{ 2, "signalling message" },
	{ 3, "repair symbol" },
	{ 4, "reserved for ISO use" },
	{ 31, "reserved for ISO use" },
	{ 32, "reserved for private use" },
	{ 63, "reserved for private use" }
};

static const value_string datatypenames2[] = {
	{ 0, "MPU" },
	{ 1, "generic object" },
	{ 2, "signalling message" },
	{ 3, "repair symbol" },
	{ 4, "reserved for ISO use" },
	{ 9, "reserved for ISO use" },
	{ 10, "reserved for private use" },
	{ 15, "reserved for private use" }
};

static const value_string f_i[] = {
        { 0, "Payload contains one or more complete signalling messages" },
        { 1, "Payload contains the first fragment of a signalling message" },
        { 2, "Payload contains a fragment of a signalling message that is neither the first nor the last fragment" },
        { 3, "Payload contains the last fragment of a signalling message" }
};
