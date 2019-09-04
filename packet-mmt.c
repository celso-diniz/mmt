/* packet-mmt.c
 * Celso Diniz <celso_diniz@hotmail.com>
 * Copyright 2018 Celso Diniz
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mmt.h"

void dissect_signal_msg_payload(proto_tree *mmt_tree, tvbuff_t *tvb, gint *offset);
void show_MPT_message(proto_tree *mmt_tree, tvbuff_t *tvb, gint *offset);
static int counter = 0;
static long double last_timestamp = 0.0;

static int
dissect_mmt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{

    gint offset = 0;
    guint8 vflag = 0, H_flag, A_flag;
    guint16 packet_type, payload_length = 0, length_ext_header = 0, timestamp_sec, timestamp_nsec, timestamp_sec_old = 0, timestamp_nsec_old = 0, delta_timestamp_sec, delta_timestamp_nsec;
    guint32 MSG_length = 0;
    gboolean packcounter_present = 0, extension_header = 0, sourceFECpayloadID = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMT");
    col_clear(pinfo->cinfo, COL_INFO);
    proto_item *ti = proto_tree_add_item(tree, proto_mmt, tvb, 0, -1, ENC_NA);
    proto_tree *mmt_tree = proto_item_add_subtree(ti, ett_mmt);
    vflag = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(mmt_tree, hf_mmt_V_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((vflag & 0xC0) == 0x00) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Data Type: %s",
            val_to_str((tvb_get_guint8(tvb, offset + 1) & 0x3F), datatypenames1, "Unknown (0x%02x)"));
        packcounter_present = tvb_get_bits8(tvb, 2, 1);
        proto_tree_add_item(mmt_tree, hf_mmt_C_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (tvb_get_bits8(tvb, 3, 2) == 1)  sourceFECpayloadID = 1;
        proto_tree_add_item(mmt_tree, hf_mmt_FEC_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mmt_tree, hf_mmt_r1_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        extension_header = tvb_get_bits8(tvb, 5, 1);
        proto_tree_add_item(mmt_tree, hf_mmt_X1_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mmt_tree, hf_mmt_R1_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(mmt_tree, hf_mmt_RES_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mmt_tree, hf_mmt_type1_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
        packet_type = tvb_get_bits16(tvb, 10, 6, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(mmt_tree, hf_mmt_packet_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(mmt_tree, hf_mmt_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(mmt_tree, hf_mmt_packet_seqno, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        if (packcounter_present) {
            proto_tree_add_item(mmt_tree, hf_mmt_packet_counter, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
        if (extension_header) {
            proto_tree_add_item(mmt_tree, hf_mmt_type_extension_header, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            length_ext_header = tvb_get_guint16(tvb, offset, FT_UINT16);
            proto_tree_add_item(mmt_tree, hf_mmt_length_extension_header, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(mmt_tree, hf_mmt_header_extension, tvb, offset, length_ext_header, ENC_BIG_ENDIAN);
            offset += length_ext_header;
        }
        switch (packet_type) {
        case (0x00):
            payload_length = tvb_get_guint16(tvb, offset, FT_UINT16);
            proto_tree_add_uint(mmt_tree, hf_mmt_payload_length, tvb, offset, 2, payload_length);
            proto_tree_add_item(mmt_tree, hf_mmt_payload_data, tvb, offset, (payload_length + 2), ENC_BIG_ENDIAN);
            offset += (payload_length + 2);
            break;
        case (0x02):
            proto_tree_add_item(mmt_tree, hf_mmt_f_i, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_res, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_H_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            H_flag = tvb_get_bits8(tvb, 6, 1);
            proto_tree_add_item(mmt_tree, hf_mmt_A_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            A_flag = tvb_get_bits8(tvb, 7, 1);
            offset += 1;
            proto_tree_add_item(mmt_tree, hf_mmt_frag_count, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            if (A_flag) {
                if (H_flag) {
                    MSG_length = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                    offset += 2;
                }
                else {
                    MSG_length = (guint32)tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                    proto_tree_add_uint(mmt_tree, hf_mmt_MSG_length, tvb, offset, 1, MSG_length);
                    offset += 1;
                }
            }
            if (H_flag) {
                offset += MSG_length + 5;
            }
            else {
                offset += MSG_length + 4;
            }
            break;
        }
        if (sourceFECpayloadID) {
            proto_tree_add_item(mmt_tree, hf_mmt_source_FEC_payload_ID, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
    }
    else {
        if ((vflag & 0xC0) == 0x40) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Data Type: %s",
                val_to_str((tvb_get_guint8(tvb, offset + 1) & 0x0F), datatypenames2, "Unknown (0x%02x)"));
            packcounter_present = tvb_get_bits8(tvb, 2, 1);
            proto_tree_add_item(mmt_tree, hf_mmt_C_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            if (tvb_get_bits8(tvb, 3, 2) == 1)  sourceFECpayloadID = 1;
            proto_tree_add_item(mmt_tree, hf_mmt_FEC_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
            extension_header = tvb_get_bits8(tvb, 5, 1);
            proto_tree_add_item(mmt_tree, hf_mmt_X2_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_R2_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_Q_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(mmt_tree, hf_mmt_F_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_E_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_B_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_I_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_type2_flags, tvb, offset, 1, ENC_BIG_ENDIAN);
            packet_type = tvb_get_bits16(tvb, 12, 4, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(mmt_tree, hf_mmt_packet_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(mmt_tree, hf_mmt_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
            guint32 timestamp_net = tvb_get_ntohl(tvb, offset);
            timestamp_sec = (guint16)(timestamp_net >> 16);
            timestamp_nsec = (guint16)(timestamp_net);
            proto_tree_add_double_format(mmt_tree, hf_mmt_ntp_delta, tvb, offset, 0, 0, "[NTP-timestamp]= %6.0f sec + %6.9f nsec", (double)(timestamp_sec), (double)(timestamp_nsec / 65536.0));
            if (!counter) {
                timestamp_sec_old = timestamp_sec;
                delta_timestamp_sec = timestamp_sec;
                timestamp_nsec_old = timestamp_nsec;
                delta_timestamp_nsec = timestamp_nsec;
            }
            else {
                delta_timestamp_sec = timestamp_sec - timestamp_sec_old;
                timestamp_sec_old = timestamp_sec;
                delta_timestamp_nsec = timestamp_nsec - timestamp_nsec_old;
                timestamp_nsec_old = timestamp_nsec;
            }
            offset += 4;
            proto_tree_add_item(mmt_tree, hf_mmt_packet_seqno, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            if (packcounter_present) {
                proto_tree_add_item(mmt_tree, hf_mmt_packet_counter, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            proto_tree_add_item(mmt_tree, hf_mmt_r2_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_type_bitrate_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_delay_sensitiv_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_tx_priority_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(mmt_tree, hf_mmt_flow_label_flags, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            if (extension_header) {
                proto_tree_add_item(mmt_tree, hf_mmt_type_extension_header, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                length_ext_header = tvb_get_guint16(tvb, offset, FT_UINT16);
                proto_tree_add_item(mmt_tree, hf_mmt_length_extension_header, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(mmt_tree, hf_mmt_extension_header, tvb, offset, length_ext_header, ENC_BIG_ENDIAN);
                offset += length_ext_header;
            }
            switch (packet_type) {
            case (0x0):
                payload_length = tvb_get_guint16(tvb, offset, FT_UINT16);
                proto_tree_add_uint(mmt_tree, hf_mmt_payload_length, tvb, offset, 2, payload_length);
                proto_tree_add_item(mmt_tree, hf_mmt_payload_data, tvb, offset, (payload_length + 2), ENC_BIG_ENDIAN);
                offset += (payload_length + 2);
                break;
            case (0x2):
                proto_tree_add_item(mmt_tree, hf_mmt_f_i, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mmt_tree, hf_mmt_res, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(mmt_tree, hf_mmt_H_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                H_flag = tvb_get_bits8(tvb, 6, 1);
                proto_tree_add_item(mmt_tree, hf_mmt_A_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
                A_flag = tvb_get_bits8(tvb, 7, 1);
                offset += 1;
                proto_tree_add_item(mmt_tree, hf_mmt_frag_count, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                if (A_flag) {
                    if (H_flag) {
                        MSG_length = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
                        offset += 4;
                    }
                    else {
                        MSG_length = (guint32)tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
                        proto_tree_add_uint(mmt_tree, hf_mmt_MSG_length, tvb, offset, 0, MSG_length);
                        offset += 2;
                    }
                }
                dissect_signal_msg_payload(mmt_tree, tvb, &offset);
                offset += MSG_length;
                break;
            }
            if (sourceFECpayloadID) {
                proto_tree_add_item(mmt_tree, hf_mmt_source_FEC_payload_ID, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
        }
    }
    counter++;
    return tvb_captured_length(tvb);
}

void dissect_signal_msg_payload(proto_tree *mmt_tree, tvbuff_t *tvb, gint *offset)
{
    guint32 length, message_id;
    message_id = tvb_get_guint16(tvb, *offset, ENC_BIG_ENDIAN);
    if (message_id > 0x10) {
        length = tvb_get_guint16(tvb, *offset+3, ENC_BIG_ENDIAN);
    }
    else {
        length = tvb_get_guint32(tvb, *offset+3, ENC_BIG_ENDIAN);
    }
    proto_tree_add_string_format(mmt_tree, hf_mmt_text, tvb, *offset, 0, "", "Message iD= %x\tLength= %d", message_id, length);

    if (message_id == 0) {
        proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "PA message");
    }
    if ( message_id >= 0x1 && message_id <= 0x10 ) {
        proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "MPI message");
    }
    if ( message_id >= 0x11 && message_id <= 0x20 ) {
        proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "MPT message");
        show_MPT_message(mmt_tree, tvb, offset);
    }
    if ( message_id >= 0x21 && message_id <= 0x1ff ) {
        proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "SM - Reserved signalling message");
     }
    if ( message_id >= 0x200 && message_id <= 0x20e ) {
        switch (message_id) {
            case (0x200):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "CRI message");
                break;
            case (0x201):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "DCI message");
                break;
            case (0x202):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "SSWR message");
                break;
            case (0x204):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "AL_FEC message");
                break;
            case (0x205):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "MC message");
                break;
            case (0x206):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "AC message");
                break;
            case (0x207):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "AF message");
                break;
            case (0x208):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "RQF message");
                break;
            case (0x209):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "ADC message");
                break;
            case (0x20A):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "HRBM Removal message");
                break;
            case (0x20Bu):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "LS message");
                break;
            case (0x20C):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "LR message");
                break;
            case (0x20D):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "NAMF message");
                break;
            case (0x20E):
                proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "LDC message");
                break;
        }
    }
    if ( message_id >= 0x20f && message_id <= 0x6fff ) {
        proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "SM - Reserved for ISO use (16-bit length message)");
    }
    if ( message_id >= 0x7000 && message_id <= 0x7fff ) {
        proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "SM - Reserved for ISO use (32-bit length message)");
    }
    if ( message_id >= 0x8000 && message_id <= 0xffff ) {
        proto_tree_add_string(mmt_tree, hf_mmt_text, tvb, *offset, 0, "SM - Reserved for private use");
        offset += 5;
    }
    offset += length;
    return;
}

void show_MPT_message(proto_tree *mmt_tree, tvbuff_t *tvb, gint *offset) {
    proto_tree_add_item(mmt_tree, hf_mmt_table_id, tvb, *offset, 2, ENC_BIG_ENDIAN);
    offset +=2;
    return;
}

void
proto_register_mmt(void)
{
	static hf_register_info hf[] = {
		{ &hf_mmt_V_flags,
			{ "version", "mmt.V_flags",
			FT_UINT8, BASE_DEC,
			NULL, MMT_V_FLAGS,
			NULL, HFILL }
		},

		{ &hf_mmt_C_flag,
			{ "packet_counter_flag", "mmt.C_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_C_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_FEC_flags,
			{ "FEC_type", "mmt.FEC_flags",
			FT_UINT8, BASE_HEX,
			VALS(fectypenames), MMT_FEC_FLAGS,
			NULL, HFILL }
		},

		{ &hf_mmt_r1_flag,
			{ "reserved", "mmt.r1_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_RP1_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_r2_flag,
			{ "reliability_flag", "mmt.r2_flag",
			FT_UINT16, BASE_HEX,
			NULL, MMT_RP2_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_X1_flag,
			{ "extension_flag", "mmt.X1_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_X1_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_X2_flag,
			{ "extension_flag", "mmt.X2_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_X2_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_R1_flag,
			{ "RAP_flag", "mmt.R1_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_RG1_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_R2_flag,
			{ "RAP_flag", "mmt.R2_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_RG2_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_RES_flags,
			{ "reserved", "mmt.RES_flags",
			FT_UINT8, BASE_HEX,
			NULL, MMT_RES_FLAGS,
			NULL, HFILL }
		},

		{ &hf_mmt_type1_flags,
			{ "type", "mmt.type1_flags",
			FT_UINT8, BASE_HEX,
			VALS(datatypenames1), MMT_TYPE1_FLAGS,
			NULL, HFILL }
		},

                { &hf_mmt_f_i,
                        { "Fragmentation Indicator", "mmt.f_i",
                        FT_UINT8, BASE_HEX,
                        VALS(f_i), MMT_FRAG_IND,
                        NULL, HFILL }
                },

                { &hf_mmt_res,
                        { "Reserved for future use", "mmt.res",
                        FT_UINT8, BASE_HEX,
                        NULL, MMT_RES_FI,
                        NULL, HFILL }
                },

                { &hf_mmt_H_flag,
                        { "H_flag", "mmt.H_flag",
                        FT_UINT8, BASE_HEX,
                        NULL, MMT_H,
                        NULL, HFILL }
                },

                { &hf_mmt_A_flag,
                        { "A_flag", "mmt.A_flag",
                        FT_UINT8, BASE_HEX,
                        NULL, MMT_A,
                        NULL, HFILL }
                },

                { &hf_mmt_frag_count,
                        { "Fragmentation Counter", "mmt.frag_count",
                        FT_UINT8, BASE_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
                },

                { &hf_mmt_type2_flags,
			{ "type", "mmt.type2_flags",
			FT_UINT8, BASE_HEX,
			VALS(datatypenames2), MMT_TYPE2_FLAGS,
			NULL, HFILL }
		},

                { &hf_mmt_packet_type,
                        { "packet_type", "mmt.packet_type",
                        FT_UINT8, BASE_HEX,
                        NULL, MMT_PACKET_TYPE,
                        NULL, HFILL }
                },

                { &hf_mmt_packet_id,
			{ "packet_id", "mmt.packet_id",
			FT_UINT16, BASE_HEX_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_mmt_timestamp,
			{ "timestamp", "mmt.timestamp",
			FT_UINT32, BASE_HEX_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},
                
                { &hf_mmt_timestamp_sec,
                        { "[timestamp_sec]", "mmt.timestamp_sec",
                        FT_UINT16, BASE_HEX_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
                },


                { &hf_mmt_timestamp_nsec,
                        { "[timestamp_nsec]", "mmt.timestamp_nsec",
                        FT_UINT16, BASE_HEX_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
                },

		{ &hf_mmt_packet_seqno,
			{ "packet_sequence_number", "mmt.packet_sequence_number",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_mmt_packet_counter,
			{ "packet_counter", "mmt.packet_counter",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_mmt_header_extension,
			{ "header_extension", "mmt.header_extension",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

                { &hf_mmt_extension_header,
                        { "extension_header", "mmt.extension_header",
                        FT_UINT16, BASE_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
                },


                { &hf_mmt_type_extension_header,
                        { "type_extension_header", "mmt.type_extension_header",
                        FT_UINT16, BASE_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
                },

                { &hf_mmt_length_extension_header,
                        { "length_extension_header", "mmt.length_extension_header",
                        FT_UINT16, BASE_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
                },

		{ &hf_mmt_payload_data,
			{ "PAYLOAD DATA", "mmt.payload_data",
			FT_BYTES, BASE_NONE,
			NULL, 0x0,
			NULL, HFILL }
		},

                { &hf_mmt_signal_payload,
                        { "SIGNALLING MESSAGE PAYLOAD DATA", "mmt.signal_payload",
                        FT_BYTES, BASE_NONE,
                        NULL, 0x0,
                        NULL, HFILL }
                },

                { &hf_mmt_source_FEC_payload_ID,
			{ "Source_FEC_payload_ID", "mmt.source_FEC_payload_ID",
			FT_UINT32, BASE_DEC,
			NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_mmt_Q_flag,
			{ "QoS_classifier_flag", "mmt.Q_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_Q_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_F_flag,
			{ "flow_identifier_flag", "mmt.F_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_F_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_E_flag,
			{ "flow_extension_flag", "mmt.E_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_E_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_B_flag,
			{ "Compression_flag", "mmt.B_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_B_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_I_flag,
			{ "Indicator_flag", "mmt.I_flag",
			FT_UINT8, BASE_HEX,
			NULL, MMT_I_FLAG,
			NULL, HFILL }
		},

		{ &hf_mmt_type_bitrate_flags,
			{ "type_of_bitrate", "mmt.type_bitrate_flags",
			FT_UINT16, BASE_HEX,
			VALS(bitratetypenames), MMT_TYPE_BITRATE_FLAGS,
			NULL, HFILL },
		},

		{ &hf_mmt_delay_sensitiv_flags,
			{ "delay_sensitivity", "mmt.delay_sensitiv_flags",
			FT_UINT16, BASE_HEX,
			VALS(delaytypenames), MMT_DELAY_SENSITIV_FLAGS,
			NULL, HFILL }
		},

		{ &hf_mmt_tx_priority_flags,
			{ "transmission_priority", "mmt.tx_priority_flags",
			FT_UINT16, BASE_HEX,
			NULL, MMT_TX_PRIORITY_FLAGS,
			NULL, HFILL }
		},

		{ &hf_mmt_flow_label_flags,
			{ "flow_label", "mmt.flow_label_flags",
			FT_UINT16, BASE_HEX,
			NULL, MMT_FLOW_LABEL_FLAGS,
			NULL, HFILL }
		},

                { &hf_mmt_ntp,
                        { "[NTP]", "mmt.ntp",
                        FT_STRING, BASE_NONE,
                        NULL, 0x0,
                        NULL, HFILL }
                },

                { &hf_mmt_ntp_delta,
                        { "[NTP-timestamp]", "mmt.ntp_delta",
                        FT_DOUBLE, BASE_NONE,
                        NULL, 0x0,
                        NULL, HFILL }
                },

                {    &hf_mmt_text,
                        { "[INFORMAÇÃO]", "mmt.text",
                        FT_STRING, BASE_NONE,
                        NULL, 0x0,
                        NULL, HFILL }
                },

                { &hf_mmt_payload_length,
                        { "[Payload length]", "mmt.payload_length",
                        FT_UINT16, BASE_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
                },

                { &hf_mmt_MSG_length,
                        { "[MSG_length]", "mmt.MSG_length",
                        FT_UINT16, BASE_HEX_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
                },
                    
                { &hf_mmt_table_id,
                        { "[counter]", "mmt.table_id",
                        FT_UINT8, BASE_HEX_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
                }

	};
	static gint *ett[] = {
		&ett_mmt
	};
	proto_mmt = proto_register_protocol(
		"MMT Protocol", /* name       */
		"MMT",      /* short name */
		"mmt"       /* abbrev     */
	);
	proto_register_field_array(proto_mmt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
 }

void
proto_reg_handoff_mmt(void)
{
	static dissector_handle_t mmt_handle;
	mmt_handle = create_dissector_handle(dissect_mmt, proto_mmt);
	dissector_add_uint("udp.port", MMT_PORT, mmt_handle);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
