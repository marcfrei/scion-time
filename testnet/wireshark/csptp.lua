local csptp = Proto("csptp", "CSPTP TLVs")

local tlv_type_names = {
    [0xFF00] = "CSPTP Request",
    [0xFF01] = "CSPTP Response",
    [0xFF02] = "CSPTP Status",
    [0xFF03] = "CSPTP UID",
    [0x8008] = "CSPTP Pad",
    [0x0009] = "CSPTP Alternate Time Offset Indicator",
}

local parent_protocol_names = {
    [0x0001] = "UDP/IPv4",
    [0x0002] = "UDP/IPv6",
    [0x0003] = "IEEE 802.3",
    [0x0004] = "DeviceNet",
    [0x0005] = "ControlNet",
    [0x0006] = "PROFINET",
}

local PTP_COMMON_HEADER_LEN = 34
local PTP_TIMESTAMP_LEN = 10
local PTP_BASE_LEN = PTP_COMMON_HEADER_LEN + PTP_TIMESTAMP_LEN

local CSPTP_REQUEST_TLV_TYPE = 0xFF00
local CSPTP_RESPONSE_TLV_TYPE = 0xFF01
local CSPTP_STATUS_TLV_TYPE = 0xFF02
local CSPTP_UID_TLV_TYPE = 0xFF03
local CSPTP_PAD_TLV_TYPE = 0x8008
local CSPTP_ALT_TIME_OFFSET_TLV_TYPE = 0x0009

local f_type = ProtoField.uint16("csptp.type", "TLV Type", base.HEX, tlv_type_names)
local f_len = ProtoField.uint16("csptp.length", "TLV Length", base.DEC)
local f_value = ProtoField.bytes("csptp.value", "TLV Value")

local f_request_flags = ProtoField.uint32("csptp.request.flags", "Request Flags", base.HEX)
local f_request_status = ProtoField.bool("csptp.request.flags.status", "Request Status TLV", 32, nil, 0x00000001)
local f_request_alt = ProtoField.bool("csptp.request.flags.alt_timescale", "Request Alternate Time Offset TLV", 32, nil, 0x00000002)

local f_response_req_ingress_nanoseconds = ProtoField.uint32("csptp.response.req_ingress.nanoseconds", "Request Ingress Timestamp Nanoseconds", base.DEC)

local f_status_gm_prio1 = ProtoField.uint8("csptp.status.gm_priority1", "Grandmaster Priority 1", base.DEC)
local f_status_gm_clock_class = ProtoField.uint8("csptp.status.gm_clock_class", "Grandmaster Clock Class", base.DEC)
local f_status_gm_clock_accuracy = ProtoField.uint8("csptp.status.gm_clock_accuracy", "Grandmaster Clock Accuracy", base.HEX)
local f_status_gm_clock_variance = ProtoField.uint16("csptp.status.gm_clock_variance", "Grandmaster Clock Variance", base.DEC)
local f_status_gm_prio2 = ProtoField.uint8("csptp.status.gm_priority2", "Grandmaster Priority 2", base.DEC)
local f_status_steps_removed = ProtoField.uint16("csptp.status.steps_removed", "Steps Removed", base.DEC)
local f_status_current_utc_offset = ProtoField.uint16("csptp.status.current_utc_offset", "Current UTC Offset", base.DEC)
local f_status_gm_identity = ProtoField.bytes("csptp.status.gm_identity", "Grandmaster Identity")
local f_status_parent_protocol = ProtoField.uint16("csptp.status.parent_protocol", "Parent Protocol", base.HEX, parent_protocol_names)
local f_status_parent_address_length = ProtoField.uint16("csptp.status.parent_address_length", "Parent Address Length", base.DEC)
local f_status_parent_address = ProtoField.bytes("csptp.status.parent_address", "Parent Address")

local f_uid_unique_identifier = ProtoField.bytes("csptp.uid.uid", "Unique Identifier")

local f_pad_bytes = ProtoField.bytes("csptp.pad.bytes", "Padding")

local f_alt_key = ProtoField.uint8("csptp.alt.key", "Key Field", base.DEC)
local f_alt_current_offset = ProtoField.int32("csptp.alt.current_offset", "Current Offset", base.DEC)
local f_alt_jump_seconds = ProtoField.int32("csptp.alt.jump_seconds", "Jump Seconds", base.DEC)
local f_alt_display_name_length = ProtoField.uint8("csptp.alt.display_name_length", "Display Name Length", base.DEC)
local f_alt_display_name = ProtoField.string("csptp.alt.display_name", "Display Name")
local f_alt_padding = ProtoField.bytes("csptp.alt.padding", "Padding")

csptp.fields = {
    f_type, f_len, f_value,
    f_request_flags, f_request_status, f_request_alt,
    f_response_req_ingress_nanoseconds,
    f_status_gm_prio1, f_status_gm_clock_class, f_status_gm_clock_accuracy, f_status_gm_clock_variance,
    f_status_gm_prio2, f_status_steps_removed, f_status_current_utc_offset, f_status_gm_identity,
    f_status_parent_protocol, f_status_parent_address_length, f_status_parent_address,
    f_uid_unique_identifier,
    f_pad_bytes,
    f_alt_key, f_alt_current_offset, f_alt_jump_seconds,
    f_alt_display_name_length, f_alt_display_name, f_alt_padding
}

local udp_table = DissectorTable.get("udp.port")
local ptp_builtin = nil
local ptp_builtin_ok, ptp_builtin_candidate = pcall(Dissector.get, "ptp")
if ptp_builtin_ok then
    ptp_builtin = ptp_builtin_candidate
end

local CSPTP_EVENT_PORTS = {
    [320] = true,
    [10320] = true,
}

local function tlv_name(tlv_type)
    return tlv_type_names[tlv_type] or string.format("Unknown TLV (0x%04X)", tlv_type)
end

local function uint_be_to_dec_string(range)
    local value = 0
    for i = 0, range:len() - 1 do
        value = value * 256 + range(i, 1):uint()
    end
    return string.format("%.0f", value)
end

local function add_decimal_range(tree, range, label)
    tree:add(range, string.format("%s: %s", label, uint_be_to_dec_string(range)))
end

local function add_int64_decimal_range(tree, range, label)
    tree:add(range, string.format("%s: %s", label, tostring(range:int64())))
end

local function add_request_value_fields(tlv_tree, value_range)
    if value_range:len() < 4 then
        tlv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Request TLV value shorter than 4 bytes")
        tlv_tree:add(f_value, value_range)
        return
    end

    tlv_tree:add(f_request_flags, value_range(0, 4))
    tlv_tree:add(f_request_status, value_range(0, 4))
    tlv_tree:add(f_request_alt, value_range(0, 4))

    if value_range:len() > 4 then
        tlv_tree:add(f_value, value_range(4, value_range:len() - 4)):set_text("Trailing Value Bytes")
    end
end

local function add_response_value_fields(tlv_tree, value_range)
    if value_range:len() < 18 then
        tlv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Response TLV value shorter than 18 bytes")
        tlv_tree:add(f_value, value_range)
        return
    end

    add_decimal_range(tlv_tree, value_range(0, 6), "Request Ingress Timestamp Seconds")
    tlv_tree:add(f_response_req_ingress_nanoseconds, value_range(6, 4))
    add_int64_decimal_range(tlv_tree, value_range(10, 8), "Correction Field")

    if value_range:len() > 18 then
        tlv_tree:add(f_value, value_range(18, value_range:len() - 18)):set_text("Trailing Value Bytes")
    end
end

local function add_status_value_fields(tlv_tree, value_range)
    if value_range:len() < 21 then
        tlv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Status TLV value shorter than minimum structure")
        tlv_tree:add(f_value, value_range)
        return
    end

    local offset = 0
    tlv_tree:add(f_status_gm_prio1, value_range(offset, 1))
    offset = offset + 1
    tlv_tree:add(f_status_gm_clock_class, value_range(offset, 1))
    offset = offset + 1
    tlv_tree:add(f_status_gm_clock_accuracy, value_range(offset, 1))
    offset = offset + 1
    tlv_tree:add(f_status_gm_clock_variance, value_range(offset, 2))
    offset = offset + 2
    tlv_tree:add(f_status_gm_prio2, value_range(offset, 1))
    offset = offset + 1
    tlv_tree:add(f_status_steps_removed, value_range(offset, 2))
    offset = offset + 2
    tlv_tree:add(f_status_current_utc_offset, value_range(offset, 2))
    offset = offset + 2
    tlv_tree:add(f_status_gm_identity, value_range(offset, 8))
    offset = offset + 8
    tlv_tree:add(f_status_parent_protocol, value_range(offset, 2))
    offset = offset + 2
    tlv_tree:add(f_status_parent_address_length, value_range(offset, 2))

    local parent_address_length = value_range(offset, 2):uint()
    offset = offset + 2

    if offset + parent_address_length > value_range:len() then
        tlv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Status TLV parent address exceeds announced TLV value length")
        return
    end

    if parent_address_length > 0 then
        tlv_tree:add(f_status_parent_address, value_range(offset, parent_address_length))
        offset = offset + parent_address_length
    end

    if offset < value_range:len() then
        tlv_tree:add(f_value, value_range(offset, value_range:len() - offset)):set_text("Trailing Value Bytes")
    end
end

local function add_uid_value_fields(tlv_tree, value_range)
    if value_range:len() < 16 then
        tlv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Unique Identifier TLV value shorter than minimum structure")
        tlv_tree:add(f_value, value_range)
        return
    end

    tlv_tree:add(f_uid_unique_identifier, value_range(0, 16))

    if value_range:len() > 16 then
        tlv_tree:add(f_value, value_range(16, value_range:len() - 16)):set_text("Trailing Value Bytes")
    end
end

local function add_pad_value_fields(tlv_tree, value_range)
    if value_range:len() > 0 then
        tlv_tree:add(f_pad_bytes, value_range)
    else
        tlv_tree:add(f_value, value_range):set_text("Padding: <empty>")
    end
end

local function add_alt_value_fields(tlv_tree, value_range)
    if value_range:len() < 16 then
        tlv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Alternate Time Offset Indicator TLV value shorter than minimum structure")
        tlv_tree:add(f_value, value_range)
        return
    end

    local offset = 0
    tlv_tree:add(f_alt_key, value_range(offset, 1))
    offset = offset + 1
    tlv_tree:add(f_alt_current_offset, value_range(offset, 4))
    offset = offset + 4
    tlv_tree:add(f_alt_jump_seconds, value_range(offset, 4))
    offset = offset + 4
    add_decimal_range(tlv_tree, value_range(offset, 6), "Time Of Next Jump")
    offset = offset + 6
    tlv_tree:add(f_alt_display_name_length, value_range(offset, 1))

    local display_name_length = value_range(offset, 1):uint()
    offset = offset + 1

    if offset + display_name_length > value_range:len() then
        tlv_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Alternate Time Offset display name exceeds announced TLV value length")
        return
    end

    if display_name_length > 0 then
        local display_name_range = value_range(offset, display_name_length)
        tlv_tree:add(f_alt_display_name, display_name_range, display_name_range:string())
        offset = offset + display_name_length
    else
        tlv_tree:add(f_alt_display_name, value_range(offset, 0), "")
    end

    if offset < value_range:len() then
        tlv_tree:add(f_alt_padding, value_range(offset, value_range:len() - offset))
    end
end

local function add_tlv_value_fields(tlv_tree, tlv_type, value_range)
    if tlv_type == CSPTP_REQUEST_TLV_TYPE then
        add_request_value_fields(tlv_tree, value_range)
    elseif tlv_type == CSPTP_RESPONSE_TLV_TYPE then
        add_response_value_fields(tlv_tree, value_range)
    elseif tlv_type == CSPTP_STATUS_TLV_TYPE then
        add_status_value_fields(tlv_tree, value_range)
    elseif tlv_type == CSPTP_UID_TLV_TYPE then
        add_uid_value_fields(tlv_tree, value_range)
    elseif tlv_type == CSPTP_PAD_TLV_TYPE then
        add_pad_value_fields(tlv_tree, value_range)
    elseif tlv_type == CSPTP_ALT_TIME_OFFSET_TLV_TYPE then
        add_alt_value_fields(tlv_tree, value_range)
    else
        tlv_tree:add(f_value, value_range)
    end
end

function csptp.dissector(buffer, pinfo, tree)
    local original_ptp = ptp_builtin
    local ptp_src_port = 319
    local ptp_dst_port = 319

    if CSPTP_EVENT_PORTS[pinfo.src_port] or CSPTP_EVENT_PORTS[pinfo.dst_port] then
        ptp_src_port = (pinfo.src_port == 10320) and 320 or 319
        ptp_dst_port = (pinfo.dst_port == 10320) and 320 or 319
    else
        ptp_src_port = (pinfo.src_port == 320) and 320 or 319
        ptp_dst_port = (pinfo.dst_port == 320) and 320 or 319
    end

    local ptp_tree = tree:add(buffer(0, math.min(buffer:len(), PTP_BASE_LEN)), "PTP")
    if original_ptp then
        local saved_src_port = pinfo.src_port
        local saved_dst_port = pinfo.dst_port

        pinfo.src_port = ptp_src_port
        pinfo.dst_port = ptp_dst_port
        original_ptp:call(buffer, pinfo, ptp_tree)
        pinfo.src_port = saved_src_port
        pinfo.dst_port = saved_dst_port
    end

    if buffer:len() <= PTP_BASE_LEN then
        return
    end

    local tlv_offset = PTP_BASE_LEN
    local csptp_tree = ptp_tree:add(csptp, buffer(tlv_offset), string.format("CSPTP TLVs (%d bytes after 34 + 10 byte PTP base)", buffer:len() - tlv_offset))

    while tlv_offset + 4 <= buffer:len() do
        local tlv_type = buffer(tlv_offset, 2):uint()
        local tlv_length = buffer(tlv_offset + 2, 2):uint()
        local tlv_total_length = 4 + tlv_length

        if tlv_offset + tlv_total_length > buffer:len() then
            local malformed_range = buffer(tlv_offset, buffer:len() - tlv_offset)
            local malformed_tree = csptp_tree:add(csptp, malformed_range, string.format("%s (truncated)", tlv_name(tlv_type)))
            malformed_tree:add(f_type, buffer(tlv_offset, 2))
            malformed_tree:add(f_len, buffer(tlv_offset + 2, 2))
            malformed_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "TLV exceeds remaining packet length")
            break
        end

        local tlv_range = buffer(tlv_offset, tlv_total_length)
        local value_range = buffer(tlv_offset + 4, tlv_length)
        local tlv_tree = csptp_tree:add(csptp, tlv_range, string.format("%s (%d bytes)", tlv_name(tlv_type), tlv_total_length))

        tlv_tree:add(f_type, buffer(tlv_offset, 2))
        tlv_tree:add(f_len, buffer(tlv_offset + 2, 2))
        add_tlv_value_fields(tlv_tree, tlv_type, value_range)

        tlv_offset = tlv_offset + tlv_total_length
    end
end

udp_table:add(319, csptp)
udp_table:add(320, csptp)
udp_table:add(10319, csptp)
udp_table:add(10320, csptp)
