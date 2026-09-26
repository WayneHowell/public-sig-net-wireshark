--==============================================================================
-- Sig-Net Protocol Framework - Wireshark Lua Dissector
--==============================================================================
--
-- Copyright (c) 2026 Singularity (UK) Ltd.
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
-- THE SOFTWARE.
--
--==============================================================================
-- Author:       Wayne Howell
-- Date:         September 26, 2026
-- Prot Version: Sig-Net v1.11 / SNOW v1.0
-- Description:  Wireshark post-dissector for Sig-Net carried over CoAP.
--               Reparses URI-Path and Sig-Net custom options in the private
--               use range (2048-64999), decodes TLV payloads, and forwards
--               embedded RDM TLVs to Wireshark's built-in RDM dissector.
--==============================================================================

local sig_net = Proto("signet", "Sig-Net")

if set_plugin_info then
    set_plugin_info({
        version = "1.3.0",
        author = "Wayne Howell",
        description = "Sig-Net Wireshark Lua post-dissector",
        repository = "private-sig-net-wireshark"
    })
end

local band = nil
local rshift = nil

if bit32 then
    band = bit32.band
    rshift = bit32.rshift
elseif bit then
    band = bit.band
    rshift = bit.rshift
else
    error("Sig-Net dissector requires Lua bit operations (bit32 or bit)")
end

local udp_payload_field = Field.new("udp.payload")
local tcp_payload_field = Field.new("tcp.payload")
local data_data_field = Field.new("data.data")

local coap_type_vals = {
    [0] = "Confirmable",
    [1] = "Non-Confirmable",
    [2] = "Acknowledgement",
    [3] = "Reset"
}

local security_mode_vals = {
    [0x00] = "Plaintext payload with HMAC-SHA256",
    [0x01] = "Open Mode (Unauthenticated)",
    [0xFF] = "Offboarded Device Beacon"
}

local query_level_vals = {
    [0x00] = "QUERY_HEARTBEAT",
    [0x01] = "QUERY_CONFIG",
    [0x02] = "QUERY_FULL",
    [0x03] = "QUERY_EXTENDED"
}

local timecode_type_vals = {
    [0x00] = "24 fps (Film)",
    [0x01] = "25 fps (EBU)",
    [0x02] = "29.97 fps (Drop Frame)",
    [0x03] = "30 fps (SMPTE Non-Drop)",
    [0x04] = "48 fps",
    [0x05] = "50 fps",
    [0x06] = "59.94 fps (Drop Frame)",
    [0x07] = "60 fps (Non-Drop)",
    [0x08] = "100 fps",
    [0x09] = "119.88 fps (Drop Frame)",
    [0x0A] = "120 fps (Non-Drop)"
}

-- Frames per second (rounded up) for each timecode type; frames must be below this.
local timecode_frame_limit = {
    [0x00] = 24, [0x01] = 25, [0x02] = 30, [0x03] = 30, [0x04] = 48, [0x05] = 50,
    [0x06] = 60, [0x07] = 60, [0x08] = 100, [0x09] = 120, [0x0A] = 120
}

local rdm_tod_control_vals = {
    [0x00] = "Force node to send TID_RDM_TOD_DATA",
    [0x01] = "Flush ToD and force full discovery"
}

local rdm_ep_config_vals = {
    [0x00] = "No background services enabled",
    [0x01] = "Enable Background Discovery",
    [0x02] = "Enable Background Queue Polling",
    [0x03] = "Enable Discovery + Queue Polling"
}

local ipv4_mode_vals = {
    [0x00] = "Static",
    [0x01] = "DHCP"
}

local ipv6_mode_vals = {
    [0x00] = "Static",
    [0x01] = "SLAAC",
    [0x02] = "DHCPv6"
}

local rt_mult_vals = {
    [0x00] = "Default multicast folding",
    [0x01] = "Custom multicast override active"
}

local identify_vals = {
    [0x00] = "Off",
    [0x01] = "Identify Subtle",
    [0x02] = "Identify Full",
    [0x03] = "Mute indicators",
    [0x04] = "Un-mute indicators"
}

local ep_identify_vals = {
    [0x00] = "Off",
    [0x01] = "Identify Subtle",
    [0x02] = "Identify Full"
}

local universe_command_vals = {
    [0x01] = "Join",
    [0x02] = "Leave"
}

local ep_protocol_vals = {
    [0x00] = "Sig-Net",
    [0x01] = "Art-Net 4",
    [0x02] = "sACN"
}

local otw_sig_type_vals = {
    [0x00] = "HMAC-SHA256",
    [0x01] = "Asymmetric ECDSA"
}

local reboot_type_vals = {
    [0xFF] = "Hardware Reset",
    [0xFE] = "Warm Reboot"
}

local ep_direction_vals = {
    [0x00] = "Disabled",
    [0x01] = "Consumer",
    [0x02] = "Supplier",
    [0x03] = "Fallback"
}

local address_type_vals = {
    [0x00] = "None",
    [0x01] = "IPv4",
    [0x02] = "IPv6"
}

local text_encoding_vals = {
    [0x00] = "ASCII"
}

local security_event_vals = {
    [0x0001] = "HMAC Verification Failure",
    [0x0002] = "Replay Attack Detected",
    [0x0003] = "DoS Rate-Limiting Activated",
    [0x0004] = "Unauthorised Onboarding Attempt",
    [0x0005] = "Sender Table Saturated",
    [0x0006] = "Cryptographic Epoch Regression",
    [0x0007] = "Sequence Contiguity Violation",
    [0x0008] = "Failed Offboard"
}

local ep_failover_mode_vals = {
    [0x00] = "Hold Last State",
    [0x01] = "Blackout",
    [0x02] = "Full",
    [0x03] = "Play Scene",
    [0x04] = "Stop generating DMX"
}

local dmx_tx_mode_vals = {
    [0x00] = "Continuous",
    [0x01] = "Delta / Change-Only"
}

local dmx_timing_vals = {
    [0x00] = "Maximum timing",
    [0x01] = "Medium timing",
    [0x02] = "Minimum timing"
}

local sig_net_option_names = {
    [2076] = "Sig-Net-Security-Mode",
    [2108] = "Sig-Net-Sender-ID",
    [2140] = "Sig-Net-Mfg-Code",
    [2172] = "Sig-Net-Session-ID",
    [2204] = "Sig-Net-Seq-Num",
    [2236] = "Sig-Net-Auth"
}

-- Fixed on-wire widths of the opaque Sig-Net options (Sig-Net v1.10+, Section 8.3).
local sig_net_option_widths = {
    [2076] = 1,
    [2108] = 8,
    [2140] = 2,
    [2172] = 4,
    [2204] = 4
}

-- URI resource lanes (Section 10.3 / Appendix A): description and HMAC key.
local uri_lanes = {
    poll = { "Discovery", "Km_global", false },
    node = { "Reply (Device to Managers)", "Kc", true },
    manager = { "Command (Manager to Device)", "Km_local", true },
    aux = { "Auxiliary", "Ks", true },
    node_beacon = { "Offboarded Beacon", "None", true },
    node_lost = { "Lost Mode", "Kc", true },
    level = { "Level Stream", "Ks", false },
    preview = { "Preview Stream", "Ks", false },
    sync = { "Sync", "Ks", false },
    timecode = { "Timecode", "Ks", false },
    snrp = { "SNOW Recovery (SNRP)", "Per payload", false }
}

-- TID dictionary (Sig-Net v1.11 Appendix C, SNOW v1.0 Section 9).
-- min/max apply to non-zero lengths; queryable TIDs also accept length 0 as a GET.
-- legacy lists lengths from earlier spec revisions that are still accepted.
local tid_defs = {
    { 0x0001, "TID_POLL", 25, 25, false },
    { 0x0002, "TID_POLL_REPLY", 12, 12, false },
    { 0x0003, "TID_SET_REPLY", 3, 3, false },
    { 0x0101, "TID_LEVEL", 1, 512, false },
    { 0x0102, "TID_PRIORITY", 1, 512, false },
    { 0x0103, "TID_PREVIEW", 1, 512, false },
    { 0x0201, "TID_SYNC", 0, 0, false },
    { 0x0202, "TID_TIMECODE", 5, 5, false },
    { 0x0203, "TID_UNIVERSE", 9, 9, false, { [7] = "pre-v1.07 TID_UNIVERSE without Originating Sender Endpoint" } },
    { 0x0204, "TID_OSC", 1, 255, false },
    { 0x0301, "TID_RDM_COMMAND", 26, 257, false },
    { 0x0302, "TID_RDM_RESPONSE", 26, 257, false },
    { 0x0303, "TID_RDM_TOD_CONTROL", 1, 1, false },
    { 0x0304, "TID_RDM_TOD_DATA", 2, 1200, false },
    { 0x0305, "TID_RDM_EP_CONFIG", 1, 1, true },
    { 0x0306, "TID_RDM_FLOW_CONTROL", 2, 2, true },
    { 0x0401, "TID_RT_OFFBOARD", 4, 4, false },
    { 0x0501, "TID_NW_MAC_ADDRESS", 6, 6, true },
    { 0x0502, "TID_NW_IPV4_MODE", 1, 1, true },
    { 0x0503, "TID_NW_IPV4_ADDRESS", 4, 4, true },
    { 0x0504, "TID_NW_IPV4_NETMASK", 4, 4, true },
    { 0x0505, "TID_NW_IPV4_GATEWAY", 4, 4, true },
    { 0x0506, "TID_NW_IPV4_CURRENT", 12, 12, true },
    { 0x0581, "TID_NW_IPV6_MODE", 1, 1, true },
    { 0x0582, "TID_NW_IPV6_ADDRESS", 16, 16, true },
    { 0x0583, "TID_NW_IPV6_PREFIX", 1, 1, true },
    { 0x0584, "TID_NW_IPV6_GATEWAY", 16, 16, true },
    { 0x0585, "TID_NW_IPV6_CURRENT", 33, 33, true },
    { 0x0601, "TID_RT_SUPPORTED_TIDS", 2, 1200, true },
    { 0x0602, "TID_RT_ENDPOINT_COUNT", 2, 2, true },
    { 0x0603, "TID_RT_PROTOCOL_VERSION", 1, 1, true },
    { 0x0604, "TID_RT_FIRMWARE_VERSION", 4, 68, true },
    { 0x0605, "TID_RT_DEVICE_LABEL", 1, 65, true },
    { 0x0606, "TID_RT_MULT_OVERRIDE", 1, 1, true },
    { 0x0607, "TID_RT_IDENTIFY", 1, 1, true },
    { 0x0608, "TID_RT_STATUS", 4, 4, true },
    { 0x0609, "TID_RT_ROLE_CAPABILITY", 4, 4, true },
    { 0x060A, "TID_RT_REBOOT", 5, 5, false },
    { 0x060B, "TID_RT_MODEL_NAME", 1, 65, true },
    { 0x060D, "TID_RT_OTW_CAPABILITY", 3, 3, true },
    { 0x0901, "TID_EP_UNIVERSE", 2, 2, true },
    { 0x0902, "TID_EP_LABEL", 1, 65, true },
    { 0x0903, "TID_EP_MULT_OVERRIDE", 4, 4, true },
    { 0x0904, "TID_EP_CAPABILITY", 6, 6, true, { [4] = "pre-v1.11 TID_EP_CAPABILITY without Maximum Merge Sources" } },
    { 0x0905, "TID_EP_DIRECTION", 1, 1, true },
    { 0x0906, "TID_EP_INPUT_PRIORITY", 1, 512, true },
    { 0x0907, "TID_EP_STATUS", 4, 4, true },
    { 0x0908, "TID_EP_FAILOVER", 3, 3, true },
    { 0x0909, "TID_EP_DMX_TIMING", 2, 2, true },
    { 0x090A, "TID_EP_REFRESH_CAPABILITY", 1, 1, true },
    { 0x090B, "TID_EP_PROTOCOL", 1, 1, true },
    { 0x090C, "TID_EP_IDENTIFY", 1, 1, true },
    { 0x7001, "TOTW_RT_COME_HOME", 18, 18, false },
    { 0x7002, "TOTW_RT_PUBLIC_KEY", 1, 1200, false },
    { 0x7003, "TOTW_RT_IDENTIFY", 32, 32, false },
    { 0x7004, "TOTW_RT_KEY_KS", 32, 32, false },
    { 0x7005, "TOTW_RT_KEY_KC", 32, 32, false },
    { 0x7006, "TOTW_RT_KEY_KM_GLOBAL", 32, 32, false },
    { 0x7007, "TOTW_RT_KEY_KM_LOCAL", 32, 32, false },
    { 0x7008, "TOTW_RT_KEY_K0", 32, 32, false },
    { 0x7009, "TOTW_RT_POM_PUBLIC_KEY", 1, 1200, false },
    { 0x700A, "TOTW_RT_POM_WIPE", 78, 78, false },
    { 0x700B, "TOTW_RT_OTW_REOPEN", 48, 80, false },
    { 0x700C, "TOTW_RT_UPDATE_POM", 1, 1200, false },
    { 0x700D, "TOTW_RT_SCOPE", 1, 32, false },
    { 0xFF01, "TID_DG_SECURITY_EVENT", 7, 23, true },
    { 0xFF02, "TID_DG_MESSAGE", 1, 64, true },
    { 0xFF03, "TID_DG_LEVEL_FOLDBACK", 1, 512, true }
}

local tid_names = {}
local tid_info = {}
for _, def in ipairs(tid_defs) do
    tid_names[def[1]] = def[2]
    tid_info[def[1]] = { name = def[2], min = def[3], max = def[4], queryable = def[5], legacy = def[6] or {} }
end

local function is_manufacturer_tid(tid)
    return tid >= 0x8000 and tid <= 0xFF00
end

local fields = {
    coap_version = ProtoField.uint8("signet.coap.version", "CoAP Version", base.DEC, nil, 0xC0),
    coap_type = ProtoField.uint8("signet.coap.type", "CoAP Type", base.DEC, coap_type_vals, 0x30),
    coap_tkl = ProtoField.uint8("signet.coap.tkl", "Token Length", base.DEC, nil, 0x0F),
    coap_code = ProtoField.uint8("signet.coap.code", "CoAP Code", base.HEX),
    coap_message_id = ProtoField.uint16("signet.coap.message_id", "CoAP Message ID", base.HEX),
    uri = ProtoField.string("signet.uri", "Sig-Net URI"),
    uri_version = ProtoField.string("signet.uri.version", "Sig-Net Version"),
    uri_scope = ProtoField.string("signet.uri.scope", "Sig-Net Scope"),
    uri_resource = ProtoField.string("signet.uri.resource", "Sig-Net Resource"),
    uri_lane = ProtoField.string("signet.uri.lane", "URI Lane"),
    uri_key = ProtoField.string("signet.uri.key", "Expected HMAC Key"),
    uri_tuid = ProtoField.string("signet.uri.tuid", "Target TUID"),
    uri_endpoint = ProtoField.uint16("signet.uri.endpoint", "Target Endpoint", base.DEC),
    uri_universe = ProtoField.uint16("signet.uri.universe", "Universe", base.DEC),
    uri_stream = ProtoField.uint16("signet.uri.stream", "Stream", base.DEC),
    security_mode = ProtoField.uint8("signet.security_mode", "Security Mode", base.HEX, security_mode_vals),
    sender_id = ProtoField.bytes("signet.sender_id", "Sender ID"),
    sender_tuid = ProtoField.string("signet.sender_tuid", "Sender TUID"),
    sender_endpoint = ProtoField.uint16("signet.sender_endpoint", "Sender Endpoint", base.DEC),
    mfg_code = ProtoField.uint16("signet.mfg_code", "Manufacturer Code", base.HEX),
    session_id = ProtoField.uint32("signet.session_id", "Session ID", base.HEX),
    seq_num = ProtoField.uint32("signet.seq_num", "Sequence Number", base.DEC),
    hmac = ProtoField.bytes("signet.hmac", "Auth (HMAC)"),
    option_number = ProtoField.uint16("signet.option.number", "Option Number", base.DEC, sig_net_option_names),
    option_length = ProtoField.uint16("signet.option.length", "Option Length", base.DEC),
    option_value = ProtoField.bytes("signet.option.value", "Option Value"),
    payload = ProtoField.bytes("signet.payload", "Payload"),
    tid = ProtoField.uint16("signet.tlv.tid", "TID", base.HEX, tid_names),
    length = ProtoField.uint16("signet.tlv.length", "Length", base.DEC),
    value = ProtoField.bytes("signet.tlv.value", "Value"),
    tids_list = ProtoField.string("signet.tids_present", "TIDs Present"),
    change_count = ProtoField.uint16("signet.change_count", "CHANGE_COUNT", base.DEC),
    set_reply_flags = ProtoField.uint8("signet.set_reply.flags", "Flags (Reserved)", base.HEX),
    ep_cap = ProtoField.uint32("signet.ep_capability", "Endpoint Capability", base.HEX),
    ep_cap_consume_level = ProtoField.bool("signet.ep_capability.consume_level", "Can Consume TID_LEVEL", 32, nil, 0x00000001),
    ep_cap_supply_level = ProtoField.bool("signet.ep_capability.supply_level", "Can Supply TID_LEVEL", 32, nil, 0x00000002),
    ep_cap_consume_rdm = ProtoField.bool("signet.ep_capability.consume_rdm", "Can Consume RDM", 32, nil, 0x00000004),
    ep_cap_supply_rdm = ProtoField.bool("signet.ep_capability.supply_rdm", "Can Supply RDM", 32, nil, 0x00000008),
    ep_cap_virtual = ProtoField.bool("signet.ep_capability.virtual", "Virtual Endpoint", 32, nil, 0x00000010),
    ep_cap_per_slot = ProtoField.bool("signet.ep_capability.per_slot_priority", "Priority Merge Mode", 32,
        { "Per-Slot Priority Merging", "Constrained Node Fallback (Universe Priority)" }, 0x00000020),
    ep_cap_reserved = ProtoField.uint32("signet.ep_capability.reserved", "Reserved", base.HEX, nil, 0xFFFFFFC0),
    ep_cap_merge_sources = ProtoField.uint16("signet.ep_capability.max_merge_sources", "Maximum Merge Sources", base.DEC),
    ep_dir = ProtoField.uint8("signet.ep_direction", "Endpoint Direction", base.HEX),
    ep_dir_mode = ProtoField.uint8("signet.ep_direction.mode", "Direction", base.DEC, ep_direction_vals, 0x03),
    ep_dir_rdm = ProtoField.bool("signet.ep_direction.rdm_enable", "RDM Enable", 8, nil, 0x04),
    ep_dir_reserved = ProtoField.uint8("signet.ep_direction.reserved", "Reserved", base.HEX, nil, 0xF8),
    ep_status = ProtoField.uint32("signet.ep_status", "Endpoint Status", base.HEX),
    ep_status_activity = ProtoField.bool("signet.ep_status.activity", "Actively Transmitting or Receiving", 32, nil, 0x00000001),
    ep_status_fault = ProtoField.bool("signet.ep_status.hardware_fault", "Hardware Fault", 32, nil, 0x00000002),
    ep_status_locked = ProtoField.bool("signet.ep_status.config_locked", "Configuration Locked via Local UI", 32, nil, 0x00000004),
    ep_status_level = ProtoField.bool("signet.ep_status.receiving_level", "Receiving TID_LEVEL", 32, nil, 0x00000008),
    ep_status_multi = ProtoField.bool("signet.ep_status.multiple_streams", "Receiving Multiple TID_LEVEL Streams", 32, nil, 0x00000010),
    ep_status_fallback = ProtoField.bool("signet.ep_status.fallback", "In Fallback Mode", 32, nil, 0x00000020),
    ep_status_failover = ProtoField.bool("signet.ep_status.failover", "In Failover Mode", 32, nil, 0x00000040),
    ep_status_reserved = ProtoField.uint32("signet.ep_status.reserved", "Reserved", base.HEX, nil, 0xFFFFFF80)
}

sig_net.fields = fields

local experts = {
    legacy = ProtoExpert.new("signet.legacy", "Legacy Sig-Net encoding from an earlier spec revision",
        expert.group.PROTOCOL, expert.severity.NOTE),
    spec = ProtoExpert.new("signet.spec_violation", "Sig-Net specification violation",
        expert.group.PROTOCOL, expert.severity.WARN),
    malformed = ProtoExpert.new("signet.malformed", "Malformed Sig-Net data",
        expert.group.MALFORMED, expert.severity.ERROR)
}

sig_net.experts = { experts.legacy, experts.spec, experts.malformed }

local rdm_dissector = nil
local rdm_dissector_name = nil

local function get_rdm_dissector()
    if rdm_dissector ~= nil then
        return rdm_dissector
    end

    local names = { "rdm", "e1.20", "e120_rdm", "rdmnet" }
    for _, name in ipairs(names) do
        local ok, dissector = pcall(Dissector.get, name)
        if ok and dissector then
            rdm_dissector = dissector
            rdm_dissector_name = name
            return rdm_dissector
        end
    end

    rdm_dissector = false
    return nil
end

local function add_text(tree_item, text)
    tree_item:add(text)
end

local function add_expert(tree_item, expert_field, text)
    tree_item:add_proto_expert_info(expert_field, text)
end

local function range_hex(range)
    local bytes = range:bytes()
    local out = {}
    for index = 0, bytes:len() - 1 do
        out[#out + 1] = string.format("%02X", bytes:get_index(index))
    end
    return table.concat(out)
end

local function range_string(range)
    local ok, value = pcall(function()
        return range:string()
    end)
    if not ok then
        return ""
    end
    return (value:gsub("[%z\1-\31\127]", "."))
end

-- Reads an unsigned integer of 0-4 bytes; zero-length is 0 (RFC 7252 uint encoding).
local function range_uint(range)
    if not range or range:len() == 0 then
        return 0
    end
    return range:uint()
end

local function bytes_to_ipv4(range)
    if range:len() ~= 4 then
        return range_hex(range)
    end
    return string.format(
        "%u.%u.%u.%u",
        range(0, 1):uint(),
        range(1, 1):uint(),
        range(2, 1):uint(),
        range(3, 1):uint()
    )
end

local function bytes_to_ipv6(range)
    if range:len() ~= 16 then
        return range_hex(range)
    end

    local groups = {}
    for index = 0, 14, 2 do
        groups[#groups + 1] = string.format("%02X%02X", range(index, 1):uint(), range(index + 1, 1):uint())
    end
    return table.concat(groups, ":")
end

local function format_tuid(range)
    return range_hex(range)
end

local function format_sender_id(range)
    if range:len() ~= 8 then
        return range_hex(range)
    end
    return string.format("%s/%u", format_tuid(range(0, 6)), range(6, 2):uint())
end

local function enum_text(value, values)
    local label = values[value]
    if label then
        return string.format("%s (0x%X)", label, value)
    end
    return string.format("Unknown (0x%X)", value)
end

local function bit_state(value, bit)
    return band(value, bit) ~= 0
end

local function default_folded_multicast(universe)
    return string.format("239.254.0.%u", ((universe - 1) % 109) + 1)
end

local function parse_extended_value(tvb, offset, nibble)
    if nibble < 13 then
        return nibble, 0
    end

    if nibble == 13 then
        if offset >= tvb:len() then
            return nil, "Missing extended option byte"
        end
        return 13 + tvb(offset, 1):uint(), 1
    end

    if nibble == 14 then
        if offset + 1 >= tvb:len() then
            return nil, "Missing extended option word"
        end
        return 269 + tvb(offset, 2):uint(), 2
    end

    return nil, "Reserved option nibble value 15"
end

local function parse_coap_packet(tvb)
    if tvb:len() < 4 then
        return nil, "Packet too short for CoAP"
    end

    local parsed = {
        options = {},
        uri_segments = {}
    }

    local first = tvb(0, 1):uint()
    parsed.version = rshift(band(first, 0xC0), 6)
    parsed.type = rshift(band(first, 0x30), 4)
    parsed.tkl = band(first, 0x0F)
    parsed.code = tvb(1, 1):uint()
    parsed.message_id = tvb(2, 2):uint()

    local offset = 4
    if offset + parsed.tkl > tvb:len() then
        return nil, "CoAP token exceeds packet length"
    end

    parsed.token = parsed.tkl > 0 and tvb(offset, parsed.tkl) or nil
    offset = offset + parsed.tkl

    local current_option = 0
    while offset < tvb:len() do
        if tvb(offset, 1):uint() == 0xFF then
            parsed.payload_marker_offset = offset
            offset = offset + 1
            break
        end

        local header_start = offset
        local byte = tvb(offset, 1):uint()
        offset = offset + 1

        local delta_nibble = rshift(band(byte, 0xF0), 4)
        local length_nibble = band(byte, 0x0F)

        local delta, delta_extra_or_error = parse_extended_value(tvb, offset, delta_nibble)
        if not delta then
            return nil, delta_extra_or_error
        end
        offset = offset + delta_extra_or_error

        local length, length_extra_or_error = parse_extended_value(tvb, offset, length_nibble)
        if not length then
            return nil, length_extra_or_error
        end
        offset = offset + length_extra_or_error

        current_option = current_option + delta
        if offset + length > tvb:len() then
            return nil, "CoAP option value exceeds packet length"
        end

        -- A zero-length option value is anchored to its header byte so the range stays in bounds.
        local value_range = (length > 0) and tvb(offset, length) or tvb(header_start, 0)
        local full_range = tvb(header_start, offset + length - header_start)
        parsed.options[#parsed.options + 1] = {
            number = current_option,
            length = length,
            value = value_range,
            range = full_range
        }

        if current_option == 11 then
            parsed.uri_segments[#parsed.uri_segments + 1] = range_string(value_range)
        end

        offset = offset + length
    end

    if offset <= tvb:len() - 1 then
        parsed.payload = tvb(offset, tvb:len() - offset)
    end

    parsed.offset_after_options = offset
    parsed.uri = "/" .. table.concat(parsed.uri_segments, "/")
    return parsed
end

local function find_option(parsed, option_number)
    for _, option in ipairs(parsed.options) do
        if option.number == option_number then
            return option
        end
    end
    return nil
end

local function is_canonical_decimal(text)
    return text:match("^%d+$") ~= nil and (text == "0" or text:sub(1, 1) ~= "0")
end

local function add_uri_tree(sig_tree, parsed)
    local segments = parsed.uri_segments
    local lane_name = segments[4] or ""
    local lane = uri_lanes[lane_name]
    local result = { lane = lane_name }

    if not lane then
        if lane_name ~= "" then
            add_expert(sig_tree, experts.spec, "Unknown Sig-Net URI resource: " .. lane_name)
        end
        return result
    end

    sig_tree:add(fields.uri_lane, lane[1])
    sig_tree:add(fields.uri_key, lane[2])

    local function add_index(field, text, label)
        if not text then
            add_expert(sig_tree, experts.spec, "URI is missing the " .. label .. " segment")
            return nil
        end
        local value = tonumber(text)
        if not is_canonical_decimal(text) or value > 0xFFFF then
            add_expert(sig_tree, experts.spec, string.format("URI %s '%s' is not a canonical decimal index", label, text))
            return nil
        end
        sig_tree:add(field, value)
        return value
    end

    if lane[3] then
        local tuid = segments[5]
        if tuid then
            sig_tree:add(fields.uri_tuid, tuid)
            if not tuid:match("^[0-9A-F]+$") or #tuid ~= 12 then
                add_expert(sig_tree, experts.spec, "URI TUID shall be 12 uppercase hexadecimal characters")
            end
        else
            add_expert(sig_tree, experts.spec, "URI is missing the {tuid} segment")
        end
        result.endpoint = add_index(fields.uri_endpoint, segments[6], "{endpoint}")
        result.tuid = tuid
    elseif lane_name == "level" then
        result.universe = add_index(fields.uri_universe, segments[5], "{universe}")
        if result.universe and (result.universe < 1 or result.universe > 63999) then
            add_expert(sig_tree, experts.spec, "Universe outside the valid range 1-63999")
        elseif result.universe then
            add_text(sig_tree, "Default Folded Multicast: " .. default_folded_multicast(result.universe))
        end
    elseif lane_name == "preview" or lane_name == "timecode" then
        result.stream = add_index(fields.uri_stream, segments[5], "{stream}")
    end

    return result
end

local function add_sig_net_option_tree(sig_tree, parsed)
    local option_tree = sig_tree:add(sig_net, string.format("Sig-Net CoAP Options (%u)", #parsed.options))

    for _, option in ipairs(parsed.options) do
        local option_name = sig_net_option_names[option.number]
        if option_name then
            local item = option_tree:add(sig_net, option.range, string.format("%s (%u), Length %u", option_name, option.number, option.length))
            item:add(fields.option_number, option.number)
            item:add(fields.option_length, option.length)
            if option.length > 0 then
                item:add(fields.option_value, option.value)
            end

            local width = sig_net_option_widths[option.number]
            if width and option.length ~= width then
                if option.length < width and option.number ~= 2108 then
                    add_expert(item, experts.legacy, string.format(
                        "%s is %u byte(s); v1.10+ requires fixed %u-byte opaque encoding (pre-v1.10 minimal uint encoding)",
                        option_name, option.length, width))
                else
                    add_expert(item, experts.malformed, string.format("%s shall be %u byte(s), found %u", option_name, width, option.length))
                end
            end

            if option.number == 2076 and option.length <= 1 then
                add_text(item, "Decoded: " .. enum_text(range_uint(option.value), security_mode_vals))
            elseif option.number == 2108 and option.length == 8 then
                add_text(item, "Decoded: " .. format_sender_id(option.value))
            elseif option.number == 2140 and option.length <= 2 then
                add_text(item, string.format("Decoded: 0x%04X", range_uint(option.value)))
            elseif option.number == 2172 and option.length <= 4 then
                add_text(item, string.format("Decoded: 0x%08X", range_uint(option.value)))
            elseif option.number == 2204 and option.length <= 4 then
                add_text(item, string.format("Decoded: %u", range_uint(option.value)))
            elseif option.number == 2236 then
                add_text(item, "Decoded: " .. (option.length > 0 and range_hex(option.value) or "(empty)"))
            end
        end
    end
end

local function add_bool_line(tree_item, label, state)
    add_text(tree_item, string.format("%s: %s", label, state and "Set" or "Clear"))
end

local function add_level_summary(tree_item, value_range, label)
    add_text(tree_item, string.format("%s slots: %u", label, value_range:len()))

    local preview = math.min(value_range:len(), 32)
    if preview > 0 then
        local parts = {}
        for index = 0, preview - 1 do
            parts[#parts + 1] = string.format("%u:%u", index + 1, value_range(index, 1):uint())
        end
        add_text(tree_item, "Preview: " .. table.concat(parts, ", "))
    end

    if value_range:len() > 32 then
        add_text(tree_item, string.format("Preview truncated at 32 of %u bytes", value_range:len()))
    end
end

local function check_priority_values(tree_item, value_range)
    for index = 0, value_range:len() - 1 do
        local value = value_range(index, 1):uint()
        if value > 200 then
            add_expert(tree_item, experts.spec, string.format("Priority value %u at slot %u exceeds the maximum of 200", value, index + 1))
            return
        end
    end
end

-- Decodes the [Encoding][String] layout used by label TIDs since v1.01.
local function decode_encoded_label(value_range, tlv_tree, label)
    local encoding = value_range(0, 1):uint()
    if encoding >= 0x20 and encoding < 0x7F then
        add_expert(tlv_tree, experts.legacy, label .. " has no leading Encoding byte (pre-v1.01 layout)")
        add_text(tlv_tree, label .. ": " .. range_string(value_range))
        return
    end

    add_text(tlv_tree, "Encoding: " .. enum_text(encoding, text_encoding_vals))
    if value_range:len() > 1 then
        add_text(tlv_tree, label .. ": " .. range_string(value_range(1, value_range:len() - 1)))
    else
        add_text(tlv_tree, label .. ": (empty)")
    end
end

local function decode_poll(value_range, tlv_tree)
    add_text(tlv_tree, "Manager TUID: " .. format_tuid(value_range(0, 6)))
    add_text(tlv_tree, string.format("Manager SoemCode: 0x%08X", value_range(6, 4):uint()))
    add_text(tlv_tree, "TUID Low: " .. format_tuid(value_range(10, 6)))
    add_text(tlv_tree, "TUID High: " .. format_tuid(value_range(16, 6)))
    local endpoint = value_range(22, 2):uint()
    add_text(tlv_tree, string.format("Endpoint: %u%s", endpoint, endpoint == 0xFFFF and " (All endpoints)" or ""))
    add_text(tlv_tree, "Query Level: " .. enum_text(value_range(24, 1):uint(), query_level_vals))
end

local function decode_poll_reply(value_range, tlv_tree)
    add_text(tlv_tree, "TUID: " .. format_tuid(value_range(0, 6)))
    add_text(tlv_tree, string.format("SoemCode: 0x%08X", value_range(6, 4):uint()))
    tlv_tree:add(fields.change_count, value_range(10, 2))
end

local function decode_set_reply(value_range, tlv_tree, ctx)
    tlv_tree:add(fields.set_reply_flags, value_range(0, 1))
    tlv_tree:add(fields.change_count, value_range(1, 2))
    if value_range(0, 1):uint() ~= 0 then
        add_expert(tlv_tree, experts.spec, "TID_SET_REPLY Flags are reserved and should be 0")
    end
    if not ctx.is_last_tlv then
        add_expert(tlv_tree, experts.spec, "TID_SET_REPLY shall be the final TLV in the packet")
    end
end

local function decode_timecode(value_range, tlv_tree)
    local hours = value_range(0, 1):uint()
    local minutes = value_range(1, 1):uint()
    local seconds = value_range(2, 1):uint()
    local frames = value_range(3, 1):uint()
    local frame_type = value_range(4, 1):uint()

    add_text(tlv_tree, string.format("Timecode: %02u:%02u:%02u:%02u", hours, minutes, seconds, frames))
    add_text(tlv_tree, "Type: " .. enum_text(frame_type, timecode_type_vals))

    if hours > 23 or minutes > 59 or seconds > 59 then
        add_expert(tlv_tree, experts.spec, "Timecode hours/minutes/seconds out of range")
    end
    local limit = timecode_frame_limit[frame_type]
    if not limit then
        add_expert(tlv_tree, experts.spec, string.format("Reserved timecode type 0x%02X", frame_type))
    elseif frames >= limit then
        add_expert(tlv_tree, experts.spec, string.format("Frame %u is out of range for %s", frames, timecode_type_vals[frame_type]))
    end
end

local function decode_uid_array(value_range, tlv_tree, label)
    if value_range:len() == 0 then
        add_text(tlv_tree, label .. ": empty")
        return
    end

    if value_range:len() % 6 ~= 0 then
        add_expert(tlv_tree, experts.malformed, string.format("%s length is not a multiple of 6", label))
    end

    local count = math.floor(value_range:len() / 6)
    add_text(tlv_tree, string.format("%s count: %u", label, count))
    for index = 0, count - 1 do
        add_text(tlv_tree, string.format("%s[%u]: %s", label, index + 1, format_tuid(value_range(index * 6, 6))))
    end
end

local function decode_rdm_tod_data(value_range, tlv_tree)
    local packet_index = value_range(0, 1):uint()
    local total_packets = value_range(1, 1):uint()
    local uid_payload_len = value_range:len() - 2

    add_text(tlv_tree, string.format("TOD Packet Index: %u", packet_index))
    add_text(tlv_tree, string.format("TOD Total Packets: %u", total_packets))
    if packet_index < 1 or packet_index > total_packets then
        add_expert(tlv_tree, experts.spec, "Packet_Index shall be in the range 1 to Total_Packets")
    end

    if uid_payload_len == 0 then
        add_text(tlv_tree, "RDM UID: empty")
        return
    end

    decode_uid_array(value_range(2, uid_payload_len), tlv_tree, "RDM UID")
end

local function call_rdm_dissector(value_range, pinfo, tlv_tree, strip_start_code)
    local dissector = get_rdm_dissector()
    if not dissector then
        add_text(tlv_tree, "Embedded RDM dissector not found. Raw RDM bytes shown only.")
        return
    end

    add_text(tlv_tree, "Embedded RDM dissector: " .. rdm_dissector_name)

    local range_for_dissector = value_range
    if strip_start_code and value_range:len() >= 2 and value_range(0, 1):uint() == 0xCC then
        range_for_dissector = value_range(1, value_range:len() - 1)
        add_text(tlv_tree, "Embedded RDM decode: stripped leading Start Code 0xCC for dissector alignment")
    end

    local ok = pcall(function()
        dissector:call(range_for_dissector:tvb(), pinfo, tlv_tree)
    end)

    if ok then
        return
    end

    local second_ok = pcall(function()
        local byte_array = ByteArray.new(range_hex(range_for_dissector))
        dissector:call(byte_array:tvb("Sig-Net Embedded RDM"), pinfo, tlv_tree)
    end)

    if not second_ok then
        add_text(tlv_tree, "Embedded RDM dissector could not be invoked. Raw RDM bytes shown only.")
    end
end

local function decode_rdm(value_range, tlv_tree, ctx, label, is_command)
    add_text(tlv_tree, string.format("%s Length: %u", label, value_range:len()))
    if value_range(0, 1):uint() ~= 0xCC then
        add_expert(tlv_tree, experts.spec, "RDM payload shall start with Start Code 0xCC")
    elseif is_command and value_range(20, 1):uint() == 0x10 then
        add_expert(tlv_tree, experts.spec, "DISCOVERY_COMMAND (0x10) shall not be encapsulated in TID_RDM_COMMAND")
    end
    call_rdm_dissector(value_range, ctx.pinfo, tlv_tree, true)
end

local function decode_ip_triplet(value_range, tlv_tree)
    add_text(tlv_tree, "IPv4 Address: " .. bytes_to_ipv4(value_range(0, 4)))
    add_text(tlv_tree, "IPv4 Netmask: " .. bytes_to_ipv4(value_range(4, 4)))
    add_text(tlv_tree, "IPv4 Gateway: " .. bytes_to_ipv4(value_range(8, 4)))
end

local function decode_ipv6_current(value_range, tlv_tree)
    add_text(tlv_tree, "IPv6 Address: " .. bytes_to_ipv6(value_range(0, 16)))
    add_text(tlv_tree, string.format("Prefix Length: %u", value_range(16, 1):uint()))
    add_text(tlv_tree, "IPv6 Gateway: " .. bytes_to_ipv6(value_range(17, 16)))
end

local function decode_supported_tids(value_range, tlv_tree)
    if value_range:len() % 2 ~= 0 then
        add_expert(tlv_tree, experts.malformed, string.format("Supported TID array length %u is not a multiple of 2", value_range:len()))
    end

    local count = math.floor(value_range:len() / 2)
    add_text(tlv_tree, string.format("Supported TIDs: %u", count))
    for index = 0, count - 1 do
        local tid = value_range(index * 2, 2):uint()
        local name = tid_names[tid] or (is_manufacturer_tid(tid) and "Manufacturer-Specific TID" or "Unknown")
        add_text(tlv_tree, string.format("Supported[%u]: %s (0x%04X)", index + 1, name, tid))
    end
end

local function decode_rt_status(value_range, tlv_tree)
    local value = value_range:uint()
    add_text(tlv_tree, string.format("Status Bitfield: 0x%08X", value))
    add_bool_line(tlv_tree, "Hardware Fault", bit_state(value, 0x00000001))
    add_bool_line(tlv_tree, "Booted from Factory Defaults", bit_state(value, 0x00000002))
    add_bool_line(tlv_tree, "Configuration Locked via Local UI", bit_state(value, 0x00000004))
    add_bool_line(tlv_tree, "Operating in Open Mode (Unauthenticated)", bit_state(value, 0x00000008))
    add_text(tlv_tree, string.format("Reserved bits (4-31): 0x%08X", band(value, 0xFFFFFFF0)))
end

local function decode_role_capability(value_range, tlv_tree)
    local value = value_range:uint()
    add_text(tlv_tree, string.format("Role Capability Bitfield: 0x%08X", value))
    add_bool_line(tlv_tree, "Node Role Supported", bit_state(value, 0x01))
    add_bool_line(tlv_tree, "Sender Role Supported", bit_state(value, 0x02))
    add_bool_line(tlv_tree, "Manager Role Supported", bit_state(value, 0x04))
    add_bool_line(tlv_tree, "Visualiser Role Supported", bit_state(value, 0x08))
    add_bool_line(tlv_tree, "Root_Firmware_Support", bit_state(value, 0x40))
    add_bool_line(tlv_tree, "Open Mode Supported", bit_state(value, 0x80))
    add_text(tlv_tree, string.format("Reserved bits: 0x%08X", band(value, 0xFFFFFF30)))
end

local function decode_endpoint_capability(value_range, tlv_tree)
    local cap_range = value_range(0, 4)
    local value = cap_range:uint()
    local cap_item = tlv_tree:add(fields.ep_cap, cap_range)
    cap_item:add(fields.ep_cap_consume_level, cap_range)
    cap_item:add(fields.ep_cap_supply_level, cap_range)
    cap_item:add(fields.ep_cap_consume_rdm, cap_range)
    cap_item:add(fields.ep_cap_supply_rdm, cap_range)
    cap_item:add(fields.ep_cap_virtual, cap_range)
    cap_item:add(fields.ep_cap_per_slot, cap_range)
    cap_item:add(fields.ep_cap_reserved, cap_range)

    local consumes_level = bit_state(value, 0x01)
    if value_range:len() == 4 then
        local merge_item = tlv_tree:add(fields.ep_cap_merge_sources, cap_range, 4)
        merge_item:set_generated()
        merge_item:append_text(" (assumed for legacy 4-byte payload)")
        add_expert(tlv_tree, experts.legacy, "Legacy 4-byte TID_EP_CAPABILITY (pre-v1.11); Maximum Merge Sources assumed to be 4")
        return
    end

    local merge_range = value_range(4, 2)
    local merge_sources = merge_range:uint()
    tlv_tree:add(fields.ep_cap_merge_sources, merge_range)
    if consumes_level and merge_sources < 4 then
        add_expert(tlv_tree, experts.spec, "Endpoints consuming TID_LEVEL shall support at least 4 merge sources")
    elseif not consumes_level and merge_sources ~= 0 then
        add_expert(tlv_tree, experts.spec, "Maximum Merge Sources shall be 0 for endpoints that do not consume TID_LEVEL")
    end
end

local function decode_endpoint_direction(value_range, tlv_tree)
    local dir_item = tlv_tree:add(fields.ep_dir, value_range)
    dir_item:add(fields.ep_dir_mode, value_range)
    dir_item:add(fields.ep_dir_rdm, value_range)
    dir_item:add(fields.ep_dir_reserved, value_range)
end

local function decode_endpoint_status(value_range, tlv_tree)
    local status_item = tlv_tree:add(fields.ep_status, value_range)
    status_item:add(fields.ep_status_activity, value_range)
    status_item:add(fields.ep_status_fault, value_range)
    status_item:add(fields.ep_status_locked, value_range)
    status_item:add(fields.ep_status_level, value_range)
    status_item:add(fields.ep_status_multi, value_range)
    status_item:add(fields.ep_status_fallback, value_range)
    status_item:add(fields.ep_status_failover, value_range)
    status_item:add(fields.ep_status_reserved, value_range)
end

local function decode_universe(value_range, tlv_tree)
    local universe = value_range(0, 2):uint()
    local address = bytes_to_ipv4(value_range(3, 4))
    add_text(tlv_tree, string.format("Universe: %u", universe))
    add_text(tlv_tree, "Command: " .. enum_text(value_range(2, 1):uint(), universe_command_vals))
    if address == "0.0.0.0" and universe >= 1 then
        add_text(tlv_tree, "Multicast IPv4 Address: 0.0.0.0 (default folding: " .. default_folded_multicast(universe) .. ")")
    else
        add_text(tlv_tree, "Multicast IPv4 Address: " .. address)
    end

    if universe < 1 or universe > 63999 then
        add_expert(tlv_tree, experts.spec, "Universe outside the valid range 1-63999")
    end

    if value_range:len() == 9 then
        add_text(tlv_tree, string.format("Originating Sender Endpoint: %u", value_range(7, 2):uint()))
    else
        add_expert(tlv_tree, experts.legacy, "Legacy 7-byte TID_UNIVERSE (pre-v1.07) without Originating Sender Endpoint")
    end
end

local function decode_otw_capability(value_range, tlv_tree)
    local protos = value_range(2, 1):uint()
    add_text(tlv_tree, string.format("OTW Listener Port: %u", value_range(0, 2):uint()))
    add_text(tlv_tree, string.format("Supported Protocols Bitfield: 0x%02X", protos))
    add_bool_line(tlv_tree, "DTLS 1.2", bit_state(protos, 0x01))
    add_bool_line(tlv_tree, "DTLS 1.3", bit_state(protos, 0x02))
    add_bool_line(tlv_tree, "TLS 1.2", bit_state(protos, 0x04))
    add_bool_line(tlv_tree, "TLS 1.3", bit_state(protos, 0x08))
    add_bool_line(tlv_tree, "Method B, PIN Onboarding", bit_state(protos, 0x10))
    add_text(tlv_tree, string.format("Reserved bits (5-7): 0x%02X", band(protos, 0xE0)))
end

local function decode_totw_come_home(value_range, tlv_tree)
    add_text(tlv_tree, "Target TUID: " .. format_tuid(value_range(0, 6)))
    add_text(tlv_tree, "New IPv4 Address: " .. bytes_to_ipv4(value_range(6, 4)))
    add_text(tlv_tree, "New IPv4 Netmask: " .. bytes_to_ipv4(value_range(10, 4)))
    add_text(tlv_tree, "New IPv4 Gateway: " .. bytes_to_ipv4(value_range(14, 4)))
end

local function decode_totw_otw_reopen(value_range, tlv_tree)
    local sig_type = value_range(6, 1):uint()
    local timeout = value_range(7, 1):uint()
    local sig_len = value_range:len() - 16

    add_text(tlv_tree, "Target TUID: " .. format_tuid(value_range(0, 6)))
    add_text(tlv_tree, "Signature Type: " .. enum_text(sig_type, otw_sig_type_vals))
    add_text(tlv_tree, string.format("Timeout: %u s%s", timeout == 0 and 60 or timeout, timeout == 0 and " (default)" or ""))
    add_text(tlv_tree, string.format("Nonce: 0x%s", range_hex(value_range(8, 8))))
    add_text(tlv_tree, string.format("Signature Block Length: %u", sig_len))

    if sig_type == 0x00 and sig_len ~= 32 then
        add_expert(tlv_tree, experts.spec, "HMAC-SHA256 signature should be 32 bytes")
    elseif sig_type == 0x01 and sig_len ~= 64 then
        add_expert(tlv_tree, experts.spec, "ECDSA raw signature should be 64 bytes")
    end
end

local function decode_security_event(value_range, tlv_tree)
    local event_code = value_range(0, 2):uint()
    local event_counter = value_range(2, 4):uint()
    local address_type = value_range(6, 1):uint()

    add_text(tlv_tree, "Event Code: " .. enum_text(event_code, security_event_vals))
    add_text(tlv_tree, string.format("Event Counter: %u", event_counter))
    add_text(tlv_tree, "Address Type: " .. enum_text(address_type, address_type_vals))

    local expected = ({ [0x00] = 7, [0x01] = 11, [0x02] = 23 })[address_type]
    if expected and value_range:len() ~= expected then
        add_expert(tlv_tree, experts.spec, string.format("Address Type %s requires a length of %u, found %u",
            address_type_vals[address_type], expected, value_range:len()))
    end

    if address_type == 0x01 and value_range:len() >= 11 then
        add_text(tlv_tree, "Source Address: " .. bytes_to_ipv4(value_range(7, 4)))
    elseif address_type == 0x02 and value_range:len() >= 23 then
        add_text(tlv_tree, "Source Address: " .. bytes_to_ipv6(value_range(7, 16)))
    end
end

local function decode_enum_byte(label, values)
    return function(value_range, tlv_tree)
        add_text(tlv_tree, label .. ": " .. enum_text(value_range(0, 1):uint(), values))
    end
end

local function decode_ipv4_value(label)
    return function(value_range, tlv_tree)
        add_text(tlv_tree, label .. ": " .. bytes_to_ipv4(value_range))
    end
end

local function decode_ipv6_value(label)
    return function(value_range, tlv_tree)
        add_text(tlv_tree, label .. ": " .. bytes_to_ipv6(value_range))
    end
end

local function decode_key_bytes(label)
    return function(value_range, tlv_tree)
        add_text(tlv_tree, string.format("%s (%u bytes)", label, value_range:len()))
    end
end

-- Decoders run only after the TLV length has been validated against tid_defs.
local tlv_decoders = {
    [0x0001] = decode_poll,
    [0x0002] = decode_poll_reply,
    [0x0003] = decode_set_reply,
    [0x0101] = function(value_range, tlv_tree)
        add_level_summary(tlv_tree, value_range, "Level")
    end,
    [0x0102] = function(value_range, tlv_tree, ctx)
        if value_range:len() == 1 then
            add_text(tlv_tree, string.format("Universe Priority (all slots): %u", value_range(0, 1):uint()))
        else
            add_level_summary(tlv_tree, value_range, "Priority")
        end
        check_priority_values(tlv_tree, value_range)
        if ctx.seen_level then
            add_expert(tlv_tree, experts.spec, "TID_PRIORITY shall be placed before TID_LEVEL in the same payload")
        end
    end,
    [0x0103] = function(value_range, tlv_tree)
        add_level_summary(tlv_tree, value_range, "Preview Level")
    end,
    [0x0201] = function(value_range, tlv_tree)
        add_text(tlv_tree, "SYNC trigger with no payload")
    end,
    [0x0202] = decode_timecode,
    [0x0203] = decode_universe,
    [0x0204] = function(value_range, tlv_tree)
        add_text(tlv_tree, "OSC Payload: " .. range_string(value_range))
    end,
    [0x0301] = function(value_range, tlv_tree, ctx)
        decode_rdm(value_range, tlv_tree, ctx, "RDM Command", true)
    end,
    [0x0302] = function(value_range, tlv_tree, ctx)
        decode_rdm(value_range, tlv_tree, ctx, "RDM Response", false)
    end,
    [0x0303] = decode_enum_byte("TOD Control", rdm_tod_control_vals),
    [0x0304] = decode_rdm_tod_data,
    [0x0305] = function(value_range, tlv_tree)
        local value = value_range(0, 1):uint()
        add_text(tlv_tree, "RDM Endpoint Config: " .. enum_text(value, rdm_ep_config_vals))
        add_bool_line(tlv_tree, "Enable Background Discovery", bit_state(value, 0x01))
        add_bool_line(tlv_tree, "Enable Background Queue Polling", bit_state(value, 0x02))
    end,
    [0x0306] = function(value_range, tlv_tree)
        local total = value_range(0, 1):uint()
        local available = value_range(1, 1):uint()
        add_text(tlv_tree, string.format("Total RDM FIFO Buffers: %u", total))
        add_text(tlv_tree, string.format("Available RDM FIFO Buffers: %u", available))
        if available > total then
            add_expert(tlv_tree, experts.spec, "Available FIFO buffers exceed the total")
        end
    end,
    [0x0401] = function(value_range, tlv_tree)
        add_text(tlv_tree, "Magic Word: " .. range_string(value_range))
        add_text(tlv_tree, string.format("Magic Word Hex: 0x%s", range_hex(value_range)))
        if value_range:uint() ~= 0x57495045 then
            add_expert(tlv_tree, experts.spec, "Magic word is not WIPE; the command will be ignored")
        end
    end,
    [0x0501] = function(value_range, tlv_tree)
        add_text(tlv_tree, "MAC Address: " .. format_tuid(value_range))
    end,
    [0x0502] = decode_enum_byte("IPv4 Mode", ipv4_mode_vals),
    [0x0503] = decode_ipv4_value("IPv4 Address"),
    [0x0504] = decode_ipv4_value("IPv4 Netmask"),
    [0x0505] = decode_ipv4_value("IPv4 Gateway"),
    [0x0506] = decode_ip_triplet,
    [0x0581] = decode_enum_byte("IPv6 Mode", ipv6_mode_vals),
    [0x0582] = decode_ipv6_value("IPv6 Address"),
    [0x0583] = function(value_range, tlv_tree)
        local prefix = value_range(0, 1):uint()
        add_text(tlv_tree, string.format("IPv6 Prefix Length: %u", prefix))
        if prefix > 128 then
            add_expert(tlv_tree, experts.spec, "IPv6 prefix length exceeds 128")
        end
    end,
    [0x0584] = decode_ipv6_value("IPv6 Gateway"),
    [0x0585] = decode_ipv6_current,
    [0x0601] = decode_supported_tids,
    [0x0602] = function(value_range, tlv_tree)
        add_text(tlv_tree, string.format("Endpoint Count: %u", value_range:uint()))
    end,
    [0x0603] = function(value_range, tlv_tree)
        add_text(tlv_tree, string.format("Protocol Version: %u", value_range(0, 1):uint()))
    end,
    [0x0604] = function(value_range, tlv_tree)
        add_text(tlv_tree, string.format("Machine Version ID: 0x%08X", value_range(0, 4):uint()))
        if value_range:len() > 4 then
            add_text(tlv_tree, "Human Version: " .. range_string(value_range(4, value_range:len() - 4)))
        end
    end,
    [0x0605] = function(value_range, tlv_tree)
        decode_encoded_label(value_range, tlv_tree, "Device Label")
    end,
    [0x0606] = decode_enum_byte("Routing State", rt_mult_vals),
    [0x0607] = decode_enum_byte("Identify State", identify_vals),
    [0x0608] = decode_rt_status,
    [0x0609] = decode_role_capability,
    [0x060A] = function(value_range, tlv_tree)
        local magic = range_string(value_range(1, 4))
        add_text(tlv_tree, "Reboot Type: " .. enum_text(value_range(0, 1):uint(), reboot_type_vals))
        add_text(tlv_tree, "Magic Word: " .. magic)
        if magic ~= "BOOT" then
            add_expert(tlv_tree, experts.spec, "Magic word is not BOOT; the command will be ignored")
        end
    end,
    [0x060B] = function(value_range, tlv_tree)
        decode_encoded_label(value_range, tlv_tree, "Model Name")
    end,
    [0x060D] = decode_otw_capability,
    [0x0901] = function(value_range, tlv_tree)
        local universe = value_range:uint()
        if universe == 0 then
            add_text(tlv_tree, "Universe: 0 (Not set)")
            return
        end
        add_text(tlv_tree, string.format("Universe: %u", universe))
        if universe > 63999 then
            add_expert(tlv_tree, experts.spec, "Universe outside the valid range 1-63999")
        end
    end,
    [0x0902] = function(value_range, tlv_tree)
        decode_encoded_label(value_range, tlv_tree, "Endpoint Label")
    end,
    [0x0903] = function(value_range, tlv_tree)
        local address = bytes_to_ipv4(value_range)
        if address == "0.0.0.0" then
            add_text(tlv_tree, "Multicast Override: 0.0.0.0 (Clear, use default folding)")
        else
            add_text(tlv_tree, "Multicast Override: " .. address)
        end
    end,
    [0x0904] = function(value_range, tlv_tree)
        if value_range:len() ~= 4 and value_range:len() ~= 6 then
            add_expert(tlv_tree, experts.malformed, string.format("TID_EP_CAPABILITY shall be 6 bytes (or legacy 4), found %u", value_range:len()))
            return
        end
        decode_endpoint_capability(value_range, tlv_tree)
    end,
    [0x0905] = decode_endpoint_direction,
    [0x0906] = function(value_range, tlv_tree)
        if value_range:len() == 1 then
            add_text(tlv_tree, string.format("Input Priority (all slots): %u", value_range(0, 1):uint()))
        else
            add_level_summary(tlv_tree, value_range, "Input Priority")
            add_text(tlv_tree, "Unaddressed slots default to 0")
        end
        check_priority_values(tlv_tree, value_range)
    end,
    [0x0907] = decode_endpoint_status,
    [0x0908] = function(value_range, tlv_tree)
        local mode = value_range(0, 1):uint()
        local scene = value_range(1, 2):uint()
        add_text(tlv_tree, "Failover Mode: " .. enum_text(mode, ep_failover_mode_vals))
        add_text(tlv_tree, string.format("Scene Number: %u%s", scene, mode ~= 0x03 and " (ignored)" or ""))
        if mode == 0x03 and scene == 0 then
            add_expert(tlv_tree, experts.spec, "Scene Number shall be 1-65535 when Mode is Play Scene")
        end
    end,
    [0x0909] = function(value_range, tlv_tree)
        add_text(tlv_tree, "Transmission Mode: " .. enum_text(value_range(0, 1):uint(), dmx_tx_mode_vals))
        add_text(tlv_tree, "Output Timing: " .. enum_text(value_range(1, 1):uint(), dmx_timing_vals))
    end,
    [0x090A] = function(value_range, tlv_tree)
        local fps = value_range(0, 1):uint()
        if fps <= 44 then
            add_text(tlv_tree, string.format("Max Refresh Capability: %u (standard DMX512, 44 fps)", fps))
        else
            add_text(tlv_tree, string.format("Max Refresh Capability: %u fps", fps))
        end
        if fps >= 251 then
            add_expert(tlv_tree, experts.spec, "Refresh capability value is in the reserved range (251-255)")
        end
    end,
    [0x090B] = decode_enum_byte("Endpoint Protocol", ep_protocol_vals),
    [0x090C] = decode_enum_byte("Endpoint Identify", ep_identify_vals),
    [0x7001] = decode_totw_come_home,
    [0x7002] = decode_key_bytes("Device Public Key"),
    [0x7003] = function(value_range, tlv_tree)
        add_text(tlv_tree, "TLS Session Fingerprint: 0x" .. range_hex(value_range))
    end,
    [0x7004] = decode_key_bytes("Ks Key"),
    [0x7005] = decode_key_bytes("Kc Key"),
    [0x7006] = decode_key_bytes("Km_global Key"),
    [0x7007] = decode_key_bytes("Km_local Key"),
    [0x7008] = decode_key_bytes("K0 Key"),
    [0x7009] = function(value_range, tlv_tree)
        local form = (value_range:len() == 65 and value_range(0, 1):uint() == 0x04) and "raw uncompressed" or "DER"
        add_text(tlv_tree, string.format("POM Public Key (%u bytes, %s)", value_range:len(), form))
    end,
    [0x700A] = function(value_range, tlv_tree)
        add_text(tlv_tree, "Target TUID: " .. format_tuid(value_range(0, 6)))
        add_text(tlv_tree, "Nonce: 0x" .. range_hex(value_range(6, 8)))
        add_text(tlv_tree, "Signature (64 bytes): 0x" .. range_hex(value_range(14, 64)))
    end,
    [0x700B] = decode_totw_otw_reopen,
    [0x700C] = function(value_range, tlv_tree)
        local form = value_range:len() == 64 and "raw secp256r1" or "DER"
        add_text(tlv_tree, string.format("Updated POM Public Key (%u bytes, %s)", value_range:len(), form))
    end,
    [0x700D] = function(value_range, tlv_tree)
        add_text(tlv_tree, "Scope Name: " .. range_string(value_range))
    end,
    [0xFF01] = decode_security_event,
    [0xFF02] = function(value_range, tlv_tree)
        add_text(tlv_tree, "Diagnostic Message: " .. range_string(value_range))
    end,
    [0xFF03] = function(value_range, tlv_tree)
        add_level_summary(tlv_tree, value_range, "Level Foldback")
    end
}

-- Applies the Appendix C length rules. Returns true when the value should be decoded.
local function validate_tlv_length(tid, length, tlv_tree, ctx)
    local info = tid_info[tid]
    if not info then
        return true
    end

    if length == 0 then
        if info.queryable then
            if ctx.lane == "node" then
                add_expert(tlv_tree, experts.spec, "Zero-length reply is not permitted on the Reply URI")
            else
                add_text(tlv_tree, "Parameter Query (GET, zero-length payload)")
            end
            return false
        end
        if info.min == 0 then
            return true
        end
        add_expert(tlv_tree, experts.malformed, info.name .. " is not queryable and shall not have a zero length")
        return false
    end

    if info.legacy[length] then
        return true
    end

    if length < info.min or length > info.max then
        local expected = (info.min == info.max) and tostring(info.min) or string.format("%u-%u", info.min, info.max)
        add_expert(tlv_tree, experts.malformed, string.format("%s length %u is invalid (expected %s)", info.name, length, expected))
        return false
    end

    return true
end

local function decode_tlvs(payload_range, sig_tree, ctx, coap_tvb, payload_abs_start)
    if not payload_range or payload_range:len() == 0 then
        add_text(sig_tree, "No application payload")
        return
    end

    sig_tree:add(fields.payload, payload_range)

    local tlv_root = sig_tree:add(sig_net, payload_range, string.format("TLVs (%u bytes)", payload_range:len()))
    local tids_present = {}
    local tids_seen = {}

    local function add_tids_summary()
        if not coap_tvb or payload_abs_start == nil then
            return
        end

        local tids_str = (#tids_present > 0) and table.concat(tids_present, ", ") or "None"
        sig_tree:add(fields.tids_list, coap_tvb(payload_abs_start, payload_range:len()), tids_str)
    end

    local offset = 0
    local index = 1

    while offset < payload_range:len() do
        if payload_range:len() - offset < 4 then
            add_expert(tlv_root, experts.malformed, string.format("Trailing %u byte(s) do not form a complete TLV header", payload_range:len() - offset))
            add_tids_summary()
            return
        end

        local abs_offset = payload_abs_start + offset
        local tid_range = coap_tvb(abs_offset, 2)
        local length_range = coap_tvb(abs_offset + 2, 2)
        local tid = tid_range:uint()
        local length = length_range:uint()
        local total = 4 + length

        if offset + total > payload_range:len() then
            add_expert(tlv_root, experts.malformed, string.format("Malformed TLV at index %u: length %u exceeds remaining payload", index, length))
            add_tids_summary()
            return
        end

        local full_range = coap_tvb(abs_offset, total)
        local value_range = (length > 0) and coap_tvb(abs_offset + 4, length) or tid_range(0, 0)
        local name = tid_names[tid] or (is_manufacturer_tid(tid) and "Manufacturer-Specific TID" or "Unknown TID")
        if not tids_seen[name] then
            tids_seen[name] = true
            tids_present[#tids_present + 1] = name
        end

        local tlv_tree = tlv_root:add(sig_net, full_range, string.format("%u: %s (0x%04X), Length %u", index, name, tid, length))
        tlv_tree:add(fields.tid, tid_range)
        tlv_tree:add(fields.length, length_range)
        if length > 0 then
            tlv_tree:add(fields.value, value_range)
        end

        if is_manufacturer_tid(tid) and ctx.mfg_code == 0 then
            add_expert(tlv_tree, experts.spec, "Manufacturer-specific TID with Sig-Net Manufacturer Code 0x0000")
        end

        ctx.is_last_tlv = (offset + total == payload_range:len())

        local decoder = tlv_decoders[tid]
        if decoder then
            if validate_tlv_length(tid, length, tlv_tree, ctx) then
                decoder(value_range, tlv_tree, ctx)
            end
        elseif not is_manufacturer_tid(tid) then
            add_text(tlv_tree, "No dedicated dissector for this TID. Raw value shown above.")
        end

        if tid == 0x0101 then
            ctx.seen_level = true
        end

        offset = offset + total
        index = index + 1
    end

    add_tids_summary()
end

local function normalize_field_to_range(field_info)
    if not field_info then
        return nil
    end

    local ok, range = pcall(function()
        return field_info.range
    end)
    if ok and range then
        return range
    end

    if type(field_info.len) == "function" and type(field_info.uint) ~= "function" then
        return field_info
    end

    return nil
end

local function get_payload_range()
    local candidates = { udp_payload_field(), tcp_payload_field(), data_data_field() }
    for _, field_info in ipairs(candidates) do
        local range = normalize_field_to_range(field_info)
        if range then
            return range
        end
    end
    return nil
end

local function looks_like_raw_tlv_payload(payload_range)
    if not payload_range or payload_range:len() < 4 then
        return false
    end

    local tid = payload_range(0, 2):uint()
    local len = payload_range(2, 2):uint()
    if 4 + len > payload_range:len() then
        return false
    end

    return (tid >= 0x7000 and tid <= 0x70FF) or tid_names[tid] ~= nil
end

local function decode_raw_tlv_fallback(payload_range, pinfo, tree)
    if not looks_like_raw_tlv_payload(payload_range) then
        return false
    end

    pinfo.cols.protocol = "SIG-NET"
    local sig_tree = tree:add(sig_net, payload_range, "Sig-Net / SNOW Raw TLV Payload")
    local ctx = {
        pinfo = pinfo,
        uri = "",
        uri_segments = {},
        lane = "",
        mfg_code = 0
    }
    decode_tlvs(payload_range, sig_tree, ctx, payload_range, 0)
    return true
end

local function add_security_options(sig_tree, parsed)
    local mode_opt = find_option(parsed, 2076)
    local sender_opt = find_option(parsed, 2108)
    local mfg_opt = find_option(parsed, 2140)
    local session_opt = find_option(parsed, 2172)
    local seq_opt = find_option(parsed, 2204)
    local auth_opt = find_option(parsed, 2236)

    local mode = nil
    if mode_opt and mode_opt.length <= 1 then
        mode = range_uint(mode_opt.value)
        sig_tree:add(fields.security_mode, mode_opt.value, mode)
    else
        add_expert(sig_tree, experts.malformed, "Security Mode option missing or invalid")
    end

    if sender_opt then
        sig_tree:add(fields.sender_id, sender_opt.value)
        if sender_opt.length == 8 then
            sig_tree:add(fields.sender_tuid, sender_opt.value(0, 6), format_tuid(sender_opt.value(0, 6)))
            sig_tree:add(fields.sender_endpoint, sender_opt.value(6, 2))
        end
    else
        add_expert(sig_tree, experts.malformed, "Sender ID option missing")
    end

    local mfg_code = 0
    if mfg_opt and mfg_opt.length <= 2 then
        mfg_code = range_uint(mfg_opt.value)
        sig_tree:add(fields.mfg_code, mfg_opt.value, mfg_code)
    else
        add_expert(sig_tree, experts.malformed, "Manufacturer Code option missing or invalid")
    end

    local session_id = nil
    if session_opt and session_opt.length <= 4 then
        session_id = range_uint(session_opt.value)
        sig_tree:add(fields.session_id, session_opt.value, session_id)
    else
        add_expert(sig_tree, experts.malformed, "Session ID option missing or invalid")
    end

    local seq_num = nil
    if seq_opt and seq_opt.length <= 4 then
        seq_num = range_uint(seq_opt.value)
        sig_tree:add(fields.seq_num, seq_opt.value, seq_num)
    else
        add_expert(sig_tree, experts.malformed, "Sequence Number option missing or invalid")
    end

    if auth_opt then
        local auth_item = sig_tree:add(fields.hmac, auth_opt.value)
        if mode == 0x00 and auth_opt.length ~= 32 then
            add_expert(auth_item, experts.spec, string.format("Mode 0x00 requires a 32-byte HMAC-SHA256, found %u bytes", auth_opt.length))
        elseif (mode == 0x01 or mode == 0xFF) and auth_opt.length ~= 0 then
            add_expert(auth_item, experts.spec, string.format("Mode 0x%02X requires a zero-length Auth option, found %u bytes", mode, auth_opt.length))
        end
    elseif mode == 0xFF then
        add_text(sig_tree, "Auth option omitted (permitted for Offboarded Beacon)")
    else
        add_expert(sig_tree, experts.malformed, "Sig-Net-Auth option missing")
    end

    if (mode == 0x01 or mode == 0xFF) and ((session_id or 0) ~= 0 or (seq_num or 0) ~= 0) then
        add_expert(sig_tree, experts.spec, "Open Mode and Beacon Mode shall transmit Session ID and Sequence Number as 0")
    elseif mode == 0x00 and seq_num == 0 then
        add_expert(sig_tree, experts.spec, "Sequence Number 0 is not valid for authenticated packets")
    end

    return mode, mfg_code, sender_opt
end

function sig_net.dissector(tvb, pinfo, tree)
    local coap_tvb = get_payload_range()
    if not coap_tvb then
        return
    end

    local parsed, err = parse_coap_packet(coap_tvb)
    if not parsed then
        decode_raw_tlv_fallback(coap_tvb, pinfo, tree)
        return
    end

    local has_sig_net = false
    for _, segment in ipairs(parsed.uri_segments) do
        if segment:lower():find("sig%-net", 1, false) then
            has_sig_net = true
            break
        end
    end
    if not has_sig_net then
        decode_raw_tlv_fallback(coap_tvb, pinfo, tree)
        return
    end

    local uri_version = parsed.uri_segments[2] or ""
    local uri_scope = parsed.uri_segments[3] or ""
    local uri_resource = (#parsed.uri_segments >= 4) and table.concat(parsed.uri_segments, "/", 4) or ""

    local summary = parsed.uri
    if uri_resource ~= "" then
        summary = uri_resource
    end

    local info_text = tostring(pinfo.cols.info)
    if not info_text:find("Sig-Net " .. summary, 1, true) then
        pinfo.cols.info:append(" [Sig-Net " .. summary .. "]")
    end
    pinfo.cols.protocol = "SIG-NET"

    local sig_tree = tree:add(sig_net, coap_tvb, "Sig-Net")
    sig_tree:add(fields.coap_version, coap_tvb(0, 1))
    sig_tree:add(fields.coap_type, coap_tvb(0, 1))
    sig_tree:add(fields.coap_tkl, coap_tvb(0, 1))
    sig_tree:add(fields.coap_code, coap_tvb(1, 1))
    sig_tree:add(fields.coap_message_id, coap_tvb(2, 2))
    sig_tree:add(fields.uri, parsed.uri)
    sig_tree:add(fields.uri_version, uri_version)
    sig_tree:add(fields.uri_scope, uri_scope)
    sig_tree:add(fields.uri_resource, uri_resource)

    if parsed.type ~= 1 or parsed.code ~= 0x02 then
        add_expert(sig_tree, experts.spec, "Sig-Net uses CoAP Non-Confirmable POST messages only")
    end
    if #uri_scope < 1 or #uri_scope > 32 then
        add_expert(sig_tree, experts.spec, "Scope shall be 1 to 32 characters")
    end

    local uri_info = add_uri_tree(sig_tree, parsed)
    local mode, mfg_code, sender_opt = add_security_options(sig_tree, parsed)

    add_text(sig_tree, string.format("CoAP Header: ver=%u, type=%s, code=0x%02X, message_id=0x%04X", parsed.version, coap_type_vals[parsed.type] or "Unknown", parsed.code, parsed.message_id))
    add_text(sig_tree, string.format("URI Path: %s", parsed.uri))
    add_sig_net_option_tree(sig_tree, parsed)

    if sender_opt then
        add_text(sig_tree, "Sender ID Summary: " .. format_sender_id(sender_opt.value))
    end
    if mode then
        add_text(sig_tree, "Security Mode Summary: " .. enum_text(mode, security_mode_vals))
    end

    local ctx = {
        pinfo = pinfo,
        uri = parsed.uri,
        uri_segments = parsed.uri_segments,
        lane = uri_info.lane,
        mfg_code = mfg_code
    }

    decode_tlvs(parsed.payload, sig_tree, ctx, coap_tvb, parsed.offset_after_options)
end

register_postdissector(sig_net)
