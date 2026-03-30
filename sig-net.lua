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
-- Date:         March 28, 2026
-- Prot Version: v0.12
-- Description:  Wireshark post-dissector for Sig-Net carried over CoAP.
--               Reparses URI-Path and Sig-Net custom options in the private
--               use range (2048-64999), decodes TLV payloads, and forwards
--               embedded RDM TLVs to Wireshark's built-in RDM dissector. 
--==============================================================================

local sig_net = Proto("SigNet", "Sig-Net")

if set_plugin_info then
    set_plugin_info({
        version = "1.0.0",
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

local coap_uri_path_field = Field.new("coap.opt.uri_path")
local udp_payload_field = Field.new("udp.payload")

local coap_type_vals = {
    [0] = "Confirmable",
    [1] = "Non-Confirmable",
    [2] = "Acknowledgement",
    [3] = "Reset"
}

local security_mode_vals = {
    [0x00] = "Plaintext payload with HMAC-SHA256",
    [0xFF] = "Unprovisioned beacon"
}

local query_level_vals = {
    [0x00] = "QUERY_HEARTBEAT",
    [0x01] = "QUERY_CONFIG",
    [0x02] = "QUERY_FULL",
    [0x03] = "QUERY_EXTENDED"
}

local timecode_type_vals = {
    [0] = "Film (24 fps)",
    [1] = "EBU (25 fps)",
    [2] = "Drop Frame (29.97 fps)",
    [3] = "SMPTE (30 fps)"
}

local rdm_tod_control_vals = {
    [0x00] = "Force node to send TID_RDM_TOD_DATA",
    [0x01] = "Flush ToD and force full discovery"
}

local rdm_tod_background_vals = {
    [0x00] = "Disable background RDM discovery",
    [0x01] = "Enable background RDM discovery"
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
    [0x01] = "On"
}

local ep_direction_vals = {
    [0x00] = "Disabled",
    [0x01] = "Consumer",
    [0x02] = "Supplier"
}

local address_type_vals = {
    [0x00] = "None",
    [0x01] = "IPv4",
    [0x02] = "IPv6"
}

local security_event_vals = {
    [0x0001] = "HMAC Verification Failure",
    [0x0002] = "Replay Attack Detected",
    [0x0003] = "DoS Rate-Limiting Activated",
    [0x0004] = "Unauthorised Provisioning Attempt"
}

local sig_net_option_names = {
    [2076] = "Sig-Net-Security-Mode",
    [2108] = "Sig-Net-Sender-ID",
    [2140] = "Sig-Net-Mfg-Code",
    [2172] = "Sig-Net-Session-ID",
    [2204] = "Sig-Net-Seq-Num",
    [2236] = "Sig-Net-HMAC"
}

local tid_names = {
    [0x0001] = "TID_POLL",
    [0x0002] = "TID_POLL_REPLY",
    [0x0101] = "TID_LEVEL",
    [0x0102] = "TID_PRIORITY",
    [0x0201] = "TID_SYNC",
    [0x0202] = "TID_TIMECODE",
    [0x0301] = "TID_RDM_COMMAND",
    [0x0302] = "TID_RDM_RESPONSE",
    [0x0303] = "TID_RDM_TOD_CONTROL",
    [0x0304] = "TID_RDM_TOD_DATA",
    [0x0305] = "TID_RDM_TOD_BACKGROUND",
    [0x0401] = "TID_RT_UNPROVISION",
    [0x0501] = "TID_NW_MAC_ADDRESS",
    [0x0502] = "TID_NW_IPV4_MODE",
    [0x0503] = "TID_NW_IPV4_ADDRESS",
    [0x0504] = "TID_NW_IPV4_NETMASK",
    [0x0505] = "TID_NW_IPV4_GATEWAY",
    [0x0506] = "TID_NW_IPV4_CURRENT",
    [0x0581] = "TID_NW_IPV6_MODE",
    [0x0582] = "TID_NW_IPV6_ADDRESS",
    [0x0583] = "TID_NW_IPV6_PREFIX",
    [0x0584] = "TID_NW_IPV6_GATEWAY",
    [0x0585] = "TID_NW_IPV6_CURRENT",
    [0x0601] = "TID_RT_SUPPORTED_TIDS",
    [0x0602] = "TID_RT_ENDPOINT_COUNT",
    [0x0603] = "TID_RT_PROTOCOL_VERSION",
    [0x0604] = "TID_RT_FIRMWARE_VERSION",
    [0x0605] = "TID_RT_DEVICE_LABEL",
    [0x0606] = "TID_RT_MULT",
    [0x0607] = "TID_RT_IDENTIFY",
    [0x0608] = "TID_RT_STATUS",
    [0x0609] = "TID_RT_ROLE_CAPABILITY",
    [0x0901] = "TID_EP_UNIVERSE",
    [0x0902] = "TID_EP_LABEL",
    [0x0903] = "TID_EP_MULT_OVERRIDE",
    [0x0904] = "TID_EP_DIRECTION_CAPABILITY",
    [0x0905] = "TID_EP_DIRECTION",
    [0x0906] = "TID_EP_INPUT_PRIORITY",
    [0x0907] = "TID_EP_STATUS",
    [0xFF01] = "TID_DG_SECURITY_EVENT",
    [0xFF02] = "TID_DG_MESSAGE",
    [0xFF03] = "TID_DG_LEVEL_FOLDBACK"
}

local fields = {
    coap_version = ProtoField.uint8("SigNet.coap.version", "CoAP Version", base.DEC, nil, 0xC0),
    coap_type = ProtoField.uint8("SigNet.coap.type", "CoAP Type", base.DEC, coap_type_vals, 0x30),
    coap_tkl = ProtoField.uint8("SigNet.coap.tkl", "Token Length", base.DEC, nil, 0x0F),
    coap_code = ProtoField.uint8("SigNet.coap.code", "CoAP Code", base.HEX),
    coap_message_id = ProtoField.uint16("SigNet.coap.message_id", "CoAP Message ID", base.HEX),
    uri = ProtoField.string("SigNet.uri", "Sig-Net URI"),
    uri_version = ProtoField.string("SigNet.uri.version", "Sig-Net Version"),
    uri_resource = ProtoField.string("SigNet.uri.resource", "Sig-Net Resource"),
    security_mode = ProtoField.uint8("SigNet.security_mode", "Security Mode", base.HEX, security_mode_vals),
    sender_id = ProtoField.bytes("SigNet.sender_id", "Sender ID"),
    sender_tuid = ProtoField.string("SigNet.sender_tuid", "Sender TUID"),
    sender_endpoint = ProtoField.uint16("SigNet.sender_endpoint", "Sender Endpoint", base.DEC),
    mfg_code = ProtoField.uint16("SigNet.mfg_code", "Manufacturer Code", base.HEX),
    session_id = ProtoField.uint32("SigNet.session_id", "Session ID", base.HEX),
    seq_num = ProtoField.uint32("SigNet.seq_num", "Sequence Number", base.DEC),
    hmac = ProtoField.bytes("SigNet.hmac", "HMAC"),
    option_number = ProtoField.uint16("SigNet.option.number", "Option Number", base.DEC, sig_net_option_names),
    option_length = ProtoField.uint16("SigNet.option.length", "Option Length", base.DEC),
    option_value = ProtoField.bytes("SigNet.option.value", "Option Value"),
    payload = ProtoField.bytes("SigNet.payload", "Payload"),
    tid = ProtoField.uint16("SigNet.tlv.tid", "TID", base.HEX, tid_names),
    length = ProtoField.uint16("SigNet.tlv.length", "Length", base.DEC),
    value = ProtoField.bytes("SigNet.tlv.value", "Value")
}

sig_net.fields = fields

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
    return value:gsub("[%z\1-\31\127]", ".")
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
    if range:len() ~= 6 then
        return range_hex(range)
    end
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

        local value_range = tvb(offset, length)
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

local function option_value(parsed, option_number)
    for _, option in ipairs(parsed.options) do
        if option.number == option_number then
            return option.value
        end
    end
    return nil
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

            if option.number == 2076 and option.length >= 1 then
                add_text(item, "Decoded: " .. enum_text(option.value(0, 1):uint(), security_mode_vals))
            elseif option.number == 2108 and option.length >= 8 then
                add_text(item, "Decoded: " .. format_sender_id(option.value))
            elseif option.number == 2140 and option.length >= 2 then
                add_text(item, string.format("Decoded: 0x%04X", option.value:uint()))
            elseif option.number == 2172 and option.length >= 4 then
                add_text(item, string.format("Decoded: 0x%08X", option.value:uint()))
            elseif option.number == 2204 and option.length >= 4 then
                add_text(item, string.format("Decoded: %u", option.value:uint()))
            elseif option.number == 2236 then
                add_text(item, "Decoded: " .. range_hex(option.value))
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

local function decode_poll(value_range, tlv_tree)
    if value_range:len() ~= 25 then
        add_text(tlv_tree, string.format("Unexpected length for TID_POLL: %u", value_range:len()))
        return
    end

    add_text(tlv_tree, "Manager TUID: " .. format_tuid(value_range(0, 6)))
    add_text(tlv_tree, string.format("Manager SoemCode: 0x%08X", value_range(6, 4):uint()))
    add_text(tlv_tree, "TUID Low: " .. format_tuid(value_range(10, 6)))
    add_text(tlv_tree, "TUID High: " .. format_tuid(value_range(16, 6)))
    add_text(tlv_tree, string.format("Endpoint: %u", value_range(22, 2):uint()))
    add_text(tlv_tree, "Query Level: " .. enum_text(value_range(24, 1):uint(), query_level_vals))
end

local function decode_poll_reply(value_range, tlv_tree)
    if value_range:len() ~= 12 then
        add_text(tlv_tree, string.format("Unexpected length for TID_POLL_REPLY: %u", value_range:len()))
        return
    end

    add_text(tlv_tree, "TUID: " .. format_tuid(value_range(0, 6)))
    add_text(tlv_tree, string.format("SoemCode: 0x%08X", value_range(6, 4):uint()))
    add_text(tlv_tree, string.format("CHANGE_COUNT: %u", value_range(10, 2):uint()))
end

local function decode_timecode(value_range, tlv_tree)
    if value_range:len() ~= 5 then
        add_text(tlv_tree, string.format("Unexpected length for TID_TIMECODE: %u", value_range:len()))
        return
    end

    local hours = value_range(0, 1):uint()
    local minutes = value_range(1, 1):uint()
    local seconds = value_range(2, 1):uint()
    local frames = value_range(3, 1):uint()
    local frame_type = value_range(4, 1):uint()

    add_text(tlv_tree, string.format("Timecode: %02u:%02u:%02u:%02u", hours, minutes, seconds, frames))
    add_text(tlv_tree, "Type: " .. enum_text(frame_type, timecode_type_vals))
end

local function decode_uid_array(value_range, tlv_tree, label)
    if value_range:len() == 0 then
        add_text(tlv_tree, label .. ": empty")
        return
    end

    if value_range:len() % 6 ~= 0 then
        add_text(tlv_tree, string.format("%s length is not a multiple of 6", label))
    end

    local count = math.floor(value_range:len() / 6)
    add_text(tlv_tree, string.format("%s count: %u", label, count))
    for index = 0, count - 1 do
        add_text(tlv_tree, string.format("%s[%u]: %s", label, index + 1, format_tuid(value_range(index * 6, 6))))
    end
end

local function call_rdm_dissector(value_range, pinfo, tlv_tree)
    local dissector = get_rdm_dissector()
    if not dissector then
        add_text(tlv_tree, "Embedded RDM dissector not found. Raw RDM bytes shown only.")
        return
    end

    add_text(tlv_tree, "Embedded RDM dissector: " .. rdm_dissector_name)

    local ok = pcall(function()
        dissector:call(value_range:tvb(), pinfo, tlv_tree)
    end)

    if ok then
        return
    end

    local second_ok = pcall(function()
        local byte_array = ByteArray.new(range_hex(value_range))
        dissector:call(byte_array:tvb("Sig-Net Embedded RDM"), pinfo, tlv_tree)
    end)

    if not second_ok then
        add_text(tlv_tree, "Embedded RDM dissector could not be invoked. Raw RDM bytes shown only.")
    end
end

local function decode_ip_triplet(value_range, tlv_tree)
    if value_range:len() ~= 12 then
        add_text(tlv_tree, string.format("Unexpected IPv4 triplet length: %u", value_range:len()))
        return
    end
    add_text(tlv_tree, "IPv4 Address: " .. bytes_to_ipv4(value_range(0, 4)))
    add_text(tlv_tree, "IPv4 Netmask: " .. bytes_to_ipv4(value_range(4, 4)))
    add_text(tlv_tree, "IPv4 Gateway: " .. bytes_to_ipv4(value_range(8, 4)))
end

local function decode_ipv6_current(value_range, tlv_tree)
    if value_range:len() ~= 33 then
        add_text(tlv_tree, string.format("Unexpected IPv6 current length: %u", value_range:len()))
        return
    end
    add_text(tlv_tree, "IPv6 Address: " .. bytes_to_ipv6(value_range(0, 16)))
    add_text(tlv_tree, string.format("Prefix Length: %u", value_range(16, 1):uint()))
    add_text(tlv_tree, "IPv6 Gateway: " .. bytes_to_ipv6(value_range(17, 16)))
end

local function decode_supported_tids(value_range, tlv_tree)
    if value_range:len() == 0 then
        add_text(tlv_tree, "Supported TIDs: empty")
        return
    end

    if value_range:len() % 2 ~= 0 then
        add_text(tlv_tree, string.format("Supported TID array length %u is not a multiple of 2", value_range:len()))
    end

    local count = math.floor(value_range:len() / 2)
    add_text(tlv_tree, string.format("Supported TIDs: %u", count))
    for index = 0, count - 1 do
        local tid = value_range(index * 2, 2):uint()
        add_text(tlv_tree, string.format("Supported[%u]: %s (0x%04X)", index + 1, tid_names[tid] or "Unknown", tid))
    end
end

local function decode_rt_status(value_range, tlv_tree)
    if value_range:len() ~= 4 then
        add_text(tlv_tree, string.format("Unexpected status bitfield length: %u", value_range:len()))
        return
    end

    local value = value_range:uint()
    add_text(tlv_tree, string.format("Status Bitfield: 0x%08X", value))
    add_bool_line(tlv_tree, "Hardware Fault", bit_state(value, 0x00000001))
    add_bool_line(tlv_tree, "Booted from Factory Defaults", bit_state(value, 0x00000002))
    add_bool_line(tlv_tree, "Configuration Locked via Local UI", bit_state(value, 0x00000004))
end

local function decode_role_capability(value_range, tlv_tree)
    if value_range:len() ~= 1 then
        add_text(tlv_tree, string.format("Unexpected role capability length: %u", value_range:len()))
        return
    end

    local value = value_range(0, 1):uint()
    add_text(tlv_tree, string.format("Role Capability Bitfield: 0x%02X", value))
    add_bool_line(tlv_tree, "Node Role Supported", bit_state(value, 0x01))
    add_bool_line(tlv_tree, "Sender Role Supported", bit_state(value, 0x02))
    add_bool_line(tlv_tree, "Manager Role Supported", bit_state(value, 0x04))
end

local function decode_endpoint_direction_capability(value_range, tlv_tree)
    if value_range:len() ~= 1 then
        add_text(tlv_tree, string.format("Unexpected direction capability length: %u", value_range:len()))
        return
    end

    local value = value_range(0, 1):uint()
    add_text(tlv_tree, string.format("Direction Capability Bitfield: 0x%02X", value))
    add_bool_line(tlv_tree, "Can Consume TID_LEVEL", bit_state(value, 0x01))
    add_bool_line(tlv_tree, "Can Supply TID_LEVEL", bit_state(value, 0x02))
    add_bool_line(tlv_tree, "Can Consume RDM", bit_state(value, 0x04))
    add_bool_line(tlv_tree, "Can Supply RDM", bit_state(value, 0x08))
end

local function decode_endpoint_status(value_range, tlv_tree)
    if value_range:len() ~= 4 then
        add_text(tlv_tree, string.format("Unexpected endpoint status length: %u", value_range:len()))
        return
    end

    local value = value_range:uint()
    add_text(tlv_tree, string.format("Endpoint Status Bitfield: 0x%08X", value))
    add_bool_line(tlv_tree, "Data Activity", bit_state(value, 0x00000001))
    add_bool_line(tlv_tree, "Hardware Fault", bit_state(value, 0x00000002))
    add_bool_line(tlv_tree, "Configuration Locked via Local UI", bit_state(value, 0x00000004))
end

local function decode_security_event(value_range, tlv_tree)
    if value_range:len() < 7 then
        add_text(tlv_tree, string.format("Unexpected security event length: %u", value_range:len()))
        return
    end

    local event_code = value_range(0, 2):uint()
    local event_counter = value_range(2, 4):uint()
    local address_type = value_range(6, 1):uint()

    add_text(tlv_tree, "Event Code: " .. enum_text(event_code, security_event_vals))
    add_text(tlv_tree, string.format("Event Counter: %u", event_counter))
    add_text(tlv_tree, "Address Type: " .. enum_text(address_type, address_type_vals))

    if address_type == 0x01 and value_range:len() >= 11 then
        add_text(tlv_tree, "Source Address: " .. bytes_to_ipv4(value_range(7, 4)))
    elseif address_type == 0x02 and value_range:len() >= 23 then
        add_text(tlv_tree, "Source Address: " .. bytes_to_ipv6(value_range(7, 16)))
    elseif address_type ~= 0x00 then
        add_text(tlv_tree, "Source Address: truncated")
    end
end

local tlv_decoders = {
    [0x0001] = decode_poll,
    [0x0002] = decode_poll_reply,
    [0x0101] = function(value_range, tlv_tree)
        add_level_summary(tlv_tree, value_range, "Level")
    end,
    [0x0102] = function(value_range, tlv_tree)
        if value_range:len() == 1 then
            add_text(tlv_tree, string.format("Universe Priority: %u", value_range(0, 1):uint()))
        else
            add_level_summary(tlv_tree, value_range, "Priority")
            add_text(tlv_tree, "Unspecified slots default to 100")
        end
    end,
    [0x0201] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "SYNC trigger with no payload")
        else
            add_text(tlv_tree, string.format("Unexpected non-zero sync payload length: %u", value_range:len()))
        end
    end,
    [0x0202] = decode_timecode,
    [0x0301] = function(value_range, tlv_tree, ctx)
        add_text(tlv_tree, string.format("RDM Command Length: %u", value_range:len()))
        call_rdm_dissector(value_range, ctx.pinfo, tlv_tree)
    end,
    [0x0302] = function(value_range, tlv_tree, ctx)
        add_text(tlv_tree, string.format("RDM Response Length: %u", value_range:len()))
        call_rdm_dissector(value_range, ctx.pinfo, tlv_tree)
    end,
    [0x0303] = function(value_range, tlv_tree)
        if value_range:len() ~= 1 then
            add_text(tlv_tree, string.format("Unexpected TOD control length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, "TOD Control: " .. enum_text(value_range(0, 1):uint(), rdm_tod_control_vals))
    end,
    [0x0304] = function(value_range, tlv_tree)
        decode_uid_array(value_range, tlv_tree, "RDM UID")
    end,
    [0x0305] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        if value_range:len() ~= 1 then
            add_text(tlv_tree, string.format("Unexpected TOD background length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, "Background TOD: " .. enum_text(value_range(0, 1):uint(), rdm_tod_background_vals))
    end,
    [0x0401] = function(value_range, tlv_tree)
        if value_range:len() ~= 4 then
            add_text(tlv_tree, string.format("Unexpected unprovision length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, "Magic Word: " .. range_string(value_range))
        add_text(tlv_tree, string.format("Magic Word Hex: 0x%s", range_hex(value_range)))
    end,
    [0x0501] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        if value_range:len() ~= 6 then
            add_text(tlv_tree, string.format("Unexpected MAC address length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, "MAC Address: " .. format_tuid(value_range))
    end,
    [0x0502] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "IPv4 Mode: " .. enum_text(value_range(0, 1):uint(), ipv4_mode_vals))
    end,
    [0x0503] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "IPv4 Address: " .. bytes_to_ipv4(value_range))
    end,
    [0x0504] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "IPv4 Netmask: " .. bytes_to_ipv4(value_range))
    end,
    [0x0505] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "IPv4 Gateway: " .. bytes_to_ipv4(value_range))
    end,
    [0x0506] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        decode_ip_triplet(value_range, tlv_tree)
    end,
    [0x0581] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "IPv6 Mode: " .. enum_text(value_range(0, 1):uint(), ipv6_mode_vals))
    end,
    [0x0582] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "IPv6 Address: " .. bytes_to_ipv6(value_range))
    end,
    [0x0583] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, string.format("IPv6 Prefix Length: %u", value_range(0, 1):uint()))
    end,
    [0x0584] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "IPv6 Gateway: " .. bytes_to_ipv6(value_range))
    end,
    [0x0585] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        decode_ipv6_current(value_range, tlv_tree)
    end,
    [0x0601] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        decode_supported_tids(value_range, tlv_tree)
    end,
    [0x0602] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        if value_range:len() ~= 2 then
            add_text(tlv_tree, string.format("Unexpected endpoint count length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, string.format("Endpoint Count: %u", value_range:uint()))
    end,
    [0x0603] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        if value_range:len() ~= 1 then
            add_text(tlv_tree, string.format("Unexpected protocol version length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, string.format("Protocol Version: %u", value_range(0, 1):uint()))
    end,
    [0x0604] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        if value_range:len() < 4 then
            add_text(tlv_tree, string.format("Unexpected firmware version length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, string.format("Machine Version ID: 0x%08X", value_range(0, 4):uint()))
        if value_range:len() > 4 then
            add_text(tlv_tree, "Human Version: " .. range_string(value_range(4, value_range:len() - 4)))
        end
    end,
    [0x0605] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "Device Label: " .. range_string(value_range))
    end,
    [0x0606] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        if value_range:len() ~= 1 then
            add_text(tlv_tree, string.format("Unexpected RT_MULT length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, "Routing State: " .. enum_text(value_range(0, 1):uint(), rt_mult_vals))
    end,
    [0x0607] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        if value_range:len() ~= 1 then
            add_text(tlv_tree, string.format("Unexpected identify length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, "Identify State: " .. enum_text(value_range(0, 1):uint(), identify_vals))
    end,
    [0x0608] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        decode_rt_status(value_range, tlv_tree)
    end,
    [0x0609] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        decode_role_capability(value_range, tlv_tree)
    end,
    [0x0901] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        if value_range:len() ~= 2 then
            add_text(tlv_tree, string.format("Unexpected universe length: %u", value_range:len()))
            return
        end
        add_text(tlv_tree, string.format("Universe: %u", value_range:uint()))
    end,
    [0x0902] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "Endpoint Label: " .. range_string(value_range))
    end,
    [0x0903] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "Multicast Override: " .. bytes_to_ipv4(value_range))
    end,
    [0x0904] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        decode_endpoint_direction_capability(value_range, tlv_tree)
    end,
    [0x0905] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_text(tlv_tree, "Endpoint Direction: " .. enum_text(value_range(0, 1):uint(), ep_direction_vals))
    end,
    [0x0906] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        if value_range:len() == 1 then
            add_text(tlv_tree, string.format("Input Priority (all slots): %u", value_range(0, 1):uint()))
        else
            add_level_summary(tlv_tree, value_range, "Input Priority")
            add_text(tlv_tree, "Unspecified slots default to 100")
        end
    end,
    [0x0907] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        decode_endpoint_status(value_range, tlv_tree)
    end,
    [0xFF01] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        decode_security_event(value_range, tlv_tree)
    end,
    [0xFF02] = function(value_range, tlv_tree)
        add_text(tlv_tree, "Diagnostic Message: " .. range_string(value_range))
    end,
    [0xFF03] = function(value_range, tlv_tree)
        if value_range:len() == 0 then
            add_text(tlv_tree, "Queryable GET form with zero-length payload")
            return
        end
        add_level_summary(tlv_tree, value_range, "Level Foldback")
    end
}

local function decode_tlvs(payload_range, sig_tree, ctx)
    if not payload_range or payload_range:len() == 0 then
        add_text(sig_tree, "No application payload")
        return
    end

    sig_tree:add(fields.payload, payload_range)

    local tlv_root = sig_tree:add(sig_net, payload_range, string.format("TLVs (%u bytes)", payload_range:len()))
    local offset = 0
    local index = 1

    while offset < payload_range:len() do
        if payload_range:len() - offset < 4 then
            add_text(tlv_root, string.format("Trailing %u byte(s) do not form a complete TLV header", payload_range:len() - offset))
            return
        end

        local tid_range = payload_range(offset, 2)
        local length_range = payload_range(offset + 2, 2)
        local tid = tid_range:uint()
        local length = length_range:uint()
        local total = 4 + length

        if offset + total > payload_range:len() then
            add_text(tlv_root, string.format("Malformed TLV at index %u: length %u exceeds remaining payload", index, length))
            return
        end

        local full_range = payload_range(offset, total)
        local value_range = payload_range(offset + 4, length)
        local name = tid_names[tid] or ((tid >= 0x8000) and "Manufacturer-Specific TID" or "Unknown TID")
        local tlv_tree = tlv_root:add(sig_net, full_range, string.format("%u: %s (0x%04X), Length %u", index, name, tid, length))
        tlv_tree:add(fields.tid, tid_range)
        tlv_tree:add(fields.length, length_range)
        if length > 0 then
            tlv_tree:add(fields.value, value_range)
        end

        if tid >= 0x8000 and ctx.mfg_code == 0 then
            add_text(tlv_tree, "Manufacturer-specific TID with Sig-Net Manufacturer Code 0x0000")
        end

        local decoder = tlv_decoders[tid]
        if decoder then
            decoder(value_range, tlv_tree, ctx)
        else
            add_text(tlv_tree, "No dedicated dissector for this TID. Raw value shown above.")
        end

        offset = offset + total
        index = index + 1
    end
end

local function has_sig_net_uri()
    local values = { coap_uri_path_field() }
    if not values[1] then
        return false
    end

    for _, value in ipairs(values) do
        local text = tostring(value)
        if text and text:lower():find("sig%-net", 1, false) then
            return true
        end
    end

    return false
end

local function get_coap_payload_range()
    local field_info = udp_payload_field()
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

function sig_net.dissector(tvb, pinfo, tree)
    if not has_sig_net_uri() then
        return
    end

    local coap_tvb = get_coap_payload_range()
    if not coap_tvb then
        local malformed_tree = tree:add(sig_net, tvb(), "Sig-Net")
        add_text(malformed_tree, "Could not obtain UDP payload for CoAP reparse")
        return
    end

    local parsed, err = parse_coap_packet(coap_tvb)
    if not parsed then
        local malformed_tree = tree:add(sig_net, coap_tvb, "Sig-Net")
        add_text(malformed_tree, "CoAP reparse failed: " .. tostring(err))
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
        return
    end

    local uri_version = parsed.uri_segments[2] or ""
    local uri_resource = (#parsed.uri_segments >= 3) and table.concat(parsed.uri_segments, "/", 3) or ""

    local security_mode_range = option_value(parsed, 2076)
    local sender_id_range = option_value(parsed, 2108)
    local mfg_code_range = option_value(parsed, 2140)
    local session_id_range = option_value(parsed, 2172)
    local seq_num_range = option_value(parsed, 2204)
    local hmac_range = option_value(parsed, 2236)

    local mfg_code_value = mfg_code_range and mfg_code_range:uint() or 0

    local summary = parsed.uri
    if uri_resource ~= "" then
        summary = uri_resource
    end

    local info_text = tostring(pinfo.cols.info)
    if not info_text:find("Sig-Net " .. summary, 1, true) then
        pinfo.cols.info:append(" [Sig-Net " .. summary .. "]")
    end

    local sig_tree = tree:add(sig_net, coap_tvb, "Sig-Net")
    sig_tree:add(fields.coap_version, coap_tvb(0, 1))
    sig_tree:add(fields.coap_type, coap_tvb(0, 1))
    sig_tree:add(fields.coap_tkl, coap_tvb(0, 1))
    sig_tree:add(fields.coap_code, coap_tvb(1, 1))
    sig_tree:add(fields.coap_message_id, coap_tvb(2, 2))
    sig_tree:add(fields.uri, parsed.uri)
    sig_tree:add(fields.uri_version, uri_version)
    sig_tree:add(fields.uri_resource, uri_resource)

    if security_mode_range and security_mode_range:len() >= 1 then
        sig_tree:add(fields.security_mode, security_mode_range)
    else
        add_text(sig_tree, "Security Mode option missing")
    end

    if sender_id_range then
        sig_tree:add(fields.sender_id, sender_id_range)
        if sender_id_range:len() >= 8 then
            sig_tree:add(fields.sender_tuid, format_tuid(sender_id_range(0, 6)))
            sig_tree:add(fields.sender_endpoint, sender_id_range(6, 2):uint())
        end
    else
        add_text(sig_tree, "Sender ID option missing")
    end

    if mfg_code_range then
        sig_tree:add(fields.mfg_code, mfg_code_range)
    else
        add_text(sig_tree, "Manufacturer Code option missing")
    end

    if session_id_range then
        sig_tree:add(fields.session_id, session_id_range)
    else
        add_text(sig_tree, "Session ID option missing")
    end

    if seq_num_range then
        sig_tree:add(fields.seq_num, seq_num_range)
    else
        add_text(sig_tree, "Sequence Number option missing")
    end

    if hmac_range then
        sig_tree:add(fields.hmac, hmac_range)
    else
        add_text(sig_tree, "HMAC option missing")
    end

    add_text(sig_tree, string.format("CoAP Header: ver=%u, type=%s, code=0x%02X, message_id=0x%04X", parsed.version, coap_type_vals[parsed.type] or "Unknown", parsed.code, parsed.message_id))
    add_text(sig_tree, string.format("URI Path: %s", parsed.uri))
    add_sig_net_option_tree(sig_tree, parsed)

    if sender_id_range then
        add_text(sig_tree, "Sender ID Summary: " .. format_sender_id(sender_id_range))
    end
    if security_mode_range and security_mode_range:len() >= 1 then
        add_text(sig_tree, "Security Mode Summary: " .. enum_text(security_mode_range(0, 1):uint(), security_mode_vals))
    end

    local ctx = {
        pinfo = pinfo,
        uri = parsed.uri,
        uri_segments = parsed.uri_segments,
        mfg_code = mfg_code_value
    }

    decode_tlvs(parsed.payload, sig_tree, ctx)
end

register_postdissector(sig_net)