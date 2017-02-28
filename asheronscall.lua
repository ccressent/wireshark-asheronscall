local HEADER_SIZE = 20

local ac = Proto("AC", "Asheron's Call Protocol")

local packet = {
	sequence_number = ProtoField.uint32("ac.packet.sequence_number", "Sequence Number"),
	flags           = ProtoField.uint32("ac.packet.flags",           "Flags", base.HEX),
	crc             = ProtoField.uint32("ac.packet.crc",             "CRC", base.HEX),
	id              = ProtoField.uint16("ac.packet.id",              "ID"),
	time            = ProtoField.uint16("ac.packet.time",            "Time"),
	size            = ProtoField.uint16("ac.packet.size",            "Size"),
	table           = ProtoField.uint16("ac.packet.table",           "Table")
}

local packet_flags = {
	resent = {
		mask   = 0x00000001,
		pfield = ProtoField.bool("ac.packet.flags.resent", "Resent", 32, nil, 0x00000001)
	},

	crc = {
    mask   = 0x00000002,
		pfield = ProtoField.bool("ac.packet.flags.crc", "CRC", 32, nil, 0x00000002)
  },

	fragment = {
    mask   = 0x00000004,
    pfield = ProtoField.bool("ac.packet.flags.fragment", "Fragment", 32, nil, 0x00000004)
  },

	server_switch = {
    mask   = 0x00000100,
    pfield = ProtoField.bool("ac.packet.flags.server_switch", "Server Switch", 32, nil, 0x00000100)
  },

	referral = {
    mask   = 0x00000800,
    pfield = ProtoField.bool("ac.packet.flags.referral", "Referral", 32, nil, 0x00000800)
  },

	request_retransmit = {
    mask   = 0x00001000,
    pfield = ProtoField.bool("ac.packet.flags.request_retransmit", "Request Retransmit", 32, nil, 0x00001000)
  },

	reject_retransmit = {
    mask   = 0x00002000,
    pfield = ProtoField.bool("ac.packet.flags.reject_retransmit", "Reject Retransmit", 32, nil, 0x00002000)
  },

	ack_sequence = {
    mask   = 0x00004000,
    pfield = ProtoField.bool("ac.packet.flags.ack_sequence", "ACK sequence", 32, nil, 0x00004000)
  },

	disconnect = {
    mask   = 0x00008000,
    pfield = ProtoField.bool("ac.packet.flags.disconnect", "Disconnect", 32, nil, 0x00008000)
  },

	login_request = {
    mask   = 0x00010000,
    pfield = ProtoField.bool("ac.packet.flags.login_request", "Login Request", 32, nil, 0x00010000)
  },

	world_login_request = {
    mask   = 0x00020000,
    pfield = ProtoField.bool("ac.packet.flags.world_login_request", "World Login Request", 32, nil, 0x00020000)
  },

	connect_request = {
    mask   = 0x00040000,
    pfield = ProtoField.bool("ac.packet.flags.connect_request", "Connect Request", 32, nil, 0x00040000)
  },

	connect_response = {
    mask   = 0x00080000,
    pfield = ProtoField.bool("ac.packet.flags.connect_response", "Connect Response", 32, nil, 0x00080000)
  },

	ci_command = {
    mask   = 0x00400000,
    pfield = ProtoField.bool("ac.packet.flags.ci_command", "CI Command", 32, nil, 0x00400000)
  },

	time_sync = {
    mask   = 0x01000000,
    pfield = ProtoField.bool("ac.packet.flags.time_sync", "Time Sync", 32, nil, 0x01000000)
  },

	echorequest = {
    mask   = 0x02000000,
    pfield = ProtoField.bool("ac.packet.flags.echo_request", "Echo Request", 32, nil, 0x02000000)
  },

	echoresponse = {
    mask   = 0x04000000,
    pfield = ProtoField.bool("ac.packet.flags.echo_response", "Echo Response", 32, nil, 0x04000000)
  },

	flow = {
    mask   = 0x08000000,
    pfield = ProtoField.bool("ac.packet.flags.flow", "Flow", 32, nil, 0x08000000)
  }
}

for _,field in pairs(packet) do
	ac.fields[#ac.fields+1] = field
end

for _,flag in pairs(packet_flags) do
	ac.fields[#ac.fields+1] = flag.pfield
end

function ac.dissector(buf, pinfo, root)
	local tree = root:add(ac, buf(), "Asheron's Call Protocol")

	tree:add_le(packet["sequence_number"], buf(0,4))

	local flag_tree = tree:add_le(packet["flags"], buf(4,4))
	local flags_value = buf(4,4):le_uint()

	for _,flag in pairs(packet_flags) do
    addIfFlagSet(flag_tree, flags_value, flag, buf(4,4))
	end

	tree:add_le(packet["crc"],   buf( 8,4))
	tree:add_le(packet["id"],    buf(12,2))
	tree:add_le(packet["time"],  buf(14,2))
	tree:add_le(packet["size"],  buf(16,2))
	tree:add_le(packet["table"], buf(18,2))
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(9000, ac)
udp_table:add(9001, ac)
udp_table:add(9008, ac)
udp_table:add(9009, ac)

function addIfFlagSet(tree, value, flag, ...)
  -- BUG(ccressent): doing it this way makes it so flags that are unset cannot
  -- be filtered. Need to find a function to toggle visibility of tree items.
  if bit.band(value, flag.mask) == flag.mask then
    tree:add_le(flag.pfield, ...)
  end
end
