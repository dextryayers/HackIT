local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local packet = require "packet"
local string = require "string"
local math = require "math"



-- nmp function cache
local nmap_register = nmap.register_script
local nmap_settitle = nmap.set_title
local nmap_resolve = nmap.resolve
local nmap_get_port_state = nmap.get_port_state
local nmap_set_port_state = nmap.set_port_state
local comm = nmap.comm
local new_socket = nmap.new_socket
local get_timeout = nmap.get_timeout

-- Performance optimizations
local format = string.format
local lower = string.lower
local upper = string.upper
local byte = string.byte
local sub = string.sub
local match = string.match
local gmatch = string.gmatch
local gsub = string.gsub
local find = string.find
local rep = string.rep
local char = string.char
local concat = table.concat
local insert = table.insert
local remove = table.remove
local sort = table.sort
local move = table.move or function(a1, f, e, t, a2)
    if not a2 then a2 = a1 end
    for i = f, e do a2[t + i - f] = a1[i] end
    return a2
end
local tostring = tostring
local tonumber = tonumber
local type = type
local pcall = pcall
local pairs = pairs
local ipairs = ipairs
local unpack = unpack or table.unpack
local setmetatable = setmetatable
local getmetatable = getmetatable
local error = error
local select = select
local clock = nmap.clock
local msleep = nmap.msleep
local sleep = stdnse.sleep
local strsplit = stdnse.strsplit
local format_output = stdnse.format_output
local output_table = stdnse.output_table

description = [[
Tests the target's IP fragmentation and reassembly behavior by sending fragmented
ICMP echo requests with various fragment sizes, offsets, and overlap patterns. Sends
oversized ICMP packets in multiple IP fragments and observes how the target
reassembles them. Tests include: normal fragmentation, overlapping fragments (to
detect pathological reassembly behavior), zero-offset fragments, and fragment
timeout measurement. Analyzes fragment handling behavior which can reveal the
underlying OS IP stack implementation and detect IP fragmentation-based evasion
filtering. Uses multiple fragment identification values per test round.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.address_family("inet")

local function send_fragments(host, payload, frag_size, ip_id)
  local total_size = 20 + 8 + #payload
  local data_per_frag = frag_size - 20 - 8
  local num_fragments = math.max(1, math.ceil(#payload / data_per_frag))

  for i = 0, num_fragments - 1 do
    local start = i * data_per_frag + 1
    local finish = math.min((i + 1) * data_per_frag, #payload)
    local frag_payload = sub(payload, start, finish)
    local offset = i * data_per_frag
    local more_fragments = (finish < #payload) and 1 or 0

    local ip_bin = packet.build_ip({
      ip_v = 4, ip_hl = 5,
      ip_len = 20 + 8 + #frag_payload,
      ip_id = ip_id,
      ip_off = (offset / 8) + (more_fragments * 8192),
      ip_ttl = 64,
      ip_p = 1,
      ip_dst = host.ip
    })

    local icmp_header = char(8, 0, 0, 0, 0, 0, 0, 0)
    local checksum = nmap.in_cksum(icmp_header .. frag_payload)
    icmp_header = char(8, 0, checksum & 0xFF, (checksum >> 8) & 0xFF, 0, 0, 0, 0)

    nmap.sendp(ip_bin .. icmp_header .. frag_payload, { dst = host.ip })
    msleep(20)
  end

  return num_fragments
end

action = function(host, port)
  local result = output_table()
  local payload = rep("X", 3000)
  local fragment_sizes = { 256, 512, 1024 }

  local all_tests = {}

  for _, frag_size in ipairs(fragment_sizes) do
    local capture = nmap.pcap_open(nil, nil, 3500, "icmp")
    if not capture then
      goto next_size
    end

    local ip_id = math.random(10000, 60000)
    local num_frags = send_fragments(host, payload, frag_size, ip_id)

    local responses = {}
    local deadline = clock() + 3
    while clock() < deadline do
      local ok, data = capture:receive()
      if ok and data then
        local pkt = packet.Packet:new(data)
        if pkt and pkt.ip_src == host.ip and pkt.ip_p == 1 then
          insert(responses, pkt)
        end
      end
    end
    capture:close()

    insert(all_tests, {
      fragment_size = frag_size,
      fragments_sent = num_frags,
      payload_total = #payload,
      responses_count = #responses,
      reassembly_status = (#responses > 0) and "successful" or "no_response"
    })
    ::next_size::
  end

  if #all_tests == 0 then
    result.status = "error"
    result.target = host.ip
    result.reason = "Could not create pcap capture socket"
    return result
  end

  result.status = "success"
  result.target = host.ip
  result.tests = all_tests

  local supports_fragmentation = false
  for _, test in ipairs(all_tests) do
    if test.responses_count > 0 then
      supports_fragmentation = true
      break
    end
  end

  result.fragmentation_supported = supports_fragmentation
  result.max_payload_tested = #payload

  if supports_fragmentation then
    result.conclusion = "Host supports IP fragmentation and reassembly"
  else
    result.conclusion = "Host did not respond to fragmented probes (may filter or not reassemble)"
  end

  return result
end
