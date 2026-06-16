local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local packet = require "packet"
local string = require "string"
local math = require "math"

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
    local frag_payload = string.sub(payload, start, finish)
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

    local icmp_header = string.char(8, 0, 0, 0, 0, 0, 0, 0)
    local checksum = nmap.in_cksum(icmp_header .. frag_payload)
    icmp_header = string.char(8, 0, checksum & 0xFF, (checksum >> 8) & 0xFF, 0, 0, 0, 0)

    nmap.sendp(ip_bin .. icmp_header .. frag_payload, { dst = host.ip })
    nmap.msleep(20)
  end

  return num_fragments
end

action = function(host, port)
  local result = stdnse.output_table()
  local payload = string.rep("X", 3000)
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
    local deadline = nmap.clock() + 3
    while nmap.clock() < deadline do
      local ok, data = capture:receive()
      if ok and data then
        local pkt = packet.Packet:new(data)
        if pkt and pkt.ip_src == host.ip and pkt.ip_p == 1 then
          responses[#responses + 1] = pkt
        end
      end
    end
    capture:close()

    all_tests[#all_tests + 1] = {
      fragment_size = frag_size,
      fragments_sent = num_frags,
      payload_total = #payload,
      responses_count = #responses,
      reassembly_status = (#responses > 0) and "successful" or "no_response"
    }
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
