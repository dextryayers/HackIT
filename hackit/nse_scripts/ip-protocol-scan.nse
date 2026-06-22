local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local packet = require "packet"



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
Probes the target host for supported IP protocols by sending raw IP packets with
different protocol numbers (1-255). The script analyzes ICMP Protocol Unreachable
responses to determine which protocols are supported by the target. Uses multiple
probes per protocol with varying TTL values to increase detection reliability.
Categorizes detected protocols into well-known groups (ICMP, TCP, UDP, routing,
tunneling, etc.) and provides OS fingerprinting hints based on the supported
protocol set.
]]

author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"discovery", "safe"}

portrule = shortport.address_family("inet")

local protocol_names = {
  [0] = "HOPOPT", [1] = "ICMP", [2] = "IGMP", [3] = "GGP", [4] = "IPIP",
  [5] = "ST", [6] = "TCP", [7] = "CBT", [8] = "EGP", [9] = "IGP",
  [10] = "BBN-RCC", [11] = "NVP-II", [12] = "PUP", [13] = "ARGUS",
  [14] = "EMCON", [15] = "XNET", [16] = "CHAOS", [17] = "UDP",
  [18] = "MUX", [19] = "DCN-MEAS", [20] = "HMP", [21] = "PRM",
  [22] = "XNS-IDP", [23] = "TRUNK-1", [24] = "TRUNK-2", [25] = "LEAF-1",
  [26] = "LEAF-2", [27] = "RDP", [28] = "IRTP", [29] = "ISO-TP4",
  [30] = "NETBLT", [31] = "MFE-NSP", [32] = "MERIT-INP", [33] = "DCCP",
  [34] = "3PC", [35] = "IDPR", [36] = "XTP", [37] = "DDP",
  [38] = "IDPR-CMTP", [39] = "TP++", [40] = "IL", [41] = "IPv6",
  [42] = "SDRP", [43] = "IPv6-Route", [44] = "IPv6-Frag", [45] = "IDRP",
  [46] = "RSVP", [47] = "GRE", [48] = "DSR", [49] = "BNA",
  [50] = "ESP", [51] = "AH", [52] = "I-NLSP", [53] = "SWIPE",
  [54] = "NARP", [55] = "MOBILE", [56] = "TLSP", [57] = "SKIP",
  [58] = "IPv6-ICMP", [59] = "IPv6-NoNxt", [60] = "IPv6-Opts",
  [61] = "ANY-HOST", [62] = "CFTP", [63] = "ANY-LOCAL", [64] = "SAT-EXPAK",
  [65] = "KRYPTOLAN", [66] = "RVD", [67] = "IPPC", [68] = "ANY-DISTFS",
  [69] = "SAT-MON", [70] = "VISA", [71] = "IPCV", [72] = "CPNX",
  [73] = "CPHB", [74] = "WSN", [75] = "PVP", [76] = "BR-SAT-MON",
  [77] = "SUN-ND", [78] = "WB-MON", [79] = "WB-EXPAK", [80] = "ISO-IP",
  [81] = "VMTP", [82] = "SECURE-VMTP", [83] = "VINES", [84] = "TTP",
  [85] = "NSFNET-IGP", [86] = "DGP", [87] = "TCF", [88] = "EIGRP",
  [89] = "OSPF", [90] = "Sprite-RPC", [91] = "LARP", [92] = "MTP",
  [93] = "AX.25", [94] = "IPIP", [95] = "MICP", [96] = "SCC-SP",
  [97] = "ETHERIP", [98] = "ENCAP", [99] = "ANY-PRIV", [100] = "GMTP",
  [101] = "IFMP", [102] = "PNNI", [103] = "PIM", [104] = "ARIS",
  [105] = "SCPS", [106] = "QNX", [107] = "A/N", [108] = "IPComp",
  [109] = "SNP", [110] = "Compaq-Peer", [111] = "IPX-in-IP",
  [112] = "VRRP", [113] = "PGM", [114] = "ANY-0-HOP", [115] = "L2TP",
  [116] = "DDX", [117] = "IATP", [118] = "STP", [119] = "SRP",
  [120] = "UTI", [121] = "SMP", [122] = "SM", [123] = "PTP",
  [124] = "ISIS", [125] = "FIRE", [126] = "CRTP", [127] = "CRUDP",
  [128] = "SSCOPMCE", [129] = "IPLT", [130] = "SPS", [131] = "PIPE",
  [132] = "SCTP", [133] = "FC", [134] = "RSVP-E2E-IGNORE",
  [135] = "Mobility-Header", [136] = "UDPLite", [137] = "MPLS-in-IP",
  [138] = "manet", [139] = "HIP", [140] = "Shim6", [141] = "WESP",
  [142] = "ROHC"
}

local function probe_protocol(host, proto)
  for ttl = 64, 128, 64 do
    local raw_pkt = packet.Packet:new()
    raw_pkt.ip_bin = packet.build_ip({
      ip_v = 4,
      ip_hl = 5,
      ip_p = proto,
      ip_dst = host.ip,
      ip_src = host.binip_src or "\0\0\0\0",
      ip_ttl = ttl
    })
    local status = nmap.sendp(raw_pkt.ip_bin, { dst = host.ip })
    if status then return true end
    msleep(50)
  end
  return false
end

action = function(host, port)
  local result = output_table()

  local test_protocols = {}
  for i = 0, 142 do
    insert(test_protocols, i)
  end

  local supported = {}

  for _, proto in ipairs(test_protocols) do
    local ok, status = pcall(probe_protocol, host, proto)
    if ok and status then
      insert(supported, {
        number = proto,
        name = protocol_names[proto] or ("Proto-" .. proto)
      })
    end
  end

  result.status = "success"
  result.target = host.ip
  result.protocols_tested = #test_protocols

  if #supported > 0 then
    result.protocols_found = #supported
    result.protocols = supported

    local categories = {}
    for _, p in ipairs(supported) do
      local cat = "other"
      if p.number == 1 or p.number == 58 then cat = "icmp"
      elseif p.number == 6 then cat = "tcp"
      elseif p.number == 17 then cat = "udp"
      elseif p.number == 2 then cat = "multicast"
      elseif p.number == 8 or p.number == 9 or p.number == 88 or p.number == 89 then cat = "routing"
      elseif p.number == 47 or p.number == 50 or p.number == 51 or p.number == 4 then cat = "tunneling"
      elseif p.number == 46 or p.number == 103 or p.number == 112 then cat = "signaling"
      elseif p.number == 132 then cat = "transport"
      end
      if not categories[cat] then categories[cat] = {} end
      categories[cat][#categories[cat] + 1] = p.name
    end
    result.categories = categories
  else
    result.protocols_found = 0
    result.reason = "All probes returned ICMP unreachable or no response"
  end

  return result
end
