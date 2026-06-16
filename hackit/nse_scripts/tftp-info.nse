local stdnse = require "stdnse"
local nmap = require "nmap"
local bin = require "bin"
local string = require "string"

description = [[Detects TFTP services by sending Read Request (RRQ) packets for common files. Tests multiple filenames, transfer modes, and identifies TFTP server behavior through DATA, ACK, and ERROR response analysis.]]
author = "HackIT Framework"
license = "HackIT Framework — Internal Use Only"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "udp" and port.state == "open" and port.number == 69
end

local function build_tftp_rrq(filename, mode)
  local opcode = bin.pack(">i", 1):sub(3, 4)
  local mode_str = mode or "octet"
  return opcode .. filename .. "\x00" .. mode_str .. "\x00"
end

local test_files = {
  "test", "test.txt", "config", "README",
  "config.txt", "config.sys", "config.bin",
  "version", "version.txt", "version.info",
  "firmware", "firmware.bin", "firmware.txt",
  "backup", "backup.cfg", "backup.config",
  "ios", "ios.bin", "ios.txt",
  "startup", "startup.cfg", "startup-config",
  "running", "running.cfg", "running-config",
  "flash", "flash.bin", "flash.txt",
  "image", "image.bin", "image.img",
  "kernel", "kernel.bin", "vmlinuz",
  "bootstrap", "boot.cfg", "boot.txt",
  "password", "passwd", "password.txt",
  "index", "index.html", "default",
}

local test_modes = { "octet", "netascii", "mail" }

local function parse_tftp_response(response)
  if not response or #response < 4 then return nil end

  local opcode = string.byte(response, 3) * 256 + string.byte(response, 4)
  local info = { opcode = opcode }

  local opcode_names = {
    [1] = "RRQ", [2] = "WRQ", [3] = "DATA",
    [4] = "ACK", [5] = "ERROR", [6] = "OACK",
  }
  info.opcode_name = opcode_names[opcode] or string.format("Unknown (%d)", opcode)

  if opcode == 3 then
    info.block = string.byte(response, 1) * 256 + string.byte(response, 2)
    info.data_size = #response - 4
  elseif opcode == 4 then
    info.block = string.byte(response, 1) * 256 + string.byte(response, 2)
  elseif opcode == 5 and #response > 4 then
    info.error_code = string.byte(response, 5) * 256 + string.byte(response, 6)
    local error_msgs = {
      [0] = "Not defined", [1] = "File not found", [2] = "Access violation",
      [3] = "Disk full or allocation exceeded", [4] = "Illegal TFTP operation",
      [5] = "Unknown transfer ID", [6] = "File already exists",
      [7] = "No such user", [8] = "Terminate transfer",
    }
    info.error_message = error_msgs[info.error_code] or "Unknown"
    if #response > 7 then
      local msg = response:sub(7):match("^([^\x00]+)")
      if msg then
        info.error_detail = msg
      end
    end
  elseif opcode == 6 then
    info.oack = true
    info.options = response:sub(5)
  end

  return info
end

action = function(host, port)
  local result = stdnse.output_table()
  local found = false

  for _, fname in ipairs(test_files) do
    for _, mode in ipairs(test_modes) do
      local socket = nmap.new_socket("udp")
      socket:set_timeout(3000)

      local ok, err = pcall(socket.connect, socket, host.ip, port.number)
      if not ok then
        pcall(socket.close, socket)
        if _ == 1 and _ == 1 then
          return stdnse.format_output(false, "Could not connect: " .. tostring(err))
        end
        break
      end

      local request = build_tftp_rrq(fname, mode)
      local ok2 = pcall(socket.send, socket, request)
      if not ok2 then
        pcall(socket.close, socket)
        break
      end

      local ok3, response = pcall(socket.receive_from, 3)
      pcall(socket.close, socket)

      if ok3 and response and #response >= 4 then
        local info = parse_tftp_response(response)
        if info then
          result.tftp_detected = true

          if info.opcode == 3 then
            result.service = "confirmed (DATA response)"
            result.accessible_file = fname
            result.transfer_mode = mode
            result.data_block = info.block
            result.data_bytes = info.data_size
            found = true
          elseif info.opcode == 5 then
            result.service = "detected (ERROR response)"
            result.error_code = info.error_code
            result.error_message = info.error_message
            result.error_file = fname
            found = true
          elseif info.opcode == 4 then
            result.service = "confirmed (ACK response)"
            result.accessible_file = fname
            found = true
          elseif info.opcode == 6 then
            result.service = "detected (OACK response)"
            result.accessible_file = fname
            found = true
          end

          if found then break end
        end
      end
    end
    if found then break end
  end

  if not found then
    return stdnse.format_output(false, "TFTP service not detected")
  end

  result.files_tested = #test_files
  result.modes_tested = #test_modes

  return stdnse.format_output(true, result)
end
