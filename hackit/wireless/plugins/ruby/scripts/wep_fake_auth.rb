#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

def run_aireplay_fakeauth(iface, bssid, client_mac, count)
  aireplay = `which aireplay-ng 2>/dev/null`.strip
  return nil if aireplay.empty?

  cmd = [aireplay, '-1', count.to_s, '-a', bssid, '-h', client_mac, '-e', 'weptest', iface]
  if count > 1
    cmd += ['-q', '5']
  end

  emit('aireplay_fakeauth_launch', iface, bssid, '', 0, { command: cmd.join(' ') })

  Open3.popen3(*cmd) do |stdin, stdout, stderr, thread|
    stdin.close
    readers = [stdout, stderr]
    auth_state = 'starting'
    assoc_state = nil
    ip_packets = 0

    until readers.empty?
      ready = IO.select(readers, nil, nil, 0.5)
      if ready
        ready[0].each do |r|
          begin
            line = r.gets
            if line
              line.force_encoding('UTF-8')
              emit('fakeauth_output', iface, bssid, '', 0, { line: line.strip })

              if line =~ /Association successful/i
                assoc_state = 'associated'
                emit('fakeauth_associated', iface, bssid, '', 0, { client: client_mac })
              elsif line =~ /Authentication successful/i
                auth_state = 'authenticated'
                emit('fakeauth_authenticated', iface, bssid, '', 0, { client: client_mac })
              elsif line =~ /Got (\d+) packets/i
                ip_packets = $1.to_i
              elsif line =~ /Sending Authentication Request/i
                emit('fakeauth_auth_request', iface, bssid, '', 0, { client: client_mac })
              elsif line =~ /Sending Association Request/i
                emit('fakeauth_assoc_request', iface, bssid, '', 0, { client: client_mac })
              elsif line =~ /open/i
                emit('fakeauth_wep_open', iface, bssid, '', 0, {})
              end
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
    exit_code = thread.value.exitstatus

    {
      auth_state: auth_state,
      assoc_state: assoc_state,
      ip_packets: ip_packets,
      exit_code: exit_code
    }
  end
end

begin
  iface = ARGV[0]
  bssid = ARGV[1]
  client_mac = ARGV[2]

  raise 'usage: wep_fake_auth.rb <interface> <bssid> [client_mac]' unless iface && bssid

  if client_mac.nil? || client_mac.empty?
    client_mac = `macchanger -s #{iface} 2>/dev/null | grep -i 'current' | awk '{print $3}'`.strip
    if client_mac.empty?
      client_mac = `ifconfig #{iface} 2>/dev/null | grep -oE '([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}' | head -1`.strip
    end
    if client_mac.empty?
      client_mac = 'AA:BB:CC:DD:EE:FF'
    end
  end

  count = (ARGV[3] || '3').to_i

  emit('fakeauth_start', iface, bssid, '', 0, { client_mac: client_mac, count: count })

  result = run_aireplay_fakeauth(iface, bssid, client_mac, count)

  if result
    emit('fakeauth_result', iface, bssid, '', 0, {
      client_mac: client_mac,
      auth_state: result[:auth_state],
      assoc_state: result[:assoc_state],
      associated: result[:assoc_state] == 'associated',
      authenticated: result[:auth_state] == 'authenticated',
      exit_code: result[:exit_code]
    })
  end

  emit('fakeauth_complete', iface, bssid, '', 0, { client_mac: client_mac, result: result })

rescue Interrupt
  emit('fakeauth_interrupted', iface || '', bssid || '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
