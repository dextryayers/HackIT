#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

def parse_csv_line(line, sep = ',')
  fields = []
  current = +''
  in_quotes = false
  line.each_char do |c|
    case c
    when '"' then in_quotes = !in_quotes
    when sep then (fields << current; current = +'') unless in_quotes
    else current << c
    end
  end
  fields << current
  fields.map(&:strip)
end

def parse_airodump(prefix)
  csv_path = "#{prefix}-01.csv"
  return unless File.exist?(csv_path)

  aps = {}
  clients = {}
  section = :ap

  File.readlines(csv_path).each do |line|
    next if line.strip.empty?
    line = line.encode('UTF-8', invalid: :replace, undef: :replace)
    if line.start_with?('BSSID,')
      section = :ap
      next
    elsif line.start_with?('Station MAC,')
      section = :client
      next
    end

    fields = parse_csv_line(line)
    if section == :ap && fields.size >= 14
      bssid = fields[0].upcase
      next if bssid.empty?
      aps[bssid] = {
        first_seen: fields[1], last_seen: fields[2], channel: fields[3].to_i,
        speed: fields[4], privacy: fields[5], cipher: fields[6],
        auth: fields[7], power: fields[8].to_i, beacon: fields[9].to_i,
        llc: fields[10].to_i, data_packets: fields[11].to_i, rate: fields[12],
        essid: fields[13]
      }
    elsif section == :client && fields.size >= 7
      mac = fields[0].upcase
      bssid = fields[5].upcase
      clients[mac] = {
        first_seen: fields[1], last_seen: fields[2], power: fields[3].to_i,
        packets: fields[4].to_i, bssid: bssid, rate: fields[6]
      }
    end
  end

  { aps: aps, clients: clients }
end

begin
  iface = ARGV[0]
  output_prefix = ARGV[1] || 'dump'
  channel = (ARGV[2] || '0').to_i

  raise 'interface required' unless iface

  emit('airodump_start', iface, '', '', channel, { output_prefix: output_prefix })
  airodump_bin = `which airodump-ng 2>/dev/null`.strip
  raise 'airodump-ng not found' if airodump_bin.empty?

  cmd = [airodump_bin, iface, '--write', output_prefix, '--write-interval', '1']
  cmd += ['--channel', channel.to_s] if channel > 0

  emit('airodump_launch', iface, '', '', channel, { command: cmd.join(' ') })

  Open3.popen3(*cmd) do |stdin, stdout, stderr, thread|
    stdin.close
    [stdout, stderr].each(&:close)

    loop do
      sleep 2
      break unless thread.alive?

      data = parse_airodump(output_prefix)
      data[:aps].each do |bssid, info|
        emit('ap_found', iface, bssid, info[:essid], info[:channel], info)
      end
      data[:clients].each do |mac, info|
        emit('client_found', iface, mac, '', 0, info)
      end
    end

    thread.join
  end

  emit('airodump_complete', iface, '', '', channel, { output_prefix: output_prefix })

rescue Interrupt
  emit('airodump_interrupted', iface || '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
