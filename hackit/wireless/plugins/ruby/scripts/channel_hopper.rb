#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

CHANNELS_2GHZ = (1..13).to_a.freeze
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165].freeze

def set_channel_iw(iface, channel)
  stdout, stderr, status = Open3.capture3('iw', 'dev', iface, 'set', 'channel', channel.to_s)
  if !status.success?
    stdout2, _, status2 = Open3.capture3('iwconfig', iface, 'channel', channel.to_s)
    return [status2.success?, stdout2]
  end
  [status.success?, stdout]
end

def scan_channel_iw(iface, channel)
  stdout, _, _ = Open3.capture3('iw', 'dev', iface, 'scan', '-c', channel.to_s, '--no-scan')
  aps = []
  current_bssid = nil
  current_ssid = nil
  current_signal = nil

  stdout.each_line do |line|
    if line =~ /^BSS\s+([a-fA-F0-9:]{17})/
      current_bssid = $1
      current_ssid = nil
      current_signal = nil
    elsif line =~ /SSID:\s*(.+)/
      current_ssid = $1.strip
    elsif line =~ /signal:\s*(-?\d+\.\d+)/
      current_signal = $1.to_f
    end
  end
  aps
end

def get_survey(iface)
  stdout, _, _ = Open3.capture3('iw', 'dev', iface, 'survey', 'dump')
  channels = {}
  current_channel = nil

  stdout.each_line do |line|
    if line =~ /in\s+use\s+(\d+)/
      current_channel = $1.to_i
      channels[current_channel] ||= {}
    elsif line =~ /noise:\s*(-?\d+)/
      channels[current_channel][:noise] = $1.to_i if current_channel
    elsif line =~ /channel\s+time:\s+(\d+)/
      channels[current_channel][:time] = $1.to_i if current_channel
    elsif line =~ /busy\s+time:\s+(\d+)/
      channels[current_channel][:busy] = $1.to_i if current_channel
    end
  end
  channels
end

begin
  iface = ARGV[0]
  band = (ARGV[1] || 'both').downcase
  dwell_ms = (ARGV[2] || '200').to_i

  raise 'interface required' unless iface

  channels = case band
             when '2.4', '2ghz' then CHANNELS_2GHZ
             when '5', '5ghz' then CHANNELS_5GHZ
             when 'both' then CHANNELS_2GHZ + CHANNELS_5GHZ
             else raise "invalid band: #{band}. Valid: 2.4, 5, both"
             end

  emit('channel_hopper_start', iface, '', '', 0, { band: band, dwell_ms: dwell_ms, channels_count: channels.size })

  loop do
    channels.each do |ch|
      ok, _ = set_channel_iw(iface, ch)
      unless ok
        emit('channel_set_failed', iface, '', '', ch, {})
        next
      end

      emit('channel_set', iface, '', '', ch, { dwell_ms: dwell_ms })

      aps = scan_channel_iw(iface, ch)
      emit('channel_scan', iface, '', '', ch, { aps_found: aps.size })

      survey = get_survey(iface)
      if survey[ch]
        emit('channel_survey', iface, '', '', ch, survey[ch])
      end

      sleep(dwell_ms / 1000.0)
    end
  end

rescue Interrupt
  emit('channel_hopper_interrupted', iface || '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
