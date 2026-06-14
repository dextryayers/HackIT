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

def set_channel(iface, channel)
  _, _, status = Open3.capture3('iw', 'dev', iface, 'set', 'channel', channel.to_s)
  if !status.success?
    _, _, status = Open3.capture3('iwconfig', iface, 'channel', channel.to_s)
  end
  status.success?
end

def get_survey_dump(iface)
  stdout, _, status = Open3.capture3('iw', 'dev', iface, 'survey', 'dump')
  return nil unless status.success?

  channels = {}
  current_channel = nil
  current_data = {}

  stdout.each_line do |line|
    line = line.strip
    next if line.empty?

    if line =~ /in\s+use\s+(\d+)/
      if current_channel && !current_data.empty?
        channels[current_channel] = current_data
      end
      current_channel = $1.to_i
      current_data = {}
    elsif line =~ /noise:\s*(-?\d+)/
      current_data[:noise] = $1.to_i
    elsif line =~ /channel\s+time:\s*(\d+)/
      current_data[:channel_time] = $1.to_i
    elsif line =~ /busy\s+time:\s*(\d+)/
      current_data[:busy_time] = $1.to_i
    elsif line =~ /active\s+time:\s*(\d+)/
      current_data[:active_time] = $1.to_i
    elsif line =~ /channel\s+time\s+rx:\s*(\d+)/
      current_data[:rx_time] = $1.to_i
    elsif line =~ /channel\s+time\s+tx:\s*(\d+)/
      current_data[:tx_time] = $1.to_i
    end
  end

  if current_channel && !current_data.empty?
    channels[current_channel] = current_data
  end

  channels
end

def scan_channel_aps(iface, channel)
  stdout, _, status = Open3.capture3('iw', 'dev', iface, 'scan', '-c', channel.to_s)
  return [] unless status.success?

  aps = []
  current_bssid = nil
  current_ssid = nil
  current_signal = nil
  current_channel_ap = nil

  stdout.each_line do |line|
    if line =~ /^BSS\s+([a-fA-F0-9:]{17})/
      if current_bssid && current_signal
        aps << { bssid: current_bssid, ssid: current_ssid, signal: current_signal, channel: current_channel_ap }
      end
      current_bssid = $1.upcase
      current_ssid = nil
      current_signal = nil
      current_channel_ap = nil
    elsif line =~ /SSID:\s*(.+)/
      current_ssid = $1.strip
    elsif line =~ /signal:\s*(-?\d+\.\d+)/
      current_signal = $1.to_f
    elsif line =~ /freq:\s*(\d+)/
      freq = $1.to_i
      current_channel_ap = freq_to_chan(freq)
    end
  end

  if current_bssid && current_signal
    aps << { bssid: current_bssid, ssid: current_ssid, signal: current_signal, channel: current_channel_ap }
  end

  aps
end

def freq_to_chan(freq)
  return nil if freq < 2412 || freq > 5825
  if freq >= 2412 && freq <= 2472
    ((freq - 2412) / 5) + 1
  elsif freq == 2484
    14
  elsif freq >= 5180 && freq <= 5825
    ((freq - 5180) / 5) + 36
  else
    nil
  end
end

begin
  iface = ARGV[0]
  band = (ARGV[1] || 'both').downcase

  raise 'interface required' unless iface

  channels = case band
             when '2.4', '2ghz' then CHANNELS_2GHZ
             when '5', '5ghz' then CHANNELS_5GHZ
             when 'both' then CHANNELS_2GHZ + CHANNELS_5GHZ
             else raise "invalid band: #{band}"
             end

  emit('spectrum_scan_start', iface, '', '', 0, { band: band, channels_count: channels.size })

  results = {}

  channels.each do |ch|
    ok = set_channel(iface, ch)
    unless ok
      emit('channel_set_failed', iface, '', '', ch, {})
      next
    end
    sleep(0.1)

    survey = get_survey_dump(iface)
    aps = scan_channel_aps(iface, ch)

    channel_data = {
      channel: ch,
      survey: survey[ch] || {},
      aps: aps,
      aps_count: aps.size
    }

    results[ch] = channel_data

    emit('channel_spectrum', iface, '', '', ch, channel_data)
  end

  emit('spectrum_scan_summary', iface, '', '', 0, {
    channels_scanned: results.size,
    total_aps: results.values.sum { |v| v[:aps_count] },
    channels: results.map { |ch, data|
      {
        channel: ch,
        noise: data[:survey][:noise],
        utilization_pct: data[:survey][:channel_time] && data[:survey][:channel_time] > 0 ?
          ((data[:survey][:busy_time].to_f / data[:survey][:channel_time]) * 100).round(1) : nil,
        aps_count: data[:aps_count]
      }
    }
  })

  emit('spectrum_scan_complete', iface, '', '', 0, { channels_scanned: results.size })

rescue Interrupt
  emit('spectrum_scan_interrupted', iface || '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
