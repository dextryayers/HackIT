#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

def get_station_signal(iface, bssid)
  stdout, _, status = Open3.capture3('iw', 'dev', iface, 'station', 'dump')
  return nil unless status.success?

  current_station = nil
  signals = []
  rates = []

  stdout.each_line do |line|
    if line =~ /Station\s+([a-fA-F0-9:]{17})/
      current_station = $1.upcase
    elsif line =~ /signal:\s*(-?\d+)/
      signals << $1.to_i if current_station
    elsif line =~ /signal avg:\s*(-?\d+)/
      signals << $1.to_i
    elsif line =~ /tx bitrate:\s*([\d.]+)/
      rates << { type: 'tx', rate: $1.to_f }
    elsif line =~ /rx bitrate:\s*([\d.]+)/
      rates << { type: 'rx', rate: $1.to_f }
    end
  end

  if bssid && !bssid.empty?
    return nil unless current_station == bssid.upcase
  end

  {
    station: current_station,
    signals: signals,
    rates: rates,
    min_signal: signals.min,
    max_signal: signals.max,
    avg_signal: signals.size > 0 ? (signals.sum.to_f / signals.size).round(1) : nil
  }
end

def get_iwconfig_signal(iface)
  stdout, _, _ = Open3.capture3('iwconfig', iface)
  return nil unless stdout

  signals = []
  if stdout =~ /Signal\s*level\s*[:=]\s*(-?\d+)\s*dBm/
    signals << $1.to_i
  end
  if stdout =~ /Signal\s*level\s*[:=]\s*(-?\d+)/
    signals << $1.to_i
  end
  { signals: signals, min_signal: signals.min, max_signal: signals.max, avg_signal: signals.size > 0 ? (signals.sum.to_f / signals.size).round(1) : nil, source: 'iwconfig' }
end

begin
  iface = ARGV[0]
  bssid = ARGV[1]
  duration = (ARGV[2] || '30').to_i

  raise 'interface required' unless iface

  emit('signal_monitor_start', iface, bssid || '', '', 0, { duration: duration })

  readings = []
  start_time = Time.now

  while Time.now - start_time < duration
    station_info = get_station_signal(iface, bssid)
    iwconfig_info = get_iwconfig_signal(iface)

    if station_info && station_info[:signals] && !station_info[:signals].empty?
      reading = {
        station: station_info[:station],
        signals: station_info[:signals],
        min_signal: station_info[:min_signal],
        max_signal: station_info[:max_signal],
        avg_signal: station_info[:avg_signal],
        rates: station_info[:rates]
      }
      readings << reading
      emit('signal_reading', iface, station_info[:station] || bssid || '', '', 0, reading)
    elsif iwconfig_info && iwconfig_info[:signals] && !iwconfig_info[:signals].empty?
      readings << iwconfig_info
      emit('signal_reading', iface, bssid || '', '', 0, iwconfig_info)
    else
      emit('signal_no_data', iface, bssid || '', '', 0, {})
    end

    sleep 1
  end

  if readings.size > 0
    all_signals = readings.map { |r| r[:signals] }.flatten.compact
    summary = {
      readings_count: readings.size,
      overall_min: all_signals.min,
      overall_max: all_signals.max,
      overall_avg: all_signals.size > 0 ? (all_signals.sum.to_f / all_signals.size).round(1) : nil,
      duration: duration,
      bssid: bssid || 'all'
    }
    emit('signal_monitor_summary', iface, bssid || '', '', 0, summary)
  end

  emit('signal_monitor_complete', iface, bssid || '', '', 0, { readings_count: readings.size, duration: duration })

rescue Interrupt
  emit('signal_monitor_interrupted', iface || '', bssid || '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
