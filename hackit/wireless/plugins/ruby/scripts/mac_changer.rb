#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

def get_current_mac(iface)
  stdout, _, status = Open3.capture3('ip', 'link', 'show', iface)
  return nil unless status.success?
  if stdout =~ /link\/ether\s+([a-fA-F0-9:]{17})/
    $1.downcase
  else
    nil
  end
end

def get_current_mac_ifconfig(iface)
  stdout, _, status = Open3.capture3('ifconfig', iface)
  return nil unless status.success?
  if stdout =~ /ether\s+([a-fA-F0-9:]{17})/
    $1.downcase
  else
    nil
  end
end

def set_mac_ip(iface, mac)
  cmds = [
    ['ip', 'link', 'set', iface, 'down'],
    ['ip', 'link', 'set', iface, 'address', mac],
    ['ip', 'link', 'set', iface, 'up']
  ]
  cmds.each do |cmd|
    stdout, stderr, status = Open3.capture3(*cmd)
    return false unless status.success?
  end
  true
end

def set_mac_macchanger(iface, mac)
  stdout, _, status = Open3.capture3('macchanger', '-m', mac, iface)
  status.success?
end

def set_mac_ifconfig(iface, mac)
  cmds = [
    ['ifconfig', iface, 'down'],
    ['ifconfig', iface, 'hw', 'ether', mac],
    ['ifconfig', iface, 'up']
  ]
  cmds.each do |cmd|
    _, _, status = Open3.capture3(*cmd)
    return false unless status.success?
  end
  true
end

def random_mac
  '%02x:%02x:%02x:%02x:%02x:%02x' % [
    rand(2..254) & 0xFE | 0x02,
    rand(256), rand(256), rand(256), rand(256), rand(256)
  ]
end

def restore_mac(iface)
  stdout, _, status = Open3.capture3('macchanger', '-p', iface)
  return status.success? if status.success?
  emit('mac_restore_fallback', iface, '', '', 0, { message: 'macchanger -p failed' })
  false
end

def show_mac_info(iface)
  current = get_current_mac(iface) || get_current_mac_ifconfig(iface)
  return { mac: current || 'unknown' }
end

begin
  iface = ARGV[0]
  action = ARGV[1] || 'show'
  value = ARGV[2]

  raise 'interface required' unless iface

  emit('mac_changer_start', iface, '', '', 0, { action: action })

  case action
  when 'show'
    info = show_mac_info(iface)
    emit('mac_show', iface, '', '', 0, info)

  when 'random'
    old_mac = get_current_mac(iface)
    new_mac = random_mac
    if set_mac_ip(iface, new_mac) || set_mac_macchanger(iface, new_mac) || set_mac_ifconfig(iface, new_mac)
      emit('mac_changed', iface, '', '', 0, { old_mac: old_mac, new_mac: new_mac, action: 'random' })
    else
      raise 'failed to set random MAC address'
    end

  when 'restore'
    old_mac = get_current_mac(iface)
    if restore_mac(iface)
      new_mac = get_current_mac(iface)
      emit('mac_restored', iface, '', '', 0, { old_mac: old_mac, new_mac: new_mac, action: 'restore' })
    else
      raise 'failed to restore MAC address'
    end

  when 'set'
    raise 'MAC address required for set action' unless value
    raise "invalid MAC format: #{value}" unless value =~ /^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$/
    old_mac = get_current_mac(iface)
    if set_mac_ip(iface, value) || set_mac_macchanger(iface, value) || set_mac_ifconfig(iface, value)
      emit('mac_changed', iface, '', '', 0, { old_mac: old_mac, new_mac: value.downcase, action: 'set' })
    else
      raise 'failed to set MAC address'
    end
  else
    raise "unknown action: #{action}. Valid: show, random, restore, set"
  end

  emit('mac_changer_complete', iface, '', '', 0, { action: action })

rescue Interrupt
  emit('mac_changer_interrupted', iface || '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
