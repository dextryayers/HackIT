#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

def mac_str(bytes)
  bytes.unpack('H2 H2 H2 H2 H2 H2').map { |b| b.upcase }.join(':')
end

EAPOL_HEADER_SIZE = 4

# EAPOL types
EAPOL_EAP = 0
EAPOL_START = 1
EAPOL_LOGOFF = 2
EAPOL_KEY = 3
EAPOL_ENCAP_ASF = 4

EAPOL_TYPES = %w[EAP EAPOL-Start EAPOL-Logoff EAPOL-Key Encapsulated-ASF].freeze

# Key Descriptor Versions
KEY_DESC_V1 = 1
KEY_DESC_V2 = 2

KEY_INFO_ACK = 0x0080
KEY_INFO_MIC = 0x0100
KEY_INFO_SECURE = 0x0200
KEY_INFO_ERROR = 0x0400
KEY_INFO_REQUEST = 0x0800
KEY_INFO_INSTALL = 0x0040
KEY_INFO_PAIRWISE = 0x1000

def key_info_description(ki)
  parts = []
  parts << 'ACK' if ki & KEY_INFO_ACK != 0
  parts << 'MIC' if ki & KEY_INFO_MIC != 0
  parts << 'SECURE' if ki & KEY_INFO_SECURE != 0
  parts << 'ERROR' if ki & KEY_INFO_ERROR != 0
  parts << 'REQUEST' if ki & KEY_INFO_REQUEST != 0
  parts << 'INSTALL' if ki & KEY_INFO_INSTALL != 0
  parts << 'PAIRWISE' if ki & KEY_INFO_PAIRWISE != 0
  parts.join('|')
end

def analyze_eapol_key(key_data, bssid, client)
  return unless key_data.size >= 95

  desc_version = key_data[0].ord
  key_info = key_data[1..2].unpack1('v')
  key_len = key_data[3..4].unpack1('v')
  replay_counter = key_data[5..12].unpack1('Q>')
  nonce = key_data[13..44]
  iv = key_data[45..60]
  rsc = key_data[61..68]
  mic = key_data[77..92]
  # data_len follows at 93-94, then key_data at 95+

  handshake_msg = case [key_info & KEY_INFO_ACK != 0, key_info & KEY_INFO_MIC != 0, key_info & KEY_INFO_SECURE != 0, key_info & KEY_INFO_INSTALL != 0]
                  when [true, false, false, true] then 'Message 1'
                  when [false, true, false, false] then 'Message 2'
                  when [true, true, true, true] then 'Message 3'
                  when [false, true, true, false] then 'Message 4'
                  else 'Unknown'
                  end

  result = {
    desc_version: desc_version,
    key_info: format('0x%04x', key_info),
    key_info_desc: key_info_description(key_info),
    key_len: key_len,
    replay_counter: replay_counter,
    anonce: nonce.unpack1('H*'),
    snonce: nonce.unpack1('H*'),
    iv: iv.unpack1('H*'),
    rsc: rsc.unpack1('H*'),
    mic: mic.unpack1('H*'),
    handshake_msg: handshake_msg,
    pairwise: key_info & KEY_INFO_PAIRWISE != 0
  }

  emit('eapol_key_analysis', '', bssid, '', 0, result.merge(client: client))
  result
end

def process_pcap(pcap_path)
  unless File.exist?(pcap_path)
    emit('pcap_not_found', '', '', '', 0, { path: pcap_path })
    return
  end

  file_size = File.size(pcap_path)
  emit('pcap_open', '', '', '', 0, { path: pcap_path, size: file_size })

  eapol_frames = []
  handshake_complete = false
  handshake_params = {}

  File.open(pcap_path, 'rb') do |f|
    global_header = f.read(24)
    return unless global_header && global_header.size == 24

    magic = global_header[0..3]
    if magic == "\xa1\xb2\xc3\xd4" || magic == "\xd4\xc3\xb2\xa1"
      endian = magic == "\xd4\xc3\xb2\xa1" ? :little : :big
      emit('pcap_format', '', '', '', 0, { magic: magic.unpack1('H*'), endian: endian })
    else
      emit('pcap_invalid_magic', '', '', '', 0, { magic: magic.unpack1('H*') })
      return
    end

    max_frames = 10_000
    frame_count = 0

    while frame_count < max_frames
      pkt_header = f.read(16)
      break unless pkt_header && pkt_header.size == 16

      if endian == :little
        ts_sec = pkt_header[0..3].unpack1('V')
        incl_len = pkt_header[8..11].unpack1('V')
      else
        ts_sec = pkt_header[0..3].unpack1('N')
        incl_len = pkt_header[8..11].unpack1('N')
      end

      pkt_data = f.read(incl_len)
      break unless pkt_data && pkt_data.size == incl_len
      frame_count += 1

      radiotap_len = pkt_data[2..3].unpack1('v') rescue 0
      next if radiotap_len < 4 || radiotap_len >= pkt_data.size
      frame = pkt_data[radiotap_len..]
      next if frame.nil? || frame.size < 24

      fc = frame[0..1].unpack1('v')
      frame_type = (fc >> 2) & 0x3
      frame_subtype = (fc >> 4) & 0xF
      to_ds = (fc >> 8) & 0x1
      from_ds = (fc >> 9) & 0x1

      addr1 = mac_str(frame[4..9])
      addr2 = mac_str(frame[10..15])
      addr3 = mac_str(frame[16..21])
      bssid = if to_ds == 0 && from_ds == 0
                addr3
              elsif to_ds == 1 && from_ds == 0
                addr1
              elsif to_ds == 0 && from_ds == 1
                addr2
              else
                addr3
              end

      # Look for QoS + LLC + SNAP + EAPOL
      llc_offset = 24
      if (frame_type == 2 || frame_type == 0) && frame.size > llc_offset + 8
        snap = frame[llc_offset, 8]
        if snap && snap[0..2] == "\xaa\xaa\x03" && snap[3..4] == "\x00\x00" && snap[5..7] == "\x88\x8e\x47"
          eapol_start = llc_offset + 8
          eapol_pkt = frame[eapol_start..]
          next if eapol_pkt.nil? || eapol_pkt.size < EAPOL_HEADER_SIZE

          eapol_version = eapol_pkt[0].ord
          eapol_type = eapol_pkt[1].ord
          eapol_body_len = eapol_pkt[2..3].unpack1('n')
          body = eapol_pkt[4..] || ''

          next unless eapol_type == EAPOL_KEY && body.size >= 95

          key_data = body[0..94]
          client = if from_ds == 1 then addr2 else addr1 end

          analysis = analyze_eapol_key(key_data, bssid, client)
          eapol_frames << analysis

          case analysis[:handshake_msg]
          when 'Message 1'
            handshake_params[:anonce] = analysis[:anonce]
            handshake_params[:bssid] = bssid
            handshake_params[:client] = client
          when 'Message 2'
            handshake_params[:snonce] = analysis[:snonce] if handshake_params[:anonce]
          when 'Message 3'
            handshake_params[:anonce_m3] = analysis[:anonce]
            handshake_params[:mic_m3] = analysis[:mic]
          when 'Message 4'
            handshake_params[:mic_m4] = analysis[:mic]
            handshake_complete = true
          end

          if handshake_complete && handshake_params[:anonce] && handshake_params[:snonce]
            emit('handshake_complete', '', bssid, '', 0, handshake_params)
            handshake_complete = false
          end
        end
      end
    end

    emit('eapol_summary', '', '', '', 0, {
      total_eapol_frames: eapol_frames.size,
      frames_processed: frame_count,
      bssids: eapol_frames.map { |e| e[:bssid] }.compact.uniq
    })
  end

  emit('pcap_analysis_complete', '', '', '', 0, { path: pcap_path, eapol_frames: eapol_frames.size })
end

begin
  pcap_file = ARGV[0]
  raise 'pcap_file path required' unless pcap_file

  emit('eapol_analyzer_start', '', '', '', 0, { pcap: pcap_file })
  process_pcap(pcap_file)
  emit('eapol_analyzer_complete', '', '', '', 0, {})

rescue Interrupt
  emit('eapol_analyzer_interrupted', '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
