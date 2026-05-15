require 'socket'
require 'openssl'
require 'json'

def audit_http(host, port)
  begin
    socket = TCPSocket.new(host, port)
    socket.print("GET / HTTP/1.1\r\nHost: #{host}\r\nConnection: close\r\n\r\n")
    response = socket.read
    socket.close

    headers = {}
    response.split("\r\n\r\n").first.split("\r\n").each do |line|
      if line.include?(":")
        key, value = line.split(":", 2)
        headers[key.strip] = value.strip
      end
    end

    {
      server: headers['Server'] || 'Unknown',
      powered_by: headers['X-Powered-By'],
      content_type: headers['Content-Type'],
      security_headers: {
        hsts: headers.key?('Strict-Transport-Security'),
        csp: headers.key?('Content-Security-Policy'),
        xss: headers.key?('X-XSS-Protection')
      }
    }
  rescue => e
    { error: e.message }
  end
end

def audit_ssl(host, port)
  begin
    tcp_client = TCPSocket.new(host, port)
    ssl_context = OpenSSL::SSL::SSLContext.new
    ssl_client = OpenSSL::SSL::SSLSocket.new(tcp_client, ssl_context)
    ssl_client.connect
    cert = ssl_client.peer_cert
    ssl_client.close

    {
      subject: cert.subject.to_s,
      issuer: cert.issuer.to_s,
      not_before: cert.not_before,
      not_after: cert.not_after,
      serial: cert.serial.to_s
    }
  rescue => e
    { error: e.message }
  end
end

# CLI Entry Point
target_host = ARGV[0]
target_port = ARGV[1].to_i
mode = ARGV[2] || "http"

if mode == "http"
  puts audit_http(target_host, target_port).to_json
elsif mode == "ssl"
  puts audit_ssl(target_host, target_port).to_json
else
  puts { error: "Unknown mode" }.to_json
end
