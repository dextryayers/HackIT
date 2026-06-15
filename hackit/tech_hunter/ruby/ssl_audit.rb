#!/usr/bin/env ruby
# SSL/TLS Certificate Deep Audit
require 'json'
require 'openssl'
require 'socket'
require 'resolv'

domain = ARGV[0] || ''
return puts JSON.generate({ error: 'No domain provided' }) if domain.empty?

host = domain.sub(/^https?:\/\//, '').sub(/\/.*$/, '')
port = 443

# Pre-resolve hostname using Google DNS (avoids system resolver timeouts on IPv6-only DNS)
begin
  resolv = Resolv::DNS.new(nameserver: ['8.8.8.8'])
  ip = resolv.getaddress(host).to_s
rescue => e
  ip = host # fallback to hostname if DNS fails
end

begin
  ctx = OpenSSL::SSL::SSLContext.new
  ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
  sock = TCPSocket.new(ip, port)
  sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
  ssl = OpenSSL::SSL::SSLSocket.new(sock, ctx)
  ssl.hostname = host
  ssl.sync_close = true
  ssl.connect

  cert = ssl.peer_cert
  return puts JSON.generate({ error: 'No certificate' }) unless cert

  result = {
    subject: cert.subject.to_s,
    issuer: cert.issuer.to_s,
    serial: cert.serial.to_s,
    version: cert.version,
    not_before: cert.not_before.to_s,
    not_after: cert.not_after.to_s,
    days_remaining: ((cert.not_after - Time.now) / 86400).to_i,
    expired: Time.now > cert.not_after,
    self_signed: cert.subject == cert.issuer,
    signature_algorithm: cert.signature_algorithm,
    public_key_algorithm: cert.public_key.class.name.split('::').last,
    subject_alt_names: [],
    chain_length: ssl.peer_cert_chain ? ssl.peer_cert_chain.length : 1,
  }

  # Extract SANs
  if cert.extensions
    cert.extensions.each do |ext|
      if ext.oid == 'subjectAltName'
        result[:subject_alt_names] = ext.value.split(', ').map { |v| v.sub(/^DNS:/, '') }
      end
    end
  end

  # Key size
  pk = cert.public_key
  result[:key_size] = if pk.respond_to?(:n)
    pk.n.num_bits
  elsif pk.respond_to?(:group)
    group = pk.group
    group.respond_to?(:order) ? group.order.num_bits : (group.respond_to?(:bit_length) ? group.bit_length : 256)
  else
    0
  end

  # Security checks
  warnings = []
  warnings << 'Certificate expired!' if result[:expired]
  warnings << "Expires in #{result[:days_remaining]} days" if result[:days_remaining] < 30 && result[:days_remaining] > 0
  warnings << 'Self-signed' if result[:self_signed]
  warnings << 'Weak RSA key (<2048 bits)' if result[:public_key_algorithm] == 'RSA' && result[:key_size] < 2048
  warnings << 'Weak ECDSA key (<256 bits)' if result[:public_key_algorithm] == 'EC' && result[:key_size] < 256
  result[:warnings] = warnings

  ssl.close
  sock.close

  puts JSON.generate(result)
rescue => e
  puts JSON.generate({ error: e.message })
end
