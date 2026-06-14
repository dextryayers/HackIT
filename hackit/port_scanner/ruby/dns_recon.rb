require 'resolv'
require 'socket'
require 'timeout'
require 'json'

module HackIT
  class DnsRecon
    RECORD_TYPES = %w[A AAAA MX NS TXT SOA CNAME SRV PTR]
    COMMON_SRV = %w[_http._tcp _https._tcp _smtp._tcp _imap._tcp _pop3._tcp _ldap._tcp _kerberos._tcp _sip._tcp _xmpp-client._tcp _xmpp-server._tcp]

    def self.plugin_info
      {
        name: 'DnsRecon',
        version: '1.3.0',
        description: 'Comprehensive DNS reconnaissance with record enumeration, zone transfer attempts, and DNSSEC detection',
        author: 'HackIT Team'
      }
    end

    def run(target, port = 53, opts = {})
      findings = []
      risk_score = 0
      nameservers = opts[:nameservers] || resolv_config_nameservers

      begin
        dns = Resolv::DNS.new(nameserver: nameservers)
        resolver = dns

        RECORD_TYPES.each do |rtype|
          result = query_record(target, resolver, rtype)
          unless result[:records].empty?
            result[:records].each do |rec|
              findings << "#{rtype}: #{rec}"
            end
            risk_score += 5
          end
        end

        srv_result = query_srv_records(target, resolver)
        srv_result[:records].each do |rec|
          findings << "SRV: #{rec}"
        end
        risk_score += srv_result[:risk_score]

        soa_result = query_record(target, resolver, 'SOA')
        if soa_result[:records].any?
          findings << "SOA records found - zone transfer possible"
          axfr = attempt_axfr(target, nameservers)
          axfr[:records].each do |rec|
            findings << "AXFR: #{rec}"
          end
          risk_score += axfr[:risk_score]
          unless axfr[:records].empty?
            findings << "RISK: Zone transfer succeeded - full DNS zone dumped"
            risk_score += 30
          end
        end

        dnssec = detect_dnssec(target, resolver)
        if dnssec[:detected]
          findings << "DNSSEC enabled (DO bit set, RRSIG present)"
        end

        wildcard = detect_wildcard(target, resolver)
        if wildcard
          findings << "Wildcard DNS detected (*.#{target} resolves)"
        end

        ptr = query_ptr(target, resolver)
        ptr[:records].each do |rec|
          findings << "PTR: #{rec}"
        end

      rescue => e
        findings << "DNS resolution error: #{e.message}"
      end

      { status: findings.any? ? 'completed' : 'failed', findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def resolv_config_nameservers
      config = Resolv::DNS::Config.new
      config.nameservers
    rescue
      ['8.8.8.8', '8.8.4.4']
    end

    def query_record(target, resolver, rtype)
      records = []
      begin
        case rtype
        when 'A'
          resolver.getresources(target, Resolv::DNS::Resource::IN::A).each { |r| records << r.address.to_s }
        when 'AAAA'
          resolver.getresources(target, Resolv::DNS::Resource::IN::AAAA).each { |r| records << r.address.to_s }
        when 'MX'
          resolver.getresources(target, Resolv::DNS::Resource::IN::MX).each { |r| records << "#{r.preference} #{r.exchange.to_s}" }
        when 'NS'
          resolver.getresources(target, Resolv::DNS::Resource::IN::NS).each { |r| records << r.name.to_s }
        when 'TXT'
          resolver.getresources(target, Resolv::DNS::Resource::IN::TXT).each { |r| records << r.strings.join(' ') }
        when 'SOA'
          resolver.getresources(target, Resolv::DNS::Resource::IN::SOA).each { |r| records << "#{r.mname} #{r.rname} (serial #{r.serial})" }
        when 'CNAME'
          resolver.getresources(target, Resolv::DNS::Resource::IN::CNAME).each { |r| records << r.name.to_s }
        when 'PTR'
          resolver.getresources(target, Resolv::DNS::Resource::IN::PTR).each { |r| records << r.name.to_s }
        when 'SRV'
          resolver.getresources(target, Resolv::DNS::Resource::IN::SRV).each { |r| records << "#{r.target}:#{r.port} (priority #{r.priority}, weight #{r.weight})" }
        end
      rescue
      end
      { records: records, risk_score: records.any? ? 3 : 0 }
    end

    def query_srv_records(target, resolver)
      records = []
      risk_score = 0
      COMMON_SRV.each do |srv|
        begin
          fqdn = "#{srv}.#{target}"
          resolver.getresources(fqdn, Resolv::DNS::Resource::IN::SRV).each do |r|
            records << "#{srv} -> #{r.target}:#{r.port}"
            risk_score += 3
          end
        rescue
        end
      end
      { records: records, risk_score: risk_score }
    end

    def attempt_axfr(target, nameservers)
      records = []
      risk_score = 0
      soa_ns = []
      begin
        dns = Resolv::DNS.new(nameserver: nameservers)
        dns.getresources(target, Resolv::DNS::Resource::IN::NS).each { |r| soa_ns << r.name.to_s }
      rescue
        soa_ns = nameservers
      end

      soa_ns.each do |ns|
        begin
          Timeout.timeout(3) do
            s = TCPSocket.new(ns, 53)
            transfer = "\x00\x01" # header
            transfer << "\x00\x00\x00\x01" # questions
            transfer << "\x00\x00\x00\x00" # answers
            transfer << "\x00\x00\x00\x00" # authority
            transfer << "\x00\x00\x00\x00" # additional
            name_parts = target.split('.')
            name_parts.each do |part|
              transfer << [part.length].pack('C') + part
            end
            transfer << "\x00"
            transfer << "\x00\xFC" # AXFR type
            transfer << "\x00\x01" # IN class
            len = [transfer.length].pack('n')
            s.write(len + transfer)
            response = s.read(4096)
            s.close
            if response && response.length > 16
              records << "Zone transfer attempted on #{ns} - #{response.length} bytes received"
              risk_score += 15
            end
          end
        rescue => e
          records << "AXFR failed on #{ns}: #{e.message}"
        end
      end
      { records: records, risk_score: risk_score }
    end

    def detect_dnssec(target, resolver)
      detected = false
      begin
        msg = Resolv::DNS::Message.new
        msg.add_question(target, Resolv::DNS::Resource::IN::A)
        msg.header.do = 1
        reply = resolver.send(msg)
        reply.answer.each do |name, ttl, data|
          detected = true if data.is_a?(Resolv::DNS::Resource::IN::RRSIG)
        end
        reply.authority.each do |name, ttl, data|
          detected = true if data.is_a?(Resolv::DNS::Resource::IN::RRSIG) || data.is_a?(Resolv::DNS::Resource::IN::DNSKEY)
        end
      rescue
      end
      { detected: detected }
    end

    def detect_wildcard(target, resolver)
      random = "axfr-test-#{rand(10000)}.#{target}"
      begin
        resolver.getresources(random, Resolv::DNS::Resource::IN::A).any?
      rescue
        false
      end
    end

    def query_ptr(target, resolver)
      records = []
      begin
        addr = Resolv.getaddress(target)
        resolver.getresources(addr, Resolv::DNS::Resource::IN::PTR).each { |r| records << r.name.to_s }
      rescue
      end
      { records: records, risk_score: 0 }
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || 'example.com'
  port = (ARGV[1] || 53).to_i
  dns = HackIT::DnsRecon.new
  result = dns.run(target, port)
  puts JSON.pretty_generate(result)
end
