require 'socket'
require 'openssl'
require 'json'
require 'timeout'

module HackIT
  class SslScan
    TLS_VERSIONS = {
      'SSLv2' => OpenSSL::SSL::SSLContext::TLS_SERVER,
      'SSLv3' => OpenSSL::SSL::SSLContext::TLS_SERVER,
      'TLSv1.0' => OpenSSL::SSL::SSLContext::TLS_SERVER,
      'TLSv1.1' => OpenSSL::SSL::SSLContext::TLS_SERVER,
      'TLSv1.2' => OpenSSL::SSL::SSLContext::TLS_SERVER,
      'TLSv1.3' => OpenSSL::SSL::SSLContext::TLS_SERVER
    }

    VULNERABLE_CIPHERS = {
      'ECDHE-RSA-AES128-GCM-SHA256' => false,
      'DHE-RSA-AES128-GCM-SHA256' => false,
      'ECDHE-RSA-AES256-GCM-SHA384' => false,
      'DHE-RSA-AES256-GCM-SHA384' => false,
      'ECDHE-RSA-AES128-SHA' => 30,
      'ECDHE-RSA-AES256-SHA' => 30,
      'AES128-GCM-SHA256' => false,
      'AES256-GCM-SHA384' => false,
      'AES128-SHA' => 30,
      'AES256-SHA' => 30,
      'DES-CBC3-SHA' => 60,
      'RC4-SHA' => 80,
      'RC4-MD5' => 90,
      'EXP-DES-CBC-SHA' => 100,
      'EXP-RC2-CBC-MD5' => 100,
      'EXP-RC4-MD5' => 100,
      'NULL' => 100
    }

    def self.plugin_info
      {
        name: 'SslScan',
        version: '2.0.0',
        description: 'SSL/TLS scanner: certificate extraction, protocol negotiation, cipher enumeration, vulnerability checks',
        author: 'HackIT Team'
      }
    end

    def run(target, port, opts = {})
      findings = []
      risk_score = 0

      begin
        cert_result = extract_certificate(target, port, opts)
        findings.concat(cert_result[:findings])
        risk_score += cert_result[:risk_score]

        proto_result = negotiate_protocols(target, port, opts)
        findings.concat(proto_result[:findings])
        risk_score += proto_result[:risk_score]

        cipher_result = enumerate_ciphers(target, port, opts)
        findings.concat(cipher_result[:findings])
        risk_score += cipher_result[:risk_score]

        vuln_result = check_vulnerabilities(target, port, opts)
        findings.concat(vuln_result[:findings])
        risk_score += vuln_result[:risk_score]

      rescue => e
        findings << "SSL scan error: #{e.message}"
        risk_score = 0
      end

      { status: findings.any? ? 'completed' : 'failed', findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def extract_certificate(target, port, opts)
      findings = []
      risk_score = 0
      begin
        Timeout.timeout(opts[:timeout] || 5) do
          tcp = TCPSocket.new(target, port)
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
          ssl.connect
          cert = ssl.peer_cert
          ssl.close
          tcp.close

          if cert
            findings << "Subject: #{cert.subject}"
            findings << "Issuer: #{cert.issuer}"
            findings << "Serial: #{cert.serial.to_s(16)}"
            findings << "Version: #{cert.version}"
            findings << "Signature Algorithm: #{cert.signature_algorithm}"

            san_ext = cert.extensions.find { |e| e.oid == 'subjectAltName' }
            if san_ext
              sans = san_ext.value.split(', ').map { |s| s.split(':').last }
              findings << "SANs: #{sans.join(', ')}"
            end

            findings << "Valid From: #{cert.not_before}"
            findings << "Valid Until: #{cert.not_after}"

            days_left = ((cert.not_after - Time.now) / 86400).to_i
            if days_left < 0
              findings << "RISK: Certificate EXPIRED #{days_left.abs} days ago"
              risk_score += 50
            elsif days_left < 30
              findings << "WARNING: Certificate expires in #{days_left} days"
              risk_score += 20
            elsif days_left < 90
              findings << "NOTE: Certificate expires in #{days_left} days"
              risk_score += 5
            else
              findings << "Certificate valid for #{days_left} more days"
            end

            if cert.subject.to_s == cert.issuer.to_s
              findings << "RISK: Self-signed certificate detected"
              risk_score += 30
            end

            key_length = cert.public_key.n.num_bits if cert.public_key.respond_to?(:n)
            if key_length && key_length < 2048
              findings << "RISK: Weak key length (#{key_length} bits)"
              risk_score += 40
            end
          end
        end
      rescue => e
        findings << "Certificate extraction: #{e.message}"
      end
      { findings: findings, risk_score: risk_score }
    end

    def negotiate_protocols(target, port, opts)
      findings = []
      risk_score = 0
      versions_to_test = {
        'SSLv2' => { ctx: OpenSSL::SSL::SSLContext.new, ssl_version: :SSLv2 },
        'SSLv3' => { ctx: OpenSSL::SSL::SSLContext.new, ssl_version: :SSLv3 },
        'TLSv1.0' => { ctx: OpenSSL::SSL::SSLContext.new, ssl_version: :TLSv1 },
        'TLSv1.1' => { ctx: OpenSSL::SSL::SSLContext.new, ssl_version: :TLSv1_1 },
        'TLSv1.2' => { ctx: OpenSSL::SSL::SSLContext.new, ssl_version: :TLSv1_2 },
        'TLSv1.3' => { ctx: OpenSSL::SSL::SSLContext.new, ssl_version: :TLSv1_3 }
      }

      versions_to_test.each do |name, config|
        begin
          Timeout.timeout(opts[:timeout] || 3) do
            tcp = TCPSocket.new(target, port)
            ctx = OpenSSL::SSL::SSLContext.new
            ctx.ssl_version = config[:ssl_version] if config[:ssl_version]
            ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
            ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
            ssl.connect
            ssl.close
            tcp.close
            findings << "Supports: #{name}"
            if %w[SSLv2 SSLv3].include?(name)
              findings << "RISK: Deprecated protocol #{name} enabled"
              risk_score += 40
            elsif %w[TLSv1.0 TLSv1.1].include?(name)
              findings << "WARNING: Legacy protocol #{name} enabled"
              risk_score += 20
            end
          end
        rescue
        end
      end
      { findings: findings, risk_score: risk_score }
    end

    def enumerate_ciphers(target, port, opts)
      findings = []
      risk_score = 0
      ciphers = OpenSSL::Cipher.ciphers.uniq.select { |c| c.match?(/TLS|SSL/) }
      tested = 0

      ciphers.sample(50).each do |cipher_name|
        break if tested >= 20
        begin
          Timeout.timeout(opts[:timeout] || 2) do
            tcp = TCPSocket.new(target, port)
            ctx = OpenSSL::SSL::SSLContext.new
            ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
            ctx.ciphers = cipher_name
            ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
            ssl.connect
            ssl.close
            tcp.close
            findings << "Cipher: #{cipher_name}"
            tested += 1

            vuln_score = VULNERABLE_CIPHERS.find { |k, _| cipher_name.include?(k) }
            if vuln_score
              risk_score += vuln_score[1]
              findings << "VULN: Weak cipher #{cipher_name}" if vuln_score[1]
            end
          end
        rescue
        end
      end
      findings << "Enumerated #{tested} ciphers" if tested > 0
      { findings: findings, risk_score: risk_score }
    end

    def check_vulnerabilities(target, port, opts)
      findings = []
      risk_score = 0

      findings << "Checking Heartbleed (CVE-2014-0160)..."
      if check_heartbleed(target, port, opts)
        findings << "VULNERABLE: Heartbleed (CVE-2014-0160)"
        risk_score += 90
      else
        findings << "Not vulnerable to Heartbleed"
      end

      findings << "Checking POODLE (CVE-2014-3566)..."
      if check_poodle(target, port, opts)
        findings << "VULNERABLE: POODLE (CVE-2014-3566)"
        risk_score += 70
      else
        findings << "Not vulnerable to POODLE"
      end

      findings << "Checking FREAK (CVE-2015-0204)..."
      if check_freak(target, port, opts)
        findings << "VULNERABLE: FREAK (CVE-2015-0204)"
        risk_score += 60
      else
        findings << "Not vulnerable to FREAK"
      end

      findings << "Checking LOGJAM (CVE-2015-4000)..."
      if check_logjam(target, port, opts)
        findings << "VULNERABLE: LOGJAM (CVE-2015-4000)"
        risk_score += 50
      else
        findings << "Not vulnerable to LOGJAM"
      end

      { findings: findings, risk_score: risk_score }
    end

    def check_heartbleed(target, port, opts)
      begin
        Timeout.timeout(opts[:timeout] || 3) do
          tcp = TCPSocket.new(target, port)
          payload = "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
          tcp.write(payload)
          resp = tcp.read(1024)
          tcp.close
          resp && resp.length > 100
        end
      rescue
        false
      end
    end

    def check_poodle(target, port, opts)
      begin
        Timeout.timeout(opts[:timeout] || 3) do
          tcp = TCPSocket.new(target, port)
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.ssl_version = :SSLv3 rescue :TLSv1
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
          ssl.connect
          ssl.close
          tcp.close
          true
        end
      rescue
        false
      end
    end

    def check_freak(target, port, opts)
      begin
        Timeout.timeout(opts[:timeout] || 3) do
          tcp = TCPSocket.new(target, port)
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ctx.ciphers = 'EXP'
          ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
          ssl.connect
          ssl.close
          tcp.close
          true
        end
      rescue
        false
      end
    end

    def check_logjam(target, port, opts)
      begin
        Timeout.timeout(opts[:timeout] || 3) do
          tcp = TCPSocket.new(target, port)
          ctx = OpenSSL::SSL::SSLContext.new
          ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
          ctx.ciphers = 'DHE'
          ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
          ssl.connect
          ssl.close
          tcp.close
          true
        end
      rescue
        false
      end
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || '127.0.0.1'
  port = (ARGV[1] || 443).to_i
  scanner = HackIT::SslScan.new
  result = scanner.run(target, port)
  puts JSON.pretty_generate(result)
end
