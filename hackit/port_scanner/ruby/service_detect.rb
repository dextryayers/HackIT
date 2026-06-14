require 'socket'
require 'timeout'
require 'json'

module HackIT
  class ServiceDetect
    PROBES = {
      21 => { name: 'FTP', send: "HELP\r\n", expect: /220|FTP|FileZilla|vsFTPd|ProFTPD|Pure-FTPd/i },
      22 => { name: 'SSH', send: nil, expect: /SSH|OpenSSH|dropbear|libssh/i },
      25 => { name: 'SMTP', send: "EHLO scan\r\n", expect: /220|SMTP|Postfix|Sendmail|Exim|Exchange|qmail/i },
      80 => { name: 'HTTP', send: "GET / HTTP/1.1\r\nHost: placeholder\r\nConnection: close\r\n\r\n", expect: /HTTP\/\d\.\d|Server:|Apache|nginx|IIS|lighttpd/i },
      110 => { name: 'POP3', send: "CAPA\r\n", expect: /\+OK|POP3|Dovecot|Courier/i },
      143 => { name: 'IMAP', send: "a001 CAPABILITY\r\n", expect: /\* OK|IMAP|Dovecot|Courier|Cyrus/i },
      443 => { name: 'HTTPS', send: nil, expect: nil, ssl: true },
      3306 => { name: 'MySQL', send: "\x0a", expect: /mysql|MariaDB|5\.\d+\.\d+/i },
      6379 => { name: 'Redis', send: "PING\r\n", expect: /\+PONG|-ERR|redis/i },
      27017 => { name: 'MongoDB', send: nil, expect: /MongoDB/i },
      5432 => { name: 'PostgreSQL', send: nil, expect: /PostgreSQL|PG|8\.[0-9]|9\.[0-9]/i },
      11211 => { name: 'Memcached', send: "stats\r\n", expect: /STAT|memcached|VERSION/i },
      161 => { name: 'SNMP', send: nil, expect: nil, udp: true },
      389 => { name: 'LDAP', send: nil, expect: /LDAP|OpenLDAP/i },
      1433 => { name: 'MSSQL', send: nil, expect: /MSSQL|Microsoft SQL|TDS/i },
      1521 => { name: 'Oracle', send: nil, expect: /Oracle|TNS|Xe|Oracle/i },
      5900 => { name: 'VNC', send: nil, expect: /RFB|VNC/i },
      3389 => { name: 'RDP', send: nil, expect: /RDP|Terminal|MS\-TDS/i }
    }

    PROTOCOL_BANNERS = {
      ftp: ->(b) { b[/220[\s-](.+?)(?:\r?\n|$)/, 1] },
      ssh: ->(b) { b[/SSH-\d+\.\d+-([^\r\n]+)/, 1] },
      smtp: ->(b) { b[/220[\s-]([^\r\n]+)/, 1] },
      http: ->(b) { b[/Server:\s*([^\r\n]+)/i, 1] },
      pop3: ->(b) { b[/\+OK[\s-]([^\r\n]+)/, 1] },
      imap: ->(b) { b[/\* OK[\s-]([^\r\n]+)/, 1] },
      mysql: ->(b) { b[/^.(\d+\.\d+\.\d+)/m, 1] },
      redis: ->(b) { b[/[+-]([^\r\n]+)/, 1] }
    }

    def self.plugin_info
      {
        name: 'ServiceDetect',
        version: '2.0.0',
        description: 'Service identification via banner grabbing with protocol-specific probes, version extraction, and CPE generation',
        author: 'HackIT Team'
      }
    end

    def run(target, port, opts = {})
      findings = []
      risk_score = 0
      p = port.to_i

      probe = PROBES[p]
      if probe
        result = probe_port(target, p, probe, opts)
        findings.concat(result[:findings])
        risk_score += result[:risk_score]
      else
        result = generic_probe(target, p, opts)
        findings.concat(result[:findings])
        risk_score += result[:risk_score]
      end

      if p == 443
        result = probe_port(target, 443, PROBES[443] || { name: 'HTTPS', ssl: true }, opts)
        findings.concat(result[:findings])
        risk_score += result[:risk_score]
      end

      findings << "Service: #{findings.first || 'Unknown'}" unless findings.empty?

      { status: findings.any? ? 'completed' : 'completed', findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def probe_port(target, port, probe, opts)
      findings = []
      risk_score = 0
      timeout_sec = opts[:timeout] || 5

      begin
        Timeout.timeout(timeout_sec) do
          banner = ''
          s = nil

          if probe[:ssl]
            require 'openssl'
            tcp = TCPSocket.new(target, port)
            ctx = OpenSSL::SSL::SSLContext.new
            ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
            s = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
            s.connect
          elsif probe[:udp]
            s = UDPSocket.new
            s.connect(target, port)
            s.send("", 0)
          else
            s = TCPSocket.new(target, port)
            s.write(probe[:send]) if probe[:send]
          end

          if s
            banner = s.gets(4096).to_s + s.read(2048).to_s rescue banner
            s.close rescue nil
          end

          unless banner.empty?
            findings << "Banner: #{banner.strip[0..200]}"

            version = extract_version(probe[:name], banner)
            if version
              findings << "Version: #{version}"
              cpe = generate_cpe(probe[:name], version)
              findings << "CPE: #{cpe}" if cpe
            end

            if banner.match?(/(220|\+OK).*ready/i)
              findings << "#{probe[:name]} service ready"
            end

            if probe[:expect] && banner.match?(probe[:expect])
              findings << "Confirmed: #{probe[:name]}"
            end

            if probe[:name] == 'FTP' && banner.match?(/(vsFTPd|ProFTPD|Pure-FTPd)/i)
              risk_score += 5
            elsif probe[:name] == 'SSH'
              risk_score += 3
            elsif probe[:name] == 'SMTP'
              if banner.match?(/ESMTP|Exim|Sendmail/i)
                risk_score += 10
              end
            end
          end
        end
      rescue => e
        findings << "#{probe[:name]} probe: #{e.message}"
      end

      { findings: findings, risk_score: risk_score }
    end

    def generic_probe(target, port, opts)
      findings = []
      risk_score = 0
      timeout_sec = opts[:timeout] || 3

      begin
        Timeout.timeout(timeout_sec) do
          s = TCPSocket.new(target, port)
          s.write("\r\n")
          banner = s.gets(4096).to_s + s.read(2048).to_s rescue banner
          s.close

          unless banner.to_s.empty?
            findings << "Banner: #{banner.strip[0..200]}"
            risk_score += 5
          end
        end
      rescue => e
        findings << "Generic probe: #{e.message}"
      end

      { findings: findings, risk_score: risk_score }
    end

    def extract_version(service, banner)
      patterns = {
        'FTP' => /(vsFTPd[\s-][\d.]+|FileZilla[\s-][\d.]+|ProFTPD[\s-][\d.]+|Pure-FTPd[\s-][\d.]+)/i,
        'SSH' => /OpenSSH[_-][\d.]+|dropbear[\s_][\d.]+/i,
        'SMTP' => /Postfix[\s-][\d.]+|Sendmail[\s-][\d.]+|Exim[\s-][\d.]+|Courier[\s-][\d.]+/i,
        'HTTP' => /Apache[\s/][\d.]+|nginx[\s/][\d.]+|IIS[\s/][\d.]+|lighttpd[\s/][\d.]+/i,
        'POP3' => /Dovecot[\s-][\d.]+|Courier[\s-][\d.]+/i,
        'IMAP' => /Dovecot[\s-][\d.]+|Courier[\s-][\d.]+/i,
        'MySQL' => /[\d.]+-\w+|mysql\s+Ver\s+[\d.]+/i,
        'Redis' => /redis_version:([\d.]+)/i,
        'MongoDB' => /[\d.]+/
      }

      pat = patterns[service]
      if pat && banner.match?(pat)
        banner.match(pat)[0]
      end
    end

    def generate_cpe(service, version)
      cpe_map = {
        'FTP' => 'cpe:/a:',
        'SSH' => 'cpe:/a:openbsd:openssh:',
        'HTTP' => 'cpe:/a:',
        'SMTP' => 'cpe:/a:',
        'MySQL' => 'cpe:/a:oracle:mysql:',
        'Redis' => 'cpe:/a:redis:redis:',
        'PostgreSQL' => 'cpe:/a:postgresql:postgresql:',
        'MongoDB' => 'cpe:/a:mongodb:mongodb:'
      }

      prefix = cpe_map[service]
      if prefix
        ver = version.gsub(/[^0-9.]/, '').strip
        "#{prefix}#{ver}" unless ver.empty?
      end
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || '127.0.0.1'
  port = (ARGV[1] || 80).to_i
  detect = HackIT::ServiceDetect.new
  result = detect.run(target, port)
  puts JSON.pretty_generate(result)
end
