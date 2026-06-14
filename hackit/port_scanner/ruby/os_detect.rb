require 'socket'
require 'timeout'
require 'json'

module HackIT
  class OSDetect
    TTL_SIGNATURES = {
      32 => 'Windows 95/98/NT',
      64 => 'Linux/Unix (various)',
      128 => 'Windows NT/2000/XP/7/8/10/11',
      255 => 'Cisco IOS / Solaris / FreeBSD',
      60 => 'Linux (some kernels)',
      100 => 'FreeBSD / NetBSD',
      254 => 'Solaris / AIX',
      48 => 'Android / Embedded Linux',
      30 => 'Embedded device (e.g., router)'
    }

    WINDOW_SIZE_SIGNATURES = {
      65535 => 'Linux / FreeBSD',
      8192 => 'Windows (some versions)',
      16384 => 'Windows 7/Server 2008',
      64240 => 'Windows 10/11',
      5840 => 'Cisco IOS',
      14600 => 'Solaris',
      65520 => 'macOS / BSD',
      32768 => 'OpenBSD',
      57344 => 'Linux (newer kernels)'
    }

    TCP_OPTION_SIGNATURES = {
      'mss:wscale:timestamp' => 'Linux 2.6+',
      'mss:wscale' => 'Windows',
      'mss:wscale:timestamp:sack' => 'Linux, macOS',
      'mss:nop:wscale:nop:timestamp:sack' => 'Windows 10/11',
      'mss:wscale:selective' => 'FreeBSD',
      'mss:timestamp:wscale' => 'Cisco IOS'
    }

    def self.plugin_info
      {
        name: 'OSDetect',
        version: '1.2.0',
        description: 'Remote OS detection via TTL analysis, TCP/IP fingerprint heuristics, window size, and port pattern analysis',
        author: 'HackIT Team'
      }
    end

    def run(target, port = 80, opts = {})
      findings = []
      risk_score = 0

      ttl_result = analyze_ttl(target, opts)
      findings.concat(ttl_result[:findings])
      risk_score += ttl_result[:risk_score]

      tcp_result = analyze_tcp_fingerprint(target, port, opts)
      findings.concat(tcp_result[:findings])
      risk_score += tcp_result[:risk_score]

      port_result = analyze_port_patterns(target, opts)
      findings.concat(port_result[:findings])
      risk_score += port_result[:risk_score]

      if findings.empty?
        findings << 'Unable to determine OS'
        status = 'completed'
      else
        status = 'completed'
      end

      { status: status, findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def analyze_ttl(target, opts)
      findings = []
      risk_score = 0

      begin
        Timeout.timeout(opts[:timeout] || 5) do
          s = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
          sa = Socket.sockaddr_in(80, target)
          begin
            s.connect_nonblock(sa)
          rescue Errno::EINPROGRESS
            _, writable, _ = IO.select(nil, [s], nil, 2)
            if writable
              ttl = s.getsockopt(Socket::IPPROTO_IP, Socket::IP_TTL).intvalue rescue nil
              if ttl
                findings << "TTL: #{ttl}"
                os = TTL_SIGNATURES[ttl]
                if os
                  findings << "OS Guess (TTL): #{os}"
                  risk_score += 15
                else
                  closest = TTL_SIGNATURES.keys.min_by { |k| (k - ttl).abs }
                  if closest
                    findings << "OS Guess (TTL ~#{closest}): #{TTL_SIGNATURES[closest]}"
                    risk_score += 10
                  end
                end
              end
            end
          end
          s.close
        end
      rescue => e
        findings << "TTL analysis: #{e.message}"
      end

      unless findings.any? { |f| f.start_with?('TTL:') }
        begin
          Timeout.timeout(opts[:timeout] || 3) do
            ping_out = `ping -c 1 -W 1 #{target} 2>&1`
            if ping_out.match?(/ttl=(\d+)/i)
              ttl = $1.to_i
              findings << "TTL (ping): #{ttl}"
              os = TTL_SIGNATURES[ttl]
              if os
                findings << "OS Guess (ping TTL): #{os}"
                risk_score += 10
              end
            end
          end
        rescue
        end
      end

      { findings: findings, risk_score: risk_score }
    end

    def analyze_tcp_fingerprint(target, port, opts)
      findings = []
      risk_score = 0

      begin
        Timeout.timeout(opts[:timeout] || 5) do
          s = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
          sa = Socket.sockaddr_in(port.to_i, target)

          begin
            s.connect_nonblock(sa)
          rescue Errno::EINPROGRESS
            _, writable, _ = IO.select(nil, [s], nil, 2)
            if writable
              ws = s.getsockopt(Socket::SOL_TCP, Socket::TCP_MAXSEG).inspect rescue nil
              win = s.getsockopt(Socket::SOL_SOCKET, Socket::SO_RCVBUF).intvalue rescue nil

              if win
                findings << "TCP Window: #{win}"
                sig = WINDOW_SIZE_SIGNATURES[win]
                if sig
                  findings << "OS Guess (window size): #{sig}"
                  risk_score += 10
                else
                  closest = WINDOW_SIZE_SIGNATURES.keys.min_by { |k| (k - win).abs }
                  if closest && (closest - win).abs < 5000
                    findings << "OS Guess (window ~#{closest}): #{WINDOW_SIZE_SIGNATURES[closest]}"
                    risk_score += 8
                  end
                end
              end

              tcp_info = s.getsockopt(Socket::SOL_TCP, Socket::TCP_INFO).inspect rescue nil
              findings << "TCP info: #{tcp_info[0..80]}" if tcp_info
            end
          end
          s.close
        end
      rescue => e
        findings << "TCP fingerprint: #{e.message}"
      end

      { findings: findings, risk_score: risk_score }
    end

    def analyze_port_patterns(target, opts)
      findings = []
      risk_score = 0
      open_ports = []

      common_checks = [135, 139, 445, 3389, 5985, 5986, 22, 80, 443, 8080, 8443]
      semaphore = Mutex.new
      threads = []

      common_checks.each do |p|
        threads << Thread.new do
          begin
            Timeout.timeout(opts[:timeout] || 1) do
              s = TCPSocket.new(target, p)
              s.close
              semaphore.synchronize { open_ports << p }
            end
          rescue
          end
        end
      end
      threads.each(&:join)

      unless open_ports.empty?
        findings << "Open ports: #{open_ports.sort.join(', ')}"

        if (open_ports & [135, 139, 445, 3389, 5985]).any?
          findings << "Windows-like port pattern detected (SMB/RDP/WinRM)"
          risk_score += 20
        end
        if open_ports.include?(22) && open_ports.include?(80) && !(open_ports & [135, 139, 445]).any?
          findings << "Linux/Unix-like port pattern detected (SSH+HTTP)"
          risk_score += 10
        end
        if open_ports.include?(8080) && open_ports.include?(8443)
          findings << "Possible embedded device / proxy server"
          risk_score += 5
        end
        if (open_ports & [161, 162, 514]).any?
          findings << "Network device pattern (SNMP/syslog)"
          risk_score += 15
        end
      end

      { findings: findings, risk_score: risk_score }
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || '127.0.0.1'
  port = (ARGV[1] || 80).to_i
  detect = HackIT::OSDetect.new
  result = detect.run(target, port)
  puts JSON.pretty_generate(result)
end
