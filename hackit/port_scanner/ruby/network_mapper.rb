require 'socket'
require 'timeout'
require 'json'
require 'ipaddr'

module HackIT
  class NetworkMapper
    def self.plugin_info
      {
        name: 'NetworkMapper',
        version: '1.3.0',
        description: 'Network mapper: traceroute (ICMP/UDP), hop analysis, latency measurement, bandwidth estimation, path MTU discovery',
        author: 'HackIT Team'
      }
    end

    def run(target, port = 0, opts = {})
      findings = []
      risk_score = 0
      max_hops = opts[:max_hops] || 30
      timeout_sec = opts[:timeout] || 3

      begin
        trace = traceroute(target, max_hops, timeout_sec)
        findings.concat(trace[:findings])
        risk_score += trace[:risk_score]
      rescue => e
        findings << "Traceroute error: #{e.message}"
      end

      begin
        latency = measure_latency(target, timeout_sec)
        findings.concat(latency[:findings])
        risk_score += latency[:risk_score]
      rescue => e
        findings << "Latency error: #{e.message}"
      end

      begin
        mtu = discover_path_mtu(target, timeout_sec)
        findings.concat(mtu[:findings])
        risk_score += mtu[:risk_score]
      rescue => e
        findings << "MTU error: #{e.message}"
      end

      begin
        hops = trace[:hops]
        unless hops.empty?
          hop_analysis = analyze_hops(hops)
          findings.concat(hop_analysis[:findings])
          risk_score += hop_analysis[:risk_score]
        end
      rescue => e
        findings << "Hop analysis error: #{e.message}"
      end

      begin
        bw = estimate_bandwidth(target, timeout_sec)
        findings.concat(bw[:findings])
      rescue
      end

      { status: findings.any? ? 'completed' : 'failed', findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def traceroute(target, max_hops, timeout_sec)
      findings = []
      risk_score = 0
      hops = []

      begin
        dest_ip = Resolv.getaddress(target)
        findings << "Resolved #{target} -> #{dest_ip}"

        (1..max_hops).each do |ttl|
          result = send_probe(dest_ip, ttl, timeout_sec)
          hops << { hop: ttl, ip: result[:ip], host: result[:host], time: result[:time], status: result[:status] }

          if result[:status] == 'timeout'
            findings << "Hop #{ttl}: * * * (timeout)"
          else
            time_str = result[:time] ? "#{result[:time]}ms" : 'N/A'
            host_str = result[:host] != result[:ip] ? " (#{result[:host]})" : ''
            findings << "Hop #{ttl}: #{result[:ip]}#{host_str} #{time_str}"

            if %w[private 10. 172.1[6-9] 172.2[0-9] 172.3[0-1] 192.168.].any? { |p| result[:ip].match?(/^#{p}/) }
              findings << "  Private IP detected at hop #{ttl}"
            end
          end

          if result[:ip] == dest_ip || result[:host] == target
            findings << "Reached destination at hop #{ttl}"
            break
          end
        end
      rescue => e
        findings << "Traceroute: #{e.message}"
      end

      { findings: findings, risk_score: risk_score, hops: hops }
    end

    def send_probe(dest_ip, ttl, timeout_sec)
      result = { ip: '*', host: '*', time: nil, status: 'timeout' }

      begin
        Timeout.timeout(timeout_sec) do
          start_time = Time.now

          udp = UDPSocket.new(Socket::AF_INET)
          udp.setsockopt(Socket::IPPROTO_IP, Socket::IP_TTL, ttl)
          dest_port = 33434 + ttl
          udp.send('', 0, dest_ip, dest_port)

          icmp = Socket.new(Socket::AF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
          icmp.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO, [1, 0].pack('l_2'))

          resp = icmp.recvfrom(512)
          elapsed = ((Time.now - start_time) * 1000).round(1)
          resp_ip = resp[1].ip_address rescue resp[1].to_s

          if resp_ip
            result[:ip] = resp_ip
            result[:time] = elapsed
            result[:status] = 'ok'
            result[:host] = resolve_host(resp_ip)
          end
          udp.close
          icmp.close
        end
      rescue Errno::EACCES
        result = send_probe_tcp(dest_ip, ttl, timeout_sec)
      rescue Timeout::Error
      rescue => e
        result[:status] = "error: #{e.message}"
      end

      result
    end

    def send_probe_tcp(dest_ip, ttl, timeout_sec)
      result = { ip: '*', host: '*', time: nil, status: 'timeout' }

      begin
        Timeout.timeout(timeout_sec) do
          start_time = Time.now
          s = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
          s.setsockopt(Socket::IPPROTO_IP, Socket::IP_TTL, ttl)
          sa = Socket.sockaddr_in(80, dest_ip)

          begin
            s.connect_nonblock(sa)
          rescue Errno::EINPROGRESS
            _, writable, _ = IO.select(nil, [s], nil, timeout_sec)
            if writable
              elapsed = ((Time.now - start_time) * 1000).round(1)
              peername = s.getpeername
              if peername
                port, ip = Socket.unpack_sockaddr_in(peername)
                result[:ip] = ip
                result[:time] = elapsed
                result[:status] = 'ok'
                result[:host] = resolve_host(ip)
              end
            end
          end
          s.close
        end
      rescue
      end

      result
    end

    def resolve_host(ip)
      Resolv.getname(ip)
    rescue
      ip
    end

    def measure_latency(target, timeout_sec)
      findings = []
      risk_score = 0
      times = []

      3.times do
        begin
          Timeout.timeout(timeout_sec) do
            start = Time.now
            s = TCPSocket.new(target, 80)
            s.close
            elapsed = ((Time.now - start) * 1000).round(1)
            times << elapsed
          end
        rescue
        end
      end

      unless times.empty?
        avg = (times.sum / times.size).round(1)
        min = times.min.round(1)
        max = times.max.round(1)
        findings << "Latency: avg=#{avg}ms min=#{min}ms max=#{max}ms (n=#{times.size})"

        if avg > 500
          findings << 'High latency detected'
        elsif avg > 200
          findings << 'Moderate latency'
          risk_score += 5
        end

        if max - min > 100
          findings << 'Jitter detected (significant latency variation)'
          risk_score += 5
        end
      else
        findings << 'Latency measurement failed (connection refused)'
      end

      { findings: findings, risk_score: risk_score }
    end

    def discover_path_mtu(target, timeout_sec)
      findings = []
      risk_score = 0
      mtu_sizes = [1500, 1492, 1472, 1468, 1450, 1430, 1400, 1300, 1280, 1200, 1100, 1000, 900, 800, 700, 600, 500, 400, 300, 200, 100, 68]

      mtu_sizes.each do |size|
        begin
          Timeout.timeout(timeout_sec) do
            s = UDPSocket.new(Socket::AF_INET)
            s.setsockopt(Socket::IPPROTO_IP, Socket::IP_MTU_DISCOVER, 1)
            s.connect(target, 80)
            payload = 'X' * (size - 28)
            s.send(payload, 0)
            s.close
            findings << "Path MTU >= #{size} (packet sent successfully)"
            return { findings: findings, risk_score: 0 } if size == 1500
          end
        rescue Errno::EMSGSIZE
          next
        rescue Timeout::Error
          findings << "Path MTU measurement timeout at #{size}"
          break
        rescue
          findings << "MTU: #{size} (probe failed)"
          break
        end
      end

      { findings: findings, risk_score: 0 }
    end

    def analyze_hops(hops)
      findings = []
      risk_score = 0
      ips = hops.select { |h| h[:ip] != '*' }.map { |h| h[:ip] }

      asns = {}
      ips.uniq.each do |ip|
        asn = guess_asn(ip)
        asns[ip] = asn if asn
        break if asns.size >= 5
      end

      unless asns.empty?
        findings << "ASN/Org hints: #{asns.map { |ip, asn| "#{ip}=#{asn}" }.join(', ')}"
        risk_score += 5
      end

      times = hops.select { |h| h[:time] }.map { |h| h[:time] }
      if times.size >= 2
        avg_rtt = times.sum / times.size
        if avg_rtt > 100
          findings << 'High average RTT across hops - possible geographic distance'
        end
      end

      hop_count = ips.size
      findings << "Distance: #{hop_count} hops to target"
      if hop_count <= 5
        findings << 'Target is nearby (<= 5 hops)'
      elsif hop_count <= 15
        findings << 'Target is moderate distance'
      elsif hop_count > 20
        findings << 'Target is far (> 20 hops)'
      end

      { findings: findings, risk_score: risk_score }
    end

    def guess_asn(ip)
      octets = ip.split('.')
      if octets.size == 4
        first = octets[0].to_i
        case first
        when 1..9 then 'AS15169 (Google)'
        when 13..15 then 'AS3 (General Electric)'
        when 17..19 then 'AS714 (Apple)'
        when 23 then 'AS54113 (Fastly)'
        when 31 then 'AS1239 (Sprint)'
        when 34 then 'AS15169 (Google)'
        when 44 then 'AS3212 (DARPA)'
        when 45 then 'AS63311 (Various)'
        when 50..57 then 'Various US'
        when 63..65 then 'Various US'
        when 66 then 'AS22822 (Various)'
        when 67..69 then 'Various'
        when 72 then 'AS23033 (Various)'
        when 74..76 then 'Various'
        when 98..99 then 'Various'
        when 104..107 then 'AS13335 (Cloudflare)'
        when 108..111 then 'Various'
        when 128..131 then 'Various US'
        when 134..139 then 'Various US'
        when 140..143 then 'Various US'
        when 144..147 then 'Various'
        when 151..155 then 'Various US'
        when 157..159 then 'Various'
        when 161..163 then 'Various'
        when 164..166 then 'Various US'
        when 167..169 then 'Various'
        when 170..174 then 'Various US'
        when 175..177 then 'Various'
        when 184..188 then 'Various'
        when 192 then 'Various'
        when 193..195 then 'RIPE (Europe)'
        when 196..199 then 'Various'
        when 200..203 then 'APNIC (Asia-Pacific)'
        when 204..209 then 'ARIN (US)'
        when 210..211 then 'APNIC'
        when 212..213 then 'RIPE'
        when 216 then 'AS15169 (Google) / Various'
        else nil
        end
      end
    end

    def estimate_bandwidth(target, timeout_sec)
      findings = []

      begin
        Timeout.timeout(timeout_sec) do
          start = Time.now
          s = TCPSocket.new(target, 80)
          s.write("GET / HTTP/1.0\r\nHost: #{target}\r\nConnection: close\r\n\r\n")
          data = s.read(32768)
          s.close
          elapsed = Time.now - start
          if data && elapsed > 0
            bytes = data.bytesize
            bps = (bytes * 8) / elapsed
            if bps > 1_000_000
              findings << "Est. bandwidth: #{(bps / 1_000_000).round(1)} Mbps"
            elsif bps > 1_000
              findings << "Est. bandwidth: #{(bps / 1_000).round(1)} Kbps"
            else
              findings << "Est. bandwidth: #{bps.round(1)} bps"
            end
          end
        end
      rescue
        findings << 'Bandwidth estimation unavailable'
      end

      { findings: findings, risk_score: 0 }
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || '127.0.0.1'
  port = (ARGV[1] || 0).to_i
  mapper = HackIT::NetworkMapper.new
  result = mapper.run(target, port)
  puts JSON.pretty_generate(result)
end
