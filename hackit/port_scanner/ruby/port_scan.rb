require 'socket'
require 'timeout'
require 'json'

module HackIT
  class PortScan
    WELL_KNOWN = {
      21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP', 53 => 'DNS',
      80 => 'HTTP', 110 => 'POP3', 111 => 'RPC', 135 => 'RPC', 139 => 'NetBIOS',
      143 => 'IMAP', 161 => 'SNMP', 389 => 'LDAP', 443 => 'HTTPS',
      445 => 'SMB', 465 => 'SMTPS', 500 => 'ISAKMP', 514 => 'Syslog',
      587 => 'SMTP', 636 => 'LDAPS', 993 => 'IMAPS', 995 => 'POP3S',
      1433 => 'MSSQL', 1521 => 'Oracle', 2049 => 'NFS', 3306 => 'MySQL',
      3389 => 'RDP', 5432 => 'PostgreSQL', 5900 => 'VNC', 5985 => 'WinRM',
      5986 => 'WinRMs', 6379 => 'Redis', 8080 => 'HTTP-Alt', 8443 => 'HTTPS-Alt',
      9100 => 'JetDirect', 9200 => 'Elasticsearch', 11211 => 'Memcached',
      27017 => 'MongoDB', 50070 => 'Hadoop'
    }

    def self.plugin_info
      {
        name: 'PortScan',
        version: '2.1.0',
        description: 'Port scanning engine with TCP connect scan, configurable concurrency, SYN scan simulation, and service detection',
        author: 'HackIT Team'
      }
    end

    def run(target, port = nil, opts = {})
      findings = []
      risk_score = 0

      ports_to_scan = if port && port != 0
        [port.to_i]
      else
        opts[:ports] || common_ports
      end

      concurrency = opts[:concurrency] || 20
      scan_timeout = opts[:timeout] || 2

      open_ports = tcp_connect_scan(target, ports_to_scan, concurrency, scan_timeout)

      if opts[:syn_scan]
        syn_results = syn_scan_simulation(target, open_ports, scan_timeout)
        findings.concat(syn_results[:findings])
        risk_score += syn_results[:risk_score]
      end

      open_ports.each do |p|
        service = WELL_KNOWN[p] || "unknown-#{p}"
        findings << "OPEN: #{p}/tcp #{service}"

        risk_score += case service
        when 'Telnet', 'FTP', 'SNMP' then 20
        when 'MSSQL', 'Oracle', 'MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'Memcached' then 15
        when 'SSH', 'SMTP', 'POP3', 'IMAP' then 10
        when 'NetBIOS', 'SMB', 'RDP' then 25
        when 'VNC', 'RPC' then 30
        else 5
        end
      end

      findings << "Scan complete: #{open_ports.size} open ports found"

      { status: findings.any? ? 'completed' : 'completed', findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def common_ports
      [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443,
       445, 465, 500, 514, 587, 636, 993, 995, 1433, 1521, 2049, 3306,
       3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9100, 9200,
       11211, 27017, 50070]
    end

    def tcp_connect_scan(target, ports, concurrency, timeout_sec)
      open_ports = []
      mutex = Mutex.new
      queue = Queue.new
      ports.each { |p| queue << p }

      threads = []
      thread_count = [concurrency, ports.size].min
      thread_count = 1 if thread_count < 1

      thread_count.times do
        threads << Thread.new do
          loop do
            p = nil
            mutex.synchronize { p = queue.pop(true) rescue nil }
            break unless p

            begin
              Timeout.timeout(timeout_sec) do
                s = TCPSocket.new(target, p)
                s.close
                mutex.synchronize { open_ports << p }
              end
            rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Timeout::Error
            rescue => e
            end
          end
        end
      end

      threads.each(&:join)
      open_ports.sort
    end

    def syn_scan_simulation(target, open_ports, timeout_sec)
      findings = []
      risk_score = 0
      additional = []
      (1..1024).each do |p|
        break if additional.size >= 5
        next if open_ports.include?(p)
        begin
          Timeout.timeout(0.5) do
            s = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
            s.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
            sa = Socket.sockaddr_in(p, target)
            begin
              s.connect_nonblock(sa)
            rescue Errno::EINPROGRESS
              _, writable, _ = IO.select(nil, [s], nil, 0.3)
              if writable
                so_error = s.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR)
                if so_error.intvalue == 0
                  additional << p
                end
              end
            end
            s.close
          end
        rescue
        end
      end
      unless additional.empty?
        findings << "SYN scan detected additional ports: #{additional.join(', ')}"
        risk_score += 5 * additional.size
      end
      { findings: findings, risk_score: risk_score }
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || '127.0.0.1'
  port = (ARGV[1] || 0).to_i
  opts = {}
  opts[:concurrency] = (ARGV[2] || 20).to_i if ARGV[2]
  scanner = HackIT::PortScan.new
  result = scanner.run(target, port, opts)
  puts JSON.pretty_generate(result)
end
