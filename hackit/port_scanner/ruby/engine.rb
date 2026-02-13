require 'socket'
require 'json'
require 'timeout'
require 'thread'

class RubyScanner
  def initialize(host, ports, timeout = 1, threads = 50)
    @host = host
    @ports = ports
    @timeout = timeout
    @threads = threads
  end

  def scan
    results = []
    queue = Queue.new
    @ports.each { |p| queue << p }

    workers = (1..@threads).map do
      Thread.new do
        until queue.empty?
          port = queue.pop(true) rescue nil
          next unless port

          begin
            Timeout.timeout(@timeout) do
              s = TCPSocket.new(@host, port)
              banner = ""
              begin
                # Some protocols need a probe to send banner
                if [80, 8080, 443].include?(port)
                  s.write("HEAD / HTTP/1.0\r\n\r\n")
                end
                
                # Use select for timeout on read
                if IO.select([s], nil, nil, @timeout)
                  banner = s.recv_nonblock(1024)
                end
              rescue IO::WaitReadable, Errno::EAGAIN
                # No immediate banner
              rescue => e
                # Ignore read errors
              end
              s.close
              results << {
                port: port,
                status: "open",
                service: detect_service(port),
                banner: banner.strip.gsub(/[^[:print:]]/, '.')
              }
            end
          rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Timeout::Error, Errno::ETIMEDOUT
            # Port closed or filtered
          rescue => e
            # Other errors
          end
        end
      end
    end

    workers.each(&:join)
    results.sort_by { |r| r[:port] }
  end

  def detect_service(port)
    case port
    when 80 then "http"
    when 443 then "https"
    when 22 then "ssh"
    when 21 then "ftp"
    when 25 then "smtp"
    when 53 then "dns"
    when 110 then "pop3"
    when 143 then "imap"
    when 3306 then "mysql"
    when 5432 then "postgresql"
    when 6379 then "redis"
    when 27017 then "mongodb"
    when 3389 then "rdp"
    when 445 then "microsoft-ds"
    else "unknown"
    end
  end
end

if __FILE__ == $0
  host = ARGV[0] || 'localhost'
  ports_arg = ARGV[1] || '1-1024'
  
  ports = []
  ports_arg.split(',').each do |p|
    if p.include?('-')
      start_p, end_p = p.split('-').map(&:to_i)
      ports.concat((start_p..end_p).to_a)
    else
      ports << p.to_i
    end
  end

  timeout = (ARGV[2] || 1000).to_f / 1000.0
  threads = (ARGV[3] || 50).to_i

  scanner = RubyScanner.new(host, ports, timeout, threads)
  puts JSON.generate(scanner.scan)
end
