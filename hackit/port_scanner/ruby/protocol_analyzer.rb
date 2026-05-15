require 'socket'
require 'timeout'

module HackIT
  class ProtocolAnalyzer
    def initialize(host, port, timeout = 2)
      @host = host
      @port = port
      @timeout = timeout
    end

    def analyze
      puts "[*] HackIT : Deep Protocol Analysis for #{@host}:#{@port}..."
      case @port
      when 80, 443, 8080
        analyze_http
      when 21
        analyze_ftp
      when 22
        analyze_ssh
      else
        generic_probe
      end
    end

    private

    def analyze_http
      begin
        Timeout.timeout(@timeout) do
          s = TCPSocket.new(@host, @port)
          s.write("OPTIONS * HTTP/1.1\r\nHost: #{@host}\r\n\r\n")
          response = s.read(1024)
          s.close
          return "HTTP Methods: " + (response.match(/Allow: (.*)/) ? $1 : "Unknown")
        end
      rescue => e
        "HTTP Analysis Error: #{e.message}"
      end
    end

    def generic_probe
      "Generic Probe Completed"
    end
  end
end

if __FILE__ == $0
  host = ARGV[0] || "127.0.0.1"
  port = (ARGV[1] || 80).to_i
  analyzer = HackIT::ProtocolAnalyzer.new(host, port)
  puts analyzer.analyze
end
