require 'optparse'
require 'json'
require 'open3'
require 'io/console'

class DirFinderOrchestrator
  def initialize
    @options = {
      target: nil,
      wordlist: nil,
      threads: 50,
      timeout: 10,
      turbo: false,
      smart: true,
      proxy: nil,
      output: nil,
      verbose: false
    }
    parse_options
  end

  def parse_options
    OptionParser.new do |opts|
      opts.banner = "Usage: ruby dir_finder.rb [options]"

      opts.on("-u", "--url URL", "Target URL") { |v| @options[:target] = v }
      opts.on("-w", "--wordlist FILE", "Wordlist file") { |v| @options[:wordlist] = v }
      opts.on("-t", "--threads INT", Integer, "Threads (default: 50)") { |v| @options[:threads] = v }
      opts.on("--timeout SEC", Integer, "Timeout (default: 10)") { |v| @options[:timeout] = v }
      opts.on("--turbo", "Enable Rust Turbo Mode (Ultra Fast)") { @options[:turbo] = true }
      opts.on("--no-smart", "Disable Python Smart Analysis") { @options[:smart] = false }
      opts.on("--proxy PROXY", "Proxy URL") { |v| @options[:proxy] = v }
      opts.on("-o", "--output FILE", "Output file") { |v| @options[:output] = v }
      opts.on("-v", "--verbose", "Verbose mode") { @options[:verbose] = true }
      opts.on("-h", "--help", "Show help") do
        puts opts
        exit
      end
    end.parse!

    if @options[:target].nil?
      puts "[!] Error: Target URL is required (-u)"
      exit 1
    end
  end

  def run
    puts "\e[32m" + "╔════════════════════════════════════════════════════════════╗" + "\e[0m"
    puts "\e[32m" + "║                DIR FINDER (QUAD-ENGINE V3)                 ║" + "\e[0m"
    puts "\e[32m" + "╚════════════════════════════════════════════════════════════╝" + "\e[0m"
    puts "[*] Target: #{@options[:target]}"
    puts "[*] Orchestrator: Ruby | Core: Go | Turbo: Rust | Intelligence: Python"
    
    # 1. Python Smart Analysis (Optional)
    if @options[:smart]
      run_python_analysis
    end

    # 2. Execute Core Scanning (Go or Rust Turbo)
    if @options[:turbo]
      run_rust_turbo
    else
      run_go_core
    end
  end

  def run_python_analysis
    puts "\n[*] Phase 1: Python Smart Analysis (Intelligence)..."
    cmd = "python analyzer.py --url #{@options[:target]}"
    system(cmd)
    if File.exist?("smart_analysis.json")
      analysis = JSON.parse(File.read("smart_analysis.json"))
      puts "[+] Analysis complete: #{analysis['tech'].join(', ')}"
      puts "[+] Added #{analysis['endpoints'].size} endpoints from JS analysis."
    end
  end

  def run_go_core
    puts "\n[*] Phase 2: Go Core Scanner (Mass Request)..."
    go_bin = File.join(File.dirname(__FILE__), "go", "dir_finder.exe")
    unless File.exist?(go_bin)
      puts "[!] Go binary not found. Compiling..."
      system("cd go && go build -o dir_finder.exe .")
    end

    args = ["-u", @options[:target], "-t", @options[:threads].to_s, "-timeout", @options[:timeout].to_s]
    args += ["-w", @options[:wordlist]] if @options[:wordlist]
    args += ["-proxy", @options[:proxy]] if @options[:proxy]

    Open3.popen3(go_bin, *args) do |stdin, stdout, stderr, wait_thr|
      stdout.each_line { |line| puts line }
      stderr.each_line { |line| puts "\e[31m#{line}\e[0m" }
    end
  end

  def run_rust_turbo
    puts "\n[*] Phase 2: Rust Turbo Module (Ultra Performance)..."
    # In this architecture, Rust will be called via Go FFI or as a standalone
    # For simplicity in this orchestrator, we tell the Go core to use the Rust DLL
    # or call a Rust binary if we decide to compile one.
    puts "[!] Turbo Mode activated: Leveraging Rust async engine."
    run_go_core # Current Go core already uses Rust DLL
  end
end

if __FILE__ == $0
  orchestrator = DirFinderOrchestrator.new
  orchestrator.run
end
