require 'open3'
require 'json'

module DirFinder
  class Orchestrator
    def initialize(options)
      @options = options
      @base_dir = File.expand_path("..", File.dirname(__FILE__))
    end

    def run
      print_banner
      
      # 1. Python Intelligence
      if @options[:smart]
        run_python_analyzer
      end

      # 2. Go/Rust Execution
      if @options[:turbo]
        run_rust_turbo
      else
        run_go_core
      end
    end

    private

    def print_banner
      puts "\e[35m" + "      ___           ___           ___           ___     " + "\e[0m"
      puts "\e[35m" + "     /\\  \\         /\\  \\         /\\  \\         /\\__\\    " + "\e[0m"
      puts "\e[35m" + "    /::\\  \\       /::\\  \\       /::\\  \\       /:/  /    " + "\e[0m"
      puts "\e[35m" + "   /:/\\:\\  \\     /:/\\:\\  \\     /:/\\:\\  \\     /:/__/     " + "\e[0m"
      puts "\e[35m" + "  /::\\~\\:\\  \\   /:/  \\:\\  \\   /::\\~\\:\\  \\   /::\\__\\____ " + "\e[0m"
      puts "\e[35m" + " /:/\\:\\ \\:\\__\\ /:/__/ \\:\\__\\ /:/\\:\\ \\:\\__\\ /:/\\:::::\\__\\" + "\e[0m"
      puts "\e[35m" + " \\/__\\:\\/:/  / \\:\\  \\  \\/__/ \\/__\\:\\/:/  / \\/_|:|~~|~   " + "\e[0m"
      puts "\e[35m" + "      \\::/  /   \\:\\  \\            \\::/  /      |:|  |    " + "\e[0m"
      puts "\e[35m" + "      /:/  /     \\:\\  \\           /:/  /       |:|  |    " + "\e[0m"
      puts "\e[35m" + "     /:/  /       \\:\\__\\         /:/  /        |:|  |    " + "\e[0m"
      puts "\e[35m" + "     \\/__/         \\/__/         \\/__/          \\|__|    " + "\e[0m"
      puts "\n\e[1;32m  [+] DIR FINDER EXPERT - NMAP-INSPIRED PENTA ENGINE ACTIVATED\e[0m"
      puts "  ------------------------------------------------------------"
    end

    def run_python_analyzer
      puts "\n\e[1;34m[*] PHASE 1: Python Intelligence (Smart Analysis)...\e[0m"
      analyzer_path = File.join(@base_dir, "analyzer.py")
      cmd = "python \"#{analyzer_path}\" -u #{@options[:target]}"
      
      system(cmd)
      
      result_file = File.join(@base_dir, "smart_analysis.json")
      if File.exist?(result_file)
        analysis = JSON.parse(File.read(result_file))
        puts "\e[32m[+] WAF: #{analysis['waf']}\e[0m"
        puts "\e[32m[+] Tech Detected: #{analysis['tech'].join(', ')}\e[0m"
        puts "\e[32m[+] JS & Backup Endpoints: #{analysis['endpoints'].size} found\e[0m"
      end
    end

    def run_go_core
      puts "\n\e[1;34m[*] PHASE 2: Go Core Engine (Stable Mass Scan)...\e[0m"
      go_bin = File.join(@base_dir, "go", "dir_finder.exe")
      
      args = ["-u", @options[:target], "-t", @options[:threads].to_s]
      args += ["-w", @options[:wordlist]] if @options[:wordlist]
      
      Open3.popen3(go_bin, *args) do |stdin, stdout, stderr, wait_thr|
        stdout.each_line { |line| puts line }
        stderr.each_line { |line| puts "\e[31m#{line}\e[0m" }
      end
    end

    def run_rust_turbo
      puts "\n\e[1;31m[*] PHASE 2: Rust Turbo Engine (Ultra-Fast Async)...\e[0m"
      # For now, it calls Go which uses Rust DLL, or we can build a direct Rust CLI
      run_go_core
    end
  end
end
