require 'optparse'

module DirFinder
  class CLI
    def self.parse
      options = {
        target: nil,
        wordlist: nil,
        threads: 50,
        timeout: 10,
        turbo: false,
        smart: true,
        proxy: nil,
        output: nil,
        verbose: false,
        recursive: false
      }

      OptionParser.new do |opts|
        opts.banner = "Usage: ruby main.rb [options]"
        opts.separator ""
        opts.separator "TARGET OPTIONS:"
        opts.on("-u", "--url URL", "Target URL") { |v| options[:target] = v }
        opts.on("-w", "--wordlist FILE", "Wordlist file") { |v| options[:wordlist] = v }
        
        opts.separator ""
        opts.separator "PERFORMANCE OPTIONS:"
        opts.on("-t", "--threads INT", Integer, "Threads (default: 50)") { |v| options[:threads] = v }
        opts.on("--timeout SEC", Integer, "Timeout in seconds") { |v| options[:timeout] = v }
        opts.on("--turbo", "Enable Rust Turbo Mode") { options[:turbo] = true }
        
        opts.separator ""
        opts.separator "SCANNING OPTIONS:"
        opts.on("--recursive", "Enable recursive scanning") { options[:recursive] = true }
        opts.on("--no-smart", "Disable Python Smart Analysis") { options[:smart] = false }
        
        opts.separator ""
        opts.separator "OUTPUT & DEBUG:"
        opts.on("-o", "--output FILE", "Output file") { |v| options[:output] = v }
        opts.on("-v", "--verbose", "Verbose mode") { options[:verbose] = true }
        
        opts.on_tail("-h", "--help", "Show this message") do
          puts opts
          exit
        end
      end.parse!

      if options[:target].nil?
        puts "\e[31m[!] Error: Target URL (-u) is mandatory.\e[0m"
        exit 1
      end

      options
    end
  end
end
