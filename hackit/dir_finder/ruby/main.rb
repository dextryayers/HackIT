require_relative 'cli'
require_relative 'orchestrator'

begin
  options = DirFinder::CLI.parse
  orchestrator = DirFinder::Orchestrator.new(options)
  orchestrator.run
rescue Interrupt
  puts "\n\e[31m[!] Scan interrupted by user.\e[0m"
  exit 130
rescue => e
  puts "\e[31m[!] Fatal Error: #{e.message}\e[0m"
  puts e.backtrace if ARGV.include?('--debug')
end
