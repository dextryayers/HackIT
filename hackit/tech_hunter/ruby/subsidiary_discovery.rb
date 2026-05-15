require 'json'

def discover_subsidiaries(domain)
  # Heuristic/OSINT Simulation: Identifying subsidiaries and alternate brands
  # In production, this would query Crunchbase, LinkedIn, or similar APIs
  base_name = domain.split('.').first
  
  {
    "aliases" => [
      "dev.#{domain}",
      "staging.#{domain}",
      "internal.#{domain}",
      "test-#{base_name}.io",
      "#{base_name}-acquisitions.net"
    ],
    "subsidiaries" => [
      "#{base_name} Labs",
      "#{base_name} Security Services",
      "#{base_name} Cloud Infrastructure"
    ]
  }
end

if __FILE__ == $0
  domain = ARGV[0] || "example.com"
  puts JSON.generate(discover_subsidiaries(domain))
end
