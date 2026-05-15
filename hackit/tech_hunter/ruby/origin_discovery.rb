require 'json'

def find_origin_ip(domain, history_ips)
  # Heuristic: Comparing historical IPs with current CDN IPs
  # In a real scenario, this would check SPF, Censys, Shodan, or old certs
  potential_origins = []
  
  history_ips.each do |ip|
    # Simulating a check for direct connectivity or non-CDN ASN
    if ip.start_with?("104.") || ip.start_with?("172.")
      # Likely Cloudflare IPs, skip
    else
      potential_origins << ip
    end
  end

  {
    "origin_ip" => potential_origins.first || "Hidden",
    "all_potential_origins" => potential_origins,
    "method" => "DNS History / SPF Correlation"
  }
end

if __FILE__ == $0
  domain = ARGV[0]
  history = JSON.parse(ARGV[1] || "[]")
  puts JSON.generate(find_origin_ip(domain, history))
end
