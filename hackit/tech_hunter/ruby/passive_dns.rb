require 'json'

def correlate_passive_dns(domain)
  # Simulating passive DNS data correlation
  internal_domains = [
    "db-prod-01.internal.#{domain}",
    "vpn-gateway.#{domain}",
    "staging-cluster.internal.#{domain}",
    "gitlab.internal.#{domain}",
    "k8s-master.local",
    "jenkins.internal.#{domain}",
    "mail-internal.#{domain}"
  ]
  
  {
    "possible_internal_domains" => internal_domains,
    "last_seen_ips" => ["10.0.5.12", "192.168.1.100"]
  }
end

if __FILE__ == $0
  domain = ARGV[0] || "example.com"
  puts JSON.generate(correlate_passive_dns(domain))
end
