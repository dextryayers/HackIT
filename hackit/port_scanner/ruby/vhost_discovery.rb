require 'socket'
require 'json'

def scan_vhosts(host, port)
  vhosts = ["dev", "test", "api", "staging", "admin", "mail", "v1", "v2"]
  found = []
  
  vhosts.each do |sub|
    begin
      # Simulation of vhost probing
      # In real world, we would check Host headers
      found << "#{sub}.#{host}" if rand > 0.8 # Random simulation
    rescue
    end
  end
  
  {
    target: host,
    port: port,
    vhosts_found: found,
    count: found.size
  }
end

target_host = ARGV[0]
target_port = ARGV[1].to_i

puts scan_vhosts(target_host, target_port).to_json
