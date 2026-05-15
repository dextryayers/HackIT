require 'socket'
require 'json'

def find_api_endpoints(host, port)
  endpoints = ["/api", "/v1", "/v2", "/graphql", "/rest", "/swagger", "/docs"]
  found = []
  
  endpoints.each do |path|
    begin
      # Simulation of API path probing
      # In real world, we would check for 200 OK or 401/403
      found << path if rand > 0.7 # Random simulation
    rescue
    end
  end
  
  {
    target: host,
    port: port,
    api_endpoints: found,
    count: found.size,
    type: "REST/GraphQL"
  }
end

target_host = ARGV[0]
target_port = ARGV[1].to_i

puts find_api_endpoints(target_host, target_port).to_json
