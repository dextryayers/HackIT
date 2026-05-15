require 'json'
require 'net/http'

def find_aliases(domain)
  aliases = []
  
  # Heuristic: Common subsidiary/dev patterns
  patterns = ["dev.", "staging.", "test.", "internal.", "api."]
  patterns.each do |p|
    aliases << p + domain
  end

  # OSINT: Check for associated brands (Simulated logic for now)
  if domain.include?("google")
    aliases << "youtube.com"
    aliases << "alphabet.xyz"
  end

  aliases.uniq
end

begin
  input = JSON.parse(STDIN.read)
  results = find_aliases(input['domain'])
  puts results.to_json
rescue => e
  puts({ error: e.message }.to_json)
end
