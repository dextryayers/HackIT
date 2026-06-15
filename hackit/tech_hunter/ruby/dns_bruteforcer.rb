#!/usr/bin/env ruby
require 'json'
require 'resolv'
require 'timeout'

begin
  domain = ARGV[0] || ''
  raise 'No domain provided' if domain.empty?

  # Smaller wordlist for speed
  wordlist = %w[
    www mail admin blog api dev test staging cdn app web vpn remote
    git wiki help support status monitor dashboard analytics media
    static images backup db proxy ns1 ns2 mx
  ]

  resolver = Resolv::DNS.new(nameserver: ['8.8.8.8'], time: 3)
  subdomains = {}
  mutex = Mutex.new
  queue = wordlist.dup
  threads = []

  8.times do
    threads << Thread.new do
      while (sub = mutex.synchronize { queue.shift })
        fqdn = "#{sub}.#{domain}"
        begin
          Timeout.timeout(4) do
            addresses = resolver.getresources(fqdn, Resolv::DNS::Resource::IN::A)
            unless addresses.empty?
              ips = addresses.map { |a| a.address.to_s }
              mutex.synchronize { subdomains[fqdn] = ips }
            end
          end
        rescue StandardError
          nil
        end
      end
    end
  end

  threads.each(&:join)
  resolver.close rescue nil

  resolved_ips = {}
  subdomains_list = subdomains.keys.sort
  subdomains.each { |s, ips| resolved_ips[s] = ips.size == 1 ? ips.first : ips }

  result = {
    subdomains: subdomains_list,
    count: subdomains_list.size,
    resolved_ips: resolved_ips
  }

  puts JSON.generate(result)
rescue StandardError => e
  puts JSON.generate({ error: e.message })
end
