#!/usr/bin/env ruby
require 'json'
require 'resolv'

domain = ARGV[0] || ''
return puts JSON.generate({ records: [], error: "no domain" }) if domain.empty?

res = Resolv::DNS.new
records = { a: [], mx: [], ns: [], txt: [], cname: [] }

begin
  records[:a] = res.getresources(domain, Resolv::DNS::Resource::IN::A).map(&:address).map(&:to_s)
rescue; end

begin
  records[:mx] = res.getresources(domain, Resolv::DNS::Resource::IN::MX).map { |mx| "#{mx.preference} #{mx.exchange.to_s}" }
rescue; end

begin
  records[:ns] = res.getresources(domain, Resolv::DNS::Resource::IN::NS).map(&:name).map(&:to_s)
rescue; end

begin
  records[:txt] = res.getresources(domain, Resolv::DNS::Resource::IN::TXT).map { |t| t.strings.join(' ') }
rescue; end

begin
  cname = res.getresource(domain, Resolv::DNS::Resource::IN::CNAME)
  records[:cname] = [cname.name.to_s]
rescue; end

# SPF check
records[:txt].each do |t|
  if t.include?('spf') || t.include?('v=spf')
    records[:spf] = t
    break
  end
end

# DMARC check
begin
  dmarc = res.getresources("_dmarc.#{domain}", Resolv::DNS::Resource::IN::TXT)
  records[:dmarc] = dmarc.map { |d| d.strings.join(' ') }.first
rescue; end

puts JSON.generate(records)
