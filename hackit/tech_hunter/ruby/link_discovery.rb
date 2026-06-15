#!/usr/bin/env ruby
require 'json'
require 'uri'

begin
  body = ARGV[0] || ''
  base_url = ARGV[1] || ''

  base = begin
    URI.parse(base_url)
  rescue StandardError
    nil
  end
  base_host = base ? base.host : nil

  internal = []
  external = []
  resources = []
  mailto = []
  telephone = []
  javascript = []
  fragment = []
  suspicious = []

  all = body.scan(/\s(?:href|src|data-src|action)\s*=\s*["']([^"']+)["']/i).flatten
  all.concat body.scan(/<iframe[^>]+src\s*=\s*["']([^"']+)["']/i).flatten

  all.uniq.each do |raw|
    link = raw.gsub(/[\r\n]/, '').strip
    next if link.empty?

    if link.start_with?('mailto:')
      mailto << link
    elsif link.start_with?('tel:')
      telephone << link
    elsif link.start_with?('javascript:')
      javascript << link
      suspicious << link
    elsif link.start_with?('#')
      fragment << link
    elsif link.start_with?('data:')
      suspicious << link
    elsif link.start_with?('//')
      next
    elsif link.start_with?('/') || link.start_with?('./') || link.start_with?('../')
      internal << link
    elsif link =~ /\Ahttps?:\/\//i
      begin
        u = URI.parse(link)
        if base_host && u.host == base_host
          internal << link
        elsif u.host
          external << link
        else
          internal << link
        end
      rescue StandardError
        internal << link
      end
    elsif link =~ /\A[a-zA-Z][\w+\-.]*:/
      suspicious << link
    else
      internal << link
    end
  end

  categories = {
    internal_links: internal.uniq.size,
    external_links: external.uniq.size,
    resource_links: resources.uniq.size,
    mailto_links: mailto.uniq.size,
    tel_links: telephone.uniq.size,
    javascript_links: javascript.uniq.size,
    fragment_links: fragment.uniq.size
  }

  result = {
    total_links: all.uniq.size,
    categories: categories,
    suspicious: suspicious.uniq,
    all_links: {
      internal: internal.uniq,
      external: external.uniq,
      mailto: mailto.uniq,
      tel: telephone.uniq,
      javascript: javascript.uniq,
      fragment: fragment.uniq
    }
  }

  puts JSON.generate(result)
rescue StandardError => e
  puts JSON.generate({ error: e.message })
end
