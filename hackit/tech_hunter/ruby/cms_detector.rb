#!/usr/bin/env ruby
require 'json'

begin
  body = ARGV[0] || ''
  headers_json = ARGV[1] || '{}'
  headers = JSON.parse(headers_json) rescue {}

  body_lower = body.downcase
  all_cms_hits = []

  fingerprints = {
    'WordPress' => {
      patterns: ['wp-content', 'wp-json', 'wp-includes', 'wp-admin', 'xmlrpc.php'],
      gen_pattern: /generator["']?\s*content\s*=\s*["']?WordPress\s*(\d+\.\d+(?:\.\d+)?)/i,
      theme_pattern: /\/wp-content\/themes\/([^\/"']+)/i,
      plugin_pattern: /\/wp-content\/plugins\/([^\/"']+)/i
    },
    'Drupal' => {
      patterns: ['drupal', '/sites/default/', '/core/', 'drupal.settings', 'drupal.js'],
      gen_pattern: /generator["']?\s*content\s*=\s*["']?Drupal\s*(\d+\.\d+(?:\.\d+)?)/i,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Joomla' => {
      patterns: ['/components/', '/modules/', 'joomla', 'joomla.js', 'option=com_'],
      gen_pattern: /generator["']?\s*content\s*=\s*["']?Joomla!\s*(\d+\.\d+(?:\.\d+)?)/i,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Magento' => {
      patterns: ['mage', 'skin/frontend', 'magento-store', 'productaddtocart'],
      gen_pattern: nil,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Shopify' => {
      patterns: ['shopify', '/cdn/shop/', 'myshopify', 'shopifybuy'],
      gen_pattern: nil,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Wix' => {
      patterns: ['wixstatic', '_wix', 'wix.getservicetopology'],
      gen_pattern: nil,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Squarespace' => {
      patterns: ['squarespace', 'collections/'],
      gen_pattern: nil,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Ghost' => {
      patterns: ['ghost', 'ghost.io'],
      gen_pattern: /generator["']?\s*content\s*=\s*["']?Ghost\s*(\d+\.\d+(?:\.\d+)?)/i,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'TYPO3' => {
      patterns: ['typo3', 'tx_', 'fe_users'],
      gen_pattern: /generator["']?\s*content\s*=\s*["']?TYPO3\s*CMS\s*(\d+\.\d+(?:\.\d+)?)/i,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Umbraco' => {
      patterns: ['umbraco', '/umbraco/'],
      gen_pattern: /umbraco/i,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Jekyll' => {
      patterns: ['jekyll', 'github-pages'],
      gen_pattern: /generator["']?\s*content\s*=\s*["']?Jekyll\s*(\d+\.\d+(?:\.\d+)?)/i,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Hugo' => {
      patterns: ['hugo'],
      gen_pattern: /generator["']?\s*content\s*=\s*["']?Hugo\s*(\d+\.\d+(?:\.\d+)?)/i,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Contentful' => {
      patterns: ['contentful'],
      gen_pattern: nil,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Strapi' => {
      patterns: ['strapi'],
      gen_pattern: nil,
      theme_pattern: nil,
      plugin_pattern: nil
    },
    'Directus' => {
      patterns: ['directus'],
      gen_pattern: nil,
      theme_pattern: nil,
      plugin_pattern: nil
    }
  }

  best_cms = nil
  best_confidence = 0
  best_version = nil
  best_theme = nil
  best_plugins = []

  fingerprints.each do |name, fp|
    matches = fp[:patterns].count { |p| body_lower.include?(p) }
    next if matches == 0

    conf = (matches.to_f / fp[:patterns].size * 100).round
    version = nil

    if fp[:gen_pattern]
      m = body.match(fp[:gen_pattern])
      version = m[1] if m
      conf += 10 if version
    end

    if name == 'WordPress'
      gen_match = body.match(/generator["']?\s*content\s*=\s*["']?WordPress\s*(\d+\.\d+(?:\.\d+)?)/i)
      version = gen_match[1] if gen_match
      theme_matches = body.scan(/\/wp-content\/themes\/([^\/"']+)/i).flatten.uniq
      best_theme = theme_matches.first if theme_matches.any?
      plugin_matches = body.scan(/\/wp-content\/plugins\/([^\/"']+)/i).flatten.uniq
      best_plugins = plugin_matches if plugin_matches.any?
    end

    hit = { cms: name, confidence: [conf, 100].min }
    hit[:version] = version if version
    all_cms_hits << hit

    if conf > best_confidence
      best_cms = name
      best_confidence = conf
      best_version = version
    end
  end

  result = {
    cms: best_cms,
    version: best_version,
    confidence: best_confidence,
    all_cms_hits: all_cms_hits
  }
  result[:theme] = best_theme if best_theme
  result[:plugins] = best_plugins if best_plugins&.any?

  puts JSON.generate(result)
rescue StandardError => e
  puts JSON.generate({ error: e.message })
end
