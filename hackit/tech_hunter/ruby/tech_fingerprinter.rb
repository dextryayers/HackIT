#!/usr/bin/env ruby
require 'json'

begin
  body = ARGV[0] || ''
  headers_json = ARGV[1] || '{}'
  _headers = JSON.parse(headers_json) rescue {}

  body_lower = body.downcase
  cms = []
  frontend = []
  analytics = []

  if body_lower.include?('wp-content') || body_lower.include?('wp-json') || body_lower.include?('wp-includes') || body_lower.include?('wp-admin')
    cms << 'WordPress'
  end
  if body_lower.include?('drupal') || body_lower.include?('drupal.js') || body_lower.include?('/sites/default/') || body_lower.include?('/core/')
    cms << 'Drupal'
  end
  if body_lower.include?('joomla') || body_lower.include?('/components/') || body_lower.include?('/modules/') || body_lower.include?('/templates/')
    cms << 'Joomla'
  end
  if body_lower.include?('magento') || body_lower.include?('skin/frontend') || body_lower.include?('mage.cookies')
    cms << 'Magento'
  end
  if body_lower.include?('myshopify.com') || body_lower.include?('shopify') || body_lower.include?('/cdn/shop/')
    cms << 'Shopify'
  end
  if body_lower.include?('wixstatic.com') || body_lower.include?('wix') || body_lower.include?('_wix')
    cms << 'Wix'
  end
  if body_lower.include?('squarespace.com') || body_lower.include?('static.squarespace')
    cms << 'Squarespace'
  end
  if body_lower.include?('ghost') || body_lower.include?('ghost.io')
    cms << 'Ghost'
  end

  if body_lower.include?('react') || body_lower.include?('reactdom') || body_lower.include?('createelement') || body_lower.include?('_reactroot')
    frontend << 'React'
  end
  if body_lower.include?('vue') || body_lower.include?('v-bind') || body_lower.include?('v-model') || body_lower.include?('v-if') || body_lower.include?('v-for')
    frontend << 'Vue'
  end
  if body_lower.include?('ng-app') || body_lower.include?('ng-') || body_lower.include?('_ngcontent')
    frontend << 'Angular'
  end
  if body_lower.include?('svelte') || body_lower.include?('__svelte')
    frontend << 'Svelte'
  end
  if body_lower.include?('x-data') || body_lower.include?('x-init') || body_lower.include?('x-show') || body_lower.include?('alpinejs')
    frontend << 'Alpine'
  end
  if body_lower.include?('htmx') || body_lower.include?('hx-get') || body_lower.include?('hx-post') || body_lower.include?('hx-target')
    frontend << 'HTMX'
  end

  if body_lower.include?('ga.js') || body_lower.include?('analytics.js') || body_lower.include?('gtag') || body_lower.include?('gtm-')
    analytics << 'Google Analytics'
  end
  if body_lower.include?('fbq') || body_lower.include?('fbevents')
    analytics << 'Facebook Pixel'
  end
  if body_lower.include?('hotjar')
    analytics << 'Hotjar'
  end
  if body_lower.include?('cf-email') || body_lower.include?('__cfduid')
    analytics << 'Cloudflare'
  end

  result = {
    cms: cms,
    frontend: frontend,
    analytics: analytics,
    count: cms.size + frontend.size + analytics.size
  }

  puts JSON.generate(result)
rescue StandardError => e
  puts JSON.generate({ error: e.message })
end
