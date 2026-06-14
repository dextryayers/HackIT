require 'socket'
require 'net/http'
require 'openssl'
require 'json'
require 'uri'

module HackIT
  class WebScraper
    CMS_PATTERNS = {
      'WordPress' => [/wp-content/, /wp-includes/, /wordpress/i, /wp-json/],
      'Drupal' => [/drupal/i, /sites\/default/, /core\/themes/],
      'Joomla' => [/joomla/i, /option=com_/, /\/components\/com_/],
      'Magento' => [/mage/i, /skin\/frontend/, /Magento/],
      'Shopify' => [/myshopify\.com/, /cdn\.shopify/, /shopify/],
      'Ghost' => [/ghost/i, /ghost\/api/],
      'Wix' => [/wix\.com/, /_wix/]
    }

    JS_PATTERNS = {
      'React' => [/react\.js|react\.min\.js|react-dom/i, /__react/i, /data-react/],
      'Vue' => [/vue\.js|vue\.min\.js/i, /__vue__/],
      'Angular' => [/angular\.js|angular\.min\.js/i, /ng-app|ng-controller/],
      'jQuery' => [/jquery[-.]\d+\.\d+\.\d+\.js|jquery\.min\.js/i],
      'Next.js' => [/\/_next\/static/, /next\.js/i],
      'Nuxt' => [/\/_nuxt\//, /nuxt\.js/i],
      'Svelte' => [/svelte/i, /__svelte/],
      'Ember' => [/ember\.js|ember\.min\.js/i]
    }

    ANALYTICS_PATTERNS = {
      'Google Analytics' => [/google-analytics\.com\/analytics\.js/i, /ga\.js|gtag\/js/i, /gtm\.js/i],
      'Facebook Pixel' => [/connect\.facebook\.net\/en_us\/fbevents/i, /fbq\s*\(/],
      'Hotjar' => [/hotjar\.com/i, /_hjSettings/],
      'Mixpanel' => [/cdn\.mixpanel\.com/i, /mixpanel\.init/],
      'Segment' => [/cdn\.segment\.com/i, /analytics\.js/],
      'Matomo' => [/matomo\.js/i, /piwik\.js/i],
      'HubSpot' => [/js\.hs-scripts\.com/i, /hs-analytics/],
      'LinkedIn Insight' => [/snap\.licdn\.com\/li\.lite/i]
    }

    CDN_PATTERNS = {
      'Cloudflare' => [/cloudflare/i, /__cfduid/i, /cf-ray/i],
      'Akamai' => [/akamai/i, /aka-|akamaized/],
      'Fastly' => [/fastly/i, /x-fastly/i, /fastly-ssl/],
      'CloudFront' => [/cloudfront\.net/i, /x-amz-cf/i],
      'StackPath' => [/stackpathdns\.com/i, /stackpath\.com/i],
      'KeyCDN' => [/keycdn\.com/i, /kxcdn\.com/]
    }

    def self.plugin_info
      {
        name: 'WebScraper',
        version: '2.1.0',
        description: 'Web scraping and technology detection via HTTP/HTTPS analysis',
        author: 'HackIT Team'
      }
    end

    def run(target, port, opts = {})
      findings = []
      risk_score = 0
      proto = opts[:ssl] || port.to_i == 443 ? 'https' : 'http'
      url = "#{proto}://#{target}:#{port}"

      begin
        result = fetch_url(url, opts)
        findings.concat(result[:findings])
        risk_score += result[:risk_score]

        tech = detect_technologies(result[:body], result[:headers])
        findings.concat(tech[:findings])
        risk_score += tech[:risk_score]

        sec = analyze_security_headers(result[:headers])
        findings.concat(sec[:findings])
        risk_score += sec[:risk_score]

        cms = detect_cms(result[:body], result[:headers])
        findings.concat(cms[:findings])
        risk_score += cms[:risk_score]

        js = detect_js_frameworks(result[:body])
        findings.concat(js[:findings]) unless js[:findings].empty?

        analytics = detect_analytics(result[:body])
        findings.concat(analytics[:findings]) unless analytics[:findings].empty?

        cdn = detect_cdn(result[:headers])
        findings.concat(cdn[:findings]) unless cdn[:findings].empty?

      rescue => e
        findings << "Error: #{e.message}"
        risk_score = 0
      end

      { status: findings.any? ? 'completed' : 'failed', findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def fetch_url(url, opts)
      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = opts[:timeout] || 5
      http.read_timeout = opts[:timeout] || 5
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE

      findings = []
      risk_score = 0
      response = nil
      body = ''
      headers = {}

      begin
        response = http.request_get(uri.request_uri, { 'User-Agent' => 'Mozilla/5.0 (compatible; HackIT/2.0)' })
        body = response.body.to_s
        response.each_header { |k, v| headers[k.downcase] = v }
        findings << "Status: #{response.code} #{response.message}"
        findings << "Server: #{headers['server']}" if headers['server']
        findings << "X-Powered-By: #{headers['x-powered-by']}" if headers['x-powered-by']

        if response.code.to_i >= 400
          risk_score += 20
          findings << "HTTP error code #{response.code}"
        end

        head_response = http.request_head(uri.request_uri, { 'User-Agent' => 'Mozilla/5.0 (compatible; HackIT/2.0)' })
        if head_response.key?('accept-ranges') || head_response.key?('content-length')
          findings << "Content-Length: #{head_response['content-length']}" if head_response['content-length']
        end
      rescue => e
        findings << "HTTP request failed: #{e.message}"
      end

      { body: body, headers: headers, findings: findings, risk_score: risk_score }
    end

    def detect_technologies(body, headers)
      findings = []
      risk_score = 0
      powered_by = headers['x-powered-by']
      findings << "X-Powered-By: #{powered_by}" if powered_by
      if body.match?(/<title>([^<]*)<\/title>/i)
        findings << "Page Title: #{$1.strip}"
      end
      meta_desc = body.match(/<meta\s+name=["']description["']\s+content=["']([^"']*)["']/i)
      findings << "Meta Description: #{meta_desc[1][0..80]}" if meta_desc
      meta_keys = body.match(/<meta\s+name=["']keywords["']\s+content=["']([^"']*)["']/i)
      findings << "Meta Keywords: #{meta_keys[1][0..80]}" if meta_keys

      generator = body.match(/<meta\s+name=["']generator["']\s+content=["']([^"']*)["']/i)
      if generator
        findings << "Generator: #{generator[1]}"
        risk_score += 5
      end

      if body.match?(/<meta\s+http-equiv=["']refresh["']/i)
        findings << "Meta refresh detected (potential redirect)"
      end

      { findings: findings, risk_score: risk_score }
    end

    def analyze_security_headers(headers)
      findings = []
      risk_score = 0
      sec = {
        'strict-transport-security' => ['HSTS', 1],
        'content-security-policy' => ['CSP', 2],
        'x-frame-options' => ['X-Frame-Options', 2],
        'x-content-type-options' => ['X-Content-Type-Options', 1],
        'x-xss-protection' => ['X-XSS-Protection', 1],
        'referrer-policy' => ['Referrer-Policy', 1],
        'permissions-policy' => ['Permissions-Policy', 1],
        'access-control-allow-origin' => ['CORS', 3]
      }
      sec.each do |hdr, info|
        if headers[hdr]
          findings << "#{info[0]}: #{headers[hdr]}"
          risk_score -= info[1]
        else
          findings << "Missing #{info[0]} header" unless info[0] == 'CORS'
          risk_score += info[1]
        end
      end
      if headers['access-control-allow-origin'] == '*'
        findings << 'CORS allows all origins (*)'
        risk_score += 10
      end
      if headers['x-frame-options']&.downcase == 'deny' || headers['x-frame-options']&.downcase == 'sameorigin'
        risk_score -= 2
      end
      [risk_score, 0].max
      { findings: findings, risk_score: [risk_score, 0].max }
    end

    def detect_cms(body, headers)
      findings = []
      risk_score = 0
      CMS_PATTERNS.each do |name, patterns|
        patterns.each do |pat|
          if body.match?(pat)
            findings << "CMS Detected: #{name}"
            risk_score += 10
            break
          end
        end
      end

      if headers['x-generator']&.match?(/wordpress/i)
        findings << 'Confirmed: WordPress (via X-Generator header)'
      end
      { findings: findings, risk_score: risk_score }
    end

    def detect_js_frameworks(body)
      findings = []
      JS_PATTERNS.each do |name, patterns|
        patterns.each do |pat|
          if body.match?(pat)
            findings << "JS Framework: #{name}"
            break
          end
        end
      end
      { findings: findings, risk_score: 0 }
    end

    def detect_analytics(body)
      findings = []
      ANALYTICS_PATTERNS.each do |name, patterns|
        patterns.each do |pat|
          if body.match?(pat)
            findings << "Analytics: #{name}"
            break
          end
        end
      end
      { findings: findings, risk_score: 0 }
    end

    def detect_cdn(headers)
      findings = []
      header_str = headers.values.join(' ')
      CDN_PATTERNS.each do |name, patterns|
        patterns.each do |pat|
          if headers.values.any? { |v| v.match?(pat) }
            findings << "CDN: #{name}"
            break
          end
        end
      end
      { findings: findings, risk_score: 0 }
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || '127.0.0.1'
  port = (ARGV[1] || 80).to_i
  opts = ARGV[2] ? { ssl: ARGV[2] == 'ssl' } : {}
  scraper = HackIT::WebScraper.new
  result = scraper.run(target, port, opts)
  puts JSON.pretty_generate(result)
end
