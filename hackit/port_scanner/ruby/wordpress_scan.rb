require 'socket'
require 'net/http'
require 'openssl'
require 'json'
require 'uri'

module HackIT
  class WordPressScan
    COMMON_PLUGINS = %w[
      akismet hello-dolly jetpack wordfence yoast-seo contact-form-7 woocommerce
      elementor wp-super-cache w3-total-cache all-in-one-seo-pack ninja-forms
      gravityforms revslider layerSlider visual-composer js_composer
      woocommerce-gateway-stripe woocommerce-gateway-paypal-express
      wordpress-seo redirection akismet nextgen-gallery soliloquy
      tablepress better-wp-security google-analytics-dashboard-for-wp
      wp-file-manager duplicator updraftplus backupwordpress
      mailchimp-for-wp newsletter smart-slider-3 formidable formidablepro
      bbpress buddypress wpmu-dev-post-votes simple-share-buttons-adder
      total-theme-core unyson fusion-core fusion-builder
      litespeed-cache autoptimize wp-rocket cache-enabler
      really-simple-ssl hide-my-wp wp-hide-security
      backwpup mainwp-child mainwp-child-reports
      broken-link-checker loginizer loginpress
      wordfence-login-security ithemes-security-pro
      the-events-calendar event-tickets jnews-review
      wp-members simple-membership paid-memberships-pro
      ultimate-member memberpress learnpress lifter-lms
      tutor woof-product-filter yith-woocommerce-ajax-search
      polylang translatepress-multilingual sitepress-multilingual-cms
      wp-rocket autoptimize wp-smushit smush imagify
    ]

    COMMON_THEMES = %w[
      twentyseventeen twentysixteen twentyfifteen twentyfourteen twentythirteen
      twentytwelve twentyeleven twentytwenty twentytwentyone twentytwentytwo
      twentytwentythree twentytwentyfour astra generatepress oceanwp
      neve hestia zakra customify storefront flatsome divi
      avada bridge enfold the7 be-themes betheme
      porto woodmart socialv arkavastra hueman
      sputnick wr-nitrox salient jevelin chiron
      boundless brook cleansimple cloud meks
    ]

    VERSION_PATHS = [
      '/readme.html', '/license.txt', '/wp-includes/version.php',
      '/wp-includes/js/wp-embed.min.js', '/wp-includes/css/wp-admin.min.css'
    ]

    ENDPOINTS = [
      '/xmlrpc.php', '/wp-json/', '/wp-json/wp/v2/', '/wp-json/wp/v2/users/',
      '/wp-content/debug.log', '/wp-content/uploads/',
      '/wp-includes/', '/wp-admin/', '/wp-admin/admin-ajax.php',
      '/wp-login.php', '/wp-register.php', '/wp-cron.php',
      '/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php.save',
      '/wp-content/themes/', '/wp-content/plugins/'
    ]

    def self.plugin_info
      {
        name: 'WordPressScan',
        version: '2.0.0',
        description: 'WordPress scanner: version detection, plugin/theme enumeration, user discovery, and security endpoint checks',
        author: 'HackIT Team'
      }
    end

    def run(target, port, opts = {})
      findings = []
      risk_score = 0
      proto = opts[:ssl] || port.to_i == 443 ? 'https' : 'http'
      base_url = "#{proto}://#{target}:#{port}"

      begin
        unless is_wordpress?(base_url, opts)
          findings << 'Not a WordPress site'
          return { status: 'completed', findings: findings, risk_score: 0 }
        end
        findings << 'WordPress detected'

        vers = detect_version(base_url, opts)
        findings.concat(vers[:findings])
        risk_score += vers[:risk_score]

        plugins = enumerate_plugins(base_url, opts)
        findings.concat(plugins[:findings])
        risk_score += plugins[:risk_score]

        themes = enumerate_themes(base_url, opts)
        findings.concat(themes[:findings])
        risk_score += themes[:risk_score]

        users = enumerate_users(base_url, opts)
        findings.concat(users[:findings])
        risk_score += users[:risk_score]

        endpoints = check_endpoints(base_url, opts)
        findings.concat(endpoints[:findings])
        risk_score += endpoints[:risk_score]

      rescue => e
        findings << "WordPress scan error: #{e.message}"
      end

      { status: findings.any? ? 'completed' : 'failed', findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def is_wordpress?(base_url, opts)
      begin
        uri = URI.parse(base_url)
        http = build_http(uri, opts)
        req = Net::HTTP::Get.new(uri.request_uri, user_agent)
        res = http.request(req)
        body = res.body.to_s.downcase

        return true if body.match?(/wp-content|wp-includes|wordpress/i)

        ['/wp-admin/', '/wp-includes/', '/wp-content/'].any? do |p|
          begin
            u = URI.parse("#{base_url}#{p}")
            h = build_http(u, opts)
            r = Net::HTTP::Get.new(u.request_uri, user_agent)
            resp = h.request(r)
            resp.code.to_i == 200 || resp.code.to_i == 301 || resp.code.to_i == 302
          rescue
            false
          end
        end
      rescue
        false
      end
    end

    def detect_version(base_url, opts)
      findings = []
      risk_score = 0

      VERSION_PATHS.each do |path|
        begin
          uri = URI.parse("#{base_url}#{path}")
          http = build_http(uri, opts)
          req = Net::HTTP::Get.new(uri.request_uri, user_agent)
          res = http.request(req)
          if res.code.to_i == 200
            body = res.body.to_s
            ver = extract_version(body)
            if ver
              findings << "WordPress version: #{ver}"
              risk_score += 5
              break
            end
          end
        rescue
        end
      end

      if findings.empty?
        begin
          uri = URI.parse(base_url)
          http = build_http(uri, opts)
          req = Net::HTTP::Get.new(uri.request_uri, user_agent)
          res = http.request(req)
          generator = res.body.to_s.match(/<meta\s+name=["']generator["'][^>]*content=["']WordPress\s*([\d.]+)["']/i)
          if generator
            findings << "WordPress version: #{generator[1]}"
            risk_score += 5
          end
        rescue
        end
      end

      { findings: findings, risk_score: risk_score }
    end

    def extract_version(body)
      patterns = [
        /Version\s*([\d.]+)/,
        /wordpress_version\s*=\s*'([\d.]+)'/i,
        /wp-embed\.min\.js\?ver=([\d.]+)/,
        /ver=([\d.]+)/
      ]
      patterns.each do |pat|
        m = body.match(pat)
        return m[1] if m
      end
      nil
    end

    def enumerate_plugins(base_url, opts)
      findings = []
      risk_score = 0
      found = []

      COMMON_PLUGINS.each_with_index do |plugin, idx|
        break if found.size >= 20
        paths = [
          "/wp-content/plugins/#{plugin}/",
          "/wp-content/plugins/#{plugin}/readme.txt",
          "/wp-content/plugins/#{plugin}/index.php"
        ]
        paths.each do |path|
          begin
            uri = URI.parse("#{base_url}#{path}")
            http = build_http(uri, opts)
            req = Net::HTTP::Get.new(uri.request_uri, user_agent)
            res = http.request(req)
            if res.code.to_i == 200 || res.code.to_i == 403
              found << plugin
              findings << "Plugin: #{plugin}"
              risk_score += 5
              break
            end
          rescue
          end
        end
      end

      { findings: findings, risk_score: risk_score }
    end

    def enumerate_themes(base_url, opts)
      findings = []
      risk_score = 0

      COMMON_THEMES.each do |theme|
        begin
          uri = URI.parse("#{base_url}/wp-content/themes/#{theme}/")
          http = build_http(uri, opts)
          req = Net::HTTP::Get.new(uri.request_uri, user_agent)
          res = http.request(req)
          if res.code.to_i == 200 || res.code.to_i == 301 || res.code.to_i == 302
            findings << "Theme: #{theme}"
            risk_score += 3
          end
        rescue
        end
      end

      { findings: findings, risk_score: risk_score }
    end

    def enumerate_users(base_url, opts)
      findings = []
      risk_score = 0

      [1, 2, 3, 4, 5, 10, 100].each do |uid|
        begin
          uri = URI.parse("#{base_url}/wp-json/wp/v2/users/#{uid}")
          http = build_http(uri, opts)
          req = Net::HTTP::Get.new(uri.request_uri, user_agent)
          res = http.request(req)
          if res.code.to_i == 200
            begin
              data = JSON.parse(res.body)
              name = data['name'] || data['slug'] || "User##{uid}"
              findings << "User: #{name} (ID: #{uid})"
              risk_score += 10
            rescue
              findings << "User found: ID #{uid}"
              risk_score += 8
            end
          end
        rescue
        end
      end

      unless findings.any? { |f| f.include?('User') }
        begin
          uri = URI.parse("#{base_url}/?author=1")
          http = build_http(uri, opts)
          req = Net::HTTP::Get.new(uri.request_uri, user_agent)
          res = http.request(req)
          if res.code.to_i == 301 || res.code.to_i == 302
            location = res['location'].to_s
            if location.match?(/\/author\//)
              username = location.split('/author/').last.split('/').first
              findings << "User (via redirect): #{username}"
              risk_score += 8
            end
          end
        rescue
        end
      end

      { findings: findings, risk_score: risk_score }
    end

    def check_endpoints(base_url, opts)
      findings = []
      risk_score = 0

      ENDPOINTS.each do |ep|
        begin
          uri = URI.parse("#{base_url}#{ep}")
          http = build_http(uri, opts)
          req = Net::HTTP::Get.new(uri.request_uri, user_agent)
          res = http.request(req)

          if res.code.to_i == 200 || res.code.to_i == 403 || res.code.to_i == 401
            findings << "Endpoint: #{ep} (#{res.code})"

            case ep
            when '/xmlrpc.php'
              findings << 'RISK: XML-RPC enabled (brute force, pingback abuse)'
              risk_score += 15
            when '/wp-json/'
              findings << 'REST API enabled'
              risk_score += 5
            when '/wp-json/wp/v2/users/'
              risk_score += 10
            when '/debug.log'
              findings << 'WARNING: Debug log exposed!'
              risk_score += 30
            when '/wp-config.php.bak', '/wp-config.php.old', '/wp-config.php.save'
              findings << 'CRITICAL: wp-config backup exposed!'
              risk_score += 40
            else
              risk_score += 5
            end
          end
        rescue
        end
      end

      { findings: findings, risk_score: risk_score }
    end

    def build_http(uri, opts)
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = opts[:timeout] || 3
      http.read_timeout = opts[:timeout] || 3
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http
    end

    def user_agent
      { 'User-Agent' => 'Mozilla/5.0 (compatible; HackIT-WP/2.0)' }
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || '127.0.0.1'
  port = (ARGV[1] || 80).to_i
  opts = { ssl: ARGV[2] == 'ssl' }
  scanner = HackIT::WordPressScan.new
  result = scanner.run(target, port, opts)
  puts JSON.pretty_generate(result)
end
