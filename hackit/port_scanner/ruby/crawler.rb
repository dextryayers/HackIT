require 'socket'
require 'net/http'
require 'openssl'
require 'json'
require 'uri'

module HackIT
  class Crawler
    SENSITIVE_PATHS = [
      '/admin', '/config', '/backup', '/.git', '/.env', '/.svn', '/.DS_Store',
      '/wp-admin', '/wp-content', '/wp-includes', '/administrator', '/phpmyadmin',
      '/crossdomain.xml', '/clientaccesspolicy.xml', '/sitemap.xml', '/robots.txt',
      '/server-status', '/server-info', '/info.php', '/test.php', '/phpinfo.php',
      '/wsdl', '/api/wsdl', '/soap', '/api/soap', '/graphql', '/api/graphql',
      '/swagger', '/api/swagger', '/docs', '/api/docs', '/api/v1', '/api/v2',
      '/v1', '/v2', '/beta', '/staging', '/dev', '/test', '/debug',
      '/logs', '/error_log', '/access_log', '/var/log', '/tmp',
      '/web.config', '/.htaccess', '/.htpasswd', '/config.php', '/config.php.bak',
      '/database.yml', '/.gitignore', '/composer.json', '/package.json', '/Dockerfile',
      '/docker-compose.yml', '/Makefile', '/README', '/CHANGELOG', '/license.txt',
      '/cgi-bin', '/cgi-bin/test.cgi', '/cgi-bin/status', '/icons/',
      '/shell', '/cmd', '/exec', '/upload', '/uploads', '/files',
      '/download', '/downloads', '/media', '/assets', '/static',
      '/api/health', '/api/status', '/api/metrics', '/metrics',
      '/actuator', '/actuator/health', '/actuator/info', '/actuator/env',
      '/actuator/beans', '/actuator/mappings', '/actuator/trace',
      '/.well-known', '/.well-known/security.txt', '/.well-known/acme-challenge'
    ]

    COMMON_EXTENSIONS = %w[.php .asp .aspx .jsp .do .action .html .htm .shtml .cfm .py .rb .pl .cgi]

    def self.plugin_info
      {
        name: 'Crawler',
        version: '2.0.0',
        description: 'Web crawler that discovers links, forms, comments, hidden directories, sensitive files, and API endpoints with robots.txt parsing',
        author: 'HackIT Team'
      }
    end

    def run(target, port, opts = {})
      findings = []
      risk_score = 0
      proto = opts[:ssl] || port.to_i == 443 ? 'https' : 'http'
      base_url = "#{proto}://#{target}:#{port}"

      discovered_paths = []
      discovered_forms = []
      discovered_comments = []
      discovered_links = []
      max_pages = opts[:max_pages] || 20

      begin
        robots = fetch_robots_txt(base_url, opts)
        findings.concat(robots[:findings]) if robots[:findings].any?

        sitemap = fetch_sitemap(base_url, opts)
        findings.concat(sitemap[:findings])

        crawl_result = crawl_home(base_url, opts)
        findings.concat(crawl_result[:findings])
        discovered_links.concat(crawl_result[:links])
        discovered_forms.concat(crawl_result[:forms])
        discovered_comments.concat(crawl_result[:comments])

        paths_result = check_sensitive_paths(base_url, opts)
        paths_result[:paths].each do |fp|
          findings << "Found: #{fp[:path]} (#{fp[:status]})"
          risk_score += fp[:risk]
        end
        discovered_paths.concat(paths_result[:paths])

        unless discovered_links.empty?
          discovered_links.uniq.take(max_pages - 5).each do |link|
            next if link == base_url || link.include?('#')
            sub_result = crawl_page(link, opts)
            sub_result[:forms].each { |f| discovered_forms << f }
            sub_result[:comments].each { |c| discovered_comments << c }
          end
        end

      rescue => e
        findings << "Crawl error: #{e.message}"
      end

      if discovered_forms.any?
        findings << "Forms found: #{discovered_forms.size}"
        risk_score += discovered_forms.size * 3
      end
      if discovered_comments.any?
        findings << "HTML comments with #{discovered_comments.size} potential info leaks"
        risk_score += discovered_comments.size * 5
      end

      api_findings = discovered_paths.select { |p| p[:path].match?(/\/api\/|\/v\d+\/|\/graphql|\/rest|\/swagger/) }
      unless api_findings.empty?
        findings << "API endpoints: #{api_findings.map { |p| p[:path] }.join(', ')}"
        risk_score += api_findings.size * 5
      end

      findings << "Discovered #{discovered_paths.size} paths, #{discovered_forms.size} forms, #{discovered_comments.size} comments"

      { status: findings.any? ? 'completed' : 'failed', findings: findings, risk_score: [risk_score, 100].min }
    end

    private

    def fetch_robots_txt(base_url, opts)
      findings = []
      begin
        uri = URI.parse("#{base_url}/robots.txt")
        http = build_http(uri, opts)
        req = Net::HTTP::Get.new(uri.request_uri, headers)
        res = http.request(req)
        if res.code.to_i == 200
          findings << "robots.txt found (#{res.body.length} bytes)"
          disallows = res.body.scan(/Disallow:\s*(.*)/i).flatten.map(&:strip).reject(&:empty?)
          findings << "Disallowed paths: #{disallows.join(', ')}" unless disallows.empty?
        end
      rescue
      end
      { findings: findings }
    end

    def fetch_sitemap(base_url, opts)
      findings = []
      %w[/sitemap.xml /sitemap_index.xml /sitemap/].each do |path|
        begin
          uri = URI.parse("#{base_url}#{path}")
          http = build_http(uri, opts)
          req = Net::HTTP::Get.new(uri.request_uri, headers)
          res = http.request(req)
          if res.code.to_i == 200
            urls = res.body.scan(/<loc>(.*?)<\/loc>/i).flatten
            findings << "Sitemap found: #{path} (#{urls.size} URLs)" unless urls.empty?
          end
        rescue
        end
      end
      { findings: findings }
    end

    def crawl_home(base_url, opts)
      findings = []
      links = []
      forms = []
      comments = []

      begin
        uri = URI.parse(base_url)
        http = build_http(uri, opts)
        req = Net::HTTP::Get.new(uri.request_uri, headers)
        res = http.request(req)

        if res.code.to_i == 200
          body = res.body.to_s

          links = body.scan(/href=["']([^"']+)["']/i).flatten +
                  body.scan(/src=["']([^"']+)["']/i).flatten +
                  body.scan(/action=["']([^"']+)["']/i).flatten
          links = links.map { |l| l.start_with?('http') ? l : URI.join(base_url, l).to_s rescue nil }.compact.uniq
          findings << "Discovered #{links.size} links on homepage" unless links.empty?

          forms = body.scan(/<form[^>]*>(.*?)<\/form>/im).flatten
          forms.each do |f|
            action = f.match(/action=["']([^"']*)["']/i)
            method = f.match(/method=["']([^"']*)["']/i)
            inputs = f.scan(/<input[^>]*>/i).size
            findings << "Form: action=#{action[1] rescue 'none'} method=#{method[1]&.upcase rescue 'GET'} inputs=#{inputs}"
          end

          comments = body.scan(/<!--(.*?)-->/m).flatten
          comments = comments.map(&:strip).reject(&:empty?)
          comments.each do |c|
            findings << "Comment: #{c[0..120]}" if c.length > 10 && !c.match?(/\[if|<!\[endif/i)
          end
        end
      rescue => e
        findings << "Homepage crawl: #{e.message}"
      end

      { findings: findings, links: links, forms: forms, comments: comments }
    end

    def crawl_page(url, opts)
      forms = []
      comments = []

      begin
        uri = URI.parse(url)
        http = build_http(uri, opts)
        req = Net::HTTP::Get.new(uri.request_uri, headers)
        res = http.request(req)

        if res.code.to_i == 200
          body = res.body.to_s
          forms = body.scan(/<form[^>]*>(.*?)<\/form>/im)
          comments = body.scan(/<!--(.*?)-->/m).flatten.map(&:strip).reject(&:empty?)
        end
      rescue
      end

      { forms: forms, comments: comments }
    end

    def check_sensitive_paths(base_url, opts)
      paths = []
      semaphore = Mutex.new
      threads = []

      SENSITIVE_PATHS.each do |path|
        threads << Thread.new do
          begin
            uri = URI.parse("#{base_url}#{path}")
            http = build_http(uri, opts)
            req = Net::HTTP::Get.new(uri.request_uri, headers)
            res = http.request(req)

            if res.code.to_i == 200
              risk = case path
              when '/.git', '/.env', '/.svn', '/backup', '/config', '/database.yml'
                25
              when '/admin', '/phpmyadmin', '/administrator', '/wp-admin'
                15
              when '/crossdomain.xml', '/clientaccesspolicy.xml'
                10
              when '/server-status', '/server-info', '/info.php', '/phpinfo.php'
                20
              when '/actuator', '/actuator/env', '/actuator/beans'
                20
              when '/api/', '/graphql', '/swagger', '/docs'
                10
              when '/robots.txt', '/sitemap.xml'
                2
              else
                5
              end

              semaphore.synchronize do
                paths << { path: path, status: res.code, risk: risk }
                risk = 0
              end
            end
          rescue
          end
        end
      end
      threads.each(&:join)

      { paths: paths }
    end

    def build_http(uri, opts)
      http = Net::HTTP.new(uri.host, uri.port)
      http.open_timeout = opts[:timeout] || 3
      http.read_timeout = opts[:timeout] || 3
      http.use_ssl = uri.scheme == 'https'
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      http
    end

    def headers
      {
        'User-Agent' => 'Mozilla/5.0 (compatible; HackIT-Crawler/2.0)',
        'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language' => 'en-US,en;q=0.5'
      }
    end
  end
end

if __FILE__ == $0
  target = ARGV[0] || '127.0.0.1'
  port = (ARGV[1] || 80).to_i
  opts = { ssl: ARGV[2] == 'ssl' }
  crawler = HackIT::Crawler.new
  result = crawler.run(target, port, opts)
  puts JSON.pretty_generate(result)
end
