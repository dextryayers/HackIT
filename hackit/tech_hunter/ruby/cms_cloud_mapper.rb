require 'json'

def detect_cms_and_cloud(domain, body, headers)
  body_lower = body.downcase
  headers_lower = headers.downcase
  
  # CMS Logic
  cms = "None"
  if body_lower.include?("wp-content") || body_lower.include?("wordpress")
    cms = "WordPress"
    # User Request: If WordPress is detected, others are false
    framework = "None"
    backend = "PHP (WordPress Core)"
  else
    if body_lower.include?("drupal")
      cms = "Drupal"
    end
    # Simple framework inference
    framework = "Custom"
    if body_lower.include?("laravel")
      framework = "Laravel"
    elsif body_lower.include?("django")
      framework = "Django"
    end
  end

  # Cloud Assets Simulation
  base = domain.split('.').first
  cloud_assets = {
    "s3_buckets" => ["#{base}-data", "#{base}-assets", "#{base}-backup"],
    "gcp_buckets" => ["#{base}-storage"],
    "firebase" => ["#{base}-auth", "#{base}-db"],
    "github_org" => "https://github.com/#{base}"
  }

  {
    "cms" => cms,
    "framework" => framework,
    "cloud_assets" => cloud_assets
  }
end

if __FILE__ == $0
  domain = ARGV[0] || "example.com"
  body = ARGV[1] || ""
  headers = ARGV[2] || ""
  puts JSON.generate(detect_cms_and_cloud(domain, body, headers))
end
