require 'json'

def deep_cms_audit(body)
  findings = []
  
  # Deep Wordpress Audit
  if body =~ /wp-content/
    findings << "Theme: " + body.match(/themes\/([^\/]+)/)[1] rescue nil
    findings << "Plugin: " + body.match(/plugins\/([^\/]+)/)[1] rescue nil
  end

  # Deep Drupal Audit
  if body =~ /Drupal/
    findings << "Drupal Config Detected"
  end

  findings.compact
end

begin
  input = JSON.parse(STDIN.read)
  results = deep_cms_audit(input['body'])
  puts results.to_json
rescue => e
  puts({ error: e.message }.to_json)
end
