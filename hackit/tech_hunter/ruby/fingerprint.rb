#!/usr/bin/env ruby
# Web Technology Fingerprinter (via stdin JSON)
require 'json'

input = STDIN.read
data = JSON.parse(input) rescue {}
body = data['body'] || ''
headers = data['headers'] || {}

body_lower = body.downcase
server = (headers['Server'] || headers['server'] || '').downcase
x_powered = (headers['X-Powered-By'] || headers['x-powered-by'] || '').downcase
set_cookie = (headers['Set-Cookie'] || headers['set-cookie'] || '').downcase

techs = []

# JavaScript Frameworks
if body.include?('__NEXT_DATA__') || body.include?('_next/static')
  techs << { Name: "Next.js", Category: "JavaScript Framework", Confidence: 90, Version: "" }
elsif body.include?('__NUXT__') || body.include?('_nuxt/')
  techs << { Name: "Nuxt.js", Category: "JavaScript Framework", Confidence: 90, Version: "" }
elsif body.include?('___gatsby') || body.include?('gatsby-')
  techs << { Name: "Gatsby", Category: "JavaScript Framework", Confidence: 85, Version: "" }
end

# SPA Detection
if body.include?('react') || body.include?('react-dom') || body.include?('createElement')
  techs << { Name: "React", Category: "JavaScript Framework", Confidence: 80, Version: "" }
end
if body.include?('vue') || body.include?('vue.js') || body.include?('v-bind') || body.include?('v-model')
  techs << { Name: "Vue.js", Category: "JavaScript Framework", Confidence: 80, Version: "" }
end
if body.include?('angular') || body.include?('ng-app') || body.include?('ng-controller')
  techs << { Name: "Angular", Category: "JavaScript Framework", Confidence: 80, Version: "" }
end

# CSS Frameworks
if body.include?('bootstrap') || body.include?('bootstrap.min')
  techs << { Name: "Bootstrap", Category: "CSS Framework", Confidence: 85, Version: "" }
end
if body.include?('tailwind') || body.include?('tailwindcss')
  techs << { Name: "Tailwind CSS", Category: "CSS Framework", Confidence: 85, Version: "" }
end

# JavaScript Libraries
if body.include?('jquery') || body.include?('jQuery')
  ver = body.match(/jquery[.-](\d+\.\d+(?:\.\d+)?)/i)
  techs << { Name: "jQuery", Category: "JavaScript Library", Confidence: 90, Version: ver ? ver[1] : "" }
end

# Analytics
if body.include?('google-analytics') || body.include?('gtag(')
  techs << { Name: "Google Analytics", Category: "Analytics", Confidence: 85, Version: "" }
end
if body.include?('hotjar') || body.include?('hj(')
  techs << { Name: "Hotjar", Category: "Analytics", Confidence: 80, Version: "" }
end

# Web Servers
if server.include?('nginx')
  ver = server.match(/nginx\/(\d+\.\d+(?:\.\d+)?)/)
  techs << { Name: "Nginx", Category: "Web Server", Confidence: 95, Version: ver ? ver[1] : "" }
elsif server.include?('apache')
  ver = server.match(/Apache\/(\d+\.\d+(?:\.\d+)?)/)
  techs << { Name: "Apache", Category: "Web Server", Confidence: 95, Version: ver ? ver[1] : "" }
elsif server.include?('cloudflare')
  techs << { Name: "Cloudflare", Category: "CDN", Confidence: 95, Version: "" }
end

# Programming Languages
if x_powered.include?('php') || server.include?('php')
  techs << { Name: "PHP", Category: "Programming Language", Confidence: 80, Version: "" }
end
if x_powered.include?('asp.net') || server.include?('asp.net')
  techs << { Name: "ASP.NET", Category: "Programming Language", Confidence: 80, Version: "" }
end

puts JSON.generate(techs)
