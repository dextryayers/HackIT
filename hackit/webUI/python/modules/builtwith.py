import httpx
import asyncio
import re
import json
from collections import defaultdict
from models import IntelligenceFinding

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
BUILTWITH_API = "https://api.builtwith.com/v21/api.json"

TECH_CATEGORIES = {
    "cms": "CMS",
    "framework": "Web Framework",
    "cdn": "CDN",
    "analytics": "Analytics",
    "tracking": "Tracking",
    "ad": "Advertising",
    "payment": "Payment Processor",
    "hosting": "Hosting",
    "email": "Email Service",
    "ssl": "SSL/TLS",
    "widget": "Widget",
    "cdn_provider": "CDN",
    "cms_framework": "CMS",
    "javascript_framework": "JavaScript Framework",
    "css_framework": "CSS Framework",
    "web_server": "Web Server",
    "os": "Operating System",
    "database": "Database",
    "programming_language": "Programming Language",
    "reverse_proxy": "Reverse Proxy",
    "security": "Security Service",
    "marketing_automation": "Marketing Automation",
    "tag_manager": "Tag Manager",
    "live_chat": "Live Chat",
    "video": "Video Platform",
    "font": "Font Service",
    "map": "Mapping Service",
    "ecommerce": "E-commerce",
    "forum": "Forum Software",
    "blog": "Blog Platform",
    "wiki": "Wiki Software",
    "learning_management": "LMS",
    "customer_relationship": "CRM",
    "erp": "ERP",
    "social_network": "Social Network",
    "comment": "Comment System",
    "newsletter": "Newsletter",
    "payment_processor": "Payment Processor",
    "affiliate": "Affiliate Program",
    "seo": "SEO Tool",
    "performance": "Performance",
    "security": "Security",
    "accessibility": "Accessibility",
    "font_service": "Font Service",
    "development": "Development Tool",
    "documentation": "Documentation Tool",
}

EOL_TECHNOLOGIES = {
    "php 5": "End of Life since 2018",
    "php 7.0": "End of Life since 2018",
    "php 7.1": "End of Life since 2019",
    "php 7.2": "End of Life since 2020",
    "php 7.3": "End of Life since 2021",
    "php 7.4": "End of Life since 2022",
    "php 8.0": "Security Support only",
    "jquery 1": "End of Life",
    "jquery 2": "End of Life",
    "angularjs": "End of Life (1.x)",
    "internet explorer": "End of Life",
    "flash": "End of Life",
    "coldfusion": "End of Life support",
    "windows server 2003": "End of Life",
    "windows server 2008": "End of Life",
    "windows server 2012": "Extended Support only",
    "ubuntu 16": "End of Life",
    "ubuntu 18": "End of Life",
    "centos 6": "End of Life",
    "centos 7": "End of Life",
    "nginx 1.1": "Old version",
    "apache 2.0": "Old version",
    "apache 2.2": "Old version",
    "python 2": "End of Life",
    "ruby 2": "Security Maintenance",
    "node 8": "End of Life",
    "node 10": "End of Life",
    "node 12": "End of Life",
    "tomcat 7": "End of Life",
    "tomcat 8": "End of Life",
    "iis 7": "Old version",
    "iis 8": "Old version",
}

TECH_RISK_MAP = {
    "web_server": 2,
    "cdn": 1,
    "cms": 5,
    "framework": 3,
    "analytics": 2,
    "tracking": 3,
    "ad": 2,
    "payment": 7,
    "hosting": 3,
    "email": 4,
    "widget": 2,
    "javascript_framework": 2,
    "css_framework": 1,
    "database": 6,
    "os": 4,
    "programming_language": 3,
    "security": 1,
    "reverse_proxy": 2,
    "ecommerce": 6,
    "forum": 4,
    "wiki": 3,
    "crm": 5,
    "erp": 6,
    "payment_processor": 7,
    "seo": 1,
    "performance": 1,
}

TECHNOLOGY_SIGNATURES = {
    "WordPress": {"category": "CMS", "patterns": [r"wp-content", r"wp-includes", r"wordpress", r"wp-json"]},
    "Joomla": {"category": "CMS", "patterns": [r"joomla", r"com_content", r"com_modules", r"com_users"]},
    "Drupal": {"category": "CMS", "patterns": [r"drupal", r"drupal.js", r"sites/all", r"drupalSettings"]},
    "Magento": {"category": "E-commerce", "patterns": [r"magento", r"mage/", r"skin/frontend", r"lib/prototype"]},
    "Shopify": {"category": "E-commerce", "patterns": [r"shopify", r"myshopify", r"cdn\.shopify\.com"]},
    "WooCommerce": {"category": "E-commerce", "patterns": [r"woocommerce", r"wc-api", r"woo-variation"]},
    "Laravel": {"category": "Framework", "patterns": [r"laravel", r"csrf-token", r"livewire"]},
    "Django": {"category": "Framework", "patterns": [r"django", r"csrfmiddlewaretoken", r"__admin__"]},
    "Ruby on Rails": {"category": "Framework", "patterns": [r"rails", r"turbolinks", r"csrf-param"]},
    "Express": {"category": "Framework", "patterns": [r"express", r"x-powered-by.*express"]},
    "Next.js": {"category": "Framework", "patterns": [r"__next", r"next\.js", r"_next/static", r"next/static"]},
    "Nuxt.js": {"category": "Framework", "patterns": [r"__nuxt", r"nuxt\.js", r"_nuxt/"]},
    "Gatsby": {"category": "Framework", "patterns": [r"gatsby", r"___gatsby"]},
    "Vue.js": {"category": "JavaScript Framework", "patterns": [r"vue\.js", r"vue\.min\.js", r"__vue__", r"v-bind"]},
    "React": {"category": "JavaScript Framework", "patterns": [r"react\.js", r"react\.min\.js", r"reactroot", r"__react"]},
    "Angular": {"category": "JavaScript Framework", "patterns": [r"angular\.js", r"angular\.min\.js", r"ng-app", r"ng-version"]},
    "Svelte": {"category": "JavaScript Framework", "patterns": [r"svelte", r"__svelte"]},
    "jQuery": {"category": "JavaScript Library", "patterns": [r"jquery", r"jQuery"]},
    "Bootstrap": {"category": "CSS Framework", "patterns": [r"bootstrap", r"bootstrap\.min\.css", r"col-md-"]},
    "Tailwind CSS": {"category": "CSS Framework", "patterns": [r"tailwind", r"tailwindcss"]},
    "Foundation": {"category": "CSS Framework", "patterns": [r"foundation\.css", r"foundation\.min\.css", r"zurb"]},
    "Materialize": {"category": "CSS Framework", "patterns": [r"materialize", r"materialize\.css"]},
    "Nginx": {"category": "Web Server", "patterns": [r"nginx"]},
    "Apache": {"category": "Web Server", "patterns": [r"apache"]},
    "IIS": {"category": "Web Server", "patterns": [r"iis", r"x-aspnet"]},
    "Cloudflare": {"category": "CDN", "patterns": [r"cloudflare", r"cf-ray"]},
    "Akamai": {"category": "CDN", "patterns": [r"akamai", r"akamaized"]},
    "Fastly": {"category": "CDN", "patterns": [r"fastly"]},
    "Google Analytics": {"category": "Analytics", "patterns": [r"google-analytics", r"ga\(", r"gtag"]},
    "Facebook Pixel": {"category": "Analytics", "patterns": [r"facebook.*pixel", r"fbq\("]},
    "Hotjar": {"category": "Analytics", "patterns": [r"hotjar", r"hj\("]},
    "Mixpanel": {"category": "Analytics", "patterns": [r"mixpanel"]},
    "Matomo": {"category": "Analytics", "patterns": [r"matomo", r"piwik"]},
    "Intercom": {"category": "Live Chat", "patterns": [r"intercom"]},
    "Drift": {"category": "Live Chat", "patterns": [r"drift"]},
    "Zendesk": {"category": "Live Chat", "patterns": [r"zendesk"]},
    "Tawk.to": {"category": "Live Chat", "patterns": [r"tawk"]},
    "LiveChat": {"category": "Live Chat", "patterns": [r"livechat"]},
    "Stripe": {"category": "Payment Processor", "patterns": [r"stripe\.com", r"pk_live_", r"sk_live_"]},
    "PayPal": {"category": "Payment Processor", "patterns": [r"paypal", r"paypalobjects"]},
    "Braintree": {"category": "Payment Processor", "patterns": [r"braintree"]},
    "Square": {"category": "Payment Processor", "patterns": [r"square\.com", r"squareup"]},
    "Google Tag Manager": {"category": "Tag Manager", "patterns": [r"googletagmanager", r"gtm\.js"]},
    "Segment": {"category": "Analytics", "patterns": [r"segment\.com", r"analytics\.js"]},
    "Amplitude": {"category": "Analytics", "patterns": [r"amplitude"]},
    "FullStory": {"category": "Analytics", "patterns": [r"fullstory"]},
    "CrazyEgg": {"category": "Analytics", "patterns": [r"crazyegg"]},
    "Optimizely": {"category": "Analytics", "patterns": [r"optimizely"]},
    "VWO": {"category": "Analytics", "patterns": [r"vwo"]},
    "Disqus": {"category": "Comment System", "patterns": [r"disqus"]},
    "Facebook Comments": {"category": "Comment System", "patterns": [r"facebook.*comments"]},
    "Mailchimp": {"category": "Newsletter", "patterns": [r"mailchimp"]},
    "SendGrid": {"category": "Email Service", "patterns": [r"sendgrid"]},
    "Mailgun": {"category": "Email Service", "patterns": [r"mailgun"]},
    "Postmark": {"category": "Email Service", "patterns": [r"postmark"]},
    "AWS": {"category": "Cloud Platform", "patterns": [r"amazonaws", r"aws"]},
    "Google Cloud": {"category": "Cloud Platform", "patterns": [r"googleapis", r"gstatic"]},
    "Azure": {"category": "Cloud Platform", "patterns": [r"azure", r"windows\.net"]},
    "Heroku": {"category": "Cloud Platform", "patterns": [r"heroku"]},
    "Netlify": {"category": "Cloud Platform", "patterns": [r"netlify"]},
    "Vercel": {"category": "Cloud Platform", "patterns": [r"vercel"]},
    "DigitalOcean": {"category": "Cloud Platform", "patterns": [r"digitalocean"]},
    "php": {"category": "Programming Language", "patterns": [r"php"]},
    "Python": {"category": "Programming Language", "patterns": [r"python"]},
    "Ruby": {"category": "Programming Language", "patterns": [r"ruby"]},
    "Node.js": {"category": "Programming Language", "patterns": [r"node\.js", r"nodejs"]},
    "Java": {"category": "Programming Language", "patterns": [r"java"]},
    "Go": {"category": "Programming Language", "patterns": [r"golang"]},
    "Rust": {"category": "Programming Language", "patterns": [r"rust"]},
    "MySQL": {"category": "Database", "patterns": [r"mysql"]},
    "PostgreSQL": {"category": "Database", "patterns": [r"postgres", r"pgsql"]},
    "MongoDB": {"category": "Database", "patterns": [r"mongodb", r"mongo"]},
    "Redis": {"category": "Database", "patterns": [r"redis"]},
    "Elasticsearch": {"category": "Database", "patterns": [r"elasticsearch", r"elastic"]},
    "Linux": {"category": "Operating System", "patterns": [r"linux", r"ubuntu", r"debian"]},
    "Windows Server": {"category": "Operating System", "patterns": [r"windows"]},
    "Docker": {"category": "Virtualization", "patterns": [r"docker"]},
    "Kubernetes": {"category": "Virtualization", "patterns": [r"kubernetes", r"k8s"]},
    "CloudFlare": {"category": "CDN", "patterns": [r"cloudflare"]},
    "Sucuri": {"category": "Security", "patterns": [r"sucuri"]},
    "ModSecurity": {"category": "Security", "patterns": [r"mod_security", r"modsecurity"]},
    "CAPTCHA": {"category": "Security", "patterns": [r"recaptcha", r"captcha"]},
    "hCaptcha": {"category": "Security", "patterns": [r"hcaptcha"]},
    "Gravatar": {"category": "Widget", "patterns": [r"gravatar"]},
    "Google Fonts": {"category": "Font Service", "patterns": [r"fonts\.googleapis", r"fonts\.gstatic"]},
    "Font Awesome": {"category": "Font Service", "patterns": [r"font-awesome", r"fontawesome"]},
    "Typekit": {"category": "Font Service", "patterns": [r"typekit"]},
    "Vimeo": {"category": "Video Platform", "patterns": [r"vimeo"]},
    "YouTube": {"category": "Video Platform", "patterns": [r"youtube\.com"]},
    "Wistia": {"category": "Video Platform", "patterns": [r"wistia"]},
    "Brightcove": {"category": "Video Platform", "patterns": [r"brightcove"]},
    "Google Maps": {"category": "Mapping Service", "patterns": [r"maps\.googleapis", r"maps\.google\.com"]},
    "Mapbox": {"category": "Mapping Service", "patterns": [r"mapbox"]},
    "Leaflet": {"category": "Mapping Service", "patterns": [r"leaflet"]},
    "OpenStreetMap": {"category": "Mapping Service", "patterns": [r"openstreetmap"]},
    "TinyMCE": {"category": "Widget", "patterns": [r"tinymce"]},
    "CKEditor": {"category": "Widget", "patterns": [r"ckeditor"]},
    "CodeMirror": {"category": "Widget", "patterns": [r"codemirror"]},
    "Highlight.js": {"category": "Widget", "patterns": [r"highlight\.js"]},
    "Prism.js": {"category": "Widget", "patterns": [r"prism\.js"]},
    "Three.js": {"category": "JavaScript Library", "patterns": [r"three\.js"]},
    "D3.js": {"category": "JavaScript Library", "patterns": [r"d3\.js", r"d3\.min\.js"]},
    "Chart.js": {"category": "JavaScript Library", "patterns": [r"chart\.js", r"chart\.min\.js"]},
    "Moment.js": {"category": "JavaScript Library", "patterns": [r"moment\.js"]},
    "Lodash": {"category": "JavaScript Library", "patterns": [r"lodash\.js", r"_."]},
    "Axios": {"category": "JavaScript Library", "patterns": [r"axios"]},
    "Socket.IO": {"category": "JavaScript Library", "patterns": [r"socket\.io"]},
    "GSAP": {"category": "JavaScript Library", "patterns": [r"gsap"]},
    "Swiper": {"category": "JavaScript Library", "patterns": [r"swiper"]},
    "Alpine.js": {"category": "JavaScript Framework", "patterns": [r"alpine\.js"]},
    "Bulma": {"category": "CSS Framework", "patterns": [r"bulma", r"\.has-", r"\.is-"]},
    "Semantic UI": {"category": "CSS Framework", "patterns": [r"semantic\.ui", r"semantic-ui", r"semantic.min.css"]},
    "UIKit": {"category": "CSS Framework", "patterns": [r"uikit", r"uikit\.min\.js"]},
    "Material UI": {"category": "CSS Framework", "patterns": [r"@material-ui", r"mui"]},
    "Ant Design": {"category": "CSS Framework", "patterns": [r"ant-design", r"antd", r"anticon"]},
    "Chakra UI": {"category": "CSS Framework", "patterns": [r"chakra-ui", r"chakra"]},
    "Preact": {"category": "JavaScript Framework", "patterns": [r"preact", r"preact\.js"]},
    "Stimulus": {"category": "JavaScript Framework", "patterns": [r"stimulus", r"stimulus\.js"]},
    "HTMX": {"category": "JavaScript Library", "patterns": [r"htmx", r"hx-", r"hx-get"]},
    "Turbo": {"category": "JavaScript Library", "patterns": [r"turbo\.js", r"@hotwired/turbo"]},
    "Stimulus Reflex": {"category": "JavaScript Library", "patterns": [r"stimulus_reflex", r"reflex"]},
    "Tailwind UI": {"category": "CSS Framework", "patterns": [r"tailwindcss"]},
    "SweetAlert2": {"category": "JavaScript Library", "patterns": [r"sweetalert2", r"Swal\.fire"]},
    "Toastr": {"category": "JavaScript Library", "patterns": [r"toastr", r"toastr\.js"]},
    "Select2": {"category": "JavaScript Library", "patterns": [r"select2", r"select2\.min\.js"]},
    "DataTables": {"category": "JavaScript Library", "patterns": [r"datatables", r"\.DataTable"]},
    "Owl Carousel": {"category": "JavaScript Library", "patterns": [r"owlcarousel", r"owl\.carousel"]},
    "FancyBox": {"category": "JavaScript Library", "patterns": [r"fancybox", r"fancyBox"]},
    "Isotope": {"category": "JavaScript Library", "patterns": [r"isotope", r"isotope\.pkgd"]},
    "Masonry": {"category": "JavaScript Library", "patterns": [r"masonry", r"masonry\.pkgd"]},
    "Webpack": {"category": "Build Tool", "patterns": [r"webpack"]},
    "Vite": {"category": "Build Tool", "patterns": [r"vite", r"vite\.js"]},
    "ESBuild": {"category": "Build Tool", "patterns": [r"esbuild"]},
    "Parcel": {"category": "Build Tool", "patterns": [r"parcel"]},
    "Babel": {"category": "Build Tool", "patterns": [r"babel"]},
    "Gulp": {"category": "Build Tool", "patterns": [r"gulpfile", r"gulp\.js"]},
    "Grunt": {"category": "Build Tool", "patterns": [r"gruntfile", r"grunt\.js"]},
    "TypeScript": {"category": "Programming Language", "patterns": [r"typescript", r"\.ts"]},
    "Swift": {"category": "Programming Language", "patterns": [r"swift"]},
    "Kotlin": {"category": "Programming Language", "patterns": [r"kotlin"]},
    "Scala": {"category": "Programming Language", "patterns": [r"scala"]},
    "Perl": {"category": "Programming Language", "patterns": [r"perl"]},
    "Haskell": {"category": "Programming Language", "patterns": [r"haskell"]},
    "Elixir": {"category": "Programming Language", "patterns": [r"elixir"]},
    "Clojure": {"category": "Programming Language", "patterns": [r"clojure"]},
    "MariaDB": {"category": "Database", "patterns": [r"mariadb"]},
    "SQLite": {"category": "Database", "patterns": [r"sqlite"]},
    "Cassandra": {"category": "Database", "patterns": [r"cassandra"]},
    "Neo4j": {"category": "Database", "patterns": [r"neo4j"]},
    "CouchDB": {"category": "Database", "patterns": [r"couchdb"]},
    "Firebase": {"category": "BaaS", "patterns": [r"firebase", r"firebaseio"]},
    "Supabase": {"category": "BaaS", "patterns": [r"supabase"]},
    "Directus": {"category": "Headless CMS", "patterns": [r"directus"]},
    "Strapi": {"category": "Headless CMS", "patterns": [r"strapi"]},
    "Contentful": {"category": "Headless CMS", "patterns": [r"contentful"]},
    "Sanity": {"category": "Headless CMS", "patterns": [r"sanity"]},
    "Prismic": {"category": "Headless CMS", "patterns": [r"prismic"]},
    "Ghost": {"category": "CMS", "patterns": [r"ghost", r"ghost\.io"]},
    "Hugo": {"category": "CMS", "patterns": [r"hugo"]},
    "Jekyll": {"category": "CMS", "patterns": [r"jekyll"]},
    "Wix": {"category": "CMS", "patterns": [r"wix", r"wixstatic"]},
    "Squarespace": {"category": "CMS", "patterns": [r"squarespace"]},
    "Weebly": {"category": "CMS", "patterns": [r"weebly"]},
    "Blogger": {"category": "CMS", "patterns": [r"blogger"]},
    "TYPO3": {"category": "CMS", "patterns": [r"typo3"]},
    "Concrete5": {"category": "CMS", "patterns": [r"concrete5"]},
    "October CMS": {"category": "CMS", "patterns": [r"octobercms"]},
    "Craft CMS": {"category": "CMS", "patterns": [r"craftcms"]},
    "Statamic": {"category": "CMS", "patterns": [r"statamic"]},
    "Webflow": {"category": "CMS", "patterns": [r"webflow"]},
    "Umbraco": {"category": "CMS", "patterns": [r"umbraco"]},
    "Sitecore": {"category": "CMS", "patterns": [r"sitecore"]},
    "Kentico": {"category": "CMS", "patterns": [r"kentico"]},
    "SharePoint": {"category": "CMS", "patterns": [r"sharepoint"]},
    "Moodle": {"category": "CMS", "patterns": [r"moodle"]},
    "Drupal Commerce": {"category": "E-commerce", "patterns": [r"drupal.*commerce", r"commerce"]},
    "PrestaShop": {"category": "E-commerce", "patterns": [r"prestashop"]},
    "OpenCart": {"category": "E-commerce", "patterns": [r"opencart"]},
    "Zen Cart": {"category": "E-commerce", "patterns": [r"zen-cart", r"zencart"]},
    "osCommerce": {"category": "E-commerce", "patterns": [r"oscommerce"]},
    "BigCommerce": {"category": "E-commerce", "patterns": [r"bigcommerce"]},
    "Squarespace Commerce": {"category": "E-commerce", "patterns": [r"squarespace.*commerce"]},
    "Ecwid": {"category": "E-commerce", "patterns": [r"ecwid"]},
    "Snipcart": {"category": "E-commerce", "patterns": [r"snipcart"]},
    "Gumroad": {"category": "E-commerce", "patterns": [r"gumroad"]},
    "Lemon Squeezy": {"category": "E-commerce", "patterns": [r"lemonsqueezy"]},
    "Paddle": {"category": "Payment Processor", "patterns": [r"paddle\.com", r"paddlejs"]},
    "Mollie": {"category": "Payment Processor", "patterns": [r"mollie"]},
    "Adyen": {"category": "Payment Processor", "patterns": [r"adyen"]},
    "Worldpay": {"category": "Payment Processor", "patterns": [r"worldpay"]},
    "Authorize.Net": {"category": "Payment Processor", "patterns": [r"authorize\.net"]},
    "2Checkout": {"category": "Payment Processor", "patterns": [r"2checkout"]},
    "iDEAL": {"category": "Payment Processor", "patterns": [r"ideal"]},
    "Razorpay": {"category": "Payment Processor", "patterns": [r"razorpay"]},
    "PayU": {"category": "Payment Processor", "patterns": [r"payu"]},
    "Mercado Pago": {"category": "Payment Processor", "patterns": [r"mercadopago"]},
    "PagSeguro": {"category": "Payment Processor", "patterns": [r"pagseguro"]},
    "Flutterwave": {"category": "Payment Processor", "patterns": [r"flutterwave"]},
    "Paystack": {"category": "Payment Processor", "patterns": [r"paystack"]},
    "Eway": {"category": "Payment Processor", "patterns": [r"eway"]},
    "Freshdesk": {"category": "Customer Support", "patterns": [r"freshdesk"]},
    "Zendesk Chat": {"category": "Live Chat", "patterns": [r"zopim", r"zendesk_chat"]},
    "Olark": {"category": "Live Chat", "patterns": [r"olark"]},
    "LivePerson": {"category": "Live Chat", "patterns": [r"liveperson"]},
    "Crisp": {"category": "Live Chat", "patterns": [r"crisp"]},
    "HubSpot": {"category": "CRM", "patterns": [r"hubspot"]},
    "Salesforce": {"category": "CRM", "patterns": [r"salesforce"]},
    "Salesforce Commerce Cloud": {"category": "E-commerce", "patterns": [r"demandware"]},
    "Marketo": {"category": "Marketing Automation", "patterns": [r"marketo"]},
    "HubSpot Analytics": {"category": "Analytics", "patterns": [r"hs-analytics", r"hubspot\.com.*analytics"]},
    "Heap": {"category": "Analytics", "patterns": [r"heap\.io", r"heapanalytics"]},
    "Snowplow": {"category": "Analytics", "patterns": [r"snowplow"]},
    "RudderStack": {"category": "Analytics", "patterns": [r"rudderstack", r"rudderanalytics"]},
    "Mouseflow": {"category": "Analytics", "patterns": [r"mouseflow"]},
    "Lucky Orange": {"category": "Analytics", "patterns": [r"luckyorange"]},
    "Clicky": {"category": "Analytics", "patterns": [r"clicky"]},
    "Statcounter": {"category": "Analytics", "patterns": [r"statcounter"]},
    "Open Web Analytics": {"category": "Analytics", "patterns": [r"openwebanalytics"]},
    "Fathom": {"category": "Analytics", "patterns": [r"fathom"]},
    "Plausible": {"category": "Analytics", "patterns": [r"plausible"]},
    "Simple Analytics": {"category": "Analytics", "patterns": [r"simpleanalytics"]},
    "Umami": {"category": "Analytics", "patterns": [r"umami"]},
    "GoatCounter": {"category": "Analytics", "patterns": [r"goatcounter"]},
    "Microsoft Clarity": {"category": "Analytics", "patterns": [r"clarity\.ms", r"microsoft\.com/clarity"]},
    "Yandex Metrica": {"category": "Analytics", "patterns": [r"yandex.*metrika", r"mc\.yandex"]},
    "Piwik PRO": {"category": "Analytics", "patterns": [r"piwik\.pro"]},
    "New Relic": {"category": "APM", "patterns": [r"newrelic", r"newrelic\.com"]},
    "Datadog": {"category": "APM", "patterns": [r"datadog"]},
    "Dynatrace": {"category": "APM", "patterns": [r"dynatrace"]},
    "AppDynamics": {"category": "APM", "patterns": [r"appdynamics"]},
    "Sentry": {"category": "APM", "patterns": [r"sentry"]},
    "Rollbar": {"category": "APM", "patterns": [r"rollbar"]},
    "Bugsnag": {"category": "APM", "patterns": [r"bugsnag"]},
    "LogRocket": {"category": "APM", "patterns": [r"logrocket"]},
    "FullStory": {"category": "Analytics", "patterns": [r"fullstory"]},
    "Auth0": {"category": "Authentication", "patterns": [r"auth0"]},
    "Firebase Auth": {"category": "Authentication", "patterns": [r"firebase.*auth"]},
    "Clerk": {"category": "Authentication", "patterns": [r"clerk"]},
    "NextAuth": {"category": "Authentication", "patterns": [r"next-auth"]},
    "Okta": {"category": "Authentication", "patterns": [r"okta"]},
    "OneLogin": {"category": "Authentication", "patterns": [r"onelogin"]},
    "PingIdentity": {"category": "Authentication", "patterns": [r"pingidentity"]},
    "Keycloak": {"category": "Authentication", "patterns": [r"keycloak"]},
    "FusionAuth": {"category": "Authentication", "patterns": [r"fusionauth"]},
    "Amazon Cognito": {"category": "Authentication", "patterns": [r"cognito"]},
    "Azure AD": {"category": "Authentication", "patterns": [r"azure.*ad", r"login\.microsoftonline"]},
    "Cloudflare Turnstile": {"category": "Security", "patterns": [r"turnstile"]},
    "reCAPTCHA v3": {"category": "Security", "patterns": [r"recaptcha.*v3", r"grecaptcha"]},
    "Cloudflare Bot Management": {"category": "Security", "patterns": [r"cf.*bot", r"bot_management"]},
    "Imperva": {"category": "Security", "patterns": [r"imperva", r"incapsula"]},
    "Barracuda": {"category": "Security", "patterns": [r"barracuda"]},
    "F5 BIG-IP": {"category": "Security", "patterns": [r"bigip", r"f5"]},
    "Fortinet": {"category": "Security", "patterns": [r"fortinet", r"fortigate"]},
    "Palo Alto": {"category": "Security", "patterns": [r"paloalto", r"panw"]},
    "Radware": {"category": "Security", "patterns": [r"radware"]},
    "AWS WAF": {"category": "Security", "patterns": [r"awswaf", r"x-amzn-waf"]},
    "GCP Cloud Armor": {"category": "Security", "patterns": [r"cloud-armor"]},
}

VERSION_PATTERNS = {
    "WordPress": [r"(?i)wordpress\s*(\d+\.\d+(?:\.\d+)?)", r"ver=(\d+\.\d+(?:\.\d+)?)"],
    "jQuery": [r"(?i)jquery[.-](\d+\.\d+(?:\.\d+)?)", r"jquery.*v?(\d+\.\d+(?:\.\d+)?)"],
    "Bootstrap": [r"(?i)bootstrap[.-](\d+\.\d+(?:\.\d+)?)", r"bootstrap.*v?(\d+\.\d+(?:\.\d+)?)"],
    "Angular": [r"(?i)angular[.-](\d+\.\d+(?:\.\d+)?)", r"ng-version=\"(\d+\.\d+(?:\.\d+)?)"],
    "React": [r"(?i)react[.-](\d+\.\d+(?:\.\d+)?)"],
    "Vue.js": [r"(?i)vue[.-](\d+\.\d+(?:\.\d+)?)"],
    "Laravel": [r"(?i)laravel[./](\d+\.\d+(?:\.\d+)?)"],
    "Drupal": [r"(?i)drupal[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Magento": [r"(?i)magento[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Shopify": [r"(?i)shopify[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Django": [r"(?i)django[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Next.js": [r"(?i)next[.-]?(\d+\.\d+(?:\.\d+)?)"],
    "Nginx": [r"(?i)nginx/(\d+\.\d+(?:\.\d+)?)"],
    "Apache": [r"(?i)apache/(\d+\.\d+(?:\.\d+)?)"],
    "IIS": [r"(?i)iis/(\d+\.\d+)"],
    "Node.js": [r"(?i)node[/.](\d+\.\d+(?:\.\d+)?)"],
    "php": [r"(?i)php/(\d+\.\d+(?:\.\d+)?)", r"x-powered-by.*php/(\d+\.\d+(?:\.\d+)?)"],
    "Python": [r"(?i)python/(\d+\.\d+(?:\.\d+)?)"],
    "Ruby": [r"(?i)ruby/(\d+\.\d+(?:\.\d+)?)"],
}

async def query_builtwith_api(domain: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.get(
            BUILTWITH_API,
            params={"KEY": "", "LOOKUP": domain},
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        return resp.json() if resp.status_code == 200 else {}
    except:
        return {}

async def scrape_builtwith(domain: str, client: httpx.AsyncClient) -> list:
    try:
        resp = await client.get(
            f"https://builtwith.com/{domain}",
            headers={"User-Agent": UA},
            timeout=15.0,
        )
        if resp.status_code == 200:
            text = resp.text
            tech_entries = re.findall(r'data-tech="([^"]+)"', text)
            tech_names = re.findall(r'<a[^>]*href="/[^"]*"[^>]*>([^<]+)</a>', text)
            combined = set()
            for t in tech_entries + tech_names:
                t = t.strip()
                if len(t) > 2 and t not in ("Home", "About", "Contact"):
                    combined.add(t)
            return list(combined)[:40]
    except:
        pass
    return []

async def analyze_technology_signatures(html: str, headers: dict, base_url: str) -> list:
    findings = []
    try:
        html_lower = html.lower() if html else ""
        header_str = " ".join(str(v).lower() for v in headers.values()) if headers else ""
        combined = html_lower + " " + header_str

        for tech_name, tech_info in TECHNOLOGY_SIGNATURES.items():
            for pattern in tech_info["patterns"]:
                if re.search(pattern, combined):
                    category = tech_info["category"]
                    version = None
                    if tech_name in VERSION_PATTERNS:
                        for vpat in VERSION_PATTERNS[tech_name]:
                            vm = re.search(vpat, combined)
                            if vm:
                                version = vm.group(1)
                                break
                    confidence = "High" if version else "Medium"
                    findings.append(IntelligenceFinding(
                        entity=f"{tech_name}" + (f" v{version}" if version else ""),
                        type=f"BuiltWith Signature: {category}",
                        source="BuiltWith",
                        confidence=confidence,
                        color="blue" if category == "CMS" else ("orange" if category == "Framework" else "slate"),
                        threat_level="Informational",
                        raw_data=f"Matched pattern '{pattern}' for {tech_name} (v{version if version else 'N/A'})",
                        tags=["technology", "signature", category.lower().replace(" ", "-")]
                    ))
                    break
    except:
        pass
    return findings

async def analyze_headers(html: str, headers: dict) -> list:
    findings = []
    try:
        tech_headers = {
            "x-powered-by": "X-Powered-By",
            "x-generator": "X-Generator",
            "x-drupal-cache": "Drupal Cache",
            "x-drupal-dynamic-cache": "Drupal Dynamic Cache",
            "x-joomla-cache": "Joomla Cache",
            "x-varnish": "Varnish",
            "x-served-by": "Served By",
            "x-cache": "Cache Status",
            "x-cache-hits": "Cache Hits",
            "x-proxy-cache": "Proxy Cache",
            "x-aspnet-version": "ASP.NET Version",
            "x-aspnetmvc-version": "ASP.NET MVC Version",
            "x-runtime": "Runtime",
            "x-version": "Version",
            "x-generator": "Generator",
            "x-wordpress": "WordPress",
        }
        for header_key, label in tech_headers.items():
            val = headers.get(header_key) if isinstance(headers, dict) else headers.get(header_key, "")
            if val:
                findings.append(IntelligenceFinding(
                    entity=f"{label}: {val[:100]}",
                    type="BuiltWith: Header Technology",
                    source="BuiltWith",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    raw_data=f"{header_key}: {val}",
                    tags=["technology", "header"]
                ))
    except:
        pass
    return findings

def detect_version(name: str) -> tuple:
    m = re.search(r'(v?\d+\.\d+(?:\.\d+)?)', name)
    if m:
        return m.group(1), name.replace(m.group(1), "").strip()
    return None, name

def check_eol(name: str, version: str = None) -> tuple:
    lower = name.lower()
    if version:
        check = f"{lower} {version}"
        for key, status in EOL_TECHNOLOGIES.items():
            if key in check:
                return True, status
    for key, status in EOL_TECHNOLOGIES.items():
        if key in lower:
            return True, status
    return False, None

def tech_risk_score(category: str) -> int:
    for cat_key, risk in TECH_RISK_MAP.items():
        if cat_key in category.lower():
            return risk
    return 3

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    t = target.strip().lower()
    if t.startswith("http"):
        from urllib.parse import urlparse
        t = urlparse(t).netloc

    api_data = await query_builtwith_api(t, client)
    api_results = api_data.get("Results", [])

    tech_groups = defaultdict(list)
    seen_techs = set()

    if api_results:
        for result in api_results[:3]:
            paths = result.get("Result", {}).get("Paths", [])
            for tech in paths[:40] if isinstance(paths, list) else []:
                if not isinstance(tech, dict):
                    continue
                tech_name = (tech.get("name") or tech.get("description", "")).strip()
                if not tech_name or tech_name in seen_techs:
                    continue
                seen_techs.add(tech_name)

                tech_cat_raw = tech.get("category", "").lower().replace(" ", "_")
                sub_cat = tech.get("subCategory", "")
                first_seen = tech.get("firstseen", "")
                last_seen = tech.get("lastseen", "")
                recent = tech.get("recent", False)
                is_paid = tech.get("paid", False)
                link_rel = tech.get("linkrelationship", "")

                display_cat = TECH_CATEGORIES.get(tech_cat_raw, tech.get("category", "Technology"))
                version, clean_name = detect_version(tech_name)
                is_eol, eol_note = check_eol(tech_name)
                risk = tech_risk_score(tech_cat_raw)

                confidence = "High" if recent else ("Medium" if last_seen else "Low")
                color = "red" if is_eol else ("orange" if risk >= 5 else ("slate" if risk >= 3 else "emerald"))
                threat = "High Risk" if is_eol else ("Elevated Risk" if risk >= 6 else "Informational")

                tags_list = ["technology", display_cat.lower().replace(" ", "-")]
                if is_eol:
                    tags_list.append("end-of-life")
                if is_paid:
                    tags_list.append("paid")
                tags_list.append(f"risk-{risk}")

                entity_parts = [clean_name or tech_name]
                if version:
                    entity_parts.append(f"v{version}")
                if first_seen:
                    entity_parts.append(f"(since {first_seen[:7]})")
                entity = " ".join(entity_parts)

                findings.append(IntelligenceFinding(
                    entity=entity,
                    type=f"BuiltWith: {display_cat}",
                    source="BuiltWith",
                    confidence=confidence,
                    color=color,
                    threat_level=threat,
                    status="Confirmed" if recent else "Historical",
                    raw_data=f"Category: {tech.get('category', '')} | Version: {version or 'N/A'} | First: {first_seen or 'N/A'} | Last: {last_seen or 'N/A'}",
                    tags=tags_list,
                ))

                tech_groups[display_cat].append(tech_name)

                if is_eol and eol_note:
                    findings.append(IntelligenceFinding(
                        entity=f"{clean_name or tech_name}: {eol_note}",
                        type="BuiltWith: End-of-Life Warning",
                        source="BuiltWith",
                        confidence="High",
                        color="red",
                        threat_level="High Risk",
                        status="Confirmed",
                        tags=["technology", "end-of-life", "security"],
                    ))

    scraped_techs = await scrape_builtwith(t, client)
    for st in scraped_techs:
        if st not in seen_techs:
            seen_techs.add(st)
            version, clean_name = detect_version(st)
            entity = f"{clean_name or st} v{version}" if version else st
            findings.append(IntelligenceFinding(
                entity=entity,
                type="BuiltWith: Technology (Scraped)",
                source="BuiltWith",
                confidence="Medium",
                color="slate",
                status="Confirmed",
                tags=["technology", "scraped"],
            ))

    base_url = f"https://{t}"
    try:
        resp = await client.get(base_url, timeout=15.0, follow_redirects=True,
            headers={"User-Agent": UA})
        html = resp.text
        headers = dict(resp.headers)

        sig_findings = await analyze_technology_signatures(html, headers, base_url)
        for sf in sig_findings:
            if sf.entity not in seen_techs:
                seen_techs.add(sf.entity)
                findings.append(sf)

        hdr_findings = await analyze_headers(html, headers)
        findings.extend(hdr_findings)
    except:
        pass

    for cat, items in sorted(tech_groups.items(), key=lambda x: -len(x[1])):
        findings.append(IntelligenceFinding(
            entity=f"{cat}: {len(items)} technology(ies)",
            type="BuiltWith: Category Summary",
            source="BuiltWith",
            confidence="Medium",
            color="slate",
            status="Analyzed",
            tags=["technology", "summary", cat.lower().replace(" ", "-")],
        ))

    total_risk = sum(tech_risk_score(cat.lower().replace(" ", "_")) for cat in tech_groups)
    findings.append(IntelligenceFinding(
        entity=f"Technology risk score: {total_risk} across {len(seen_techs)} technology(ies)",
        type="BuiltWith: Risk Summary",
        source="BuiltWith",
        confidence="Medium",
        color="red" if total_risk > 50 else ("orange" if total_risk > 25 else "emerald"),
        threat_level="Elevated Risk" if total_risk > 25 else "Informational",
        status="Analyzed",
        tags=["technology", "risk-assessment", "summary"],
    ))

    if "CMS" in tech_groups:
        cms_list = ", ".join(tech_groups["CMS"][:5])
        findings.append(IntelligenceFinding(
            entity=f"CMS: {cms_list}",
            type="BuiltWith: CMS Detection",
            source="BuiltWith",
            confidence="High",
            color="blue",
            status="Confirmed",
            tags=["technology", "cms"],
        ))

    dependency_chains = []
    if "CDN" in tech_groups and "Web Server" in tech_groups:
        dependency_chains.append("CDN + Web Server")
    if "CMS" in tech_groups and "Database" in tech_groups:
        dependency_chains.append("CMS + Database")
    if "Analytics" in tech_groups and "Tag Manager" in tech_groups:
        dependency_chains.append("Analytics + Tag Manager")
    if "E-commerce" in tech_groups and "Payment Processor" in tech_groups:
        dependency_chains.append("E-commerce + Payment")
    if "Framework" in tech_groups and "Database" in tech_groups:
        dependency_chains.append("Framework + Database")
    if dependency_chains:
        findings.append(IntelligenceFinding(
            entity=" | ".join(dependency_chains),
            type="BuiltWith: Dependency Chain",
            source="BuiltWith",
            confidence="Low",
            color="slate",
            status="Inferred",
            tags=["technology", "dependency"],
        ))

    if not findings:
        findings.append(IntelligenceFinding(
            entity=f"No technology data for {t}",
            type="BuiltWith: No Results",
            source="BuiltWith",
            confidence="Low",
            color="slate",
            status="Failed",
            tags=["error"],
        ))

    return findings
