import httpx
import re
import asyncio
import json
from urllib.parse import urlparse
from datetime import datetime
from module_common import safe_fetch, safe_fetch_json, make_finding, is_ip, resolve_ip, EMAIL_RE, classify_email, extract_emails, compute_hash


LEADERSHIP_TITLES = [
    "ceo", "cto", "cfo", "coo", "cmo", "cio", "ciso", "cso",
    "founder", "co-founder", "cofounder", "owner",
    "president", "vp", "vice president", "director",
    "head of", "lead", "chief", "principal",
    "chairman", "chairperson", "board member", "executive director",
    "managing director", "partner", "managing partner",
    "svp", "senior vice president", "evp", "executive vice president",
    "avp", "assistant vice president", "associate director",
    "team lead", "tech lead", "engineering lead",
    "architect", "solution architect", "enterprise architect",
    "fellow", "distinguished engineer", "principal engineer",
    "staff engineer", "senior staff engineer",
    "advisor", "board advisor", "technical advisor",
]

DEPARTMENT_TITLES = [
    "engineering", "security", "product", "marketing", "sales",
    "hr", "human resources", "finance", "legal", "operations",
    "support", "devops", "infrastructure", "data",
    "research", "design", "qa", "quality assurance", "it",
    "customer success", "customer support", "accounting",
    "business development", "corporate development", "strategy",
    "communications", "public relations", "corporate communications",
    "recruiting", "talent acquisition", "people",
    "compliance", "risk", "audit", "internal audit",
    "supply chain", "procurement", "purchasing",
    "facilities", "administration", "office",
    "training", "learning", "enablement",
    "revenue", "growth", "demand generation",
    "brand", "creative", "content",
    "partnerships", "alliances", "channel",
    "cloud", "platform", "architecture",
    "ai", "machine learning", "ml", "data science",
]

TECH_STACK_PATTERNS = [
    (r'wordpress', 'CMS', 'WordPress'),
    (r'drupal', 'CMS', 'Drupal'),
    (r'joomla', 'CMS', 'Joomla'),
    (r'wp-content|wp-includes', 'CMS', 'WordPress'),
    (r'shopify', 'E-commerce', 'Shopify'),
    (r'magento', 'E-commerce', 'Magento'),
    (r'woocommerce', 'E-commerce', 'WooCommerce'),
    (r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', 'CMS Generator', None),
    (r'react\.js|react-dom|react/', 'Framework', 'React'),
    (r'angular[^<]*|ng-', 'Framework', 'Angular'),
    (r'vue\.js|vue\.min\.js', 'Framework', 'Vue.js'),
    (r'next\.js|_next/', 'Framework', 'Next.js'),
    (r'nuxt', 'Framework', 'Nuxt.js'),
    (r'gatsby', 'Framework', 'Gatsby'),
    (r'jquery', 'Library', 'jQuery'),
    (r'bootstrap', 'Library', 'Bootstrap'),
    (r'tailwind', 'Library', 'Tailwind CSS'),
    (r'google-analytics|ga\.js|gtag', 'Analytics', 'Google Analytics'),
    (r'gtm\.js|googletagmanager', 'Analytics', 'Google Tag Manager'),
    (r'fbevents\.js|fbq\(', 'Analytics', 'Facebook Pixel'),
    (r'hotjar', 'Analytics', 'Hotjar'),
    (r'intercom', 'Analytics', 'Intercom'),
    (r'mixpanel', 'Analytics', 'Mixpanel'),
    (r'sentry\.js|raven\.js', 'Monitoring', 'Sentry'),
    (r'datadog|dd-trace', 'Monitoring', 'Datadog'),
    (r'cloudflare', 'CDN', 'Cloudflare'),
    (r'cloudfront\.net', 'CDN', 'AWS CloudFront'),
    (r's3\.amazonaws\.com', 'Cloud', 'AWS S3'),
    (r'netlify', 'Hosting', 'Netlify'),
    (r'vercel', 'Hosting', 'Vercel'),
    (r'heroku', 'Hosting', 'Heroku'),
    (r'stripe\.com', 'Payment', 'Stripe'),
    (r'paypal', 'Payment', 'PayPal'),
    (r'cdn-cgi/', 'Security', 'Cloudflare'),
    (r'recaptcha|g-recaptcha', 'Security', 'reCAPTCHA'),
    (r'hubspot', 'CRM', 'HubSpot'),
    (r'salesforce', 'CRM', 'Salesforce'),
    (r'zendesk', 'Support', 'Zendesk'),
    (r'discord\.net|discord\.com', 'Social', 'Discord'),
    (r'slack\.com', 'Social', 'Slack'),
    (r'laravel', 'Framework', 'Laravel'),
    (r'symfony', 'Framework', 'Symfony'),
    (r'django', 'Framework', 'Django'),
    (r'flask', 'Framework', 'Flask'),
    (r'rails|ruby-on-rails', 'Framework', 'Ruby on Rails'),
    (r'express|express\.js', 'Framework', 'Express.js'),
    (r'fastapi', 'Framework', 'FastAPI'),
    (r'asp\.net|\.aspx|\.ashx|web\.config', 'Framework', 'ASP.NET'),
    (r'svelte', 'Framework', 'Svelte'),
    (r'sapper', 'Framework', 'Sapper'),
    (r'remix', 'Framework', 'Remix'),
    (r'eleventy|11ty', 'Framework', 'Eleventy'),
    (r'hugo', 'Framework', 'Hugo'),
    (r'jekyll', 'Framework', 'Jekyll'),
    (r'hexo', 'Framework', 'Hexo'),
    (r'quasar', 'Framework', 'Quasar'),
    (r'vuetify', 'Library', 'Vuetify'),
    (r'chakra-ui|chakra', 'Library', 'Chakra UI'),
    (r'material-ui|mui\.com|@mui', 'Library', 'Material UI'),
    (r'ant-design|antd', 'Library', 'Ant Design'),
    (r'shadcn', 'Library', 'shadcn/ui'),
    (r'radix-ui', 'Library', 'Radix UI'),
    (r'primereact|primeng', 'Library', 'Prime UI'),
    (r'storybook', 'Library', 'Storybook'),
    (r'lodash', 'Library', 'Lodash'),
    (r'axios', 'Library', 'Axios'),
    (r'moment\.js', 'Library', 'Moment.js'),
    (r'dayjs', 'Library', 'Day.js'),
    (r'chart\.js', 'Library', 'Chart.js'),
    (r'd3\.js|d3\.min\.js', 'Library', 'D3.js'),
    (r'three\.js|three\.min\.js', 'Library', 'Three.js'),
    (r'jwt|jsonwebtoken', 'Library', 'JWT'),
    (r'socket\.io', 'Library', 'Socket.IO'),
    (r'prisma', 'Library', 'Prisma'),
    (r'typeorm', 'Library', 'TypeORM'),
    (r'sequelize', 'Library', 'Sequelize'),
    (r'mongoose', 'Library', 'Mongoose'),
    (r'nginx|nginx\.org', 'Server', 'Nginx'),
    (r'apache|httpd', 'Server', 'Apache'),
    (r'caddy', 'Server', 'Caddy'),
    (r'traefik', 'Server', 'Traefik'),
    (r'openresty', 'Server', 'OpenResty'),
    (r'nginx/cf', 'Server', 'Nginx'),
    (r'mariadb', 'Database', 'MariaDB'),
    (r'mysql', 'Database', 'MySQL'),
    (r'postgresql|pgsql|postgres', 'Database', 'PostgreSQL'),
    (r'mongodb|mongo', 'Database', 'MongoDB'),
    (r'redis', 'Database', 'Redis'),
    (r'elasticsearch', 'Database', 'Elasticsearch'),
    (r'cassandra', 'Database', 'Cassandra'),
    (r'dynamodb', 'Database', 'DynamoDB'),
    (r'cockroachdb', 'Database', 'CockroachDB'),
    (r'sqlite', 'Database', 'SQLite'),
    (r'mssql|microsoft sql|sqlserver', 'Database', 'MSSQL'),
    (r'firebase', 'Cloud', 'Firebase'),
    (r'supabase', 'Cloud', 'Supabase'),
    (r'cloudflare\.com', 'CDN', 'Cloudflare'),
    (r'cloudfront\.net', 'CDN', 'AWS CloudFront'),
    (r'fastly', 'CDN', 'Fastly'),
    (r'akamai', 'CDN', 'Akamai'),
    (r'keycdn', 'CDN', 'KeyCDN'),
    (r'stackpath|maxcdn', 'CDN', 'StackPath'),
    (r'cdn77', 'CDN', 'CDN77'),
    (r'bunnycdn|bunny\.net', 'CDN', 'Bunny CDN'),
    (r'failover\.biz\.tr|\.pagedemo\.co', 'CDN', 'Generic CDN'),
    (r'incapsula|imperva', 'CDN', 'Incapsula'),
    (r'sucuri', 'CDN', 'Sucuri'),
    (r'digitalocean', 'Hosting', 'DigitalOcean'),
    (r'aws\.amazon|ec2\.amazonaws|compute\.amazonaws', 'Hosting', 'AWS'),
    (r'azure\.com|windows\.net|azureedge', 'Hosting', 'Azure'),
    (r'gcp|googleapis|appspot\.com', 'Hosting', 'Google Cloud'),
    (r'linode', 'Hosting', 'Linode'),
    (r'ovh', 'Hosting', 'OVH'),
    (r'hetzner', 'Hosting', 'Hetzner'),
    (r'vultr', 'Hosting', 'Vultr'),
    (r'hostinger', 'Hosting', 'Hostinger'),
    (r'siteground', 'Hosting', 'SiteGround'),
    (r'wpengine|wpe\.com', 'Hosting', 'WP Engine'),
    (r'pantheon', 'Hosting', 'Pantheon'),
    (r'fly\.io', 'Hosting', 'Fly.io'),
    (r'render\.com', 'Hosting', 'Render'),
    (r'railway\.app', 'Hosting', 'Railway'),
    (r'cicd|jenkins|gitlab-ci|github\.actions|circleci|travis-ci', 'CI/CD', 'Generic CI/CD'),
    (r'segment\.com', 'Analytics', 'Segment'),
    (r'amplitude', 'Analytics', 'Amplitude'),
    (r'fullstory', 'Analytics', 'FullStory'),
    (r'heap', 'Analytics', 'Heap'),
    (r'crisp', 'Support', 'Crisp'),
    (r'freshdesk', 'Support', 'Freshdesk'),
    (r'helpscout', 'Support', 'Help Scout'),
    (r'tawk', 'Support', 'Tawk.to'),
    (r'livchat|livechat', 'Support', 'LiveChat'),
    (r'olark', 'Support', 'Olark'),
    (r'braintree', 'Payment', 'Braintree'),
    (r'squareup|square\.com', 'Payment', 'Square'),
    (r'adyen', 'Payment', 'Adyen'),
    (r'razorpay', 'Payment', 'Razorpay'),
    (r'paddle\.com', 'Payment', 'Paddle'),
    (r'lemonsqueezy|lemon\.squeezy', 'Payment', 'Lemon Squeezy'),
    (r'chargebee', 'Payment', 'Chargebee'),
    (r'recurly', 'Payment', 'Recurly'),
    (r'mailchimp', 'Marketing', 'Mailchimp'),
    (r'sendgrid', 'Marketing', 'SendGrid'),
    (r'postmark', 'Marketing', 'Postmark'),
    (r'mailgun', 'Marketing', 'Mailgun'),
    (r'sendinblue|brevo', 'Marketing', 'Brevo'),
    (r'convertkit', 'Marketing', 'ConvertKit'),
    (r'klaviyo', 'Marketing', 'Klaviyo'),
    (r'activecampaign', 'Marketing', 'ActiveCampaign'),
    (r'plausible', 'Analytics', 'Plausible'),
    (r'fathom', 'Analytics', 'Fathom Analytics'),
    (r'matomo|piwik', 'Analytics', 'Matomo'),
    (r'newrelic|new-relic', 'Monitoring', 'New Relic'),
    (r'rollbar', 'Monitoring', 'Rollbar'),
    (r'bugsnag', 'Monitoring', 'Bugsnag'),
    (r'appdynamics', 'Monitoring', 'AppDynamics'),
    (r'dynatrace', 'Monitoring', 'Dynatrace'),
    (r'prometheus', 'Monitoring', 'Prometheus'),
    (r'grafana', 'Monitoring', 'Grafana'),
    (r'datadog', 'Monitoring', 'Datadog'),
    (r'elastic\.apm|apm\.elastic', 'Monitoring', 'Elastic APM'),
    (r'auth0', 'Security', 'Auth0'),
    (r'okta', 'Security', 'Okta'),
    (r'fission|fusionauth|keycloak', 'Security', 'Keycloak/FusionAuth'),
    (r'duosecurity|duo\.com', 'Security', 'Duo Security'),
    (r'hcaptcha', 'Security', 'hCaptcha'),
    (r'cloudflare-turnstile|turnstile', 'Security', 'Cloudflare Turnstile'),
    (r'akismet', 'Security', 'Akismet'),
    (r'defender|wordfence|sucuri-security', 'Security', 'WordPress Security'),
    (r'algolia', 'Search', 'Algolia'),
    (r'meilisearch', 'Search', 'Meilisearch'),
    (r'typesense', 'Search', 'Typesense'),
    (r'solr', 'Search', 'Apache Solr'),
    (r'lunr\.js', 'Search', 'Lunr.js'),
    (r'fuse\.js', 'Search', 'Fuse.js'),
    (r'monaco|monaco-editor', 'Editor', 'Monaco Editor'),
    (r'codemirror', 'Editor', 'CodeMirror'),
    (r'tinymce|froala|ckeditor', 'Editor', 'Rich Text Editor'),
    (r'tailscale', 'Networking', 'Tailscale'),
    (r'zerotier', 'Networking', 'ZeroTier'),
    (r'wireguard', 'Networking', 'WireGuard'),
    (r'cloudflare\.com/cdn-cgi/trace', 'Security', 'Cloudflare Trace'),
    (r'auth\.js|next-auth', 'Security', 'Auth.js'),
    (r'clerk', 'Security', 'Clerk'),
]

SOCIAL_PLATFORMS = [
    ("YouTube", r'youtube\.com/(?:@|channel/|user/|c/|watch\?v=)([a-zA-Z0-9_-]+)'),
    ("Crunchbase", r'crunchbase\.com/organization/([a-zA-Z0-9_-]+)'),
    ("Crunchbase", r'crunchbase\.com/company/([a-zA-Z0-9_-]+)'),
    ("Glassdoor", r'glassdoor\.com/(?:Overview|Reviews)/[A-Za-z0-9_-]+'),
    ("AngelList", r'angel\.co/([a-zA-Z0-9_-]+)'),
    ("AngelList", r'angellist\.com/([a-zA-Z0-9_-]+)'),
    ("ProductHunt", r'producthunt\.com/(?:@|companies/)([a-zA-Z0-9_-]+)'),
    ("ProductHunt", r'producthunt\.com/posts/([a-zA-Z0-9_-]+)'),
    ("Instagram", r'instagram\.com/([a-zA-Z0-9_.-]+)'),
    ("Instagram", r'ig\.me/([a-zA-Z0-9_-]+)'),
    ("Facebook", r'facebook\.com/([a-zA-Z0-9._-]+)'),
    ("Facebook", r'fb\.com/([a-zA-Z0-9._-]+)'),
    ("Twitter/X", r'twitter\.com/([a-zA-Z0-9_]+)'),
    ("Twitter/X", r'x\.com/([a-zA-Z0-9_]+)'),
    ("LinkedIn", r'linkedin\.com/company/([a-zA-Z0-9_-]+)'),
    ("LinkedIn", r'linkedin\.com/in/([a-zA-Z0-9_-]+)'),
    ("GitHub", r'github\.com/([a-zA-Z0-9_-]+)'),
    ("GitLab", r'gitlab\.com/([a-zA-Z0-9_-]+)'),
    ("Bitbucket", r'bitbucket\.org/([a-zA-Z0-9_-]+)'),
    ("Medium", r'medium\.com/[@]?([a-zA-Z0-9_-]+)'),
    ("Dev.to", r'dev\.to/([a-zA-Z0-9_-]+)'),
    ("Hashnode", r'hashnode\.com/[@]?([a-zA-Z0-9_-]+)'),
    ("Substack", r'substack\.com/[@]?([a-zA-Z0-9_-]+)'),
    ("YouTube", r'youtube\.com/(?:@|channel/|user/|c/)([a-zA-Z0-9_-]+)'),
    ("Vimeo", r'vimeo\.com/([a-zA-Z0-9_-]+)'),
    ("Dailymotion", r'dailymotion\.com/([a-zA-Z0-9_-]+)'),
    ("Twitch", r'twitch\.com/([a-zA-Z0-9_]+)'),
    ("TikTok", r'tiktok\.com/[@]([a-zA-Z0-9_.-]+)'),
    ("Snapchat", r'snapchat\.com/add/([a-zA-Z0-9_.-]+)'),
    ("Pinterest", r'pinterest\.com/([a-zA-Z0-9_-]+)'),
    ("Tumblr", r'([a-zA-Z0-9_-]+)\.tumblr\.com'),
    ("Reddit", r'reddit\.com/user/([a-zA-Z0-9_-]+)'),
    ("HackerNews", r'news\.ycombinator\.com/user\?id=([a-zA-Z0-9_-]+)'),
    ("Stack Overflow", r'stackoverflow\.com/users/\d+/([a-zA-Z0-9_-]+)'),
    ("Docker Hub", r'hub\.docker\.com/u/([a-zA-Z0-9_-]+)'),
    ("NPM", r'npmjs\.com/~([a-zA-Z0-9_-]+)'),
    ("PyPI", r'pypi\.org/user/([a-zA-Z0-9_-]+)'),
    ("HackerOne", r'hackerone\.com/([a-zA-Z0-9_-]+)'),
    ("Bugcrowd", r'bugcrowd\.com/([a-zA-Z0-9_-]+)'),
    ("Keybase", r'keybase\.io/([a-zA-Z0-9_-]+)'),
    ("Discord", r'discord\.(?:gg|com/invite)/([a-zA-Z0-9_-]+)'),
    ("Telegram", r't\.me/([a-zA-Z0-9_-]+)'),
    ("WhatsApp", r'wa\.me/(\d+)'),
    ("Signal", r'signal\.me/#p/([a-zA-Z0-9_-]+)'),
    ("Slack", r'slack\.com/([a-zA-Z0-9_-]+)'),
    ("ProductHunt", r'producthunt\.com/(?:@|companies/)([a-zA-Z0-9_-]+)'),
    ("ProductHunt", r'producthunt\.com/posts/([a-zA-Z0-9_-]+)'),
    ("AngelList", r'angel\.co/([a-zA-Z0-9_-]+)'),
    ("AngelList", r'angellist\.com/([a-zA-Z0-9_-]+)'),
    ("Goodreads", r'goodreads\.com/([a-zA-Z0-9_-]+)'),
    ("Strava", r'strava\.com/athletes/(\d+)'),
    ("Spotify", r'open\.spotify\.com/user/([a-zA-Z0-9_-]+)'),
    ("SoundCloud", r'soundcloud\.com/([a-zA-Z0-9_-]+)'),
    ("Bandcamp", r'([a-zA-Z0-9_-]+)\.bandcamp\.com'),
    ("Behance", r'behance\.net/([a-zA-Z0-9_-]+)'),
    ("Dribbble", r'dribbble\.com/([a-zA-Z0-9_-]+)'),
    ("ArtStation", r'artstation\.com/([a-zA-Z0-9_-]+)'),
    ("Flickr", r'flickr\.com/people/([a-zA-Z0-9_-]+)'),
    ("Figma", r'figma\.com/[@]?([a-zA-Z0-9_-]+)'),
    ("Patron", r'patreon\.com/([a-zA-Z0-9_-]+)'),
    ("Ko-fi", r'ko-fi\.com/([a-zA-Z0-9_-]+)'),
    ("BuyMeACoffee", r'buymeacoffee\.com/([a-zA-Z0-9_-]+)'),
    ("Etsy", r'etsy\.com/shop/([a-zA-Z0-9_-]+)'),
    ("eBay", r'ebay\.com/usr/([a-zA-Z0-9_-]+)'),
    ("Fiverr", r'fiverr\.com/([a-zA-Z0-9_-]+)'),
    ("Upwork", r'upwork\.com/freelancers/~([a-zA-Z0-9_-]+)'),
    ("Freelancer", r'freelancer\.com/u/([a-zA-Z0-9_-]+)'),
    ("About.me", r'about\.me/([a-zA-Z0-9_-]+)'),
    ("Linktree", r'linktr\.ee/([a-zA-Z0-9_-]+)'),
    ("Calendly", r'calendly\.com/([a-zA-Z0-9_-]+)'),
]

INDUSTRY_KEYWORDS = [
    ("Technology / Software", ["software", "saas", "cloud", "platform", "app", "dev", "api", "tech", "digital",
                               "data", "analytics", "ai", "machine learning", "cyber", "security", "infrastructure"]),
    ("E-commerce / Retail", ["shop", "store", "ecommerce", "retail", "marketplace", "buy", "cart", "checkout",
                              "product", "merchant", "wholesale"]),
    ("Finance / Fintech", ["bank", "finance", "fintech", "payment", "invest", "crypto", "blockchain", "insurance",
                            "loan", "credit", "trading", "wealth"]),
    ("Healthcare / Biotech", ["health", "medical", "pharma", "biotech", "clinical", "patient", "doctor", "hospital",
                               "wellness", "therapy"]),
    ("Education / Edtech", ["education", "learn", "course", "school", "academy", "training", "university",
                             "student", "teach", "tutorial"]),
    ("Marketing / Media", ["marketing", "media", "advertise", "content", "social media", "brand", "creative",
                            "design", "agency", "publish", "news"]),
    ("Enterprise / B2B", ["enterprise", "b2b", "business", "corporate", "solution", "workflow", "automation",
                           "productivity", "collaboration"]),
    ("HR / Recruiting", ["recruit", "talent", "hire", "career", "job", "employ", "staff", "workforce", "hr",
                          "human resource"]),
    ("Legal / Compliance", ["legal", "law", "compliance", "attorney", "regulatory", "patent", "trademark",
                             "intellectual property"]),
    ("Real Estate / Construction", ["real estate", "property", "construction", "building", "rent", "mortgage",
                                      "apartment", "housing", "architect"]),
    ("Gaming / Entertainment", ["game", "gaming", "entertainment", "esports", "casino", "betting",
                                  "gambling", "streaming", "media", "movie", "music", "studio"]),
    ("Travel / Hospitality", ["travel", "hotel", "booking", "trip", "flight", "vacation",
                                "tourism", "hospitality", "airline", "cruise", "rental"]),
    ("Energy / Utilities", ["energy", "solar", "renewable", "power", "electric", "utility",
                              "oil", "gas", "petroleum", "mining", "nuclear"]),
    ("Transportation / Logistics", ["logistics", "shipping", "delivery", "freight", "courier",
                                      "transport", "cargo", "warehouse", "supply chain", "mobility"]),
    ("Food / Beverage", ["food", "restaurant", "beverage", "catering", "delivery", "meal",
                           "kitchen", "brewery", "cafe", "coffee", "wine"]),
    ("Fashion / Beauty", ["fashion", "beauty", "clothing", "apparel", "cosmetic", "skincare",
                            "jewelry", "accessories", "footwear", "lingerie"]),
    ("Nonprofit / NGO", ["nonprofit", "ngo", "charity", "foundation", "donate", "philanthropy",
                           "volunteer", "humanitarian", "advocacy"]),
    ("Government / Public Sector", ["government", "public sector", "municipal", "federal",
                                      "state", "agency", "administration", "civic", "city"]),
    ("Telecommunications", ["telecom", "telecommunication", "mobile", "cellular", "broadband",
                              "wireless", "isp", "internet", "network", "voip"]),
    ("Agriculture / Farming", ["agriculture", "farming", "agri", "farm", "crop", "livestock",
                                 "organic", "sustainable", "food production"]),
    ("Manufacturing / Industrial", ["manufacturing", "industrial", "factory", "production",
                                      "machinery", "equipment", "automation", "engineering"]),
    ("Sports / Fitness", ["sport", "fitness", "athlete", "gym", "workout", "wellness",
                            "yoga", "outdoor", "recreation"]),
    ("Insurance", ["insurance", "insure", "underwriting", "claims", "broker", "actuarial"]),
    ("Consulting / Professional Services", ["consulting", "consultancy", "advisory", "professional services",
                                              "management consulting", "strategy"]),
]

MONTH_ABBR = r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)'


async def extract_org_from_whois(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    domain = target.strip().lower()
    try:
        resp = await safe_fetch(client, f"https://api.hackertarget.com/whois/?q={domain}", timeout=10.0)
        if resp and resp.status_code == 200:
            text = resp.text
            org_keys = [
                "Registrant Organization", "OrgName", "org_name",
                "Organization", "company", "Company",
            ]
            email_keys = [
                "Registrant Email", "Tech Email", "Admin Email",
                "Abuse Email", "abuse-mailbox",
            ]
            for line in text.split("\n"):
                for key in org_keys:
                    if line.lower().startswith(key.lower()) and ":" in line:
                        val = line.split(":", 1)[1].strip()
                        if val and val != "N/A" and val != "None":
                            findings.append(make_finding(
                                entity=val[:200],
                                ftype="WHOIS: Organization",
                                source="PeopleOrgOSINT (HackerTarget)",
                                confidence="High",
                                color="emerald",
                                threat_level="Informational",
                                status="Found in WHOIS",
                                raw_data=line[:500],
                                tags=["whois", "organization", val[:50].lower().replace(" ", "-")]
                            ))
                            break
                for key in email_keys:
                    if line.lower().startswith(key.lower()) and ":" in line:
                        val = line.split(":", 1)[1].strip()
                        if val and "@" in val:
                            findings.append(make_finding(
                                entity=val[:200],
                                ftype="WHOIS: Contact Email",
                                source="PeopleOrgOSINT (HackerTarget)",
                                confidence="High",
                                color="cyan",
                                threat_level="Informational",
                                status="Found in WHOIS",
                                resolution=f"Role: {key}",
                                raw_data=line[:500],
                                tags=["whois", "email", "contact"]
                            ))
                            break
                if "Registrant Name" in line and ":" in line:
                    val = line.split(":", 1)[1].strip()
                    if val and val != "N/A" and val != "None":
                        findings.append(make_finding(
                            entity=val[:200],
                            ftype="WHOIS: Registrant Name",
                            source="PeopleOrgOSINT (HackerTarget)",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            tags=["whois", "person"]
                        ))
    except:
        pass
    return findings


async def extract_org_from_ssl(target: str) -> list:
    findings = []
    try:
        import ssl
        import socket
        from osint_common import get_ssl_cert_info, parse_cert_to_dict
        cert_info = await get_ssl_cert_info(target)
        if cert_info and cert_info.get("cert"):
            cert = cert_info["cert"]
            parsed = parse_cert_to_dict(cert)
            org = parsed.get("issuer", {}).get("organizationName", "")
            cn = parsed.get("issuer", {}).get("commonName", "")
            subj_org = parsed.get("subject", {}).get("organizationName", "")
            if org:
                findings.append(make_finding(
                    entity=org[:200],
                    ftype="SSL: Issuer Organization",
                    source="PeopleOrgOSINT (SSL)",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="Found in SSL cert",
                    tags=["ssl", "organization"]
                ))
            if subj_org and subj_org != org:
                findings.append(make_finding(
                    entity=subj_org[:200],
                    ftype="SSL: Subject Organization",
                    source="PeopleOrgOSINT (SSL)",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    tags=["ssl", "organization", "subject"]
                ))
            if cn:
                findings.append(make_finding(
                    entity=cn[:200],
                    ftype="SSL: Common Name",
                    source="PeopleOrgOSINT (SSL)",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["ssl", "common-name"]
                ))
    except:
        pass
    return findings


async def extract_people_from_html(html: str, target: str) -> list:
    findings = []
    domain_short = target.split(".")[0] if "." in target else target

    # Extract team page links
    team_paths = re.findall(
        r'href=["\'](/?(?:team|about|company|people|leadership|management|board|executives|our-team|staff|employees|who-we-are|about-us|our-company|our-story|meet-the-team|meet-our-team|meet-us|the-team|our-people|our-leadership|management-team|executive-team|leadership-team|board-of-directors|advisors|partners|founders|our-founders|core-team|team-members|our-team-members|key-people|our-organization|about-company|corporate|investors|careers|join-us|work-with-us)[^"\']*)["\']',
        html, re.IGNORECASE
    )
    for path in set(team_paths[:5]):
        findings.append(make_finding(
            entity=f"https://{target}{path}",
            ftype="Team/About Page Link",
            source="PeopleOrgOSINT (HTML)",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Found",
            tags=["team-page", "about-page"]
        ))

    # Extract social links
    social_patterns = [
        (r'linkedin\.com/company/([a-zA-Z0-9_-]+)', "LinkedIn Company"),
        (r'linkedin\.com/in/([a-zA-Z0-9_-]+)', "LinkedIn Profile"),
        (r'github\.com/([a-zA-Z0-9_-]+)', "GitHub Profile"),
        (r'twitter\.com/([a-zA-Z0-9_]+)', "Twitter/X Profile"),
        (r'x\.com/([a-zA-Z0-9_]+)', "X Profile"),
        (r'facebook\.com/([a-zA-Z0-9._-]+)', "Facebook Page"),
        (r'crunchbase\.com/organization/([a-zA-Z0-9_-]+)', "Crunchbase"),
        (r'angel\.co/([a-zA-Z0-9_-]+)', "AngelList"),
        (r'instagram\.com/([a-zA-Z0-9_.-]+)', "Instagram Profile"),
        (r'youtube\.com/(?:@|channel/|user/|c/)([a-zA-Z0-9_-]+)', "YouTube Channel"),
        (r'tiktok\.com/@([a-zA-Z0-9_.-]+)', "TikTok Profile"),
        (r'snapchat\.com/add/([a-zA-Z0-9_.-]+)', "Snapchat Profile"),
        (r'reddit\.com/user/([a-zA-Z0-9_-]+)', "Reddit Profile"),
        (r'twitch\.tv/([a-zA-Z0-9_]+)', "Twitch Channel"),
        (r'discord\.(?:gg|com/invite)/([a-zA-Z0-9_-]+)', "Discord Server"),
        (r'telegram\.org/([a-zA-Z0-9_-]+)', "Telegram"),
        (r't\.me/([a-zA-Z0-9_-]+)', "Telegram Profile"),
        (r'medium\.com/@?([a-zA-Z0-9_-]+)', "Medium Profile"),
        (r'dev\.to/([a-zA-Z0-9_-]+)', "Dev.to Profile"),
        (r'hashnode\.com/@?([a-zA-Z0-9_-]+)', "Hashnode Blog"),
        (r'substack\.com/@?([a-zA-Z0-9_-]+)', "Substack Newsletter"),
        (r'producthunt\.com/@?([a-zA-Z0-9_-]+)', "ProductHunt Profile"),
        (r'hackerone\.com/([a-zA-Z0-9_-]+)', "HackerOne Profile"),
        (r'bugcrowd\.com/([a-zA-Z0-9_-]+)', "Bugcrowd Profile"),
        (r'keybase\.io/([a-zA-Z0-9_-]+)', "Keybase Profile"),
        (r'pinterest\.com/([a-zA-Z0-9_-]+)', "Pinterest Profile"),
        (r'behance\.net/([a-zA-Z0-9_-]+)', "Behance Profile"),
        (r'dribbble\.com/([a-zA-Z0-9_-]+)', "Dribbble Profile"),
        (r'artstation\.com/([a-zA-Z0-9_-]+)', "ArtStation Profile"),
        (r'flickr\.com/people/([a-zA-Z0-9_-]+)', "Flickr Profile"),
        (r'patreon\.com/([a-zA-Z0-9_-]+)', "Patreon Profile"),
        (r'gitlab\.com/([a-zA-Z0-9_-]+)', "GitLab Profile"),
        (r'bitbucket\.org/([a-zA-Z0-9_-]+)', "Bitbucket Profile"),
        (r'stackoverflow\.com/users/\d+/([a-zA-Z0-9_-]+)', "StackOverflow Profile"),
    ]
    for pattern, label in social_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for m in matches[:2]:
            findings.append(make_finding(
                entity=m[:200],
                ftype=f"Social: {label}",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Found in HTML",
                tags=["social", label.lower().replace(" ", "-")]
            ))

    # Additional social platforms
    for platform_name, pattern in SOCIAL_PLATFORMS:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for m in matches[:2]:
            findings.append(make_finding(
                entity=m[:200] if isinstance(m, str) else str(m)[:200],
                ftype=f"Social: {platform_name}",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="Found in HTML",
                tags=["social", platform_name.lower().replace(" ", "-")]
            ))

    # Technology stack extraction
    tech_found = set()
    for pattern, tech_type, tech_name in TECH_STACK_PATTERNS:
        if tech_name:
            if re.search(pattern, html, re.IGNORECASE):
                key = f"{tech_type}:{tech_name}"
                if key not in tech_found:
                    tech_found.add(key)
                    findings.append(make_finding(
                        entity=tech_name[:200],
                        ftype=f"Technology: {tech_type}",
                        source="PeopleOrgOSINT (HTML)",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        status="Detected",
                        tags=["tech-stack", tech_type.lower().replace(" ", "-"), tech_name.lower().replace(" ", "-")]
                    ))
        else:
            m = re.search(pattern, html, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                key = f"Generator:{val}"
                if key not in tech_found:
                    tech_found.add(key)
                    findings.append(make_finding(
                        entity=val[:200],
                        ftype=f"Technology: {tech_type}",
                        source="PeopleOrgOSINT (HTML)",
                        confidence="High",
                        color="slate",
                        threat_level="Informational",
                        status="Detected",
                        tags=["tech-stack", tech_type.lower().replace(" ", "-"), val[:30].lower().replace(" ", "-")]
                    ))

    # Extract JSON-LD structured data
    ld_json = re.findall(
        r'<script[^>]*ftype=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        html, re.IGNORECASE | re.DOTALL
    )
    for block in ld_json[:5]:
        try:
            data = json.loads(block)
            if isinstance(data, dict):
                for key in ["name", "legalName", "alternateName"]:
                    val = data.get(key, "")
                    if val:
                        findings.append(make_finding(
                            entity=val[:200],
                            ftype="Schema.org: Organization Name",
                            source="PeopleOrgOSINT (JSON-LD)",
                            confidence="High",
                            color="emerald",
                            threat_level="Informational",
                            tags=["json-ld", "schema", "organization"]
                        ))
                founder = data.get("founder", "")
                if isinstance(founder, dict) and founder.get("name"):
                    findings.append(make_finding(
                        entity=founder["name"][:200],
                        ftype="Schema.org: Founder",
                        source="PeopleOrgOSINT (JSON-LD)",
                        confidence="Medium",
                        color="cyan",
                        threat_level="Informational",
                        tags=["json-ld", "founder", "person"]
                    ))
                employees = data.get("numberOfEmployees", "")
                if employees:
                    findings.append(make_finding(
                        entity=str(employees)[:100],
                        ftype="Schema.org: Employee Count",
                        source="PeopleOrgOSINT (JSON-LD)",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["json-ld", "employees"]
                    ))
                same_as = data.get("sameAs", [])
                if isinstance(same_as, list):
                    for link in same_as:
                        findings.append(make_finding(
                            entity=link[:200],
                            ftype="Schema.org: SameAs (Social)",
                            source="PeopleOrgOSINT (JSON-LD)",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            tags=["json-ld", "social-link"]
                        ))
                # Description from JSON-LD
                desc = data.get("description", "")
                if desc:
                    findings.append(make_finding(
                        entity=desc[:200],
                        ftype="Schema.org: Description",
                        source="PeopleOrgOSINT (JSON-LD)",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["json-ld", "description", "org-profile"]
                    ))
                # Founding date from JSON-LD
                founding_date = data.get("foundingDate", "") or data.get("foundingDate", "")
                if founding_date:
                    findings.append(make_finding(
                        entity=str(founding_date)[:100],
                        ftype="Schema.org: Founding Date",
                        source="PeopleOrgOSINT (JSON-LD)",
                        confidence="Medium",
                        color="amber",
                        threat_level="Informational",
                        tags=["json-ld", "founding-date"]
                    ))
                # Location from JSON-LD
                address = data.get("address", {})
                if isinstance(address, dict):
                    parts = []
                    for addr_key in ["streetAddress", "addressLocality", "addressRegion", "postalCode", "addressCountry"]:
                        if address.get(addr_key):
                            parts.append(address[addr_key])
                    if parts:
                        findings.append(make_finding(
                            entity=", ".join(parts)[:200],
                            ftype="Schema.org: Address",
                            source="PeopleOrgOSINT (JSON-LD)",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            tags=["json-ld", "address", "location"]
                        ))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("@type") in ("Organization", "Corporation", "LocalBusiness", "NGO"):
                        for key in ["name", "legalName"]:
                            val = item.get(key, "")
                            if val:
                                findings.append(make_finding(
                                    entity=val[:200],
                                    ftype="Schema.org: Organization Name",
                                    source="PeopleOrgOSINT (JSON-LD)",
                                    confidence="High",
                                    color="emerald",
                                    threat_level="Informational",
                                    tags=["json-ld", "schema", "organization"]
                                ))
                        emp = item.get("numberOfEmployees", "")
                        if emp:
                            findings.append(make_finding(
                                entity=str(emp)[:100],
                                ftype="Schema.org: Employee Count",
                                source="PeopleOrgOSINT (JSON-LD)",
                                confidence="Medium",
                                color="slate",
                                threat_level="Informational",
                                tags=["json-ld", "employees"]
                            ))
                        desc = item.get("description", "")
                        if desc:
                            findings.append(make_finding(
                                entity=desc[:200],
                                ftype="Schema.org: Description",
                                source="PeopleOrgOSINT (JSON-LD)",
                                confidence="Medium",
                                color="slate",
                                threat_level="Informational",
                                tags=["json-ld", "description", "org-profile"]
                            ))
                        fdate = item.get("foundingDate", "")
                        if fdate:
                            findings.append(make_finding(
                                entity=str(fdate)[:100],
                                ftype="Schema.org: Founding Date",
                                source="PeopleOrgOSINT (JSON-LD)",
                                confidence="Medium",
                                color="amber",
                                threat_level="Informational",
                                tags=["json-ld", "founding-date"]
                            ))
                        addr = item.get("address", {})
                        if isinstance(addr, dict):
                            parts = []
                            for ak in ["streetAddress", "addressLocality", "addressRegion", "postalCode", "addressCountry"]:
                                if addr.get(ak):
                                    parts.append(addr[ak])
                            if parts:
                                findings.append(make_finding(
                                    entity=", ".join(parts)[:200],
                                    ftype="Schema.org: Address",
                                    source="PeopleOrgOSINT (JSON-LD)",
                                    confidence="High",
                                    color="slate",
                                    threat_level="Informational",
                                    tags=["json-ld", "address", "location"]
                                ))
        except:
            pass

    # Meta tags extraction
    for pattern, label, key_name in [
        (r'<meta\s+property=["\']og:site_name["\'][^>]*content=["\']([^"\']+)["\']', "OG Site Name", "meta"),
        (r'<meta\s+name=["\']twitter:site["\'][^>]*content=["\']([^"\']+)["\']', "Twitter Site", "meta"),
        (r'<meta\s+name=["\']author["\'][^>]*content=["\']([^"\']+)["\']', "Meta Author", "meta"),
        (r'<meta\s+name=["\']application-name["\'][^>]*content=["\']([^"\']+)["\']', "App Name", "meta"),
    ]:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            findings.append(make_finding(
                entity=m.group(1)[:200],
                ftype=f"Meta: {label}",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["meta", label.lower().replace(" ", "-")]
            ))

    # Description extraction
    desc_sources = [
        (r'<meta\s+name=["\']description["\'][^>]*content=["\']([^"\']+)["\']', "Meta Description", "meta"),
        (r'<meta\s+property=["\']og:description["\'][^>]*content=["\']([^"\']+)["\']', "OG Description", "meta"),
        (r'<meta\s+name=["\']twitter:description["\'][^>]*content=["\']([^"\']+)["\']', "Twitter Description", "meta"),
    ]
    for pattern, label, _ in desc_sources:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            desc_val = m.group(1).strip()
            if desc_val:
                findings.append(make_finding(
                    entity=desc_val[:200],
                    ftype=f"Description: {label}",
                    source="PeopleOrgOSINT (HTML)",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["description", "org-profile", label.lower().replace(" ", "-")]
                ))

    # Copyright notice
    copyright_match = re.search(
        r'(?:copyright|©)\s*(?:20\d\d[-\s]*20\d\d|20\d\d)\s*([^.\n]{5,80})',
        html, re.IGNORECASE
    )
    if copyright_match:
        entity = copyright_match.group(1).strip()
        if len(entity) > 3 and domain_short.lower() not in entity.lower():
            findings.append(make_finding(
                entity=entity[:200],
                ftype="Copyright: Organization Name",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["copyright", "organization"]
            ))

    # Founding year from copyright
    founding_year_match = re.search(
        r'(?:copyright|©)\s*(20\d\d)',
        html, re.IGNORECASE
    )
    if founding_year_match:
        year = founding_year_match.group(1)
        current_year = datetime.now().year
        if int(year) < current_year:
            findings.append(make_finding(
                entity=year[:10],
                ftype="Founding Year (Copyright)",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="amber",
                threat_level="Informational",
                status=f"Earliest copyright year: {year}",
                tags=["founding-year", "copyright"]
            ))

    # Founding year from meta tags
    for pattern, label in [
        (r'<meta\s+name=["\']founding-date["\'][^>]*content=["\']([^"\']+)["\']', "Meta Founding Date"),
        (r'<meta\s+name=["\']foundingdate["\'][^>]*content=["\']([^"\']+)["\']', "Meta Founding Date"),
    ]:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            findings.append(make_finding(
                entity=m.group(1)[:50],
                ftype="Founding Year",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="amber",
                threat_level="Informational",
                tags=["founding-year", "meta"]
            ))

    # Location from meta geo tags
    geo_patterns = [
        (r'<meta\s+name=["\']geo\.placename["\'][^>]*content=["\']([^"\']+)["\']', "Geo Place Name"),
        (r'<meta\s+name=["\']geo\.region["\'][^>]*content=["\']([^"\']+)["\']', "Geo Region"),
        (r'<meta\s+name=["\']ICBM["\'][^>]*content=["\']([^"\']+)["\']', "Geo Coordinates"),
    ]
    for pattern, label in geo_patterns:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            findings.append(make_finding(
                entity=m.group(1)[:200],
                ftype=f"Location: {label}",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["geo", "location", label.lower().replace(" ", "-")]
            ))

    # Employee count from meta tags
    emp_patterns = [
        (r'<meta\s+name=["\']employee-count["\'][^>]*content=["\']([^"\']+)["\']', "Meta Employee Count"),
        (r'<meta\s+name=["\']employees["\'][^>]*content=["\']([^"\']+)["\']', "Meta Employees"),
        (r'employee(?:s)?[:\s]+(\d[\d,+]*)', "Inline Employee Count"),
    ]
    for pattern, label in emp_patterns:
        for m in re.finditer(pattern, html, re.IGNORECASE):
            val = m.group(1).strip()
            findings.append(make_finding(
                entity=val[:100],
                ftype=f"Employee Count: {label}",
                source="PeopleOrgOSINT (HTML)",
                confidence="Low",
                color="slate",
                threat_level="Informational",
                tags=["employees", "org-profile"]
            ))

    # Footer organization info
    footer_match = re.search(
        r'<footer[^>]*>(.*?)</footer>',
        html, re.IGNORECASE | re.DOTALL
    )
    if footer_match:
        footer_html = footer_match.group(1)
        # Extract company name from footer
        footer_text = re.sub(r'<[^>]+>', ' ', footer_html).strip()
        footer_text = re.sub(r'\s+', ' ', footer_text)
        # Footer copyright
        fc = re.search(r'(?:copyright|©)\s*(?:20\d\d[-\s]*20\d\d|20\d\d)\s*([^.\n]{5,80})', footer_html, re.IGNORECASE)
        if fc:
            org = fc.group(1).strip()
            if org and len(org) > 3:
                findings.append(make_finding(
                    entity=org[:200],
                    ftype="Footer: Organization Name",
                    source="PeopleOrgOSINT (HTML)",
                    confidence="Medium",
                    color="emerald",
                    threat_level="Informational",
                    status="Found in footer",
                    tags=["footer", "organization"]
                ))
        # Footer address
        addr_markers = ["address", "street", "suite", "avenue", "boulevard", "drive", "lane", "road", "floor", "plaza"]
        footer_lines = footer_text.split(".")
        for line in footer_lines:
            line_clean = line.strip()
            if any(m in line_clean.lower() for m in addr_markers) and len(line_clean) > 15 and len(line_clean) < 250:
                findings.append(make_finding(
                    entity=line_clean[:200],
                    ftype="Footer: Address",
                    source="PeopleOrgOSINT (HTML)",
                    confidence="Low",
                    color="slate",
                    threat_level="Informational",
                    tags=["footer", "address", "location"]
                ))
                break
        # Footer email
        fe = re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', footer_html)
        for email in set(fe):
            findings.append(make_finding(
                entity=email,
                ftype="Footer: Contact Email",
                source="PeopleOrgOSINT (HTML)",
                confidence="High",
                color="cyan",
                threat_level="Informational",
                status="Found in footer",
                tags=["footer", "email", "contact"]
            ))
        # Footer phone
        phones = re.findall(r'[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9]', footer_html)
        for phone in phones[:2]:
            findings.append(make_finding(
                entity=phone.strip()[:30],
                ftype="Footer: Phone Number",
                source="PeopleOrgOSINT (HTML)",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                tags=["footer", "phone", "contact"]
            ))

    return findings


async def search_github_org(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    domain_short = target.split(".")[0] if "." in target else target
    try:
        resp = await safe_fetch(client, f"https://api.github.com/search/users?q={domain_short}+in:name+type:org",
            timeout=10.0, headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "application/vnd.github.v3+json"
            })
        if resp and resp.status_code == 200:
            data = resp.json()
            items = data.get("items", [])
            for item in items[:3]:
                findings.append(make_finding(
                    entity=item.get("login", "")[:200],
                    ftype="GitHub Organization Match",
                    source="PeopleOrgOSINT (GitHub)",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    resolution=item.get("html_url", ""),
                    raw_data=f"GitHub: {item.get('login')} - {item.get('html_url')}",
                    tags=["github", "organization", f"github-{item.get('login', '')}"]
                ))
    except:
        pass
    return findings


async def search_security_contacts(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    paths = [
        "/.well-known/security.txt",
        "/security.txt",
        "/security.md",
        "/.well-known/vulnerability-disclosure-policy",
    ]
    for path in paths:
        try:
            resp = await safe_fetch(client, f"https://{target}{path}", timeout=8.0)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                findings.append(make_finding(
                    entity=f"https://{target}{path}",
                    ftype="Security Contact File",
                    source="PeopleOrgOSINT",
                    confidence="High",
                    color="emerald",
                    threat_level="Informational",
                    status="Found",
                    raw_data=resp.text[:500],
                    tags=["security", "contact", path.split("/")[-1]]
                ))
                emails = re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', resp.text)
                for email in emails[:3]:
                    findings.append(make_finding(
                        entity=email,
                        ftype="Security Contact Email",
                        source="PeopleOrgOSINT",
                        confidence="High",
                        color="cyan",
                        threat_level="Informational",
                        status="Found in security.txt",
                        resolution="Security contact",
                        tags=["security", "email", "contact"]
                    ))
        except:
            pass
    return findings


async def extract_emails_from_page(html: str, target: str) -> list:
    findings = []
    emails = re.findall(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', html)
    domain_lower = target.lower()
    domain_short = target.split(".")[0] if "." in target else target
    domain_clean = re.sub(r'^www\.', '', domain_lower)

    found_emails = set()
    for email in set(emails):
        email_domain = email.split("@")[-1].lower()
        if email_domain == domain_lower or email_domain.endswith("." + domain_lower):
            found_emails.add(email)
            findings.append(make_finding(
                entity=email,
                ftype="Corporate Email Address",
                source="PeopleOrgOSINT (HTML)",
                confidence="High",
                color="cyan",
                threat_level="Informational",
                status="Found on website",
                tags=["email", "corporate"]
            ))

    # Suggest likely email formats based on domain
    if found_emails:
        sample = next(iter(found_emails))
        local_part = sample.split("@")[0]
        formats = []
        if "." in local_part:
            first, last = local_part.split(".", 1)
            formats.append("firstname.lastname")
            formats.append(f"Suggested: {first}.{last}@{domain_clean}")
        elif "_" in local_part:
            first, last = local_part.split("_", 1)
            formats.append("firstname_lastname")
            formats.append(f"Suggested: {first}_{last}@{domain_clean}")
        else:
            formats.append("single-word")
        formats.append(f"first@domain (first@{domain_clean})")
        formats.append(f"first.last@domain (first.last@{domain_clean})")
        if local_part.isalpha():
            formats.append(f"firstl@domain ({local_part[0]}{domain_clean})")
            formats.append(f"flast@domain ({local_part[0]}{local_part if len(local_part) > 1 else ''}{domain_clean})")

        findings.append(make_finding(
            entity=domain_clean[:100],
            ftype="Email Format Suggestion",
            source="PeopleOrgOSINT (HTML)",
            confidence="Medium",
            color="cyan",
            threat_level="Informational",
            status="Likely email patterns",
            resolution="; ".join(formats[:5]),
            tags=["email", "format", "osint"]
        ))

    return findings


async def extract_contact_page(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    contact_paths = ["/contact", "/contact-us", "/contactus", "/about", "/about-us"]
    for path in contact_paths:
        try:
            resp = await safe_fetch(client, f"https://{target}{path}", timeout=8.0)
            if resp and resp.status_code == 200 and len(resp.text) > 200:
                html = resp.text.lower()
                phones = re.findall(r'[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9]', html)
                for phone in phones[:2]:
                    findings.append(make_finding(
                        entity=phone.strip()[:30],
                        ftype="Contact Phone Number",
                        source="PeopleOrgOSINT",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["contact", "phone"]
                    ))
                addr_markers = ["address", "street", "suite", "avenue", "boulevard", "drive", "lane", "road"]
                lines = html.split("\n")
                for line in lines:
                    line_clean = line.strip()
                    if any(m in line_clean for m in addr_markers) and len(line_clean) > 15 and len(line_clean) < 200:
                        findings.append(make_finding(
                            entity=re.sub(r'<[^>]+>', '', line_clean).strip()[:200],
                            ftype="Office Address",
                            source="PeopleOrgOSINT",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            tags=["contact", "address", "location"]
                        ))
                        break
                break
        except:
            continue
    return findings


async def search_crunchbase(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    domain_short = target.split(".")[0] if "." in target else target
    domain_clean = re.sub(r'^www\.', '', domain_short)

    # Try Crunchbase API first (free tier, may work without key for limited queries)
    api_urls = [
        f"https://api.crunchbase.com/api/v4/entities/organizations/{domain_clean}",
        f"https://api.crunchbase.com/v3.1/odm-organizations?domain_name={target}",
    ]
    api_success = False
    for api_url in api_urls:
        if api_success:
            break
        try:
            resp = await safe_fetch(client, 
                api_url,
                timeout=8.0,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if resp.status_code == 200:
                data = resp.json()
                api_success = True
                props = data.get("data", {}).get("properties", data.get("properties", {}))
                if not props:
                    props = data.get("data", {})
                name = props.get("name", props.get("title", ""))
                if name:
                    findings.append(make_finding(
                        entity=name[:200],
                        ftype="Crunchbase: Organization Name",
                        source="PeopleOrgOSINT (Crunchbase)",
                        confidence="High",
                        color="emerald",
                        threat_level="Informational",
                        status="Found via Crunchbase API",
                        tags=["crunchbase", "organization", "api"]
                    ))
                desc = props.get("description", props.get("short_description", ""))
                if desc:
                    findings.append(make_finding(
                        entity=desc[:200],
                        ftype="Crunchbase: Description",
                        source="PeopleOrgOSINT (Crunchbase)",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["crunchbase", "description", "org-profile"]
                    ))
                for emp_field in ["num_employees_min", "num_employees_max", "employee_count", "employees"]:
                    emp = props.get(emp_field, "")
                    if emp:
                        findings.append(make_finding(
                            entity=str(emp)[:100],
                            ftype="Crunchbase: Employee Count",
                            source="PeopleOrgOSINT (Crunchbase)",
                            confidence="Medium",
                            color="slate",
                            threat_level="Informational",
                            tags=["crunchbase", "employees"]
                        ))
                        break
                founded = props.get("founded_on", props.get("founded_date", props.get("founded", "")))
                if founded:
                    findings.append(make_finding(
                        entity=str(founded)[:50],
                        ftype="Crunchbase: Founding Date",
                        source="PeopleOrgOSINT (Crunchbase)",
                        confidence="Medium",
                        color="amber",
                        threat_level="Informational",
                        tags=["crunchbase", "founding-date"]
                    ))
                location = props.get("location", props.get("city", ""))
                if location:
                    findings.append(make_finding(
                        entity=str(location)[:200],
                        ftype="Crunchbase: Location",
                        source="PeopleOrgOSINT (Crunchbase)",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["crunchbase", "location"]
                    ))
                industry = props.get("industry", props.get("categories", ""))
                if industry:
                    findings.append(make_finding(
                        entity=str(industry)[:200],
                        ftype="Crunchbase: Industry",
                        source="PeopleOrgOSINT (Crunchbase)",
                        confidence="Medium",
                        color="slate",
                        threat_level="Informational",
                        tags=["crunchbase", "industry"]
                    ))
                cb_url = props.get("crunchbase_url", props.get("permalink", ""))
                if cb_url:
                    findings.append(make_finding(
                        entity=str(cb_url)[:200],
                        ftype="Crunchbase: Profile URL",
                        source="PeopleOrgOSINT (Crunchbase)",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        tags=["crunchbase", "profile"]
                    ))
                # Category/industry array
                for arr_key in ["categories", "industries"]:
                    for item in props.get(arr_key, []):
                        if isinstance(item, dict) and item.get("value"):
                            findings.append(make_finding(
                                entity=item["value"][:200],
                                ftype="Crunchbase: Category",
                                source="PeopleOrgOSINT (Crunchbase)",
                                confidence="Medium",
                                color="slate",
                                threat_level="Informational",
                                tags=["crunchbase", "industry", "category"]
                            ))
                        elif isinstance(item, str):
                            findings.append(make_finding(
                                entity=item[:200],
                                ftype="Crunchbase: Category",
                                source="PeopleOrgOSINT (Crunchbase)",
                                confidence="Medium",
                                color="slate",
                                threat_level="Informational",
                                tags=["crunchbase", "industry", "category"]
                            ))
        except:
            pass

    # Fallback: web scrape Crunchbase search
    if not api_success:
        try:
            search_url = f"https://www.crunchbase.com/organization/{domain_clean}"
            resp = await safe_fetch(client, search_url, timeout=10.0, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if resp and resp.status_code == 200:
                findings.append(make_finding(
                    entity=search_url,
                    ftype="Crunchbase: Profile Page",
                    source="PeopleOrgOSINT (Crunchbase)",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    status="Crunchbase page found",
                    tags=["crunchbase", "profile"]
                ))
        except:
            pass

    return findings


async def search_linkedin_company(target: str, client: httpx.AsyncClient) -> list:
    findings = []
    domain_clean = re.sub(r'^www\.', '', target)
    domain_short = target.split(".")[0] if "." in target else target

    # Try direct LinkedIn company page via Google cache
    cache_urls = [
        f"https://webcache.googleusercontent.com/search?q=cache:linkedin.com/company/{domain_short}",
        f"https://webcache.googleusercontent.com/search?q=cache:linkedin.com/company/{domain_clean}",
    ]
    for cache_url in cache_urls:
        try:
            resp = await safe_fetch(client, cache_url, timeout=8.0, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            if resp and resp.status_code == 200 and len(resp.text) > 200:
                linkedin_url = f"linkedin.com/company/{domain_short}"
                findings.append(make_finding(
                    entity=linkedin_url[:200],
                    ftype="LinkedIn: Company Page",
                    source="PeopleOrgOSINT (LinkedIn)",
                    confidence="Medium",
                    color="purple",
                    threat_level="Informational",
                    status="LinkedIn company page detected via cache",
                    tags=["linkedin", "social", "company"]
                ))
                # Try to extract employee count from cached page
                emp_match = re.search(r'(\d[\d,.-]*)\s*(?:employees|on LinkedIn)', resp.text, re.IGNORECASE)
                if emp_match:
                    findings.append(make_finding(
                        entity=emp_match.group(1).strip()[:50],
                        ftype="LinkedIn: Employee Count",
                        source="PeopleOrgOSINT (LinkedIn)",
                        confidence="Low",
                        color="slate",
                        threat_level="Informational",
                        tags=["linkedin", "employees"]
                    ))
                # Try to extract industry from cached page
                ind_match = re.search(r'industry[":\s]+([^"<,]{3,60})', resp.text, re.IGNORECASE)
                if ind_match:
                    findings.append(make_finding(
                        entity=ind_match.group(1).strip()[:100],
                        ftype="LinkedIn: Industry",
                        source="PeopleOrgOSINT (LinkedIn)",
                        confidence="Low",
                        color="slate",
                        threat_level="Informational",
                        tags=["linkedin", "industry"]
                    ))
                break
        except:
            continue

    # Also check if LinkedIn company URL is embedded elsewhere
    try:
        resp = await safe_fetch(client, f"https://{target}/linkedin", timeout=8.0)
        if resp and resp.status_code == 200 and "linkedin.com/company" in resp.text:
            findings.append(make_finding(
                entity=f"linkedin.com/company/{domain_short}",
                ftype="LinkedIn: Company Page (Redirect)",
                source="PeopleOrgOSINT (LinkedIn)",
                confidence="Medium",
                color="purple",
                threat_level="Informational",
                status="LinkedIn redirect found",
                tags=["linkedin", "social", "company"]
            ))
    except:
        pass

    return findings


async def classify_industry(html: str, target: str) -> list:
    findings = []
    html_lower = html.lower()
    text_only = re.sub(r'<[^>]+>', ' ', html_lower)
    text_only = re.sub(r'\s+', ' ', text_only)

    best_match = None
    best_score = 0
    industry_matches = []

    for industry, keywords in INDUSTRY_KEYWORDS:
        score = 0
        matched_kw = []
        for kw in keywords:
            count = len(re.findall(re.escape(kw), text_only))
            if count > 0:
                score += count
                matched_kw.append(kw)
        if score > best_score:
            best_score = score
            best_match = industry
            industry_matches = matched_kw

    # Also check meta keywords
    meta_keywords = re.search(
        r'<meta\s+name=["\']keywords["\'][^>]*content=["\']([^"\']+)["\']',
        html, re.IGNORECASE
    )
    if meta_keywords:
        kw_content = meta_keywords.group(1).lower()
        findings.append(make_finding(
            entity=kw_content[:200],
            ftype="Meta: Keywords",
            source="PeopleOrgOSINT (HTML)",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["meta", "keywords", "industry"]
        ))
        for industry, keywords in INDUSTRY_KEYWORDS:
            for kw in keywords:
                if kw in kw_content:
                    if industry == best_match:
                        best_score += 3
                    findings.append(make_finding(
                        entity=f"{industry} (matched keyword: {kw})",
                        ftype="Industry Classification",
                        source="PeopleOrgOSINT (HTML)",
                        confidence="Low",
                        color="slate",
                        threat_level="Informational",
                        tags=["industry", "classification", industry.lower().replace(" ", "-")]
                    ))

    if best_match and best_score > 2:
        findings.append(make_finding(
            entity=f"{best_match} (score: {best_score}, keywords: {', '.join(industry_matches[:5])})",
            ftype="Industry Classification (Primary)",
            source="PeopleOrgOSINT (HTML)",
            confidence="Medium",
            color="emerald",
            threat_level="Informational",
            status=f"Top industry match: {best_match}",
            tags=["industry", "classification", "org-profile", best_match.lower().replace(" ", "-")]
        ))

    return findings


async def extract_locations(html: str, target: str) -> list:
    findings = []
    html_lower = html.lower()
    text_only = re.sub(r'<[^>]+>', ' ', html_lower)
    text_only = re.sub(r'\s+', ' ', text_only)

    # Common US/global city-state patterns
    city_state = re.findall(
        r'([A-Z][a-z]+(?:[\s-][A-Z][a-z]+)*),?\s*([A-Z]{2})\s+\d{5}(?:-\d{4})?',
        html
    )
    for city, state in city_state[:3]:
        findings.append(make_finding(
            entity=f"{city}, {state}",
            ftype="Location: City, State + Zip",
            source="PeopleOrgOSINT (HTML)",
            confidence="Medium",
            color="slate",
            threat_level="Informational",
            tags=["location", "address"]
        ))

    # City, Country patterns
    city_country = re.findall(
        r'([A-Z][a-z]+(?:[\s-][A-Z][a-z]+)*),?\s*(?:USA|United States|UK|United Kingdom|Canada|Germany|France|Australia|Japan|Singapore|India|China|Brazil)',
        html
    )
    for loc in set(city_country[:3]):
        findings.append(make_finding(
            entity=loc[:200],
            ftype="Location: City, Country",
            source="PeopleOrgOSINT (HTML)",
            confidence="Low",
            color="slate",
            threat_level="Informational",
            tags=["location"]
        ))

    return findings


async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    html = ""
    try:
        resp = await safe_fetch(client, f"https://{domain}", timeout=15.0, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        if resp:
            html = resp.text[:200000]
    except:
        pass

    tasks = [
        extract_org_from_whois(domain, client),
        extract_org_from_ssl(domain),
        search_github_org(domain, client),
        search_security_contacts(domain, client),
        extract_contact_page(domain, client),
        search_crunchbase(domain, client),
        search_linkedin_company(domain, client),
    ]

    if html:
        tasks.append(extract_people_from_html(html, domain))
        tasks.append(extract_emails_from_page(html, domain))
        tasks.append(classify_industry(html, domain))
        tasks.append(extract_locations(html, domain))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, list):
            findings.extend(result)

    # Deduplicate by entity+type
    seen = set()
    deduped = []
    for f in findings:
        key = (f.entity, f.type)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped

    org_names = [f.entity for f in findings if "Organization" in f.type or "Org" in f.type or "Crunchbase" in f.type]
    people_count = sum(1 for f in findings if "Email" in f.type or "Name" in f.type or "Founder" in f.type)
    social_count = sum(1 for f in findings if "Social" in f.type or "GitHub" in f.type or "LinkedIn" in f.type or "Crunchbase" in f.type)
    tech_count = sum(1 for f in findings if "Technology" in f.type)
    employee_count = next((f.entity for f in findings if "Employee Count" in f.type or "Employees" in f.type), "Unknown")
    industry_findings = [f for f in findings if "Industry Classification" in f.type]
    industry = industry_findings[0].entity if industry_findings else "Unknown"

    org_profile_parts = []
    if org_names:
        org_profile_parts.append(f"Org: {list(set(org_names))[:3]}")
    org_profile_parts.append(f"Industry: {industry}")
    org_profile_parts.append(f"Employees: {employee_count}")
    org_profile_parts.append(f"People/Contacts: {people_count}")
    org_profile_parts.append(f"Social/Profiles: {social_count}")
    if tech_count:
        org_profile_parts.append(f"Tech Stack Items: {tech_count}")

    findings.append(make_finding(
        entity=f"People & Org OSINT: {len(set(org_names))} orgs, {people_count} contacts, {social_count} social links, {tech_count} tech items",
        ftype="People & Org OSINT Summary",
        source="PeopleOrgOSINT",
        confidence="Medium",
        color="purple",
        threat_level="Informational",
        status=f"{len(findings)} findings",
        tags=["people-osint", "org-osint", "summary"]
    ))

    findings.append(make_finding(
        entity=" | ".join(org_profile_parts),
        ftype="Organization Profile Summary",
        source="PeopleOrgOSINT",
        confidence="Medium",
        color="emerald",
        threat_level="Informational",
        status="Org profile compiled",
        tags=["org-profile", "summary", "osint"]
    ))

    return findings
