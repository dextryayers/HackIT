use crate::common::*;
use crate::{progress, progress_done};
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::RecordType;

pub async fn check(target: &str) -> SubdomainTakeoverResult {
    progress!("subdomain_takeover", "running");
    let mut result = SubdomainTakeoverResult { target: target.into(), checks: vec![] };

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let takeover_services: &[(&str, &[&str], &str)] = &[
        ("aws-s3", &["s3.amazonaws.com", "s3.us-east-1.amazonaws.com", "s3-website"], "AWS S3 Bucket"),
        ("aws-cloudfront", &["cloudfront.net"], "AWS CloudFront"),
        ("azure-webapp", &["azurewebsites.net", "azurewebsites.windows.net"], "Azure Web App"),
        ("azure-trafficmanager", &["trafficmanager.net"], "Azure Traffic Manager"),
        ("azure-cdn", &["azureedge.net", "azurefd.net"], "Azure CDN"),
        ("github-pages", &["github.io"], "GitHub Pages"),
        ("gitlab-pages", &["gitlab.io"], "GitLab Pages"),
        ("heroku", &["herokuapp.com", "herokudns.com"], "Heroku"),
        ("netlify", &["netlify.app", "netlify.com"], "Netlify"),
        ("vercel", &["vercel.app", "now.sh"], "Vercel"),
        ("shopify", &["myshopify.com"], "Shopify"),
        ("surge", &["surge.sh"], "Surge"),
        ("firebase", &["firebaseapp.com", "web.app"], "Firebase"),
        ("pantheon", &["pantheonsite.io", "pantheon.io"], "Pantheon"),
        ("bitbucket", &["bitbucket.io"], "Bitbucket Pages"),
        ("fly", &["fly.dev", "fly.io"], "Fly.io"),
        ("render", &["onrender.com"], "Render"),
        ("wordpress", &["wordpress.com"], "WordPress.com"),
        ("zendesk", &["zendesk.com"], "Zendesk"),
        ("statuspage", &["statuspage.io"], "StatusPage"),
        ("freshdesk", &["freshdesk.com"], "Freshdesk"),
        ("helpscout", &["helpscout.net"], "HelpScout"),
        ("cargo", &["cargocollective.com"], "Cargo Collective"),
        ("fastly", &["fastly.net", "fastlylb.net"], "Fastly"),
        ("strikingly", &["strikingly.com", "strikinglydns.com"], "Strikingly"),
        ("unbounce", &["unbounce.com", "unbouncepages.com"], "Unbounce"),
        ("tumblr", &["tumblr.com"], "Tumblr"),
        ("squarespace", &["squarespace.com", "squarespace.site"], "Squarespace"),
        ("wix", &["wixsite.com", "wixstudio.com", "editorx.io"], "Wix"),
        ("simply", &["simply.com"], "Simply.com"),
        ("hatch", &["hatchbox.io"], "Hatchbox"),
    ];

    for (prefix, cname_targets, service) in takeover_services {
        let sub = format!("{}.{}", prefix, target);
        if let Ok(resp) = resolver.lookup(&sub, RecordType::CNAME).await {
            for r in resp.iter() {
                let cname_str = r.to_string().to_lowercase();
                for cname_target in *cname_targets {
                    if cname_str.contains(cname_target) {
                        result.checks.push(TakeoverCheck {
                            subdomain: sub.clone(),
                            cname: Some(cname_str.clone()),
                            service: Some(service.to_string()),
                            vulnerable: true,
                            description: Some(format!("{} may be vulnerable to takeover via {}", sub, service)),
                        });
                        break;
                    }
                }
            }
        }
        match resolver.lookup(&sub, RecordType::A).await {
            Ok(_) => {}
            Err(_) => {}
        }
    }

    progress_done!("subdomain_takeover");
    result
}
