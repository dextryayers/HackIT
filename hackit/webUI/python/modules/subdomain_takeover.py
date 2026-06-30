import httpx
import socket
import asyncio
import json
import re
import dns.resolver
from datetime import datetime
from models import IntelligenceFinding
from urllib.parse import urlparse

CLOUD_SERVICES = {
    "AWS S3": {
        "domains": ["s3.amazonaws.com", "s3-website", "s3.us-east-1",
                    "s3-eu-west", "s3.ap-southeast", "s3.dualstack",
                    "s3.us-west", "amazonaws.com", "s3.console.aws.amazon.com",
                    "s3-regions", "s3.dualstack.us-east-1",
                    "s3.amazonaws.com", "s3.af-south-1.amazonaws.com",
                    "s3.ap-east-1.amazonaws.com", "s3.ap-south-1.amazonaws.com",
                    "s3.ap-northeast-1.amazonaws.com", "s3.ap-northeast-2.amazonaws.com",
                    "s3.ap-northeast-3.amazonaws.com", "s3.ca-central-1.amazonaws.com",
                    "s3.eu-central-1.amazonaws.com", "s3.eu-north-1.amazonaws.com",
                    "s3.eu-south-1.amazonaws.com", "s3.eu-west-1.amazonaws.com",
                    "s3.eu-west-2.amazonaws.com", "s3.eu-west-3.amazonaws.com",
                    "s3.me-south-1.amazonaws.com", "s3.sa-east-1.amazonaws.com",
                    "s3.us-east-2.amazonaws.com", "s3.us-west-1.amazonaws.com",
                    "s3.us-west-2.amazonaws.com", "s3-website.ap-northeast-2.amazonaws.com",
                    "s3-website.ap-south-1.amazonaws.com", "s3-website.ca-central-1.amazonaws.com",
                    "s3-website.eu-central-1.amazonaws.com", "s3-website.eu-west-1.amazonaws.com",
                    "s3-website.eu-west-2.amazonaws.com", "s3-website.sa-east-1.amazonaws.com",
                    "s3-website.us-east-2.amazonaws.com"],
        "fingerprints": ["NoSuchBucket", "The specified bucket does not exist",
                         "404 Not Found", "NoSuchBucketPolicy",
                         "the specified bucket does not exist",
                         "bucket does not exist", "no such bucket",
                         "the bucket you are attempting to access must be addressed",
                         "bucket you are attempting to access must be addressed",
                         "the bucket does not exist", "nosuchbucket",
                         "specified bucket does not exist", "404 Not Found - NoSuchBucket",
                         "the bucket doesnot exist"],
        "headers": ["x-amz-bucket-region", "x-amz-request-id"],
        "status_codes": [404, 403],
    },
    "AWS CloudFront": {
        "domains": ["cloudfront.net", "d1", "d2", "d3", "d4", "d5", "d6",
                    "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14",
                    "d15", "d20", "d25", "d30"],
        "fingerprints": ["error: the request could not be satisfied",
                         "badrequest", "x-cache: error from cloudfront",
                         "cloudfront", "the request could not be satisfied",
                         "cloudfront domain", "error from cloudfront",
                         "the request could not be satisfied - cloudfront",
                         "cloudfront is not configured to deliver content",
                         "this distribution is not configured to deliver content",
                         "the request could not be satisfied - bad request",
                         "cloudfront domain does not exist",
                         "cloudfront domain does not exists",
                         "this domain (cloudfront) is not configured"],
        "headers": ["x-cache", "via"],
        "status_codes": [403, 404, 400],
    },
    "AWS ELB": {
        "domains": ["elb.amazonaws.com", "eu-west-1.elb.amazonaws.com",
                    "us-east-1.elb.amazonaws.com", "ap-southeast-1.elb.amazonaws.com",
                    "ap-northeast-1.elb.amazonaws.com"],
        "fingerprints": ["there is no load balancer configured",
                         "load balancer not found", "elb - 404"],
        "headers": [],
        "status_codes": [404],
    },
    "AWS EC2": {
        "domains": ["compute.amazonaws.com", "compute-1.amazonaws.com",
                    "ec2-", "us-east-1.compute.amazonaws.com",
                    "eu-west-1.compute.amazonaws.com",
                    "us-west-2.compute.amazonaws.com",
                    "ap-southeast-1.compute.amazonaws.com",
                    "ap-northeast-1.compute.amazonaws.com",
                    "sa-east-1.compute.amazonaws.com"],
        "fingerprints": ["no such host", "server not found",
                         "this ec2 instance does not exist",
                         "ec2 instance not found", "no such instance"],
        "headers": [],
        "status_codes": [404],
    },
    "AWS API Gateway": {
        "domains": ["execute-api", "amazonaws.com"],
        "fingerprints": ["no such api", "api not found",
                         "the api you are trying to access does not exist",
                         "api gateway not found", "rest api not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Azure App Service": {
        "domains": ["azurewebsites.net", "cloudapp.net", "azureedge.net",
                    "trafficmanager.net", "blob.core.windows.net", "azurefd.net",
                    "azure-api.net", "azurecontainer.io", "azuremicroservices.io",
                    "appservicebox.net", "azurewebsites.windows.net",
                    "azurewebsites.us", "azurewebsites.china",
                    "p.azurewebsites.net", "privatelink.azurewebsites.net"],
        "fingerprints": ["there is no app hosted here",
                         "the web app you are trying to access does not exist",
                         "this web app has been removed",
                         "404 site not found", "app service - 404",
                         "azure web app", "this web app has been deleted",
                         "the webapp you are trying to access does not exist",
                         "this azure web app has been deleted",
                         "azurewebsites - 404 not found",
                         "error 404 - app service",
                         "there is no app hosted here - azurewebsites",
                         "the app service you are trying to access does not exist"],
        "headers": ["x-azure-ref", "x-powered-by"],
        "status_codes": [404, 403],
    },
    "Azure Traffic Manager": {
        "domains": ["trafficmanager.net"],
        "fingerprints": ["endpoint not found", "traffic manager endpoint not found",
                         "no traffic manager endpoint",
                         "trafficmanager - endpoint not found",
                         "the endpoint you are looking for does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Azure CDN": {
        "domains": ["azureedge.net", "azurefd.net", "msecnd.net",
                    "azure.microsoft.com"],
        "fingerprints": ["cdn endpoint not found", "azure cdn not found",
                         "the azure cdn endpoint was not found",
                         "azure cdn resource not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Azure Front Door": {
        "domains": ["azurefd.net"],
        "fingerprints": ["front door not found", "azure front door endpoint not found",
                         "the front door you are looking for does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "GitHub Pages": {
        "domains": ["github.io"],
        "fingerprints": ["there isn't a github pages site here",
                         "github pages site not found",
                         "404 not found", "github pages",
                         "no such site", "github pages - 404",
                         "there isnt a github pages site here",
                         "this page does not exist - github pages",
                         "the github pages site you are looking for does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Heroku": {
        "domains": ["herokuapp.com", "herokudns.com", "heroku.com",
                    "herokuapp.io", "herokuapp.org"],
        "fingerprints": ["no such app", "heroku | no such app",
                         "there is nothing here yet",
                         "heroku platform", "this app does not exist",
                         "no such app - heroku",
                         "there is nothing here yet - heroku",
                         "application not found - heroku",
                         "the app you are looking for does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "GitLab": {
        "domains": ["gitlab.io", "gitlabusercontent.com"],
        "fingerprints": ["the page you're looking for could not be found",
                         "page not found", "gitlab 404",
                         "project not found", "site not found",
                         "gitlab pages - 404", "gitlab project not found",
                         "this project does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Netlify": {
        "domains": ["netlify.app", "netlify.com"],
        "fingerprints": ["not found - netlify", "page not found",
                         "netlify site not found", "site not found - netlify",
                         "netlify 404", "netlify - 404 not found",
                         "the site you are looking for does not exist - netlify",
                         "netlify app not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Pantheon": {
        "domains": ["pantheonsite.io", "pantheon.io"],
        "fingerprints": ["no site found", "this site is no longer available",
                         "pantheon 404", "pantheon site not found",
                         "pantheon - 404", "the site you are looking for is no longer available"],
        "headers": [],
        "status_codes": [404],
    },
    "Shopify": {
        "domains": ["myshopify.com", "shopify.com", "shopifypreview.com"],
        "fingerprints": ["sorry, this shop is currently unavailable",
                         "shopify", "this store is unavailable",
                         "no store found", "shopify 404",
                         "shopify store not found",
                         "this shop is currently unavailable",
                         "the store you are looking for does not exist - shopify",
                         "shopify - 404 not found"],
        "headers": [],
        "status_codes": [404, 410],
    },
    "Squarespace": {
        "domains": ["squarespace.com", "sqsp.com", "squarespace.site"],
        "fingerprints": ["no site found", "this site is no longer available",
                         "domain not found", "squarespace - no such site",
                         "squarespace 404", "squarespace page not found",
                         "the squarespace site you are looking for does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Tumblr": {
        "domains": ["tumblr.com"],
        "fingerprints": ["there's nothing here", "page not found",
                         "whatever you were looking for doesn't exist",
                         "tumblr 404", "tumblr page not found",
                         "thats not a tumblr page",
                         "this page does not exist - tumblr"],
        "headers": [],
        "status_codes": [404],
    },
    "WordPress": {
        "domains": ["wordpress.com", "wpengine.com", "wpenginepowered.com",
                    "wordpresssite.com", "wp.com"],
        "fingerprints": ["domain not found", "wordpress.com",
                         "doesn't exist", "compare to",
                         "no site found", "this site does not exist",
                         "wordpress - 404", "wordpress site not found",
                         "this site does not exist - wordpress"],
        "headers": [],
        "status_codes": [404],
    },
    "Zendesk": {
        "domains": ["zendesk.com"],
        "fingerprints": ["help center closed",
                         "no longer available", "zendesk - page not found",
                         "zendesk help center",
                         "this zendesk help center is no longer available",
                         "zendesk - 404 not found"],
        "headers": [],
        "status_codes": [404, 410],
    },
    "Freshdesk": {
        "domains": ["freshdesk.com", "freshservice.com"],
        "fingerprints": ["this support portal is no longer available",
                         "freshdesk - 404", "portal not found",
                         "freshdesk portal not found",
                         "this helpdesk portal is no longer available"],
        "headers": [],
        "status_codes": [404],
    },
    "Readme.io": {
        "domains": ["readme.io", "readme.com"],
        "fingerprints": ["project doesn't exist", "page not found",
                         "readme 404", "project not found",
                         "readme project not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Surge.sh": {
        "domains": ["surge.sh"],
        "fingerprints": ["project not found", "surge - page not found",
                         "there is no such project", "surge 404",
                         "surge project not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Fly.io": {
        "domains": ["fly.dev", "fly.io"],
        "fingerprints": ["app not found", "404 not found",
                         "no such app", "fly app not found",
                         "fly.io - 404", "this fly app does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Fastly": {
        "domains": ["fastly.net", "fastly.com", "fastlylb.net",
                    "fastly.pages", "fastly-edge.com"],
        "fingerprints": ["fastly error: unknown domain",
                         "fastly - domain not found",
                         "domain unknown", "fastly 404",
                         "unknown domain - fastly",
                         "the domain you requested does not exist on fastly",
                         "fastly - the domain could not be found"],
        "headers": ["x-timer", "x-served-by", "x-cache-hits"],
        "status_codes": [404, 503],
    },
    "Bitbucket": {
        "domains": ["bitbucket.io"],
        "fingerprints": ["repository not found",
                         "this repository has been deleted",
                         "bitbucket 404", "bitbucket - 404",
                         "this bitbucket repository does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Unbounce": {
        "domains": ["unbouncepages.com", "unbounce.com"],
        "fingerprints": ["unbounce - page not found",
                         "the page you requested does not exist",
                         "landing page not found",
                         "unbounce landing page not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Wix": {
        "domains": ["wixstudio.com", "editorx.io", "wixsite.com"],
        "fingerprints": ["sorry, this site is not published",
                         "wix - 404", "this site was created",
                         "wix site not found",
                         "this wix site is not published",
                         "the wix site you are looking for does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Strikingly": {
        "domains": ["strikingly.com", "strikinglydns.com"],
        "fingerprints": ["site not found", "strikingly 404",
                         "strikingly site not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Cargo": {
        "domains": ["cargocollective.com"],
        "fingerprints": ["page not found", "site not found",
                         "cargo collective site not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Tilda": {
        "domains": ["tilda.ws"],
        "fingerprints": ["page not found", "site not found",
                         "tilda page not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Helpjuice": {
        "domains": ["helpjuice.com"],
        "fingerprints": ["kb not found", "knowledge base not found",
                         "helpjuice knowledge base not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Teamwork": {
        "domains": ["teamwork.com"],
        "fingerprints": ["project not found", "teamwork project not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Intercom": {
        "domains": ["custom.intercom.help"],
        "fingerprints": ["page not found", "help center not found",
                         "intercom help center closed",
                         "intercom help center not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Kinsta": {
        "domains": ["kinstacdn.com"],
        "fingerprints": ["no site found", "kinsta 404",
                         "site not found on kinsta"],
        "headers": [],
        "status_codes": [404],
    },
    "DigitalOcean": {
        "domains": ["digitaloceanspaces.com", "do-digitaloceanspaces.com",
                    "cdn.digitaloceanspaces.com"],
        "fingerprints": ["no such space", "space not found",
                         "digitalocean space not found",
                         "no such space - digitalocean",
                         "the digitalocean space you are looking for does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Vercel": {
        "domains": ["vercel.app", "now.sh"],
        "fingerprints": ["404: this page could not be found",
                         "vercel 404", "not found - vercel",
                         "this deployment does not exist",
                         "vercel - 404", "this page could not be found - vercel",
                         "the vercel deployment you are looking for does not exist"],
        "headers": ["x-vercel-id", "x-vercel-cache"],
        "status_codes": [404],
    },
    "Render": {
        "domains": ["onrender.com", "render.com"],
        "fingerprints": ["render 404", "page not found",
                         "site not found on render",
                         "render - 404", "the render site does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Firebase": {
        "domains": ["firebaseapp.com", "web.app", "firebaseio.com"],
        "fingerprints": ["site not found", "firebase 404",
                         "project not found", "this site is not available",
                         "firebase hosting site not found",
                         "this firebase project does not exist",
                         "the firebase site you are looking for does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Cloudflare Workers": {
        "domains": ["workers.dev"],
        "fingerprints": ["workers script not found",
                         "route not found", "cloudflare workers 404",
                         "the workers script you are looking for does not exist",
                         "workers - 404", "this workers route does not exist"],
        "headers": ["cf-ray", "cf-worker"],
        "status_codes": [404, 1101],
    },
    "Cloudflare Pages": {
        "domains": ["pages.dev"],
        "fingerprints": ["page not found", "cloudflare pages 404",
                         "this project does not exist",
                         "cloudflare pages project not found",
                         "the cloudflare pages site you are looking for does not exist"],
        "headers": ["cf-ray"],
        "status_codes": [404],
    },
    "Cloudflare CDN": {
        "domains": ["cloudflare.com", "cdn.cloudflare.com"],
        "fingerprints": ["cloudflare - 404", "domain not found on cloudflare",
                         "the cloudflare domain does not exist"],
        "headers": ["cf-ray"],
        "status_codes": [404],
    },
    "KintoBlocks": {
        "domains": ["kinsta.cloud", "kinsta.app", "kintohost.com"],
        "fingerprints": ["no site found", "site not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Cargo Collective": {
        "domains": ["cargocollective.com"],
        "fingerprints": ["cargo site not found", "404 not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Umbler": {
        "domains": ["umbler.net", "umbler.com"],
        "fingerprints": ["site not found", "umbler 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Tictail": {
        "domains": ["tictail.com"],
        "fingerprints": ["store not found", "no such store"],
        "headers": [],
        "status_codes": [404],
    },
    "Bytehost": {
        "domains": ["bytehost.net"],
        "fingerprints": ["host not found", "bytehost 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Campaign Monitor": {
        "domains": ["createsend.com", "campaignmonitor.com"],
        "fingerprints": ["page not found", "no such page"],
        "headers": [],
        "status_codes": [404],
    },
    "Acquia": {
        "domains": ["acquia-sites.com"],
        "fingerprints": ["site not found", "acquia 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Proposify": {
        "domains": ["proposify.com"],
        "fingerprints": ["proposal not found", "page not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Simplebooklet": {
        "domains": ["simplebooklet.com"],
        "fingerprints": ["booklet not found", "simplebooklet 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Apigee": {
        "domains": ["apigee.net"],
        "fingerprints": ["api portal not found", "apigee 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Smartling": {
        "domains": ["smartling.com"],
        "fingerprints": ["page not found", "smartling 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Qualtrics": {
        "domains": ["qualtrics.com"],
        "fingerprints": ["survey not found", "qualtrics 404"],
        "headers": [],
        "status_codes": [404],
    },
    "StatusPage.io": {
        "domains": ["statuspage.io"],
        "fingerprints": ["page not found", "statuspage not found",
                         "no status page found"],
        "headers": [],
        "status_codes": [404],
    },
    "PagerDuty": {
        "domains": ["pagerduty.com"],
        "fingerprints": ["page not found", "pagerduty 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Atlassian": {
        "domains": ["atlassian.net", "jira.com", "bitbucket.org"],
        "fingerprints": ["page not found", "atlassian 404",
                         "site does not exist",
                         "the atlassian site you are looking for does not exist",
                         "atlassian - 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Ghost": {
        "domains": ["ghost.io"],
        "fingerprints": ["page not found", "ghost 404", "site not found"],
        "headers": [],
        "status_codes": [404],
    },
    "TinyLetter": {
        "domains": ["tinyletter.com"],
        "fingerprints": ["page not found", "tinyletter 404"],
        "headers": [],
        "status_codes": [404],
    },
    "SendGrid": {
        "domains": ["sendgrid.net", "sendgrid.me"],
        "fingerprints": ["page not found", "sendgrid 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Mailgun": {
        "domains": ["mailgun.org", "mailgun.net", "mg."],
        "fingerprints": ["page not found", "mailgun 404", "domain not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Mailchimp": {
        "domains": ["mailchimp.com", "list-manage.com"],
        "fingerprints": ["page not found", "mailchimp 404", "campaign not found"],
        "headers": [],
        "status_codes": [404],
    },
    "HelpScout": {
        "domains": ["helpscout.net", "helpscoutdocs.com"],
        "fingerprints": ["page not found", "help scout 404", "article not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Freshworks": {
        "domains": ["freshworks.com", "freshservice.com"],
        "fingerprints": ["portal not found", "page not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Webflow": {
        "domains": ["webflow.io", "webflow.com"],
        "fingerprints": ["site not found", "webflow 404", "no such site"],
        "headers": [],
        "status_codes": [404],
    },
    "Carrd": {
        "domains": ["carrd.co"],
        "fingerprints": ["page not found", "carrd 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Jimdo": {
        "domains": ["jimdosite.com", "jimdo.com"],
        "fingerprints": ["site not found", "jimdo 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Weebly": {
        "domains": ["weebly.com"],
        "fingerprints": ["page not found", "weebly 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Yola": {
        "domains": ["yolasite.com"],
        "fingerprints": ["site not found", "yola 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Duda": {
        "domains": ["dudamobile.com", "duda.com"],
        "fingerprints": ["site not found", "duda 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Ucraft": {
        "domains": ["ucraft.net", "ucraft.com"],
        "fingerprints": ["site not found", "ucraft 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Voog": {
        "domains": ["voog.com"],
        "fingerprints": ["page not found", "voog 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Typo3": {
        "domains": ["typo3.com", "typo3.org"],
        "fingerprints": ["page not found", "typo3 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Sitecore": {
        "domains": ["sitecore.net", "sitecore.com"],
        "fingerprints": ["page not found", "sitecore 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Pulsar": {
        "domains": ["pulsar.com"],
        "fingerprints": ["page not found", "pulsar 404"],
        "headers": [],
        "status_codes": [404],
    },
    "OpenSocial": {
        "domains": ["opensocial.com"],
        "fingerprints": ["page not found", "opensocial 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Ning": {
        "domains": ["ning.com"],
        "fingerprints": ["site not found", "ning 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Yahoo": {
        "domains": ["yahoo.com", "yahoogroups.com"],
        "fingerprints": ["page not found", "yahoo 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Google Cloud Storage": {
        "domains": ["storage.googleapis.com", "appspot.com",
                    "googleapis.com", "googlecloud.com",
                    "storage.cloud.google.com"],
        "fingerprints": ["not found", "404 not found", "no such object",
                         "the specified bucket does not exist",
                         "bucket does not exist", "no such bucket",
                         "the specified object does not exist",
                         "google cloud storage - 404"],
        "headers": [],
        "status_codes": [404, 403],
    },
    "Google App Engine": {
        "domains": ["appspot.com"],
        "fingerprints": ["not found", "app engine 404",
                         "this application does not exist",
                         "the app engine application you are looking for does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Google Cloud Run": {
        "domains": ["run.app"],
        "fingerprints": ["not found", "cloud run 404",
                         "this cloud run service does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Oracle Cloud": {
        "domains": ["oraclecloud.com", "oci-"],
        "fingerprints": ["not found", "page not found", "oracle cloud 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Oracle Objects": {
        "domains": ["objectstorage.", "oraclecloud.com"],
        "fingerprints": ["bucket not found", "object storage 404",
                         "the specified bucket does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "IBM Cloud": {
        "domains": ["cloud.ibm.com", "appdomain.cloud"],
        "fingerprints": ["not found", "page not found", "app not found",
                         "ibm cloud 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Alibaba Cloud": {
        "domains": ["aliyuncs.com"],
        "fingerprints": ["not found", "bucket not found", "access denied",
                         "alibaba cloud 404", "the bucket does not exist",
                         "no such bucket"],
        "headers": [],
        "status_codes": [404, 403],
    },
    "Alibaba CDN": {
        "domains": ["alicdn.com"],
        "fingerprints": ["cdn domain not found", "alibaba cdn 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Linode": {
        "domains": ["linode.com", "linodeobjects.com"],
        "fingerprints": ["not found", "page not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Linode Object Storage": {
        "domains": ["linodeobjects.com"],
        "fingerprints": ["bucket not found", "no such bucket",
                         "the specified object does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Vultr": {
        "domains": ["vultr.com", "vultrobjects.com"],
        "fingerprints": ["not found", "page not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Vultr Object Storage": {
        "domains": ["vultrobjects.com"],
        "fingerprints": ["bucket not found", "no such bucket"],
        "headers": [],
        "status_codes": [404],
    },
    "UpCloud": {
        "domains": ["upcloud.site"],
        "fingerprints": ["not found", "page not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Scaleway": {
        "domains": ["scw.cloud", "scaleway.com"],
        "fingerprints": ["not found", "page not found"],
        "headers": [],
        "status_codes": [404],
    },
    "Scaleway Object Storage": {
        "domains": ["scw.cloud"],
        "fingerprints": ["bucket not found", "no such bucket",
                         "the requested bucket does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Hetzner": {
        "domains": ["hetzner.com", "hetzner.cloud"],
        "fingerprints": ["not found", "page not found"],
        "headers": [],
        "status_codes": [404],
    },
    "OVH": {
        "domains": ["ovh.com", "ovhcloud.com"],
        "fingerprints": ["not found", "page not found", "ovh 404"],
        "headers": [],
        "status_codes": [404],
    },
    "OVH Object Storage": {
        "domains": ["ovh.net"],
        "fingerprints": ["bucket not found", "no such container"],
        "headers": [],
        "status_codes": [404],
    },
    "Cpanel": {
        "domains": ["cpanel.com", "cpanel.net"],
        "fingerprints": ["not found", "cpanel 404",
                         "the cpanel site does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Plesk": {
        "domains": ["plesk.com"],
        "fingerprints": ["not found", "plesk 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Namecheap": {
        "domains": ["namecheap.com", "namecheaphosting.com"],
        "fingerprints": ["not found", "namecheap 404", "site not found"],
        "headers": [],
        "status_codes": [404],
    },
    "HostGator": {
        "domains": ["hostgator.com", "hostgator.net"],
        "fingerprints": ["not found", "hostgator 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Bluehost": {
        "domains": ["bluehost.com", "bluehost.net"],
        "fingerprints": ["not found", "bluehost 404"],
        "headers": [],
        "status_codes": [404],
    },
    "SiteGround": {
        "domains": ["siteground.net"],
        "fingerprints": ["not found", "siteground 404"],
        "headers": [],
        "status_codes": [404],
    },
    "DreamHost": {
        "domains": ["dreamhost.com", "dreamhosters.com"],
        "fingerprints": ["not found", "dreamhost 404", "site not found"],
        "headers": [],
        "status_codes": [404],
    },
    "A2 Hosting": {
        "domains": ["a2hosting.com"],
        "fingerprints": ["not found", "a2 hosting 404"],
        "headers": [],
        "status_codes": [404],
    },
    "InMotion": {
        "domains": ["inmotionhosting.com"],
        "fingerprints": ["not found", "inmotion 404"],
        "headers": [],
        "status_codes": [404],
    },
    "GoDaddy": {
        "domains": ["godaddy.com", "secureserver.net"],
        "fingerprints": ["page not found", "godaddy 404",
                         "the godaddy site is not available"],
        "headers": [],
        "status_codes": [404],
    },
    "Hostinger": {
        "domains": ["hostingerapp.com", "hostinger.com"],
        "fingerprints": ["not found", "hostinger 404", "site not found"],
        "headers": [],
        "status_codes": [404],
    },
    "InfinityFree": {
        "domains": ["infinityfree.net", "infinityfreeapp.com"],
        "fingerprints": ["not found", "infinity free 404"],
        "headers": [],
        "status_codes": [404],
    },
    "AwardSpace": {
        "domains": ["awardspace.net", "awardspace.com"],
        "fingerprints": ["not found", "awardspace 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Byet": {
        "domains": ["byet.net", "byet.org"],
        "fingerprints": ["not found", "byet 404"],
        "headers": [],
        "status_codes": [404],
    },
    "000Webhost": {
        "domains": ["000webhostapp.com", "000webhost.com"],
        "fingerprints": ["not found", "000webhost 404",
                         "the hosting account does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "WooCommerce": {
        "domains": ["woocommerce.com"],
        "fingerprints": ["page not found", "woocommerce 404",
                         "no store found"],
        "headers": [],
        "status_codes": [404],
    },
    "BigCommerce": {
        "domains": ["bigcommerce.com", "mybigcommerce.com"],
        "fingerprints": ["page not found", "bigcommerce 404",
                         "no such store - bigcommerce"],
        "headers": [],
        "status_codes": [404],
    },
    "Salesforce": {
        "domains": ["salesforce.com", "force.com", "cloudforce.com"],
        "fingerprints": ["page not found", "salesforce 404",
                         "the salesforce site does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "HubSpot": {
        "domains": ["hubspot.com", "hubspot.net"],
        "fingerprints": ["page not found", "hubspot 404",
                         "the hubspot page does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Marketo": {
        "domains": ["marketo.com", "marketo.net"],
        "fingerprints": ["page not found", "marketo 404"],
        "headers": [],
        "status_codes": [404],
    },
    "ClickFunnels": {
        "domains": ["clickfunnels.com"],
        "fingerprints": ["page not found", "clickfunnels 404",
                         "the funnel does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Kajabi": {
        "domains": ["kajabi.com", "kajabimembers.com"],
        "fingerprints": ["page not found", "kajabi 404",
                         "the kajabi site does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Teachable": {
        "domains": ["teachable.com", "teachable.net"],
        "fingerprints": ["page not found", "teachable 404",
                         "the course does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Thinkific": {
        "domains": ["thinkific.com"],
        "fingerprints": ["page not found", "thinkific 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Podia": {
        "domains": ["podia.com"],
        "fingerprints": ["page not found", "podia 404",
                         "the podia site does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Gumroad": {
        "domains": ["gumroad.com"],
        "fingerprints": ["page not found", "gumroad 404",
                         "the gumroad page does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Memberful": {
        "domains": ["memberful.com"],
        "fingerprints": ["page not found", "memberful 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Substack": {
        "domains": ["substack.com", "substack.net"],
        "fingerprints": ["page not found", "substack 404",
                         "the substack publication does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Medium": {
        "domains": ["medium.com"],
        "fingerprints": ["page not found", "medium 404",
                         "the medium page does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Notion": {
        "domains": ["notion.site"],
        "fingerprints": ["page not found", "notion 404",
                         "the notion page does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Coda": {
        "domains": ["coda.io"],
        "fingerprints": ["page not found", "coda 404",
                         "the coda doc does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Tally": {
        "domains": ["tally.so"],
        "fingerprints": ["page not found", "tally 404",
                         "the form does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Typeform": {
        "domains": ["typeform.com"],
        "fingerprints": ["page not found", "typeform 404",
                         "the typeform does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "JotForm": {
        "domains": ["jotform.com"],
        "fingerprints": ["page not found", "jotform 404",
                         "the form does not exist - jotform"],
        "headers": [],
        "status_codes": [404],
    },
    "Google Forms": {
        "domains": ["google.com"],
        "fingerprints": ["page not found", "google forms 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Disqus": {
        "domains": ["disqus.com"],
        "fingerprints": ["page not found", "disqus 404",
                         "the disqus forum does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Canny": {
        "domains": ["canny.io"],
        "fingerprints": ["page not found", "canny 404",
                         "the canny board does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "UserVoice": {
        "domains": ["uservoice.com"],
        "fingerprints": ["page not found", "uservoice 404",
                         "the forum does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "ProductBoard": {
        "domains": ["productboard.com"],
        "fingerprints": ["page not found", "productboard 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Trello": {
        "domains": ["trello.com"],
        "fingerprints": ["page not found", "trello 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Asana": {
        "domains": ["asana.com"],
        "fingerprints": ["page not found", "asana 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Monday": {
        "domains": ["monday.com"],
        "fingerprints": ["page not found", "monday 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Airtable": {
        "domains": ["airtable.com"],
        "fingerprints": ["page not found", "airtable 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Figma": {
        "domains": ["figma.com"],
        "fingerprints": ["page not found", "figma 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Miro": {
        "domains": ["miro.com", "realtimeboard.com"],
        "fingerprints": ["page not found", "miro 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Lucid": {
        "domains": ["lucid.app", "lucidchart.com"],
        "fingerprints": ["page not found", "lucid 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Canva": {
        "domains": ["canva.com"],
        "fingerprints": ["page not found", "canva 404"],
        "headers": [],
        "status_codes": [404],
    },
    "MongoDB Atlas": {
        "domains": ["mongodb.net"],
        "fingerprints": ["page not found", "mongodb atlas 404",
                         "the mongodb cluster does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Redis Labs": {
        "domains": ["redislabs.com", "rediscloud.com"],
        "fingerprints": ["page not found", "redis 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Snowflake": {
        "domains": ["snowflakecomputing.com"],
        "fingerprints": ["page not found", "snowflake 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Databricks": {
        "domains": ["databricks.com", "gcp.databricks.com", "azure.databricks.com"],
        "fingerprints": ["page not found", "databricks 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Elastic Cloud": {
        "domains": ["elastic-cloud.com", "elastic.co"],
        "fingerprints": ["page not found", "elastic cloud 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Auth0": {
        "domains": ["auth0.com"],
        "fingerprints": ["page not found", "auth0 404",
                         "the auth0 tenant does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Okta": {
        "domains": ["okta.com", "oktapreview.com"],
        "fingerprints": ["page not found", "okta 404",
                         "the okta application does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Duo": {
        "domains": ["duosecurity.com"],
        "fingerprints": ["page not found", "duo 404"],
        "headers": [],
        "status_codes": [404],
    },
    "CloudAMQP": {
        "domains": ["cloudamqp.com"],
        "fingerprints": ["page not found", "cloudamqp 404",
                         "the rabbitmq instance does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Aiven": {
        "domains": ["aivencloud.com"],
        "fingerprints": ["page not found", "aiven 404"],
        "headers": [],
        "status_codes": [404],
    },
    "DigitalOcean App": {
        "domains": ["ondigitalocean.app"],
        "fingerprints": ["app not found", "digitalocean app 404",
                         "the app does not exist on digitalocean"],
        "headers": [],
        "status_codes": [404],
    },
    "Northflank": {
        "domains": ["northflank.app"],
        "fingerprints": ["page not found", "northflank 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Koyeb": {
        "domains": ["koyeb.app"],
        "fingerprints": ["page not found", "koyeb 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Railway": {
        "domains": ["railway.app"],
        "fingerprints": ["page not found", "railway 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Cyclic": {
        "domains": ["cyclic.app"],
        "fingerprints": ["page not found", "cyclic 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Deno Deploy": {
        "domains": ["deno.dev"],
        "fingerprints": ["page not found", "deno deploy 404",
                         "the deno deployment does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Begin": {
        "domains": ["begin.app"],
        "fingerprints": ["page not found", "begin 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Tiiny": {
        "domains": ["tiiny.host"],
        "fingerprints": ["page not found", "tiiny 404",
                         "the tiiny site does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Neocities": {
        "domains": ["neocities.org"],
        "fingerprints": ["page not found", "neocities 404",
                         "the neocities site does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Glitch": {
        "domains": ["glitch.me"],
        "fingerprints": ["page not found", "glitch 404",
                         "the glitch app does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Codepen": {
        "domains": ["codepen.io"],
        "fingerprints": ["page not found", "codepen 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Replit": {
        "domains": ["replit.app", "replit.dev"],
        "fingerprints": ["page not found", "replit 404",
                         "the repl does not exist"],
        "headers": [],
        "status_codes": [404],
    },
    "Gitpod": {
        "domains": ["gitpod.io"],
        "fingerprints": ["page not found", "gitpod 404"],
        "headers": [],
        "status_codes": [404],
    },
    "Cloud9": {
        "domains": ["c9.io", "cloud9.com"],
        "fingerprints": ["page not found", "cloud9 404"],
        "headers": [],
        "status_codes": [404],
    },
    "StackBlitz": {
        "domains": ["stackblitz.io"],
        "fingerprints": ["page not found", "stackblitz 404"],
        "headers": [],
        "status_codes": [404],
    },
    "CodeSandbox": {
        "domains": ["codesandbox.io"],
        "fingerprints": ["page not found", "codesandbox 404"],
        "headers": [],
        "status_codes": [404],
    },
}

CNAME_CACHE: dict[str, set[str]] = {}

SERVICE_CNAME_PATTERNS: dict[str, list[str]] = {
    "AWS S3": [r"s3[.-][a-z0-9-]+\.amazonaws\.com$", r"s3-website[.-]"],
    "AWS CloudFront": [r"[a-z0-9]+\.cloudfront\.net$"],
    "AWS ELB": [r"[a-z0-9-]+\.elb\.[a-z0-9-]+\.amazonaws\.com$"],
    "Azure App Service": [r"[a-z0-9-]+\.azurewebsites\.net$", r"[a-z0-9-]+\.trafficmanager\.net$"],
    "Azure CDN": [r"[a-z0-9-]+\.azureedge\.net$"],
    "GitHub Pages": [r"[a-z0-9-]+\.github\.io$"],
    "Heroku": [r"[a-z0-9-]+\.herokuapp\.com$"],
    "Netlify": [r"[a-z0-9-]+\.netlify\.app$"],
    "Vercel": [r"[a-z0-9-]+\.vercel\.app$"],
    "Firebase": [r"[a-z0-9-]+\.firebaseapp\.com$"],
    "Fastly": [r"[a-z0-9-]+\.fastly\.net$", r"[a-z0-9-]+\.fastlylb\.net$"],
    "Cloudflare Workers": [r"[a-z0-9-]+\.workers\.dev$"],
    "Cloudflare Pages": [r"[a-z0-9-]+\.pages\.dev$"],
    "DigitalOcean": [r"[a-z0-9-]+\.digitaloceanspaces\.com$"],
    "Google Cloud Storage": [r"[a-z0-9-]+\.storage\.googleapis\.com$"],
    "Google App Engine": [r"[a-z0-9-]+\.appspot\.com$"],
    "Shopify": [r"[a-z0-9-]+\.myshopify\.com$"],
    "Squarespace": [r"[a-z0-9-]+\.squarespace\.com$"],
    "WordPress": [r"[a-z0-9-]+\.wordpress\.com$"],
    "Zendesk": [r"[a-z0-9-]+\.zendesk\.com$"],
}

POTENTIALLY_VULNERABLE_STATUS_CODES = {404, 403, 410, 503, 400}
TAKEOVER_CLASSIFICATION_THRESHOLDS = {
    "confirmed": {"min_fingerprints": 2, "min_status_matches": 1},
    "potential": {"min_fingerprints": 1, "min_status_matches": 1},
}

async def resolve_cname(hostname: str) -> list[str]:
    cnames = []
    try:
        loop = asyncio.get_event_loop()
        _, _, cname_list = await loop.run_in_executor(
            None, socket.gethostbyname_ex, hostname
        )
        return cname_list
    except (socket.gaierror, socket.herror, OSError):
        pass
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, socket.getaddrinfo, hostname, 443)
        return []
    except Exception:
        return []

async def resolve_dns_chain(hostname: str) -> dict:
    result = {"a": [], "aaaa": [], "cname": [], "mx": [], "ns": [], "txt": []}
    try:
        loop = asyncio.get_event_loop()
        for rtype in ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]:
            try:
                answers = await loop.run_in_executor(
                    None, lambda rt=rtype: list(dns.resolver.resolve(hostname, rt))
                )
                result[rtype.lower()] = [str(r) for r in answers[:10]]
            except Exception:
                pass
    except Exception:
        pass
    return result

async def analyze_http_response(hostname: str, client: httpx.AsyncClient) -> dict:
    result = {"status": None, "headers": {}, "body_snippet": "", "redirect_chain": []}
    try:
        resp = await client.get(
            f"https://{hostname}", timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        result["status"] = resp.status_code
        result["headers"] = dict(resp.headers)
        result["body_snippet"] = resp.text[:3000].lower()
        for r in resp.history:
            result["redirect_chain"].append(str(r.url))
    except Exception:
        try:
            resp = await client.get(
                f"http://{hostname}", timeout=10.0, follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
            )
            result["status"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["body_snippet"] = resp.text[:3000].lower()
        except Exception:
            pass
    return result

async def get_subdomains_crtsh(domain: str, client: httpx.AsyncClient) -> set[str]:
    subdomains = set()
    try:
        resp = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith("." + domain) or n == domain:
                        if n not in subdomains:
                            subdomains.add(n)
    except Exception:
        pass
    return subdomains

async def get_subdomains_securitytrails(domain: str, client: httpx.AsyncClient) -> set[str]:
    subdomains = set()
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        resp = await client.get(
            f"https://securitytrails.com/domain/{domain}/dns",
            timeout=15.0, headers=headers
        )
        if resp.status_code == 200:
            html = resp.text
            pattern = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9.-]+\.' + re.escape(domain) + r')')
            for m in pattern.finditer(html):
                subdomains.add(m.group(1).lower())
    except Exception:
        pass
    return subdomains

async def get_subdomains_rapiddns(domain: str, client: httpx.AsyncClient) -> set[str]:
    subdomains = set()
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        resp = await client.get(
            f"https://rapiddns.io/subdomain/{domain}",
            timeout=15.0, headers=headers
        )
        if resp.status_code == 200:
            html = resp.text
            pattern = re.compile(r'<td>([a-zA-Z0-9][a-zA-Z0-9.-]+\.' + re.escape(domain) + r')</td>')
            for m in pattern.finditer(html):
                subdomains.add(m.group(1).lower())
    except Exception:
        pass
    return subdomains

async def get_subdomains_hackertarget(domain: str, client: httpx.AsyncClient) -> set[str]:
    subdomains = set()
    try:
        resp = await client.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        if resp.status_code == 200:
            for line in resp.text.strip().split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip().lower()
                    if sub.endswith("." + domain) or sub == domain:
                        subdomains.add(sub)
    except Exception:
        pass
    return subdomains

def check_service_cname(cname: str) -> str | None:
    cname_lower = cname.lower()
    for service_name, info in CLOUD_SERVICES.items():
        for cdomain in info["domains"]:
            if cdomain in cname_lower:
                return service_name
    return None

def check_service_cname_regex(cname: str) -> str | None:
    cname_lower = cname.lower()
    for service_name, patterns in SERVICE_CNAME_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, cname_lower):
                return service_name
    return None

def classify_takeover_confidence(fingerprint_matches: list, status_code: int,
                                 header_matches: list, cname_match: bool) -> str:
    score = 0
    if len(fingerprint_matches) >= 2:
        score += 2
    elif len(fingerprint_matches) >= 1:
        score += 1
    if status_code in POTENTIALLY_VULNERABLE_STATUS_CODES:
        score += 1
    if len(header_matches) >= 1:
        score += 1
    if cname_match:
        score += 1
    if score >= 4:
        return "Confirmed"
    elif score >= 2:
        return "Potential"
    else:
        return "Low"

async def verify_takeover_deep(hostname: str, service_name: str,
                                client: httpx.AsyncClient) -> tuple[str, str, dict]:
    service_info = CLOUD_SERVICES.get(service_name)
    if not service_info:
        return "inactive", "", {}

    fingerprints = service_info["fingerprints"]
    expected_headers = service_info.get("headers", [])
    expected_status = service_info.get("status_codes", [])

    http_analysis = await analyze_http_response(hostname, client)
    status_code = http_analysis.get("status")
    headers = http_analysis.get("headers", {})
    body = http_analysis.get("body_snippet", "")

    fingerprint_matches = []
    for fp in fingerprints:
        if fp.lower() in body:
            fingerprint_matches.append(fp)

    header_matches = []
    for hdr in expected_headers:
        if hdr.lower() in {k.lower(): v for k, v in headers.items()}:
            header_matches.append(hdr)

    status_match = status_code in expected_status if expected_status else status_code in POTENTIALLY_VULNERABLE_STATUS_CODES

    classification = classify_takeover_confidence(
        fingerprint_matches, status_code, header_matches, True
    )

    evidence_parts = []
    if fingerprint_matches:
        evidence_parts.append(f"Body fingerprints: {', '.join(fingerprint_matches[:3])}")
    if header_matches:
        evidence_parts.append(f"Header matches: {', '.join(header_matches)}")
    if status_code:
        evidence_parts.append(f"HTTP {status_code}")
    if http_analysis.get("redirect_chain"):
        evidence_parts.append(f"Redirects: {' -> '.join(http_analysis['redirect_chain'][:3])}")
    evidence = "; ".join(evidence_parts)

    if classification == "Confirmed":
        return "confirmed", evidence, http_analysis
    elif classification == "Potential":
        if fingerprint_matches or status_match:
            return "potential", evidence, http_analysis
    return "inactive", evidence, http_analysis

async def verify_takeover(hostname: str, service_name: str,
                          client: httpx.AsyncClient) -> tuple[bool, str]:
    service_info = CLOUD_SERVICES.get(service_name)
    if not service_info:
        return False, ""

    fingerprints = service_info["fingerprints"]
    test_url = f"https://{hostname}"

    try:
        resp = await client.get(test_url, timeout=10.0, follow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        body = resp.text.lower()[:5000]
        for fp in fingerprints:
            if fp.lower() in body:
                return True, f"Matched fingerprint: {fp}"
        resp_code_text = resp.text.lower()[:2000]
        for fp in fingerprints:
            if fp.lower() in resp_code_text:
                return True, f"Matched fingerprint: {fp}"
        if resp.status_code == 404 and any(fp in body for fp in ["not found", "does not exist", "no longer"]):
            return True, f"404 + generic takeover indicator"
    except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
        pass

    try:
        resp = await client.get(
            f"http://{hostname}", timeout=10.0, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        body = resp.text.lower()[:5000]
        for fp in fingerprints:
            if fp.lower() in body:
                return True, f"Matched fingerprint over HTTP: {fp}"
    except Exception:
        pass

    return False, ""

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    domain = target.strip().lower()
    if domain.startswith("http"):
        domain = urlparse(domain).netloc

    try:
        subdomains_set = set()

        crtsh_subs = await get_subdomains_crtsh(domain, client)
        subdomains_set.update(crtsh_subs)

        st_subs = await get_subdomains_securitytrails(domain, client)
        subdomains_set.update(st_subs)

        rd_subs = await get_subdomains_rapiddns(domain, client)
        subdomains_set.update(rd_subs)

        ht_subs = await get_subdomains_hackertarget(domain, client)
        subdomains_set.update(ht_subs)

        if domain not in subdomains_set:
            subdomains_set.add(domain)

        if not subdomains_set:
            findings.append(IntelligenceFinding(
                entity=domain,
                type="Subdomain Takeover",
                source="SubdomainTakeover",
                confidence="Low",
                color="slate",
                status="No subdomains discovered",
                resolution="CRT.sh returned no certificate results",
            ))
            return findings

        findings.append(IntelligenceFinding(
            entity=f"{len(subdomains_set)} subdomains discovered from multiple sources (crt.sh, SecurityTrails, RapidDNS, HackerTarget)",
            type="Subdomain Discovery",
            source="SubdomainTakeover",
            confidence="High",
            color="purple",
            status=f"{len(subdomains_set)} subdomains",
            resolution=domain,
        ))

        takeover_count = 0
        vulnerable_list = []
        potential_list = []
        inactive_list = []

        for subdomain in sorted(subdomains_set)[:40]:
            try:
                cnames = await resolve_cname(subdomain)
                dns_chain = await resolve_dns_chain(subdomain)

                http_analysis = await analyze_http_response(subdomain, client)

                if dns_chain.get("a"):
                    findings.append(IntelligenceFinding(
                        entity=subdomain,
                        type="DNS A Record",
                        source="SubdomainTakeover",
                        confidence="High",
                        color="blue",
                        threat_level="Informational",
                        status="Resolved",
                        resolution=", ".join(dns_chain["a"][:3]),
                        raw_data=f"A records: {', '.join(dns_chain['a'][:5])}, CNAME: {', '.join(cnames)}",
                        tags=["dns", "a-record"]
                    ))

                if dns_chain.get("cname"):
                    for cname in dns_chain["cname"]:
                        findings.append(IntelligenceFinding(
                            entity=subdomain,
                            type="DNS CNAME Record",
                            source="SubdomainTakeover",
                            confidence="High",
                            color="orange",
                            threat_level="Informational",
                            status="CNAME Found",
                            resolution=cname,
                            raw_data=f"CNAME: {subdomain} -> {cname}",
                            tags=["dns", "cname"]
                        ))

                if http_analysis.get("status"):
                    findings.append(IntelligenceFinding(
                        entity=subdomain,
                        type="HTTP Response Status",
                        source="SubdomainTakeover",
                        confidence="High",
                        color="red" if http_analysis["status"] in POTENTIALLY_VULNERABLE_STATUS_CODES else "emerald",
                        threat_level="Potential Takeover" if http_analysis["status"] in POTENTIALLY_VULNERABLE_STATUS_CODES else "Normal",
                        status=f"HTTP {http_analysis['status']}",
                        resolution=domain,
                        raw_data=f"Status: {http_analysis['status']}, Headers: {dict(list(http_analysis.get('headers', {}).items())[:5])}",
                        tags=["http-response"]
                    ))

                if http_analysis.get("headers"):
                    server_val = http_analysis["headers"].get("server", "")
                    if server_val:
                        findings.append(IntelligenceFinding(
                            entity=subdomain,
                            type="HTTP Server Header",
                            source="SubdomainTakeover",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            status=f"Server: {server_val[:100]}",
                            resolution=domain,
                            tags=["http-header"]
                        ))

                service_name = None
                for cname in cnames:
                    detected = check_service_cname(cname)
                    if detected:
                        service_name = detected
                        break
                if not service_name:
                    for cname in cnames:
                        detected = check_service_cname_regex(cname)
                        if detected:
                            service_name = detected
                            break

                if not service_name:
                    continue

                classification, evidence, http_info = await verify_takeover_deep(
                    subdomain, service_name, client)

                if classification == "confirmed":
                    status_text = "CONFIRMED - Takeover Possible"
                    color = "red"
                    threat = "Critical"
                    confidence = "High"
                elif classification == "potential":
                    status_text = "Potential - Further investigation needed"
                    color = "orange"
                    threat = "High Risk"
                    confidence = "Medium"
                else:
                    status_text = "Inactive - No takeover detected"
                    color = "slate"
                    threat = "Informational"
                    confidence = "Low"

                domain_info = evidence[:500] if evidence else "No specific evidence"
                findings.append(IntelligenceFinding(
                    entity=subdomain,
                    type=f"Takeover Check: {service_name} [{classification.upper()}]",
                    source="SubdomainTakeover",
                    confidence=confidence,
                    color=color,
                    threat_level=threat,
                    status=status_text,
                    resolution=f"CNAME: {', '.join(cnames)}",
                    raw_data=f"Service: {service_name}, "
                             f"CNAME: {', '.join(cnames)}, "
                             f"Evidence: {evidence}",
                    tags=["takeover", classification],
                ))
                if classification == "confirmed":
                    takeover_count += 1
                    vulnerable_list.append(subdomain)
                elif classification == "potential":
                    potential_list.append(subdomain)
                else:
                    inactive_list.append(subdomain)

            except Exception:
                continue

        if vulnerable_list:
            findings.append(IntelligenceFinding(
                entity=f"CONFIRMED vulnerable subdomains: {', '.join(vulnerable_list)}",
                type="Vulnerable Subdomains List (Confirmed)",
                source="SubdomainTakeover",
                confidence="High",
                color="red",
                threat_level="Critical",
                status=f"{len(vulnerable_list)} Confirmed Takeover",
                resolution=domain,
                raw_data=f"Confirmed: {', '.join(vulnerable_list)}",
                tags=["takeover", "critical", "high-risk", "confirmed"]
            ))

        if potential_list:
            findings.append(IntelligenceFinding(
                entity=f"Potential vulnerable subdomains: {', '.join(potential_list)}",
                type="Potential Subdomains List",
                source="SubdomainTakeover",
                confidence="Medium",
                color="orange",
                threat_level="High Risk",
                status=f"{len(potential_list)} Potential",
                resolution=domain,
                raw_data=f"Potential: {', '.join(potential_list)}",
                tags=["takeover", "high-risk", "potential"]
            ))

        findings.append(IntelligenceFinding(
            entity=f"Takeover scan complete: {takeover_count} confirmed, {len(potential_list)} potential, {len(inactive_list)} inactive out of {len(subdomains_set)} checked",
            type="Takeover Scan Summary",
            source="SubdomainTakeover",
            confidence="High",
            color="red" if takeover_count > 0 else "orange" if potential_list else "emerald",
            threat_level="Critical" if takeover_count > 0 else "High Risk" if potential_list else "Informational",
            status=f"{takeover_count} confirmed, {len(potential_list)} potential",
            resolution=domain,
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Subdomain takeover error: {str(e)[:150]}",
            type="Subdomain Takeover Error",
            source="SubdomainTakeover",
            confidence="Low",
            color="red",
            status="Error",
        ))

    return findings
