import httpx
import socket
import asyncio
import re
from module_common import safe_fetch, make_finding
CLOUD_METADATA_ENDPOINTS = {
    "AWS": {
        "urls": ["http://169.254.169.254/latest/meta-data/",
                 "http://169.254.169.254/latest/dynamic/instance-identity/document"],
        "headers": {"X-aws-ec2": "true"},
    },
    "GCP": {
        "urls": ["http://metadata.google.internal/computeMetadata/v1/",
                 "http://169.254.169.254/computeMetadata/v1/"],
        "headers": {"Metadata-Flavor": "Google"},
    },
    "Azure": {
        "urls": ["http://169.254.169.254/metadata/instance?api-version=2021-02-01"],
        "headers": {"Metadata": "true"},
    },
    "DigitalOcean": {
        "urls": ["http://169.254.169.254/metadata/v1.json"],
        "headers": {},
    },
}

CLOUD_IP_RANGES_URLS = {
    "AWS": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "GCP": "https://www.gstatic.com/ipranges/cloud.json",
    "Azure": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20250331.json",
    "Oracle": "",
    "DigitalOcean": "",
    "Linode": "",
    "Vultr": "",
}

CLOUD_CDN_HEADERS = {
    "cloudflare": {"name": "Cloudflare", "header": "cf-ray", "color": "orange"},
    "akamai": {"name": "Akamai", "header": "x-akamai-transformed", "color": "orange"},
    "fastly": {"name": "Fastly", "header": "x-fastly-request-id", "color": "orange"},
    "cloudfront": {"name": "CloudFront", "header": "x-amz-cf-id", "color": "orange"},
    "incapsula": {"name": "Incapsula", "header": "x-request-id", "color": "orange"},
    "sucuri": {"name": "Sucuri", "header": "x-sucuri-id", "color": "orange"},
    "stackpath": {"name": "StackPath", "header": "x-stackpath-id", "color": "orange"},
    "cachefly": {"name": "CacheFly", "header": "x-cachefly", "color": "orange"},
    "keycdn": {"name": "KeyCDN", "header": "x-keycdn", "color": "orange"},
    "bunnycdn": {"name": "BunnyCDN", "header": "x-bunnycdn", "color": "orange"},
    "section": {"name": "Section.io", "header": "x-section", "color": "orange"},
    "belugacdn": {"name": "BelugaCDN", "header": "x-belugacdn", "color": "orange"},
}

CLOUD_SERVER_HEADERS = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "cloudfront": "CloudFront",
    "amazon": "AWS",
    "amazon.com": "AWS",
    "azure": "Azure",
    "azurewebsites": "Azure App Service",
    "azureedge": "Azure CDN",
    "google": "Google Cloud",
    "gce": "Google Compute Engine",
    "gcp": "Google Cloud Platform",
    "googlecloud": "Google Cloud",
    "digitalocean": "DigitalOcean",
    "linode": "Linode",
    "vultr": "Vultr",
    "ovh": "OVH",
    "hetzner": "Hetzner",
    "heroku": "Heroku",
    "vercel": "Vercel",
    "netlify": "Netlify",
    "railway": "Railway",
    "render": "Render",
    "fly": "Fly.io",
    "ibm": "IBM Cloud",
    "oracle": "Oracle Cloud",
    "alibaba": "Alibaba Cloud",
    "tencent": "Tencent Cloud",
    "fastly": "Fastly",
    "keycdn": "KeyCDN",
    "bunnycdn": "BunnyCDN",
    "scaleway": "Scaleway",
    "upcloud": "UpCloud",
    "ionos": "IONOS",
    "contabo": "Contabo",
    "do": "DigitalOcean",
    "civo": "Civo",
    "kamatera": "Kamatera",
    "vultr": "Vultr",
    "packet": "Packet",
    "equinix": "Equinix Metal",
}

CLOUD_STORAGE_PATTERNS = {
    "s3.amazonaws.com": "AWS S3",
    "s3.us-east-1.amazonaws.com": "AWS S3 (us-east-1)",
    "s3-us-west-1.amazonaws.com": "AWS S3 (us-west-1)",
    "s3-us-west-2.amazonaws.com": "AWS S3 (us-west-2)",
    "s3-eu-west-1.amazonaws.com": "AWS S3 (eu-west-1)",
    "s3-eu-central-1.amazonaws.com": "AWS S3 (eu-central-1)",
    "s3-eu-west-2.amazonaws.com": "AWS S3 (eu-west-2)",
    "s3-eu-west-3.amazonaws.com": "AWS S3 (eu-west-3)",
    "s3-eu-north-1.amazonaws.com": "AWS S3 (eu-north-1)",
    "s3-ap-southeast-1.amazonaws.com": "AWS S3 (ap-southeast-1)",
    "s3-ap-southeast-2.amazonaws.com": "AWS S3 (ap-southeast-2)",
    "s3-ap-northeast-1.amazonaws.com": "AWS S3 (ap-northeast-1)",
    "s3-ap-south-1.amazonaws.com": "AWS S3 (ap-south-1)",
    "s3-sa-east-1.amazonaws.com": "AWS S3 (sa-east-1)",
    "s3-ca-central-1.amazonaws.com": "AWS S3 (ca-central-1)",
    "s3-me-south-1.amazonaws.com": "AWS S3 (me-south-1)",
    "s3-af-south-1.amazonaws.com": "AWS S3 (af-south-1)",
    "blob.core.windows.net": "Azure Blob Storage",
    "storage.googleapis.com": "GCP Cloud Storage",
    "digitaloceanspaces.com": "DigitalOcean Spaces",
    "storage.bunnycdn.com": "BunnyCDN Storage",
    "wasabisys.com": "Wasabi Cloud Storage",
    "backblazeb2.com": "Backblaze B2",
    "linodeobjects.com": "Linode Object Storage",
    "vultrobjects.com": "Vultr Object Storage",
    "s3.filebase.com": "Filebase",
    "s3.storageos.eu": "Storj",
    "s3.cleversafe.com": "IBM Cloud Object Storage",
    "oss-cn-hangzhou.aliyuncs.com": "Alibaba OSS",
    "oss-us-east-1.aliyuncs.com": "Alibaba OSS US",
    "cos.ap-singapore.myqcloud.com": "Tencent COS",
    "cos.ap-beijing.myqcloud.com": "Tencent COS Beijing",
    "na3.ncloudstorage.com": "Naver Cloud",
    "ru-msk.cloud.ru": "Cloud.ru",
    "hb.bizmrg.com": "VK Cloud",
}

CLOUD_PROVIDER_IP_RANGES = {
    "AWS": [
        (("54.0.0.0", "54.255.255.255"), "AWS Global"),
        (("13.0.0.0", "13.255.255.255"), "AWS Global"),
        (("15.0.0.0", "15.255.255.255"), "AWS Global"),
        (("16.0.0.0", "16.255.255.255"), "AWS Global"),
        (("18.0.0.0", "18.255.255.255"), "AWS Global"),
        (("35.0.0.0", "35.255.255.255"), "AWS Global"),
        (("44.192.0.0", "44.255.255.255"), "AWS Global"),
        (("52.0.0.0", "52.255.255.255"), "AWS Global"),
        (("3.0.0.0", "3.255.255.255"), "AWS Global"),
        (("12.0.0.0", "12.255.255.255"), "AWS Global"),
        (("99.0.0.0", "99.255.255.255"), "AWS Global"),
        (("63.0.0.0", "63.255.255.255"), "AWS Global"),
        (("56.0.0.0", "56.255.255.255"), "AWS Global"),
    ],
    "Azure": [
        (("13.64.0.0", "13.107.255.255"), "Azure Global"),
        (("20.0.0.0", "20.255.255.255"), "Azure Global"),
        (("23.96.0.0", "23.99.255.255"), "Azure Global"),
        (("40.64.0.0", "40.127.255.255"), "Azure Global"),
        (("52.128.0.0", "52.255.255.255"), "Azure Global"),
        (("65.52.0.0", "65.55.255.255"), "Azure Global"),
        (("104.208.0.0", "104.215.255.255"), "Azure Global"),
        (("137.116.0.0", "137.135.255.255"), "Azure Global"),
        (("4.0.0.0", "4.255.255.255"), "Azure Global"),
        (("51.0.0.0", "51.255.255.255"), "Azure Global"),
        (("102.0.0.0", "102.255.255.255"), "Azure Global"),
        (("168.0.0.0", "168.255.255.255"), "Azure Global"),
        (("191.0.0.0", "191.255.255.255"), "Azure Global"),
    ],
    "GCP": [
        (("8.34.0.0", "8.35.255.255"), "GCP US"),
        (("23.236.0.0", "23.236.255.255"), "GCP US"),
        (("23.251.0.0", "23.251.255.255"), "GCP US"),
        (("34.0.0.0", "34.255.255.255"), "GCP Global"),
        (("35.184.0.0", "35.255.255.255"), "GCP Global"),
        (("104.154.0.0", "104.199.255.255"), "GCP Global"),
        (("107.167.0.0", "107.167.255.255"), "GCP Global"),
        (("108.59.80.0", "108.59.95.255"), "GCP Global"),
        (("130.211.0.0", "130.211.255.255"), "GCP Global"),
        (("146.148.0.0", "146.148.255.255"), "GCP Global"),
        (("35.184.0.0", "35.215.255.255"), "GCP Global"),
        (("35.216.0.0", "35.255.255.255"), "GCP Global"),
    ],
    "DigitalOcean": [
        (("104.131.0.0", "104.131.255.255"), "DO NYC"),
        (("104.236.0.0", "104.236.255.255"), "DO SFO"),
        (("107.170.0.0", "107.170.255.255"), "DO SFO"),
        (("128.199.0.0", "128.199.255.255"), "DO SGP"),
        (("138.68.0.0", "138.68.255.255"), "DO FRA"),
        (("138.197.0.0", "138.197.255.255"), "DO NYC"),
        (("139.59.0.0", "139.59.255.255"), "DO BLR"),
        (("143.110.0.0", "143.110.255.255"), "DO Global"),
        (("146.185.0.0", "146.185.255.255"), "DO LON"),
        (("157.230.0.0", "157.230.255.255"), "DO NYC"),
        (("159.65.0.0", "159.65.255.255"), "DO SFO"),
        (("161.35.0.0", "161.35.255.255"), "DO FRA"),
        (("162.243.0.0", "162.243.255.255"), "DO NYC"),
        (("164.90.0.0", "164.90.255.255"), "DO Global"),
        (("165.22.0.0", "165.22.255.255"), "DO SGP"),
        (("167.71.0.0", "167.71.255.255"), "DO SFO"),
        (("167.99.0.0", "167.99.255.255"), "DO FRA"),
        (("174.138.0.0", "174.138.255.255"), "DO SFO"),
        (("178.62.0.0", "178.62.255.255"), "DO LON"),
        (("188.166.0.0", "188.166.255.255"), "DO AMS"),
        (("188.226.0.0", "188.226.255.255"), "DO AMS"),
        (("192.241.0.0", "192.241.255.255"), "DO NYC"),
        (("198.199.0.0", "198.199.255.255"), "DO NYC"),
        (("206.189.0.0", "206.189.255.255"), "DO SFO"),
        (("209.97.0.0", "209.97.255.255"), "DO AMS"),
    ],
    "Oracle": [
        (("129.146.0.0", "129.146.255.255"), "Oracle US-ASHBURN"),
        (("130.35.0.0", "130.35.255.255"), "Oracle US-PHOENIX"),
        (("134.70.0.0", "134.70.255.255"), "Oracle Global"),
        (("137.26.0.0", "137.26.255.255"), "Oracle US-PHOENIX"),
        (("140.91.0.0", "140.91.255.255"), "Oracle Global"),
        (("141.147.0.0", "141.147.255.255"), "Oracle Global"),
        (("144.24.0.0", "144.24.255.255"), "Oracle Global"),
        (("144.25.0.0", "144.25.255.255"), "Oracle Global"),
        (("147.154.0.0", "147.154.255.255"), "Oracle Global"),
        (("150.136.0.0", "150.136.255.255"), "Oracle Global"),
        (("152.67.0.0", "152.67.255.255"), "Oracle Global"),
        (("158.178.0.0", "158.178.255.255"), "Oracle Global"),
        (("192.29.0.0", "192.29.255.255"), "Oracle Global"),
        (("193.122.0.0", "193.122.255.255"), "Oracle Global"),
        (("205.147.0.0", "205.147.255.255"), "Oracle Global"),
        (("207.211.0.0", "207.211.255.255"), "Oracle Global"),
    ],
    "Linode": [
        (("23.92.0.0", "23.92.31.255"), "Linode Newark"),
        (("45.33.0.0", "45.33.127.255"), "Linode Newark"),
        (("45.56.0.0", "45.56.127.255"), "Linode Atlanta"),
        (("45.79.0.0", "45.79.127.255"), "Linode Dallas"),
        (("45.118.0.0", "45.118.31.255"), "Linode Tokyo"),
        (("50.116.0.0", "50.116.63.255"), "Linode Newark"),
        (("66.175.0.0", "66.175.63.255"), "Linode London"),
        (("69.164.0.0", "69.164.31.255"), "Linode Fremont"),
        (("72.14.0.0", "72.14.63.255"), "Linode Atlanta"),
        (("74.207.0.0", "74.207.255.255"), "Linode Fremont"),
        (("85.159.0.0", "85.159.15.255"), "Linode London"),
        (("96.126.0.0", "96.126.63.255"), "Linode Newark"),
        (("97.107.0.0", "97.107.31.255"), "Linode Fremont"),
        (("103.3.60.0", "103.3.63.255"), "Linode Singapore"),
        (("106.187.0.0", "106.187.31.255"), "Linode Tokyo"),
        (("108.61.0.0", "108.61.63.255"), "Linode Newark"),
        (("139.162.0.0", "139.162.255.255"), "Linode Global"),
        (("151.236.0.0", "151.236.31.255"), "Linode London"),
        (("172.104.0.0", "172.104.255.255"), "Linode Global"),
        (("173.230.0.0", "173.230.31.255"), "Linode Fremont"),
        (("173.255.0.0", "173.255.31.255"), "Linode New York"),
        (("176.58.0.0", "176.58.127.255"), "Linode London"),
        (("185.19.0.0", "185.19.31.255"), "Linode Frankfurt"),
        (("192.155.0.0", "192.155.127.255"), "Linode Global"),
        (("192.237.0.0", "192.237.31.255"), "Linode Atlanta"),
        (("192.81.0.0", "192.81.31.255"), "Linode Dallas"),
    ],
    "Vultr": [
        (("23.90.0.0", "23.90.31.255"), "Vultr New Jersey"),
        (("45.32.0.0", "45.32.255.255"), "Vultr Global"),
        (("45.63.0.0", "45.63.127.255"), "Vultr New Jersey"),
        (("45.76.0.0", "45.76.255.255"), "Vultr Global"),
        (("45.77.0.0", "45.77.255.255"), "Vultr Global"),
        (("66.42.0.0", "66.42.127.255"), "Vultr Chicago"),
        (("104.156.0.0", "104.156.255.255"), "Vultr Global"),
        (("104.207.0.0", "104.207.255.255"), "Vultr Global"),
        (("104.238.0.0", "104.238.127.255"), "Vultr Los Angeles"),
        (("107.191.0.0", "107.191.127.255"), "Vultr Atlanta"),
        (("108.61.0.0", "108.61.255.255"), "Vultr Global"),
        (("136.244.0.0", "136.244.255.255"), "Vultr Global"),
        (("141.255.0.0", "141.255.255.255"), "Vultr Global"),
        (("146.0.32.0", "146.0.63.255"), "Vultr Sydney"),
        (("149.28.0.0", "149.28.255.255"), "Vultr Global"),
        (("149.248.0.0", "149.248.127.255"), "Vultr Global"),
        (("155.138.0.0", "155.138.255.255"), "Vultr Global"),
        (("158.247.0.0", "158.247.255.255"), "Vultr Global"),
        (("192.248.0.0", "192.248.127.255"), "Vultr Global"),
        (("198.13.0.0", "198.13.127.255"), "Vultr Global"),
        (("207.148.0.0", "207.148.127.255"), "Vultr Seattle"),
        (("208.167.0.0", "208.167.255.255"), "Vultr Global"),
        (("216.238.0.0", "216.238.127.255"), "Vultr Amsterdam"),
    ],
    "Hetzner": [
        (("49.12.0.0", "49.12.255.255"), "Hetzner Nuremberg"),
        (("49.13.0.0", "49.13.255.255"), "Hetzner Nuremberg"),
        (("65.21.0.0", "65.21.255.255"), "Hetzner Helsinki"),
        (("78.46.0.0", "78.46.255.255"), "Hetzner Nuremberg"),
        (("88.198.0.0", "88.198.255.255"), "Hetzner Nuremberg"),
        (("91.190.0.0", "91.190.255.255"), "Hetzner Nuremberg"),
        (("94.130.0.0", "94.130.255.255"), "Hetzner Global"),
        (("95.216.0.0", "95.216.255.255"), "Hetzner Global"),
        (("116.202.0.0", "116.202.255.255"), "Hetzner Global"),
        (("116.203.0.0", "116.203.255.255"), "Hetzner Global"),
        (("128.140.0.0", "128.140.255.255"), "Hetzner Global"),
        (("135.181.0.0", "135.181.255.255"), "Hetzner Helsinki"),
        (("136.243.0.0", "136.243.255.255"), "Hetzner Nuremberg"),
        (("138.201.0.0", "138.201.255.255"), "Hetzner Nuremberg"),
        (("142.132.0.0", "142.132.255.255"), "Hetzner Global"),
        (("144.76.0.0", "144.76.255.255"), "Hetzner Nuremberg"),
        (("148.251.0.0", "148.251.255.255"), "Hetzner Nuremberg"),
        (("157.90.0.0", "157.90.255.255"), "Hetzner Global"),
        (("159.69.0.0", "159.69.255.255"), "Hetzner Global"),
        (("162.55.0.0", "162.55.255.255"), "Hetzner Global"),
        (("167.235.0.0", "167.235.255.255"), "Hetzner Global"),
        (("168.119.0.0", "168.119.255.255"), "Hetzner Global"),
        (("176.9.0.0", "176.9.255.255"), "Hetzner Nuremberg"),
        (("178.63.0.0", "178.63.255.255"), "Hetzner Nuremberg"),
        (("188.40.0.0", "188.40.255.255"), "Hetzner Nuremberg"),
        (("195.201.0.0", "195.201.255.255"), "Hetzner Global"),
    ],
    "OVH": [
        (("5.135.0.0", "5.135.255.255"), "OVH France"),
        (("37.187.0.0", "37.187.255.255"), "OVH France"),
        (("46.105.0.0", "46.105.255.255"), "OVH France"),
        (("51.68.0.0", "51.68.255.255"), "OVH Global"),
        (("51.75.0.0", "51.75.255.255"), "OVH Global"),
        (("51.77.0.0", "51.77.255.255"), "OVH Global"),
        (("51.79.0.0", "51.79.255.255"), "OVH Global"),
        (("51.81.0.0", "51.81.255.255"), "OVH Global"),
        (("51.83.0.0", "51.83.255.255"), "OVH Global"),
        (("51.91.0.0", "51.91.255.255"), "OVH Global"),
        (("51.161.0.0", "51.161.255.255"), "OVH Canada"),
        (("51.178.0.0", "51.178.255.255"), "OVH Global"),
        (("51.210.0.0", "51.210.255.255"), "OVH Global"),
        (("51.222.0.0", "51.222.255.255"), "OVH Global"),
        (("54.36.0.0", "54.36.255.255"), "OVH France"),
        (("54.37.0.0", "54.37.255.255"), "OVH France"),
        (("91.121.0.0", "91.121.255.255"), "OVH France"),
        (("92.222.0.0", "92.222.255.255"), "OVH France"),
        (("137.74.0.0", "137.74.255.255"), "OVH Global"),
        (("141.94.0.0", "141.94.255.255"), "OVH Global"),
        (("142.4.0.0", "142.4.255.255"), "OVH Canada"),
        (("145.239.0.0", "145.239.255.255"), "OVH Global"),
        (("147.135.0.0", "147.135.255.255"), "OVH US"),
        (("149.56.0.0", "149.56.255.255"), "OVH Canada"),
        (("151.80.0.0", "151.80.255.255"), "OVH France"),
        (("158.69.0.0", "158.69.255.255"), "OVH Canada"),
        (("164.132.0.0", "164.132.255.255"), "OVH France"),
        (("167.114.0.0", "167.114.255.255"), "OVH Canada"),
        (("176.31.0.0", "176.31.255.255"), "OVH France"),
        (("178.32.0.0", "178.32.255.255"), "OVH France"),
        (("178.33.0.0", "178.33.255.255"), "OVH France"),
        (("188.165.0.0", "188.165.255.255"), "OVH France"),
        (("192.95.0.0", "192.95.255.255"), "OVH Canada"),
        (("192.99.0.0", "192.99.255.255"), "OVH Canada"),
        (("193.70.0.0", "193.70.255.255"), "OVH France"),
        (("198.27.0.0", "198.27.255.255"), "OVH Canada"),
        (("198.50.0.0", "198.50.255.255"), "OVH Canada"),
        (("199.127.0.0", "199.127.255.255"), "OVH US"),
    ],
    "Alibaba": [
        (("8.129.0.0", "8.129.255.255"), "Alibaba CN"),
        (("8.130.0.0", "8.130.255.255"), "Alibaba CN"),
        (("8.131.0.0", "8.131.255.255"), "Alibaba CN"),
        (("39.96.0.0", "39.96.255.255"), "Alibaba CN"),
        (("39.97.0.0", "39.97.255.255"), "Alibaba CN"),
        (("39.98.0.0", "39.98.255.255"), "Alibaba CN"),
        (("39.99.0.0", "39.99.255.255"), "Alibaba CN"),
        (("39.100.0.0", "39.100.255.255"), "Alibaba CN"),
        (("39.101.0.0", "39.101.255.255"), "Alibaba CN"),
        (("39.102.0.0", "39.102.255.255"), "Alibaba CN"),
        (("39.103.0.0", "39.103.255.255"), "Alibaba CN"),
        (("39.104.0.0", "39.104.255.255"), "Alibaba CN"),
        (("39.105.0.0", "39.105.255.255"), "Alibaba CN"),
        (("39.106.0.0", "39.106.255.255"), "Alibaba CN"),
        (("39.107.0.0", "39.107.255.255"), "Alibaba CN"),
        (("47.88.0.0", "47.88.255.255"), "Alibaba Global"),
        (("47.89.0.0", "47.89.255.255"), "Alibaba Global"),
        (("47.90.0.0", "47.90.255.255"), "Alibaba Global"),
        (("47.91.0.0", "47.91.255.255"), "Alibaba Global"),
        (("47.92.0.0", "47.92.255.255"), "Alibaba Global"),
        (("47.93.0.0", "47.93.255.255"), "Alibaba Global"),
        (("47.94.0.0", "47.94.255.255"), "Alibaba Global"),
        (("47.95.0.0", "47.95.255.255"), "Alibaba Global"),
        (("47.96.0.0", "47.96.255.255"), "Alibaba Global"),
        (("47.97.0.0", "47.97.255.255"), "Alibaba Global"),
        (("47.98.0.0", "47.98.255.255"), "Alibaba Global"),
        (("47.99.0.0", "47.99.255.255"), "Alibaba Global"),
        (("47.100.0.0", "47.100.255.255"), "Alibaba Global"),
        (("47.101.0.0", "47.101.255.255"), "Alibaba Global"),
        (("47.102.0.0", "47.102.255.255"), "Alibaba Global"),
        (("47.103.0.0", "47.103.255.255"), "Alibaba Global"),
        (("47.104.0.0", "47.104.255.255"), "Alibaba Global"),
        (("47.105.0.0", "47.105.255.255"), "Alibaba Global"),
        (("47.106.0.0", "47.106.255.255"), "Alibaba Global"),
        (("47.107.0.0", "47.107.255.255"), "Alibaba Global"),
        (("47.108.0.0", "47.108.255.255"), "Alibaba Global"),
        (("47.109.0.0", "47.109.255.255"), "Alibaba Global"),
        (("47.110.0.0", "47.110.255.255"), "Alibaba Global"),
        (("47.111.0.0", "47.111.255.255"), "Alibaba Global"),
        (("47.112.0.0", "47.112.255.255"), "Alibaba Global"),
        (("47.113.0.0", "47.113.255.255"), "Alibaba Global"),
        (("47.114.0.0", "47.114.255.255"), "Alibaba Global"),
        (("47.115.0.0", "47.115.255.255"), "Alibaba Global"),
        (("47.116.0.0", "47.116.255.255"), "Alibaba Global"),
        (("47.117.0.0", "47.117.255.255"), "Alibaba Global"),
        (("47.118.0.0", "47.118.255.255"), "Alibaba Global"),
        (("47.119.0.0", "47.119.255.255"), "Alibaba Global"),
        (("47.120.0.0", "47.120.255.255"), "Alibaba Global"),
        (("47.121.0.0", "47.121.255.255"), "Alibaba Global"),
        (("47.122.0.0", "47.122.255.255"), "Alibaba Global"),
        (("47.123.0.0", "47.123.255.255"), "Alibaba Global"),
        (("47.124.0.0", "47.124.255.255"), "Alibaba Global"),
        (("47.125.0.0", "47.125.255.255"), "Alibaba Global"),
        (("47.126.0.0", "47.126.255.255"), "Alibaba Global"),
        (("47.127.0.0", "47.127.255.255"), "Alibaba Global"),
        (("47.128.0.0", "47.128.255.255"), "Alibaba Global"),
        (("47.129.0.0", "47.129.255.255"), "Alibaba Global"),
        (("47.130.0.0", "47.130.255.255"), "Alibaba Global"),
        (("47.131.0.0", "47.131.255.255"), "Alibaba Global"),
        (("47.132.0.0", "47.132.255.255"), "Alibaba Global"),
        (("47.133.0.0", "47.133.255.255"), "Alibaba Global"),
        (("47.134.0.0", "47.134.255.255"), "Alibaba Global"),
        (("47.135.0.0", "47.135.255.255"), "Alibaba Global"),
        (("47.136.0.0", "47.136.255.255"), "Alibaba Global"),
        (("47.137.0.0", "47.137.255.255"), "Alibaba Global"),
        (("47.138.0.0", "47.138.255.255"), "Alibaba Global"),
        (("47.139.0.0", "47.139.255.255"), "Alibaba Global"),
        (("47.140.0.0", "47.140.255.255"), "Alibaba Global"),
        (("47.141.0.0", "47.141.255.255"), "Alibaba Global"),
        (("47.142.0.0", "47.142.255.255"), "Alibaba Global"),
        (("47.143.0.0", "47.143.255.255"), "Alibaba Global"),
        (("47.144.0.0", "47.144.255.255"), "Alibaba Global"),
        (("47.145.0.0", "47.145.255.255"), "Alibaba Global"),
        (("47.146.0.0", "47.146.255.255"), "Alibaba Global"),
        (("47.147.0.0", "47.147.255.255"), "Alibaba Global"),
        (("47.148.0.0", "47.148.255.255"), "Alibaba Global"),
        (("47.149.0.0", "47.149.255.255"), "Alibaba Global"),
        (("47.150.0.0", "47.150.255.255"), "Alibaba Global"),
        (("47.151.0.0", "47.151.255.255"), "Alibaba Global"),
        (("47.152.0.0", "47.152.255.255"), "Alibaba Global"),
        (("47.153.0.0", "47.153.255.255"), "Alibaba Global"),
        (("47.154.0.0", "47.154.255.255"), "Alibaba Global"),
        (("47.155.0.0", "47.155.255.255"), "Alibaba Global"),
        (("47.156.0.0", "47.156.255.255"), "Alibaba Global"),
        (("47.157.0.0", "47.157.255.255"), "Alibaba Global"),
        (("47.158.0.0", "47.158.255.255"), "Alibaba Global"),
        (("47.159.0.0", "47.159.255.255"), "Alibaba Global"),
        (("47.160.0.0", "47.160.255.255"), "Alibaba Global"),
        (("47.161.0.0", "47.161.255.255"), "Alibaba Global"),
        (("47.162.0.0", "47.162.255.255"), "Alibaba Global"),
        (("47.163.0.0", "47.163.255.255"), "Alibaba Global"),
        (("47.164.0.0", "47.164.255.255"), "Alibaba Global"),
        (("47.165.0.0", "47.165.255.255"), "Alibaba Global"),
        (("47.166.0.0", "47.166.255.255"), "Alibaba Global"),
        (("47.167.0.0", "47.167.255.255"), "Alibaba Global"),
        (("47.168.0.0", "47.168.255.255"), "Alibaba Global"),
        (("47.169.0.0", "47.169.255.255"), "Alibaba Global"),
        (("47.170.0.0", "47.170.255.255"), "Alibaba Global"),
        (("47.171.0.0", "47.171.255.255"), "Alibaba Global"),
        (("47.172.0.0", "47.172.255.255"), "Alibaba Global"),
        (("47.173.0.0", "47.173.255.255"), "Alibaba Global"),
        (("47.174.0.0", "47.174.255.255"), "Alibaba Global"),
        (("47.175.0.0", "47.175.255.255"), "Alibaba Global"),
        (("47.176.0.0", "47.176.255.255"), "Alibaba Global"),
        (("47.177.0.0", "47.177.255.255"), "Alibaba Global"),
        (("47.178.0.0", "47.178.255.255"), "Alibaba Global"),
        (("47.179.0.0", "47.179.255.255"), "Alibaba Global"),
        (("47.180.0.0", "47.180.255.255"), "Alibaba Global"),
        (("47.181.0.0", "47.181.255.255"), "Alibaba Global"),
        (("47.182.0.0", "47.182.255.255"), "Alibaba Global"),
        (("47.183.0.0", "47.183.255.255"), "Alibaba Global"),
        (("47.184.0.0", "47.184.255.255"), "Alibaba Global"),
        (("47.185.0.0", "47.185.255.255"), "Alibaba Global"),
        (("47.186.0.0", "47.186.255.255"), "Alibaba Global"),
        (("47.187.0.0", "47.187.255.255"), "Alibaba Global"),
        (("47.188.0.0", "47.188.255.255"), "Alibaba Global"),
        (("47.189.0.0", "47.189.255.255"), "Alibaba Global"),
        (("47.190.0.0", "47.190.255.255"), "Alibaba Global"),
        (("47.191.0.0", "47.191.255.255"), "Alibaba Global"),
        (("47.192.0.0", "47.192.255.255"), "Alibaba Global"),
        (("47.193.0.0", "47.193.255.255"), "Alibaba Global"),
        (("47.194.0.0", "47.194.255.255"), "Alibaba Global"),
        (("47.195.0.0", "47.195.255.255"), "Alibaba Global"),
        (("47.196.0.0", "47.196.255.255"), "Alibaba Global"),
        (("47.197.0.0", "47.197.255.255"), "Alibaba Global"),
        (("47.198.0.0", "47.198.255.255"), "Alibaba Global"),
        (("47.199.0.0", "47.199.255.255"), "Alibaba Global"),
        (("47.200.0.0", "47.200.255.255"), "Alibaba Global"),
        (("47.201.0.0", "47.201.255.255"), "Alibaba Global"),
        (("47.202.0.0", "47.202.255.255"), "Alibaba Global"),
        (("47.203.0.0", "47.203.255.255"), "Alibaba Global"),
        (("47.204.0.0", "47.204.255.255"), "Alibaba Global"),
        (("47.205.0.0", "47.205.255.255"), "Alibaba Global"),
        (("47.206.0.0", "47.206.255.255"), "Alibaba Global"),
        (("47.207.0.0", "47.207.255.255"), "Alibaba Global"),
        (("47.208.0.0", "47.208.255.255"), "Alibaba Global"),
        (("47.209.0.0", "47.209.255.255"), "Alibaba Global"),
        (("47.210.0.0", "47.210.255.255"), "Alibaba Global"),
        (("47.211.0.0", "47.211.255.255"), "Alibaba Global"),
        (("47.212.0.0", "47.212.255.255"), "Alibaba Global"),
        (("47.213.0.0", "47.213.255.255"), "Alibaba Global"),
        (("47.214.0.0", "47.214.255.255"), "Alibaba Global"),
        (("47.215.0.0", "47.215.255.255"), "Alibaba Global"),
        (("47.216.0.0", "47.216.255.255"), "Alibaba Global"),
        (("47.217.0.0", "47.217.255.255"), "Alibaba Global"),
        (("47.218.0.0", "47.218.255.255"), "Alibaba Global"),
        (("47.219.0.0", "47.219.255.255"), "Alibaba Global"),
        (("47.220.0.0", "47.220.255.255"), "Alibaba Global"),
        (("47.221.0.0", "47.221.255.255"), "Alibaba Global"),
        (("47.222.0.0", "47.222.255.255"), "Alibaba Global"),
        (("47.223.0.0", "47.223.255.255"), "Alibaba Global"),
        (("47.224.0.0", "47.224.255.255"), "Alibaba Global"),
        (("47.225.0.0", "47.225.255.255"), "Alibaba Global"),
        (("47.226.0.0", "47.226.255.255"), "Alibaba Global"),
        (("47.227.0.0", "47.227.255.255"), "Alibaba Global"),
        (("47.228.0.0", "47.228.255.255"), "Alibaba Global"),
        (("47.229.0.0", "47.229.255.255"), "Alibaba Global"),
        (("47.230.0.0", "47.230.255.255"), "Alibaba Global"),
        (("47.231.0.0", "47.231.255.255"), "Alibaba Global"),
        (("47.232.0.0", "47.232.255.255"), "Alibaba Global"),
        (("47.233.0.0", "47.233.255.255"), "Alibaba Global"),
        (("47.234.0.0", "47.234.255.255"), "Alibaba Global"),
        (("47.235.0.0", "47.235.255.255"), "Alibaba Global"),
        (("47.236.0.0", "47.236.255.255"), "Alibaba Global"),
        (("47.237.0.0", "47.237.255.255"), "Alibaba Global"),
        (("47.238.0.0", "47.238.255.255"), "Alibaba Global"),
        (("47.239.0.0", "47.239.255.255"), "Alibaba Global"),
        (("47.240.0.0", "47.240.255.255"), "Alibaba Global"),
        (("47.241.0.0", "47.241.255.255"), "Alibaba Global"),
        (("47.242.0.0", "47.242.255.255"), "Alibaba Global"),
        (("47.243.0.0", "47.243.255.255"), "Alibaba Global"),
        (("47.244.0.0", "47.244.255.255"), "Alibaba Global"),
        (("47.245.0.0", "47.245.255.255"), "Alibaba Global"),
        (("47.246.0.0", "47.246.255.255"), "Alibaba Global"),
        (("47.247.0.0", "47.247.255.255"), "Alibaba Global"),
        (("47.248.0.0", "47.248.255.255"), "Alibaba Global"),
        (("47.249.0.0", "47.249.255.255"), "Alibaba Global"),
        (("47.250.0.0", "47.250.255.255"), "Alibaba Global"),
        (("47.251.0.0", "47.251.255.255"), "Alibaba Global"),
        (("47.252.0.0", "47.252.255.255"), "Alibaba Global"),
        (("47.253.0.0", "47.253.255.255"), "Alibaba Global"),
        (("47.254.0.0", "47.254.255.255"), "Alibaba Global"),
        (("47.255.0.0", "47.255.255.255"), "Alibaba Global"),
        (("99.0.0.0", "99.255.255.255"), "Alibaba Global"),
        (("106.0.0.0", "106.255.255.255"), "Alibaba Global"),
        (("112.0.0.0", "112.255.255.255"), "Alibaba Global"),
        (("114.0.0.0", "114.255.255.255"), "Alibaba Global"),
        (("115.0.0.0", "115.255.255.255"), "Alibaba Global"),
        (("118.0.0.0", "118.255.255.255"), "Alibaba Global"),
        (("119.0.0.0", "119.255.255.255"), "Alibaba Global"),
        (("120.0.0.0", "120.255.255.255"), "Alibaba Global"),
        (("121.0.0.0", "121.255.255.255"), "Alibaba Global"),
        (("122.0.0.0", "122.255.255.255"), "Alibaba Global"),
        (("123.0.0.0", "123.255.255.255"), "Alibaba Global"),
        (("124.0.0.0", "124.255.255.255"), "Alibaba Global"),
        (("125.0.0.0", "125.255.255.255"), "Alibaba Global"),
        (("139.0.0.0", "139.255.255.255"), "Alibaba Global"),
        (("140.0.0.0", "140.255.255.255"), "Alibaba Global"),
        (("149.0.0.0", "149.255.255.255"), "Alibaba Global"),
        (("157.0.0.0", "157.255.255.255"), "Alibaba Global"),
        (("161.0.0.0", "161.255.255.255"), "Alibaba Global"),
        (("162.0.0.0", "162.255.255.255"), "Alibaba Global"),
        (("163.0.0.0", "163.255.255.255"), "Alibaba Global"),
        (("165.0.0.0", "165.255.255.255"), "Alibaba Global"),
        (("167.0.0.0", "167.255.255.255"), "Alibaba Global"),
        (("168.0.0.0", "168.255.255.255"), "Alibaba Global"),
        (("169.0.0.0", "169.255.255.255"), "Alibaba Global"),
        (("170.0.0.0", "170.255.255.255"), "Alibaba Global"),
        (("171.0.0.0", "171.255.255.255"), "Alibaba Global"),
        (("172.0.0.0", "172.255.255.255"), "Alibaba Global"),
        (("173.0.0.0", "173.255.255.255"), "Alibaba Global"),
        (("175.0.0.0", "175.255.255.255"), "Alibaba Global"),
        (("180.0.0.0", "180.255.255.255"), "Alibaba Global"),
        (("182.0.0.0", "182.255.255.255"), "Alibaba Global"),
        (("183.0.0.0", "183.255.255.255"), "Alibaba Global"),
        (("185.0.0.0", "185.255.255.255"), "Alibaba Global"),
        (("192.0.0.0", "192.255.255.255"), "Alibaba Global"),
        (("198.0.0.0", "198.255.255.255"), "Alibaba Global"),
        (("202.0.0.0", "202.255.255.255"), "Alibaba Global"),
        (("203.0.0.0", "203.255.255.255"), "Alibaba Global"),
        (("205.0.0.0", "205.255.255.255"), "Alibaba Global"),
        (("206.0.0.0", "206.255.255.255"), "Alibaba Global"),
        (("207.0.0.0", "207.255.255.255"), "Alibaba Global"),
        (("208.0.0.0", "208.255.255.255"), "Alibaba Global"),
        (("209.0.0.0", "209.255.255.255"), "Alibaba Global"),
        (("210.0.0.0", "210.255.255.255"), "Alibaba Global"),
        (("211.0.0.0", "211.255.255.255"), "Alibaba Global"),
        (("212.0.0.0", "212.255.255.255"), "Alibaba Global"),
        (("213.0.0.0", "213.255.255.255"), "Alibaba Global"),
        (("218.0.0.0", "218.255.255.255"), "Alibaba Global"),
        (("219.0.0.0", "219.255.255.255"), "Alibaba Global"),
        (("220.0.0.0", "220.255.255.255"), "Alibaba Global"),
        (("221.0.0.0", "221.255.255.255"), "Alibaba Global"),
        (("222.0.0.0", "222.255.255.255"), "Alibaba Global"),
        (("223.0.0.0", "223.255.255.255"), "Alibaba Global"),
    ],
    "Scaleway": [
        (("51.15.0.0", "51.15.255.255"), "Scaleway France"),
        (("62.210.0.0", "62.210.255.255"), "Scaleway France"),
        (("163.172.0.0", "163.172.255.255"), "Scaleway France"),
        (("212.47.0.0", "212.47.255.255"), "Scaleway France"),
        (("195.154.0.0", "195.154.255.255"), "Scaleway France"),
    ],
}

def _ip_to_int(ip_str: str) -> int:
    parts = ip_str.split(".")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

def _check_ip_in_ranges(ip_str: str) -> list:
    try:
        ip_int = _ip_to_int(ip_str)
    except Exception:
        return []
    results = []
    for provider, ranges in CLOUD_PROVIDER_IP_RANGES.items():
        for (start_str, end_str), region in ranges:
            try:
                start_int = _ip_to_int(start_str)
                end_int = _ip_to_int(end_str)
                if start_int <= ip_int <= end_int:
                    results.append((provider, region))
                    break
            except Exception:
                continue
    return results

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    target = target.strip().lower()
    is_ip = False
    target_ip = target

    if target.startswith("http"):
        from urllib.parse import urlparse
        netloc = urlparse(target).netloc
        target = netloc.split(":")[0]

    try:
        import ipaddress
        ipaddress.ip_address(target)
        is_ip = True
        target_ip = target
    except ValueError:
        is_ip = False
        try:
            loop = asyncio.get_event_loop()
            target_ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(target))
            findings.append(make_finding(
                entity=target_ip,
                ftype="IP Resolution",
                source="CloudFingerprintDeep",
                confidence="High",
                color="slate",
                threat_level="Informational",
                resolution=target_ip,
                raw_data=f"{target} resolves to {target_ip}",
                tags=["dns", "resolution"]
            ))
        except Exception as e:
            findings.append(make_finding(
                entity=f"DNS resolution failed: {target}",
                ftype="DNS Error",
                source="CloudFingerprintDeep",
                confidence="Low",
                color="red",
                threat_level="Informational",
                raw_data=str(e)[:200],
                tags=["error"]
            ))
            return findings

    ip_range_findings = await _fetch_cloud_ip_ranges(target_ip, client)
    findings.extend(ip_range_findings)

    base = f"https://{target}"
    try:
        resp = await safe_fetch(client, base, follow_redirects=True, timeout=10.0,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        headers = dict(resp.headers)
        server = (headers.get("server") or "").lower()
        via = (headers.get("via") or "").lower()
        cf_ray = headers.get("cf-ray", "")
        amz_cf = headers.get("x-amz-cf-id", "")
        fastly = headers.get("x-fastly-request-id", "")
        x_powered = (headers.get("x-powered-by") or "").lower()

        all_header_vals = " ".join(str(v).lower() for v in headers.values())

        for sig, provider_name in CLOUD_SERVER_HEADERS.items():
            if sig in server or sig in via or sig in all_header_vals or sig in x_powered:
                if any(f.type == "Cloud Provider (Header)" and f.entity.startswith(provider_name) for f in findings):
                    continue
                findings.append(make_finding(
                    entity=f"{provider_name}",
                    ftype="Cloud Provider (Header)",
                    source="CloudFingerprintDeep",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Detected",
                    raw_data=f"Server/Via header contains '{sig}' -> {provider_name}",
                    tags=["cloud", provider_name.lower().replace(" ", "-")]
                ))

        if cf_ray:
            findings.append(make_finding(
                entity="Cloudflare",
                ftype="CDN Detected",
                source="CloudFingerprintDeep",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Active",
                resolution=f"cf-ray: {cf_ray}",
                raw_data=f"Cloudflare CDN detected via cf-ray header: {cf_ray}",
                tags=["cdn", "cloudflare"]
            ))

        if amz_cf:
            findings.append(make_finding(
                entity="AWS CloudFront",
                ftype="CDN Detected",
                source="CloudFingerprintDeep",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Active",
                resolution=f"x-amz-cf-id: {amz_cf}",
                raw_data="AWS CloudFront CDN detected",
                tags=["cdn", "aws", "cloudfront"]
            ))

        if fastly:
            findings.append(make_finding(
                entity="Fastly",
                ftype="CDN Detected",
                source="CloudFingerprintDeep",
                confidence="High",
                color="orange",
                threat_level="Informational",
                status="Active",
                raw_data="Fastly CDN detected",
                tags=["cdn", "fastly"]
            ))

        for cdn_key, cdn_info in CLOUD_CDN_HEADERS.items():
            if cdn_info["header"] in headers:
                findings.append(make_finding(
                    entity=cdn_info["name"],
                    ftype="CDN Detected",
                    source="CloudFingerprintDeep",
                    confidence="High",
                    color=cdn_info["color"],
                    threat_level="Informational",
                    status="Active",
                    raw_data=f"{cdn_info['name']} CDN detected via {cdn_info['header']} header",
                    tags=["cdn", cdn_key]
                ))

        x_robots = headers.get("x-robots-tag", "")
        if x_robots:
            findings.append(make_finding(
                entity=f"X-Robots-Tag: {x_robots[:100]}",
                ftype="Cloud Response Header",
                source="CloudFingerprintDeep",
                confidence="Medium",
                color="slate",
                threat_level="Informational",
                raw_data=x_robots[:500],
                tags=["header"]
            ))

        if "x-amz-" in all_header_vals or "aws" in all_header_vals:
            findings.append(make_finding(
                entity="AWS",
                ftype="Cloud Provider (Header)",
                source="CloudFingerprintDeep",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status="Suspected",
                raw_data="AWS-specific headers detected",
                tags=["cloud", "aws"]
            ))

        if "google" in all_header_vals or "gfe" in server:
            findings.append(make_finding(
                entity="Google Cloud / GFE",
                ftype="Cloud Provider (Header)",
                source="CloudFingerprintDeep",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status="Suspected",
                raw_data="Google Cloud / GFE detected",
                tags=["cloud", "gcp"]
            ))

        if "azure" in all_header_vals or "x-ms-" in all_header_vals:
            findings.append(make_finding(
                entity="Microsoft Azure",
                ftype="Cloud Provider (Header)",
                source="CloudFingerprintDeep",
                confidence="Medium",
                color="orange",
                threat_level="Informational",
                status="Suspected",
                raw_data="Azure-specific headers detected",
                tags=["cloud", "azure"]
            ))

    except Exception as e:
        findings.append(make_finding(
            entity=f"Header analysis error: {str(e)[:100]}",
            ftype="Cloud Fingerprint Error",
            source="CloudFingerprintDeep",
            confidence="Low",
            color="red",
            threat_level="Informational",
            raw_data=str(e)[:200],
            tags=["error"]
        ))

    try:
        txt_records = []
        loop = asyncio.get_event_loop()
        import dns.resolver
        try:
            resp_txt = await loop.run_in_executor(None, lambda: dns.resolver.resolve(target, 'TXT'))
            txt_records = [str(r) for r in resp_txt]
        except Exception:
            pass

        txt_combined = " ".join(txt_records).lower()
        for provider_key, provider_name in [("google-site-verification", "Google Cloud"),
                                              ("ms=ms", "Microsoft"),
                                              ("atlassian-domain-verification", "Atlassian/Cloud"),
                                              ("cloudflare-verification", "Cloudflare"),
                                              ("mailru-verification", "Mail.ru"),
                                              ("yandex-verification", "Yandex"),
                                              ("facebook-domain-verification", "Facebook"),
                                              ("amazonses", "AWS SES"),
                                              ("spf", "Email Security"),
                                              ("_globalsign", "GlobalSign"),
                                              ("docusign", "DocuSign"),
                                              ("stripe", "Stripe"),
                                              ("heroku", "Heroku"),
                                              ("google-site-verification", "Google Workspace"),
                                              ("onetrust-domain-verification", "OneTrust"),
                                              ("statuspage-domain-verification", "Statuspage"),
                                              ("atlassian-sending-domain", "Atlassian Email"),
                                              ("sendgrid", "SendGrid"),
                                              ("mailgun", "Mailgun"),
                                              ("zendesk", "Zendesk"),
                                              ("intercom", "Intercom"),
                                              ("notion", "Notion"),
                                              ("midomain", "Microsoft 365"),
                                              ("apple-domain-verification", "Apple")]:
            if provider_key in txt_combined:
                findings.append(make_finding(
                    entity=f"{provider_name}",
                    ftype="Cloud Provider (DNS TXT)",
                    source="CloudFingerprintDeep",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Verified",
                    raw_data=f"DNS TXT record contains '{provider_key}'",
                    tags=["cloud", "dns", provider_name.lower().replace(" ", "-")]
                ))

        try:
            resp_spf = await loop.run_in_executor(None, lambda: dns.resolver.resolve(target, 'TXT'))
            for r in resp_spf:
                txt = str(r)
                if "include:" in txt:
                    includes = re.findall(r'include:(\S+)', txt)
                    for inc in includes:
                        inc_lower = inc.lower()
                        for cloud_key, cloud_name in [("spf.protection.outlook.com", "Microsoft 365"),
                                                       ("aspmx.p01.dynect.net", "Oracle Cloud"),
                                                       ("_spf.google.com", "Google Workspace"),
                                                       ("servers.mcsv.net", "Mailchimp"),
                                                       ("spf.mtasv.net", "Mailgun"),
                                                       ("spf.sendgrid.net", "SendGrid"),
                                                       ("spf.mandrillapp.com", "Mandrill"),
                                                       ("amazonses.com", "AWS"),
                                                       ("mail.zendesk.com", "Zendesk"),
                                                       ("spf.ess.barracudanetworks.com", "Barracuda"),
                                                       ("spf.proofpoint.com", "Proofpoint"),
                                                       ("spf.mailjet.com", "Mailjet"),
                                                       ("spf.postmarkapp.com", "Postmark"),
                                                       ("mailgun.org", "Mailgun"),
                                                       ("spf.hostedemail.com", "Open-Xchange")]:
                            if cloud_key in inc_lower:
                                findings.append(make_finding(
                                    entity=f"{cloud_name}",
                                    ftype="Cloud Service (SPF Include)",
                                    source="CloudFingerprintDeep",
                                    confidence="High",
                                    color="blue",
                                    threat_level="Informational",
                                    status="Verified",
                                    raw_data=f"SPF include: {inc}",
                                    tags=["cloud", "email", cloud_name.lower().replace(" ", "-")]
                                ))
        except Exception:
            pass

    except Exception:
        pass

    try:
        cname_targets = []
        try:
            resp_cname = await loop.run_in_executor(None, lambda: dns.resolver.resolve(target, 'CNAME'))
            cname_targets = [str(r.target).rstrip('.') for r in resp_cname]
        except Exception:
            pass

        ns_targets = []
        try:
            resp_ns = await loop.run_in_executor(None, lambda: dns.resolver.resolve(target, 'NS'))
            ns_targets = [str(r.target).rstrip('.') for r in resp_ns]
        except Exception:
            pass

        all_dns = cname_targets + ns_targets

        for dns_target in all_dns:
            dt = dns_target.lower()

            for pattern, provider_name in CLOUD_STORAGE_PATTERNS.items():
                if pattern in dt:
                    findings.append(make_finding(
                        entity=f"{provider_name}",
                        ftype="Cloud Storage (DNS)",
                        source="CloudFingerprintDeep",
                        confidence="High",
                        color="orange",
                        threat_level="Elevated Risk",
                        status="Detected",
                        resolution=dns_target,
                        raw_data=f"DNS target: {dns_target} matches {pattern}",
                        tags=["cloud", "storage"]
                    ))

            for paas_pattern, paas_name in [("herokuapp.com", "Heroku"),
                                             ("vercel.app", "Vercel"),
                                             ("netlify.app", "Netlify"),
                                             ("onrender.com", "Render"),
                                             ("railway.app", "Railway"),
                                             ("fly.dev", "Fly.io"),
                                             ("pages.dev", "Cloudflare Pages"),
                                             ("azurewebsites.net", "Azure App Service"),
                                             ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
                                             ("firebaseapp.com", "Firebase"),
                                             ("withgoogle.com", "Google Cloud"),
                                             ("appspot.com", "Google App Engine"),
                                             ("compute.amazonaws.com", "AWS EC2"),
                                             ("amazonaws.com", "AWS"),
                                             ("trafficmanager.net", "Azure Traffic Manager"),
                                             ("cloudapp.net", "Azure Cloud Services"),
                                             ("dnsalias.com", "Azure DNS Alias"),
                                             ("dnsabr.com", "Azure DNS"),
                                             ("azureedge.net", "Azure CDN"),
                                             ("azurefd.net", "Azure Front Door"),
                                             ("akamaiedge.net", "Akamai"),
                                             ("akamaiedge-staging.net", "Akamai Staging"),
                                             ("edgesuite.net", "Akamai"),
                                             ("edgekey.net", "Akamai"),
                                             ("fastly.net", "Fastly"),
                                             ("fastlylb.net", "Fastly Load Balancer"),
                                             ("mfly.dev", "Fly.io"),
                                             ("pages.dev", "Cloudflare Pages"),
                                             ("workers.dev", "Cloudflare Workers"),
                                             ("r2.dev", "Cloudflare R2"),
                                             ("b-cdn.net", "BunnyCDN"),
                                             ("bunnycdn.com", "BunnyCDN"),
                                             ("kxcdn.com", "KeyCDN"),
                                             ("pantheonsite.io", "Pantheon"),
                                             ("wpengine.com", "WP Engine"),
                                             ("flywheelsites.com", "Flywheel"),
                                             ("kinsta.com", "Kinsta"),
                                             ("liquidweb.com", "Liquid Web")]:
                if paas_pattern in dt:
                    findings.append(make_finding(
                        entity=f"{paas_name}",
                        ftype="PaaS Platform (DNS)",
                        source="CloudFingerprintDeep",
                        confidence="High",
                        color="purple",
                        threat_level="Informational",
                        status="Detected",
                        resolution=dns_target,
                        raw_data=f"DNS to {paas_name}: {dns_target}",
                        tags=["cloud", "paas", paas_name.lower().replace(" ", "-")]
                    ))

            if any(asn_keyword in dt for asn_keyword in ["amazonaws", "cloudfront", "azure", "google", "gcp", "gce"]):
                findings.append(make_finding(
                    entity=f"Cloud-associated DNS record: {dt[:80]}",
                    ftype="DNS Cloud Indicator",
                    source="CloudFingerprintDeep",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["dns", "cloud"]
                ))
    except Exception:
        pass

    cloud_providers = set(f.entity for f in findings if "Cloud Provider" in f.type)
    cdns = set(f.entity for f in findings if f.type == "CDN Detected")
    if cloud_providers or cdns:
        providers_str = ", ".join(cloud_providers) if cloud_providers else "None"
        cdns_str = ", ".join(cdns) if cdns else "None"
        findings.append(make_finding(
            entity=f"Cloud Providers: {providers_str} | CDNs: {cdns_str}",
            ftype="Cloud Fingerprint Summary",
            source="CloudFingerprintDeep",
            confidence="High",
            color="purple",
            threat_level="Informational",
            status="Complete",
            raw_data=f"Providers: {providers_str}, CDNs: {cdns_str}",
            tags=["cloud", "summary"]
        ))

    return findings

EXTRA_CLOUD_IP_RANGES = {
    "Vercel": [
        (("76.76.21.0", "76.76.21.255"), "Vercel Edge"),
        (("76.76.21.0", "76.76.21.255"), "Vercel Global"),
    ],
    "Netlify": [
        (("75.2.0.0", "75.2.255.255"), "Netlify Global"),
        (("99.83.0.0", "99.83.255.255"), "Netlify Global"),
        (("104.16.0.0", "104.16.255.255"), "Netlify Global"),
    ],
    "Fly.io": [
        (("37.16.0.0", "37.16.15.255"), "Fly.io Global"),
        (("46.243.0.0", "46.243.31.255"), "Fly.io Global"),
    ],
    "Render": [
        (("13.48.0.0", "13.48.255.255"), "Render Stockholm"),
        (("13.49.0.0", "13.49.255.255"), "Render Stockholm"),
        (("16.16.0.0", "16.16.255.255"), "Render Frankfurt"),
    ],
    "Railway": [
        (("34.22.0.0", "34.22.255.255"), "Railway Global"),
        (("140.238.0.0", "140.238.255.255"), "Railway Global"),
    ],
    "Supabase": [
        (("44.192.0.0", "44.192.255.255"), "Supabase US"),
        (("54.197.0.0", "54.197.255.255"), "Supabase US"),
        (("54.237.0.0", "54.237.255.255"), "Supabase US"),
    ],
    "Cloudflare": [
        (("103.21.244.0", "103.21.247.255"), "Cloudflare"),
        (("103.22.200.0", "103.22.203.255"), "Cloudflare"),
        (("103.31.4.0", "103.31.7.255"), "Cloudflare"),
        (("104.16.0.0", "104.31.255.255"), "Cloudflare"),
        (("108.162.192.0", "108.162.255.255"), "Cloudflare"),
        (("131.0.72.0", "131.0.75.255"), "Cloudflare"),
        (("141.101.64.0", "141.101.127.255"), "Cloudflare"),
        (("162.158.0.0", "162.159.255.255"), "Cloudflare"),
        (("172.64.0.0", "172.71.255.255"), "Cloudflare"),
        (("173.245.48.0", "173.245.63.255"), "Cloudflare"),
        (("188.114.96.0", "188.114.127.255"), "Cloudflare"),
        (("190.93.240.0", "190.93.255.255"), "Cloudflare"),
        (("197.234.240.0", "197.234.243.255"), "Cloudflare"),
        (("198.41.128.0", "198.41.255.255"), "Cloudflare"),
    ],
    "Akamai": [
        (("2.16.0.0", "2.23.255.255"), "Akamai"),
        (("23.0.0.0", "23.79.255.255"), "Akamai"),
        (("23.192.0.0", "23.223.255.255"), "Akamai"),
        (("23.235.0.0", "23.235.127.255"), "Akamai"),
        (("23.236.0.0", "23.241.255.255"), "Akamai"),
        (("23.246.0.0", "23.255.255.255"), "Akamai"),
        (("63.98.0.0", "63.98.255.255"), "Akamai"),
        (("64.14.0.0", "64.15.255.255"), "Akamai"),
        (("65.197.0.0", "65.198.255.255"), "Akamai"),
        (("69.28.0.0", "69.29.255.255"), "Akamai"),
        (("72.246.0.0", "72.255.255.255"), "Akamai"),
        (("88.221.0.0", "88.221.255.255"), "Akamai"),
        (("92.122.0.0", "92.123.255.255"), "Akamai"),
        (("95.100.0.0", "95.101.255.255"), "Akamai"),
        (("104.64.0.0", "104.127.255.255"), "Akamai"),
        (("173.222.0.0", "173.223.255.255"), "Akamai"),
        (("184.24.0.0", "184.31.255.255"), "Akamai"),
        (("184.50.0.0", "184.51.255.255"), "Akamai"),
        (("184.84.0.0", "184.87.255.255"), "Akamai"),
    ],
    "Fastly": [
        (("23.235.32.0", "23.235.63.255"), "Fastly"),
        (("104.156.80.0", "104.156.95.255"), "Fastly"),
        (("146.75.0.0", "146.75.255.255"), "Fastly"),
        (("151.101.0.0", "151.101.255.255"), "Fastly"),
        (("172.111.64.0", "172.111.127.255"), "Fastly"),
        (("185.31.16.0", "185.31.19.255"), "Fastly"),
        (("199.27.72.0", "199.27.79.255"), "Fastly"),
    ],
    "BunnyCDN": [
        (("185.93.0.0", "185.93.15.255"), "BunnyCDN"),
        (("213.227.152.0", "213.227.159.255"), "BunnyCDN"),
        (("178.175.128.0", "178.175.143.255"), "BunnyCDN"),
    ],
    "KeyCDN": [
        (("62.210.0.0", "62.210.255.255"), "KeyCDN"),
        (("163.172.0.0", "163.172.255.255"), "KeyCDN"),
    ],
}

async def _check_ip_in_ranges_extra(ip_str: str) -> list:
    try:
        ip_int = _ip_to_int(ip_str)
    except Exception:
        return []
    results = []
    for provider, ranges in EXTRA_CLOUD_IP_RANGES.items():
        for (start_str, end_str), region in ranges:
            try:
                start_int = _ip_to_int(start_str)
                end_int = _ip_to_int(end_str)
                if start_int <= ip_int <= end_int:
                    results.append((provider, region))
                    break
            except Exception:
                continue
    return results

async def _fetch_cloud_ip_ranges(target_ip: str, client: httpx.AsyncClient) -> list:
    findings = []
    try:
        providers_found = _check_ip_in_ranges(target_ip)
        extra_found = await _check_ip_in_ranges_extra(target_ip)
        all_found = providers_found + extra_found
        seen = set()
        for provider, region in all_found:
            key = f"{provider}-{region}"
            if key not in seen:
                seen.add(key)
                findings.append(make_finding(
                    entity=f"{provider} ({region})",
                    ftype="Cloud Provider (IP Range)",
                    source="CloudFingerprintDeep",
                    confidence="High",
                    color="orange",
                    threat_level="Informational",
                    status="Verified",
                    resolution=target_ip,
                    raw_data=f"IP {target_ip} is in {provider} range ({region})",
                    tags=["cloud", provider.lower().replace(" ", "-")]
                ))
    except Exception:
        pass
    return findings
