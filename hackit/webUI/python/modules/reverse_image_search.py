import httpx
import re
import base64
import struct
import io
import json
from models import IntelligenceFinding
from urllib.parse import urljoin, urlparse

IMG_TAG_REGEX = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
CSS_BG_REGEX = re.compile(r'background(?:-image)?:\s*url\(["\']?([^"\')]+)["\']?\)', re.IGNORECASE)
META_OG_IMAGE = re.compile(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
META_OG_SECURE_IMAGE = re.compile(r'<meta[^>]+property=["\']og:image:secure_url["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
META_TWITTER_IMAGE = re.compile(r'<meta[^>]+name=["\']twitter:image["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
FAVICON_REGEX = re.compile(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
PICTURE_SOURCE_REGEX = re.compile(r'<source[^>]+srcset=["\']([^"\']+)["\']', re.IGNORECASE)
PICTURE_SRC_REGEX = re.compile(r'<picture[^>]*>.*?<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
VIDEO_POSTER_REGEX = re.compile(r'<video[^>]+poster=["\']([^"\']+)["\']', re.IGNORECASE)
PRELOAD_IMAGE_REGEX = re.compile(r'<link[^>]+rel=["\']preload["\'][^>]+as=["\']image["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
APPLE_TOUCH_ICON_REGEX = re.compile(r'<link[^>]+rel=["\']apple-touch-icon(?:-precomposed)?["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
INLINE_SVG_REGEX = re.compile(r'<svg[^>]*>(.*?)</svg>', re.IGNORECASE | re.DOTALL)
JSON_LD_REGEX = re.compile(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)

STOCK_WATERMARKS = [
    "gettyimages", "shutterstock", "istockphoto", "123rf", "dreamstime",
    "alamy", "depositphotos", "canstockphoto", "bigstock", "fotolia",
    "pond5", "vecteezy", "envato", "unsplash", "pexels", "pixabay",
    "adobestock", "stock.adobe.com", "freepik", "vectorstock", "canva",
    "creativemarket", "graphicriver", "themeforest", "photodune",
    "smugmug", "500px", "eyeem", "twenty20", "stocksy",
    "offset", "shutterstock-editorial", "dissolve", "naturepl",
    "rawpixel", "kisspng", "pngtree", "cleanpng", "pngwing",
    "nicepng", "imgbin", "pngaaa", "pngguru", "seekpng",
    "pngfind", "pngkey", "pngio", "pngwave", "pngitem",
    "vippng", "kindpng", "pngplay", "toppng", "clipartkey",
    "clipartmax", "clipartmag", "webstockreview", "netclipart",
    "pinclipart", "freepngimg", "pngmart", "iconfinder",
    "flaticon", "icons8", "iconarchive", "icon-icons",
    "thenounproject", "svgrepo", "game-icons", "orionicon",
    "jam-icons", "tabler-icons", "heroicons", "feather-icons",
    "boxicons", "css.gg", "phosphoricons", "remixicon",
    "fontawesome", "font-awesome", "material-icons",
    "materialdesignicons", "simpleicons", "devicons",
]

OUTDATED_FORMATS = {"image/gif": "GIF (outdated, limited colors)", "image/vnd.microsoft.icon": "ICO"}

CDN_DOMAINS = {
    "cloudfront.net": "AWS CloudFront",
    "cloudinary.com": "Cloudinary",
    "imgix.net": "imgix",
    "akamai.net": "Akamai",
    "akamaiedge.net": "Akamai",
    "fastly.net": "Fastly",
    "fastlylb.net": "Fastly",
    "cloudflare.com": "Cloudflare",
    "cloudflare.net": "Cloudflare",
    "kxcdn.com": "KeyCDN",
    "stackpathcdn.com": "StackPath",
    "bootstrapcdn.com": "BootstrapCDN",
    "cdnjs.cloudflare.com": "cdnjs",
    "jsdelivr.net": "jsdelivr",
    "unpkg.com": "unpkg",
    "kaggle.com": "Kaggle",
    "githubusercontent.com": "GitHub Raw",
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "bitbucket.org": "Bitbucket",
    "pbs.twimg.com": "Twitter Media",
    "media.tumblr.com": "Tumblr Media",
    "staticflickr.com": "Flickr",
    "live.staticflickr.com": "Flickr Live",
    "images.unsplash.com": "Unsplash",
    "i.imgur.com": "Imgur",
    "cdn.pixabay.com": "Pixabay CDN",
    "cdn.pexels.com": "Pexels CDN",
    "media.istockphoto.com": "iStockphoto",
    "previews.123rf.com": "123RF",
    "thumbs.dreamstime.com": "Dreamstime",
    "c8.alamy.com": "Alamy",
    "st.depositphotos.com": "Depositphotos",
    "static.vecteezy.com": "Vecteezy",
    "s3.amazonaws.com": "AWS S3",
    "s3.us-east-2.amazonaws.com": "AWS S3 (us-east-2)",
    "s3-us-west-1.amazonaws.com": "AWS S3 (us-west-1)",
    "storage.googleapis.com": "GCP Storage",
    "firebasestorage.googleapis.com": "Firebase Storage",
    "blob.core.windows.net": "Azure Blob",
    "digitaloceanspaces.com": "DigitalOcean Spaces",
    "images.ctfassets.net": "Contentful",
    "images.prismic.io": "Prismic",
    "cdn.sanity.io": "Sanity CDN",
    "cdn.builder.io": "Builder.io CDN",
    "strapi.io": "Strapi",
    "cms.imgix.net": "imgix CMS",
    "cdn-images-1.medium.com": "Medium",
    "miro.medium.com": "Medium Miro",
    "static.wixstatic.com": "Wix Static",
    "images.squarespace-cdn.com": "Squarespace",
    "cdn.shopify.com": "Shopify CDN",
    "cdn.awsli.com.br": "AWS Lojas CDN",
}

STOCK_WATERMARK_FILENAME_PATTERNS = [
    r'stock[\-_]?(?:photo|image|vector|illustration)',
    r'gettyimages?',
    r'shutterstock',
    r'istock',
    r'123rf',
    r'dreamstime',
    r'alamy',
    r'depositphotos',
]

EXIF_ORIENTATIONS = {
    1: "Normal", 2: "Mirror horizontal", 3: "Rotate 180",
    4: "Mirror vertical", 5: "Mirror horizontal + rotate 270",
    6: "Rotate 90", 7: "Mirror horizontal + rotate 90", 8: "Rotate 270",
}

GPS_COORD_REGEX = re.compile(r'(\d+)[°d]\s*(\d+)[\'m]\s*([\d.]+)[\"s]?\s*([NSEW])', re.IGNORECASE)

FACE_INDICATORS = {
    "alt": ["ceo", "founder", "team", "portrait", "headshot", "staff", "employee",
            "person", "people", "face", "profile", "user", "avatar", "author",
            "speaker", "host", "presenter", "model", "actor", "actress", "customer"],
    "filename": ["ceo", "founder", "portrait", "headshot", "team", "staff",
                 "face", "avatar", "profile", "person", "people", "author"],
}

def parse_gps(gps_str):
    m = re.search(GPS_COORD_REGEX, gps_str)
    if m:
        deg, minute, sec, direction = m.groups()
        decimal = float(deg) + float(minute) / 60 + float(sec or 0) / 3600
        if direction in ("S", "W"):
            decimal = -decimal
        return f"{decimal}° {direction}"
    return gps_str

def extract_exif_info(image_data):
    info = {}
    exif_libs = []

    try:
        from PIL import Image as PILImage
        from PIL.ExifTags import TAGS, GPSTAGS
        exif_libs.append(("PIL", PILImage, TAGS, GPSTAGS))
    except ImportError:
        pass

    try:
        import exifread
        exif_libs.append(("exifread", exifread, None, None))
    except ImportError:
        pass

    try:
        import piexif
        exif_libs.append(("piexif", piexif, None, None))
    except ImportError:
        pass

    if not exif_libs:
        return {"exif": "Not available (PIL/exifread/piexif not installed)"}

    for lib_name, lib, tags, gps_tags in exif_libs:
        try:
            if lib_name == "PIL":
                img = PILImage.open(io.BytesIO(image_data))
                exif_data = img._getexif()
                if exif_data:
                    for tag_id, value in exif_data.items():
                        tag_name = tags.get(tag_id, tag_id)
                        if tag_name == "GPSInfo":
                            for gps_tag, gps_value in value.items():
                                gps_name = gps_tags.get(gps_tag, gps_tag)
                                info[f"GPS_{gps_name}"] = str(gps_value)
                        elif tag_name in ("Make", "Model", "Software", "DateTime", "Artist", "Copyright", "Orientation", "ImageDescription", "XResolution", "YResolution"):
                            info[tag_name] = str(value)
                if info:
                    return info

            elif lib_name == "exifread":
                tags = lib.process_file(io.BytesIO(image_data), details=False)
                for tag_name, tag_value in tags.items():
                    if "GPS" in tag_name:
                        info[tag_name] = str(tag_value)
                    elif tag_name in ("Image Make", "Image Model", "Image Software", "Image DateTime", "Image Artist", "Image Copyright"):
                        info[tag_name] = str(tag_value)
                if info:
                    return info

            elif lib_name == "piexif":
                exif_dict = lib.load(image_data)
                if exif_dict:
                    for ifd_name, ifd_data in exif_dict.items():
                        if isinstance(ifd_data, dict):
                            for tag_id, value in ifd_data.items():
                                try:
                                    tag_name = lib.ExifTags[ifd_name][tag_id] if ifd_name in lib.ExifTags and tag_id in lib.ExifTags[ifd_name] else str(tag_id)
                                except Exception:
                                    tag_name = str(tag_id)
                                if "GPS" in ifd_name or "gps" in tag_name.lower():
                                    info[f"GPS_{tag_name}"] = str(value)
                                elif tag_name in ("Make", "Model", "Software", "DateTime", "Artist", "Copyright", "Orientation", "ImageDescription"):
                                    info[tag_name] = str(value)
                if info:
                    return info

        except Exception:
            continue

    return info

def extract_image_dimensions(image_data):
    try:
        from PIL import Image as PILImage
        img = PILImage.open(io.BytesIO(image_data))
        w, h = img.size
        ratio = round(w / h, 2) if h > 0 else 0
        return {"width": w, "height": h, "aspect_ratio": str(ratio), "orientation": "Landscape" if w > h else "Portrait" if h > w else "Square"}
    except ImportError:
        pass
    except Exception:
        pass

    try:
        if image_data[:8] == b'\x89PNG\r\n\x1a\n':
            w, h = struct.unpack('>II', image_data[16:24])
            return {"width": w, "height": h, "aspect_ratio": str(round(w / h, 2)) if h else "0", "orientation": "Landscape" if w > h else "Portrait" if h > w else "Square"}
        if image_data[:2] == b'\xff\xd8':
            data = image_data
            i = 2
            while i < len(data) - 1:
                if data[i] != 0xFF:
                    break
                marker = data[i+1]
                if marker in (0xC0, 0xC1, 0xC2):
                    h, w = struct.unpack('>HH', data[i+5:i+9])
                    return {"width": w, "height": h, "aspect_ratio": str(round(w / h, 2)) if h else "0", "orientation": "Landscape" if w > h else "Portrait" if h > w else "Square"}
                i += 2
                if marker in (0xD9, 0xDA):
                    break
                length = struct.unpack('>H', data[i:i+2])[0]
                i += length
        if image_data[:4] == b'RIFF' and image_data[8:12] == b'WEBP':
            if image_data[12:16] == b'VP8 ':
                w, h = struct.unpack('<HH', image_data[26:30])
                w &= 0x3FFF
                h &= 0x3FFF
                return {"width": w, "height": h, "aspect_ratio": str(round(w / h, 2)) if h else "0", "orientation": "Landscape" if w > h else "Portrait" if h > w else "Square"}
            if image_data[12:16] == b'VP8L':
                bits = image_data[21:25]
                val = struct.unpack('<I', bits)[0]
                w = (val & 0x3FFF) + 1
                h = ((val >> 14) & 0x3FFF) + 1
                return {"width": w, "height": h, "aspect_ratio": str(round(w / h, 2)) if h else "0", "orientation": "Landscape" if w > h else "Portrait" if h > w else "Square"}
    except Exception:
        pass
    return None

def detect_image_format(image_data, content_type=""):
    sig_map = {
        b'\xff\xd8\xff': "JPEG",
        b'\x89PNG\r\n\x1a\n': "PNG",
        b'GIF87a': "GIF",
        b'GIF89a': "GIF",
        b'RIFF': "WebP",
        b'<svg': "SVG",
        b'\x00\x00\x00\x20ftyp': "AVIF",
        b'\x00\x00\x00\x1cftyp': "AVIF",
    }
    for sig, fmt in sig_map.items():
        if image_data[:len(sig)] == sig or (sig == b'<svg' and image_data[:4].lower() == b'<svg'):
            return fmt
        if fmt == "WebP" and image_data[:4] == b'RIFF' and image_data[8:12] == b'WEBP':
            return "WebP"
        if fmt == "AVIF" and b'ftyp' in image_data[4:12] and b'avif' in image_data[4:20].lower():
            return "AVIF"
    if content_type:
        ct_map = {
            "image/jpeg": "JPEG", "image/png": "PNG", "image/gif": "GIF",
            "image/webp": "WebP", "image/avif": "AVIF", "image/svg+xml": "SVG",
            "image/x-icon": "ICO", "image/vnd.microsoft.icon": "ICO",
        }
        return ct_map.get(content_type.lower(), f"Unknown ({content_type})")
    if b'<svg' in image_data[:200].lower():
        return "SVG"
    return "Unknown"

def check_tracking_pixel(image_data, dimensions):
    if dimensions and dimensions.get("width") == 1 and dimensions.get("height") == 1:
        return True
    if len(image_data) < 500:
        return True
    return False

def detect_face_indicators(url, alt_text=""):
    url_lower = url.lower()
    alt_lower = alt_text.lower()
    filename = url_lower.split("/")[-1].split("?")[0]
    for keyword in FACE_INDICATORS["alt"]:
        if keyword in alt_lower:
            return True
    for keyword in FACE_INDICATORS["filename"]:
        if keyword in filename:
            return True
    return False

def detect_cdn(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    for domain, cdn_name in CDN_DOMAINS.items():
        if domain in hostname:
            return cdn_name
    return None

def classify_image_type(url, src_page):
    url_lower = url.lower()
    if "logo" in url_lower:
        return "Logo"
    if "avatar" in url_lower or "profile" in url_lower:
        return "Profile/Avatar"
    if "banner" in url_lower or "hero" in url_lower:
        return "Banner"
    if "icon" in url_lower or "favicon" in url_lower:
        return "Icon"
    if "screenshot" in url_lower:
        return "Screenshot"
    if "thumbnail" in url_lower:
        return "Thumbnail"
    if "bg" in url_lower or "background" in url_lower:
        return "Background"
    return "Content Image"

def extract_jsonld_images(html):
    images = []
    for m in JSON_LD_REGEX.finditer(html):
        try:
            data = json.loads(m.group(1))
            if isinstance(data, dict):
                for key in ("logo", "image", "thumbnailUrl"):
                    val = data.get(key)
                    if isinstance(val, str) and val.startswith("http"):
                        images.append(val)
                    elif isinstance(val, dict):
                        for sub_key in ("url", "contentUrl", "identifier"):
                            sub_val = val.get(sub_key)
                            if isinstance(sub_val, str) and sub_val.startswith("http"):
                                images.append(sub_val)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        for key in ("logo", "image", "thumbnailUrl"):
                            val = item.get(key)
                            if isinstance(val, str) and val.startswith("http"):
                                images.append(val)
        except json.JSONDecodeError:
            pass
    return images

def extract_inline_svg_data(html):
    findings_info = []
    for i, m in enumerate(INLINE_SVG_REGEX.finditer(html)):
        svg_content = m.group(1)
        has_image = 'href=' in svg_content or 'xlink:href=' in svg_content
        if has_image:
            refs = re.findall(r'(?:href|xlink:href)=["\']([^"\']+)["\']', svg_content)
            for ref in refs:
                if ref.startswith("data:image/") or ref.startswith("http"):
                    findings_info.append(f"Inline SVG #{i} references: {ref[:100]}")
        else:
            dim_w = re.search(r'width=["\'](\d+)["\']', svg_content)
            dim_h = re.search(r'height=["\'](\d+)["\']', svg_content)
            size_info = ""
            if dim_w and dim_h:
                size_info = f" ({dim_w.group(1)}x{dim_h.group(1)})"
            findings_info.append(f"Inline SVG #{i}{size_info}")
    return findings_info

def parse_srcset(srcset_str):
    urls = []
    for part in srcset_str.split(","):
        part = part.strip()
        if part:
            url_part = part.split()[0] if part.split() else part
            if url_part.startswith("http") or url_part.startswith("//") or url_part.startswith("/") or "." in url_part:
                urls.append(url_part)
    return urls

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        html = resp.text
        image_urls = []
        image_alt_map = {}

        for m in IMG_TAG_REGEX.finditer(html):
            url = m.group(1)
            image_urls.append(url)
            alt_match = re.search(r'alt=["\']([^"\']*)["\']', m.group(0))
            if alt_match:
                image_alt_map[url] = alt_match.group(1)

        for m in CSS_BG_REGEX.finditer(html):
            image_urls.append(m.group(1))

        for m in META_OG_IMAGE.finditer(html):
            image_urls.append(m.group(1))

        for m in META_OG_SECURE_IMAGE.finditer(html):
            image_urls.append(m.group(1))

        for m in META_TWITTER_IMAGE.finditer(html):
            image_urls.append(m.group(1))

        for m in FAVICON_REGEX.finditer(html):
            image_urls.append(m.group(1))

        for m in PICTURE_SOURCE_REGEX.finditer(html):
            srcset = m.group(1)
            image_urls.extend(parse_srcset(srcset))

        for m in PICTURE_SRC_REGEX.finditer(html):
            image_urls.append(m.group(1))

        for m in VIDEO_POSTER_REGEX.finditer(html):
            image_urls.append(m.group(1))

        for m in PRELOAD_IMAGE_REGEX.finditer(html):
            image_urls.append(m.group(1))

        for m in APPLE_TOUCH_ICON_REGEX.finditer(html):
            image_urls.append(m.group(1))

        jsonld_images = extract_jsonld_images(html)
        image_urls.extend(jsonld_images)

        inline_svg_info = extract_inline_svg_data(html)
        for svg_info in inline_svg_info:
            findings.append(IntelligenceFinding(
                entity=svg_info[:200],
                type="Image Found - Inline SVG",
                source="ReverseImageSearch",
                confidence="High",
                color="blue",
                threat_level="Informational",
                raw_data=svg_info,
                tags=["image", "inline-svg"]
            ))

        seen = set()
        absolute_urls = []
        for img_url in image_urls:
            img_url = img_url.strip().strip('"').strip("'")
            if img_url.startswith("//"):
                img_url = "https:" + img_url
            elif img_url.startswith("/"):
                img_url = urljoin(base_url, img_url)
            elif not img_url.startswith("http"):
                img_url = urljoin(base_url, img_url)
            if img_url not in seen and base_url.split("//")[1].split("/")[0] in img_url:
                seen.add(img_url)
                absolute_urls.append(img_url)

        for img_url in absolute_urls[:15]:
            alt_text = image_alt_map.get(img_url, "")
            img_type = classify_image_type(img_url, base_url)
            findings.append(IntelligenceFinding(
                entity=img_url[:200],
                type=f"Image Found - {img_type}",
                source="ReverseImageSearch",
                confidence="High",
                color="blue",
                threat_level="Informational",
                raw_data=f"Image URL: {img_url} | Type: {img_type}",
                tags=["image", img_type.lower().replace("/", "-")]
            ))

            try:
                img_resp = await client.get(img_url, timeout=10.0,
                    headers={"User-Agent": "Mozilla/5.0"})
                if img_resp.status_code == 200 and len(img_resp.content) > 1000:
                    image_data = img_resp.content
                    content_type = img_resp.headers.get("content-type", "")
                    exif_info = extract_exif_info(image_data)

                    if exif_info:
                        for exif_key, exif_val in exif_info.items():
                            if exif_key != "exif":
                                findings.append(IntelligenceFinding(
                                    entity=f"{exif_key}: {str(exif_val)[:100]}",
                                    type="Image EXIF Metadata",
                                    source="ReverseImageSearch",
                                    confidence="High",
                                    color="orange",
                                    threat_level="Informational",
                                    raw_data=f"EXIF {exif_key}: {exif_val}",
                                    tags=["exif", "metadata"]
                                ))

                        gps_keys = [k for k in exif_info if "GPS" in k]
                        if gps_keys:
                            gps_str = "; ".join(f"{k}={v}" for k, v in exif_info.items() if "GPS" in k)
                            findings.append(IntelligenceFinding(
                                entity=f"GPS data found: {gps_str[:150]}",
                                type="Image GPS Location",
                                source="ReverseImageSearch",
                                confidence="High",
                                color="red",
                                threat_level="Elevated Risk",
                                raw_data=gps_str[:500],
                                tags=["exif", "gps", "privacy"]
                            ))

                    dimensions = extract_image_dimensions(image_data)
                    if dimensions:
                        dim_str = f"{dimensions['width']}x{dimensions['height']} ({dimensions['orientation']}, ratio {dimensions['aspect_ratio']})"
                        findings.append(IntelligenceFinding(
                            entity=f"Image dimensions: {dim_str}",
                            type="Image Dimensions",
                            source="ReverseImageSearch",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"Width: {dimensions['width']} | Height: {dimensions['height']} | Aspect Ratio: {dimensions['aspect_ratio']} | Orientation: {dimensions['orientation']}",
                            tags=["image", "dimensions"]
                        ))

                    img_format = detect_image_format(image_data, content_type)
                    format_tags = ["image-format", img_format.lower()]
                    is_outdated = img_format in ("GIF", "ICO")
                    findings.append(IntelligenceFinding(
                        entity=f"Image format: {img_format}{' (outdated)' if is_outdated else ''}",
                        type="Image Format Detection",
                        source="ReverseImageSearch",
                        confidence="High",
                        color="yellow" if is_outdated else "slate",
                        threat_level="Informational",
                        raw_data=f"Format: {img_format} | Content-Type: {content_type} | Outdated: {is_outdated}",
                        tags=format_tags
                    ))

                    is_tracking = check_tracking_pixel(image_data, dimensions)
                    if is_tracking:
                        findings.append(IntelligenceFinding(
                            entity=f"Suspected tracking pixel: {img_url[:150]}",
                            type="Tracking Pixel Detection",
                            source="ReverseImageSearch",
                            confidence="Medium",
                            color="yellow",
                            threat_level="Low Risk",
                            raw_data=f"Tracking pixel ({dimensions['width']}x{dimensions['height']})" if dimensions else "Tracking pixel (very small file)",
                            tags=["tracking", "pixel", "privacy"]
                        ))

                    has_face = detect_face_indicators(img_url, alt_text)
                    if has_face:
                        findings.append(IntelligenceFinding(
                            entity=f"Possible people in image: {img_url[:150]}",
                            type="Face Detection Indicator",
                            source="ReverseImageSearch",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"Image may contain people (keyword match in alt/filename): {img_url}",
                            tags=["image", "people", "face-detection"]
                        ))

                    img_body_lower = image_data[:50000].lower()
                    for wm in STOCK_WATERMARKS:
                        if wm.encode() in img_body_lower or wm in exif_info.get("Software", "").lower():
                            findings.append(IntelligenceFinding(
                                entity=f"Stock photo detected: {wm}",
                                type="Stock Photo Detection",
                                source="ReverseImageSearch",
                                confidence="Medium" if wm in ("unsplash", "pexels", "pixabay") else "High",
                                color="slate",
                                threat_level="Informational",
                                raw_data=f"Watermark/copyright match: {wm} in {img_url}",
                                tags=["stock-photo", wm]
                            ))
                            break

                    cdn_name = detect_cdn(img_url)
                    if cdn_name:
                        findings.append(IntelligenceFinding(
                            entity=f"CDN: {cdn_name} - {img_url[:150]}",
                            type="Image CDN Detection",
                            source="ReverseImageSearch",
                            confidence="High",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"CDN: {cdn_name} | URL: {img_url}",
                            tags=["cdn", cdn_name.lower().replace(" ", "-")]
                        ))

                    rev_engines = [
                        ("Google Lens", f"https://lens.google.com/uploadbyurl?url={img_url}"),
                        ("TinEye", f"https://tineye.com/search?url={img_url}"),
                        ("Bing Visual Search", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{img_url}"),
                        ("Yandex Images", f"https://yandex.com/images/search?rpt=imageview&url={img_url}"),
                        ("SauceNAO", f"https://saucenao.com/search.php?url={img_url}"),
                        ("IQDB", f"https://iqdb.org/?url={img_url}"),
                        ("ImgOps", f"https://imgops.com/{img_url}"),
                        ("Trace.moe (anime)", f"https://trace.moe/?url={img_url}"),
                    ]

                    for search_engine, search_url in rev_engines:
                        findings.append(IntelligenceFinding(
                            entity=f"Reverse search: {search_engine}",
                            type="Image Reverse Search Link",
                            source="ReverseImageSearch",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"Query URL: {search_url}",
                            tags=["reverse-image-search", search_engine.lower().replace(" ", "-").replace(".", "-")]
                        ))

            except Exception:
                pass

        stock_watermark_count = sum(1 for f in findings if f.type == "Stock Photo Detection")
        gps_count = sum(1 for f in findings if f.type == "Image GPS Location")
        exif_count = sum(1 for f in findings if f.type == "Image EXIF Metadata")
        face_count = sum(1 for f in findings if f.type == "Face Detection Indicator")
        cdn_count = sum(1 for f in findings if f.type == "Image CDN Detection")
        tracking_count = sum(1 for f in findings if f.type == "Tracking Pixel Detection")
        svg_count = sum(1 for f in findings if f.type == "Image Found - Inline SVG")
        img_found_types = {}
        for f in findings:
            if f.type and f.type.startswith("Image Found"):
                img_found_types[f.type] = img_found_types.get(f.type, 0) + 1

        summary_parts = [
            f"{len(absolute_urls)} images found ({stock_watermark_count} stock, {gps_count} GPS, {exif_count} EXIF)",
        ]
        if face_count:
            summary_parts.append(f"{face_count} with people indicators")
        if cdn_count:
            summary_parts.append(f"{cdn_count} from CDNs")
        if tracking_count:
            summary_parts.append(f"{tracking_count} tracking pixels")
        if svg_count:
            summary_parts.append(f"{svg_count} inline SVGs")
        summary_str = " | ".join(summary_parts)

        findings.insert(0, IntelligenceFinding(
            entity=summary_str,
            type="Image Analysis Summary",
            source="ReverseImageSearch",
            confidence="High",
            color="purple",
            threat_level="Elevated Risk" if gps_count > 0 else "Informational",
            raw_data=(
                f"Total images: {len(absolute_urls)} | Stock: {stock_watermark_count} | "
                f"GPS: {gps_count} | EXIF: {exif_count} | Face indicators: {face_count} | "
                f"CDN hosted: {cdn_count} | Tracking pixels: {tracking_count} | "
                f"Inline SVGs: {svg_count}"
            ),
            tags=["image", "summary"]
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"Reverse Image Search error: {str(e)[:100]}",
            type="Reverse Image Search Error",
            source="ReverseImageSearch",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    async def analyze_image_diversity():
        if absolute_urls:
            ext_counts = {}
            for url in absolute_urls:
                ext = url.rsplit(".", 1)[-1].split("?")[0].lower() if "." in url else "none"
                ext_counts[ext] = ext_counts.get(ext, 0) + 1
            for ext, count in sorted(ext_counts.items(), key=lambda x: -x[1])[:5]:
                findings.append(IntelligenceFinding(entity=f"Format: .{ext} ({count} images)", type="Image Format Distribution", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["format"]))
            findings.append(IntelligenceFinding(entity=f"Format diversity: {len(ext_counts)} distinct format(s)", type="Image Format Diversity", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["format"]))

    async def analyze_image_hosting():
        if absolute_urls:
            hosts = {}
            for url in absolute_urls:
                try:
                    h = urlparse(url).hostname or ""
                    hosts[h] = hosts.get(h, 0) + 1
                except: pass
            for host, count in sorted(hosts.items(), key=lambda x: -x[1])[:6]:
                findings.append(IntelligenceFinding(entity=f"Host: {host} ({count})", type="Image Hosting Distribution", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["hosting"]))
            findings.append(IntelligenceFinding(entity=f"Hosting diversity: {len(hosts)} unique host(s)", type="Image Hosting Diversity", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["hosting"]))

    async def check_image_privacy_risks():
        gps_findings = [f for f in findings if f.type == "Image GPS Location"]
        stock_findings = [f for f in findings if f.type == "Stock Photo Detection"]
        face_findings = [f for f in findings if f.type == "Face Detection Indicator"]
        if gps_findings:
            findings.append(IntelligenceFinding(entity=f"{len(gps_findings)} image(s) with GPS data", type="Privacy Risk: GPS", source="ReverseImageSearch", confidence="High", color="red", threat_level="Elevated Risk", tags=["privacy"]))
        if stock_findings:
            findings.append(IntelligenceFinding(entity=f"{len(stock_findings)} stock photo(s)", type="Privacy Risk: Stock Photos", source="ReverseImageSearch", confidence="Medium", color="orange", tags=["privacy"]))
        if face_findings:
            findings.append(IntelligenceFinding(entity=f"{len(face_findings)} image(s) with people indicators", type="Privacy Risk: People", source="ReverseImageSearch", confidence="Low", color="orange", tags=["privacy"]))
        findings.append(IntelligenceFinding(entity="Check for embedded metadata before publishing images publicly", type="Privacy Recommendation", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["recommendation"]))
        findings.append(IntelligenceFinding(entity="Strip EXIF/GPS data from shared images", type="Privacy Recommendation", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["recommendation"]))

    async def check_tracking_analysis():
        tracking_findings = [f for f in findings if f.type == "Tracking Pixel Detection"]
        if tracking_findings:
            findings.append(IntelligenceFinding(entity=f"{len(tracking_findings)} tracking pixel(s)", type="Tracking Analysis", source="ReverseImageSearch", confidence="Medium", color="orange", tags=["tracking"]))
        else:
            findings.append(IntelligenceFinding(entity="No tracking pixels detected", type="Tracking Analysis", source="ReverseImageSearch", confidence="Low", color="emerald", tags=["tracking"]))

    async def check_image_security():
        cdn_findings = [f for f in findings if f.type == "Image CDN Detection"]
        if cdn_findings:
            cdn_names = set()
            for f in cdn_findings:
                cdn_names.add(f.entity.split(" -")[0] if " -" in f.entity else f.entity)
            findings.append(IntelligenceFinding(entity=f"CDNs: {', '.join(sorted(cdn_names))}", type="CDN Usage Summary", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["cdn"]))
        findings.append(IntelligenceFinding(entity=f"Total unique images: {len(absolute_urls)}", type="Image Count Summary", source="ReverseImageSearch", confidence="High", color="slate", tags=["summary"]))
        outdated = sum(1 for f in findings if "outdated" in (f.raw_data or "").lower())
        if outdated:
            findings.append(IntelligenceFinding(entity=f"{outdated} image(s) use outdated format(s)", type="Outdated Format Warning", source="ReverseImageSearch", confidence="Medium", color="yellow", tags=["format"]))

    async def check_reverse_search_links():
        rev_count = sum(1 for f in findings if f.type == "Image Reverse Search Link")
        findings.append(IntelligenceFinding(entity=f"Reverse image search URLs: {rev_count}", type="Reverse Search Summary", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["reverse-search"]))
        findings.append(IntelligenceFinding(entity="Use reverse search engines to find original sources", type="OSINT Recommendation", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["recommendation"]))

    async def analyze_image_sources():
        source_domains = set()
        for f in findings:
            if f.type == "Image Reverse Search Link":
                try:
                    sd = urlparse(f.entity.split(": ")[1] if ": " in f.entity else f.entity).hostname or ""
                    source_domains.add(sd)
                except: pass
        findings.append(IntelligenceFinding(entity=f"Reverse search engines: {len(source_domains)}", type="Source Diversity", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["sources"]))

    async def analyze_metadata_findings():
        meta_count = sum(1 for f in findings if f.type.startswith("Image"))
        findings.append(IntelligenceFinding(entity=f"Total metadata findings: {meta_count}", type="Metadata Volume", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["metadata"]))

    async def analyze_image_threat():
        suspicious = sum(1 for f in findings if f.threat_level in ("Elevated Risk", "High Risk"))
        findings.append(IntelligenceFinding(entity=f"Risk indicators: {suspicious}", type="Risk Assessment", source="ReverseImageSearch", confidence="Medium", color="red" if suspicious else "emerald", tags=["risk"]))

    async def analyze_network_impact():
        findings.append(IntelligenceFinding(entity=f"All images stored externally - review CDN/cloud provider", type="Network Impact", source="ReverseImageSearch", confidence="Medium", color="orange", tags=["network"]))
        findings.append(IntelligenceFinding(entity="Cached images may persist even after source deletion", type="Caching Warning", source="ReverseImageSearch", confidence="Medium", color="orange", tags=["network"]))

    async def analyze_domain_reputation():
        social_images = sum(1 for u in absolute_urls if any(d in u for d in ["facebook", "instagram", "twitter", "linkedin", "cdninstagram"]))
        findings.append(IntelligenceFinding(entity=f"Images hosted on social platforms: {social_images}", type="Social Hosting", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["reputation"]))
        findings.append(IntelligenceFinding(entity=f"Total image URLs extracted: {len(absolute_urls)}", type="Total Extracted", source="ReverseImageSearch", confidence="High", color="slate", tags=["reputation"]))

    async def analyze_exif_awareness():
        exif_count = sum(1 for f in findings if "GPS" in f.type or "EXIF" in f.type)
        findings.append(IntelligenceFinding(entity=f"EXIF/GPS findings: {exif_count}", type="EXIF Awareness", source="ReverseImageSearch", confidence="Medium", color="orange" if exif_count else "emerald", tags=["exif"]))
        findings.append(IntelligenceFinding(entity="Always verify image metadata before sharing publicly", type="EXIF Recommendation", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["exif"]))
        findings.append(IntelligenceFinding(entity=f"Image total types: {len(set(url.rsplit('.',1)[-1].split('?')[0].lower() for url in absolute_urls if '.' in url))}", type="Format Count", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["exif"]))
        findings.append(IntelligenceFinding(entity="Consider watermarking images before public sharing", type="Watermark Recommendation", source="ReverseImageSearch", confidence="Medium", color="slate", tags=["exif"]))

    await asyncio.gather(
        analyze_image_diversity(),
        analyze_image_hosting(),
        check_image_privacy_risks(),
        check_tracking_analysis(),
        check_image_security(),
        check_reverse_search_links(),
        analyze_image_sources(),
        analyze_metadata_findings(),
        analyze_image_threat(),
        analyze_network_impact(),
        analyze_domain_reputation(),
        analyze_exif_awareness(),
    )

    return findings
