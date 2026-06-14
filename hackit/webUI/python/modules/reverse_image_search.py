import httpx
import re
import base64
import struct
import io
from models import IntelligenceFinding
from urllib.parse import urljoin, urlparse

IMG_TAG_REGEX = re.compile(r'<img[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
CSS_BG_REGEX = re.compile(r'background(?:-image)?:\s*url\(["\']?([^"\')]+)["\']?\)', re.IGNORECASE)
META_OG_IMAGE = re.compile(r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)["\']', re.IGNORECASE)
FAVICON_REGEX = re.compile(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)

STOCK_WATERMARKS = [
    "gettyimages", "shutterstock", "istockphoto", "123rf", "dreamstime",
    "alamy", "depositphotos", "canstockphoto", "bigstock", "fotolia",
    "pond5", "vecteezy", "envato", "unsplash", "pexels", "pixabay",
]

EXIF_ORIENTATIONS = {
    1: "Normal", 2: "Mirror horizontal", 3: "Rotate 180",
    4: "Mirror vertical", 5: "Mirror horizontal + rotate 270",
    6: "Rotate 90", 7: "Mirror horizontal + rotate 90", 8: "Rotate 270",
}

GPS_COORD_REGEX = re.compile(r'(\d+)[°d]\s*(\d+)[\'m]\s*([\d.]+)[\"s]?\s*([NSEW])', re.IGNORECASE)

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
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS
    except ImportError:
        try:
            import exifread
            tags = exifread.process_file(io.BytesIO(image_data), details=False)
            for tag_name, tag_value in tags.items():
                if "GPS" in tag_name:
                    info[tag_name] = str(tag_value)
                elif tag_name in ("Image Make", "Image Model", "Image Software", "Image DateTime", "Image Artist", "Image Copyright"):
                    info[tag_name] = str(tag_value)
            return info
        except ImportError:
            return {"exif": "Not available (PIL/exifread not installed)"}

    try:
        img = Image.open(io.BytesIO(image_data))
        exif_data = img._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)
                if tag_name == "GPSInfo":
                    for gps_tag, gps_value in value.items():
                        gps_name = GPSTAGS.get(gps_tag, gps_tag)
                        info[f"GPS_{gps_name}"] = str(gps_value)
                elif tag_name in ("Make", "Model", "Software", "DateTime", "Artist", "Copyright", "Orientation", "ImageDescription", "XResolution", "YResolution"):
                    info[tag_name] = str(value)
    except Exception:
        pass
    return info

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

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        html = resp.text
        image_urls = []

        for m in IMG_TAG_REGEX.finditer(html):
            image_urls.append(m.group(1))
        for m in CSS_BG_REGEX.finditer(html):
            image_urls.append(m.group(1))
        for m in META_OG_IMAGE.finditer(html):
            image_urls.append(m.group(1))
        for m in FAVICON_REGEX.finditer(html):
            image_urls.append(m.group(1))

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

                    for search_engine, search_url in [
                        ("Google Images", f"https://lens.google.com/uploadbyurl?url={img_url}"),
                        ("TinEye", f"https://tineye.com/search?url={img_url}"),
                        ("Bing Visual Search", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{img_url}"),
                        ("Yandex Images", f"https://yandex.com/images/search?rpt=imageview&url={img_url}"),
                    ]:
                        findings.append(IntelligenceFinding(
                            entity=f"Reverse search: {search_engine}",
                            type="Image Reverse Search Link",
                            source="ReverseImageSearch",
                            confidence="Low",
                            color="slate",
                            threat_level="Informational",
                            raw_data=f"Query URL: {search_url}",
                            tags=["reverse-image-search", search_engine.lower().replace(" ", "-")]
                        ))

            except Exception:
                pass

        stock_watermark_count = sum(1 for f in findings if f.type == "Stock Photo Detection")
        gps_count = sum(1 for f in findings if f.type == "Image GPS Location")
        exif_count = sum(1 for f in findings if f.type == "Image EXIF Metadata")

        findings.append(IntelligenceFinding(
            entity=f"{len(absolute_urls)} images found ({stock_watermark_count} stock, {gps_count} with GPS, {exif_count} with EXIF)",
            type="Image Analysis Summary",
            source="ReverseImageSearch",
            confidence="High",
            color="purple",
            threat_level="Elevated Risk" if gps_count > 0 else "Informational",
            raw_data=f"Total images: {len(absolute_urls)} | Stock: {stock_watermark_count} | GPS: {gps_count} | EXIF: {exif_count}",
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

    return findings
