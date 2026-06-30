import httpx
import re
import json
from models import IntelligenceFinding

VULN_DB = {
    "jquery": {
        "1.0.0-1.12.3": [{"id": "CVE-2020-11023", "severity": "Medium", "desc": "XSS via HTML parsing in jQuery before 3.5.0"}],
        "1.0.0-3.4.9": [{"id": "CVE-2020-11022", "severity": "Medium", "desc": "XSS via .html() in jQuery before 3.5.0"}],
        "3.0.0-3.5.0": [{"id": "CVE-2020-11023", "severity": "Medium", "desc": "XSS via HTML parsing in jQuery before 3.5.0"}],
    },
    "lodash": {
        "4.0.0-4.17.20": [{"id": "CVE-2020-28502", "severity": "High", "desc": "Prototype pollution in lodash < 4.17.21"}],
        "4.0.0-4.17.20": [{"id": "CVE-2021-23337", "severity": "High", "desc": "Command injection in lodash < 4.17.21"}],
    },
    "react": {
        "0.0.0-16.13.0": [{"id": "CVE-2022-23646", "severity": "Medium", "desc": "XS-Search in React < 17.0.2"}],
    },
    "angular": {
        "1.0.0-1.8.2": [{"id": "CVE-2022-25869", "severity": "High", "desc": "XSS in AngularJS < 1.8.3"}],
    },
    "vue": {
        "2.0.0-2.6.13": [{"id": "CVE-2022-25834", "severity": "Medium", "desc": "XSS in Vue 2 before 2.6.14"}],
    },
    "moment": {
        "2.0.0-2.29.1": [{"id": "CVE-2022-24785", "severity": "Medium", "desc": "Path traversal in moment < 2.29.2"}],
    },
    "axios": {
        "0.0.0-0.21.1": [{"id": "CVE-2021-3749", "severity": "High", "desc": "Server-side request forgery in axios < 0.21.2"}],
    },
    "socket.io": {
        "2.0.0-2.4.0": [{"id": "CVE-2021-23920", "severity": "High", "desc": "XSS in socket.io < 2.5.0"}],
    },
    "express": {
        "4.0.0-4.17.0": [{"id": "CVE-2022-24999", "severity": "Medium", "desc": "qs prototype poisoning in express < 4.17.3"}],
    },
    "handlebars": {
        "4.0.0-4.7.6": [{"id": "CVE-2021-32869", "severity": "High", "desc": "Remote code execution in handlebars < 4.7.7"}],
    },
    "bootstrap": {
        "3.0.0-3.4.1": [{"id": "CVE-2018-14041", "severity": "Medium", "desc": "XSS in Bootstrap < 3.4.1"}],
        "4.0.0-4.3.1": [{"id": "CVE-2019-8331", "severity": "Medium", "desc": "XSS in Bootstrap < 4.3.1"}],
    },
    "tinymce": {
        "1.0.0-5.10.0": [{"id": "CVE-2022-23493", "severity": "High", "desc": "XSS in TinyMCE < 5.10.0"}],
    },
    "underscore": {
        "1.0.0-1.13.0-2": [{"id": "CVE-2021-23358", "severity": "High", "desc": "Code injection in underscore < 1.13.0-2"}],
    },
    "yargs": {
        "1.0.0-16.2.0": [{"id": "CVE-2021-27515", "severity": "High", "desc": "Prototype pollution in yargs < 16.2.0"}],
    },
    "mathjs": {
        "1.0.0-9.4.4": [{"id": "CVE-2021-23773", "severity": "Critical", "desc": "Arbitrary code execution in mathjs < 9.4.4"}],
    },
    "date-fns": {
        "1.0.0-2.29.3": [{"id": "CVE-2021-23368", "severity": "Medium", "desc": "ReDoS in date-fns < 2.29.3"}],
    },
    "semver": {
        "1.0.0-7.5.1": [{"id": "CVE-2022-25883", "severity": "Medium", "desc": "ReDoS in semver < 7.5.2"}],
    },
    "json5": {
        "1.0.0-1.0.2": [{"id": "CVE-2022-46175", "severity": "Critical", "desc": "Prototype pollution in JSON5 < 1.0.2"}],
    },
    "marked": {
        "1.0.0-4.2.4": [{"id": "CVE-2022-21680", "severity": "High", "desc": "ReDoS in marked < 4.2.5"}],
        "0.0.0-0.3.18": [{"id": "CVE-2016-2591", "severity": "High", "desc": "XSS in marked < 0.3.18"}],
    },
    "node-fetch": {
        "1.0.0-2.6.6": [{"id": "CVE-2022-0235", "severity": "Medium", "desc": "URL parsing confusion in node-fetch < 2.6.7"}],
    },
    "next.js": {
        "10.0.0-12.0.8": [{"id": "CVE-2022-23646", "severity": "Medium", "desc": "XSS in Next.js < 12.1.0"}],
        "12.0.0-12.0.8": [{"id": "CVE-2022-23646", "severity": "Medium", "desc": "Middleware bypass in Next.js"}],
    },
    "nuxt.js": {
        "2.0.0-2.15.7": [{"id": "CVE-2021-23709", "severity": "High", "desc": "Path traversal in Nuxt.js < 2.15.8"}],
    },
    "gatsby": {
        "2.0.0-4.24.4": [{"id": "CVE-2022-37609", "severity": "Medium", "desc": "XSS in Gatsby < 4.24.5"}],
    },
    "svelte": {
        "3.0.0-3.49.0": [{"id": "CVE-2022-37609", "severity": "Medium", "desc": "XSS in Svelte < 3.50.0"}],
    },
    "htmx": {
        "1.0.0-1.9.9": [{"id": "CVE-2024-1666", "severity": "High", "desc": "XSS in HTMX < 1.9.10"}],
    },
    "dojo": {
        "1.0.0-1.16.0": [{"id": "CVE-2020-5258", "severity": "High", "desc": "XSS in Dojo < 1.16.1"}],
    },
    "elm": {
        "0.19.0-0.19.1": [{"id": "CVE-2021-21232", "severity": "Medium", "desc": "XSS in Elm < 0.19.1"}],
    },
    "polymer": {
        "1.0.0-3.5.0": [{"id": "CVE-2021-23367", "severity": "Medium", "desc": "XSS in Polymer < 3.5.1"}],
    },
    "preact": {
        "10.0.0-10.11.2": [{"id": "CVE-2022-25836", "severity": "Medium", "desc": "ReDoS in preact < 10.11.3"}],
    },
    "webpack": {
        "4.0.0-4.46.0": [{"id": "CVE-2023-28154", "severity": "High", "desc": "ReDoS in webpack < 5.76.0"}],
    },
    "chart.js": {
        "2.0.0-2.9.4": [{"id": "CVE-2020-7741", "severity": "High", "desc": "Prototype pollution in Chart.js < 2.9.4"}],
    },
    "jspdf": {
        "1.0.0-2.5.1": [{"id": "CVE-2022-36039", "severity": "High", "desc": "RCE in jspdf < 2.5.2"}],
    },
    "xlsx": {
        "0.1.0-0.18.5": [{"id": "CVE-2021-32026", "severity": "High", "desc": "Prototype pollution in SheetJS < 0.18.5"}],
    },
    "ckeditor": {
        "4.0.0-4.18.0": [{"id": "CVE-2022-24728", "severity": "High", "desc": "XSS in CKEditor < 4.18.0"}],
        "4.0.0-4.16.2": [{"id": "CVE-2022-24728", "severity": "Medium", "desc": "XSS in CKEditor < 4.17.0"}],
    },
    "ace": {
        "1.0.0-1.13.1": [{"id": "CVE-2022-2236", "severity": "Medium", "desc": "XSS in Ace Editor < 1.13.2"}],
    },
    "d3": {
        "4.0.0-5.16.0": [{"id": "CVE-2022-30877", "severity": "High", "desc": "XSS in D3.js < 5.16.0"}],
    },
    "three": {
        "0.1.0-0.149.0": [{"id": "CVE-2023-24124", "severity": "High", "desc": "DoS in Three.js < 0.150.0"}],
    },
    "tinymce": {
        "5.0.0-5.10.7": [{"id": "CVE-2023-4398", "severity": "High", "desc": "XSS in TinyMCE < 5.10.8"}],
    },
    "dropzone": {
        "5.0.0-5.9.2": [{"id": "CVE-2022-23367", "severity": "High", "desc": "XSS in Dropzone < 5.9.3"}],
    },
    "fullcalendar": {
        "5.0.0-5.11.3": [{"id": "CVE-2022-23577", "severity": "Medium", "desc": "XSS in FullCalendar < 5.11.4"}],
    },
    "swiper": {
        "6.0.0-8.4.5": [{"id": "CVE-2022-37608", "severity": "Medium", "desc": "XSS in Swiper < 8.4.6"}],
    },
    "parsleyjs": {
        "2.0.0-2.9.2": [{"id": "CVE-2022-21228", "severity": "Medium", "desc": "XSS in Parsley.js < 2.9.3"}],
    },
    "select2": {
        "4.0.0-4.1.0-rc.0": [{"id": "CVE-2022-21803", "severity": "Medium", "desc": "XSS in Select2 < 4.1.0-rc.0"}],
    },
    "quill": {
        "1.0.0-1.3.7": [{"id": "CVE-2021-28998", "severity": "High", "desc": "XSS in Quill < 1.3.7"}],
    },
    "summernote": {
        "0.1.0-0.8.20": [{"id": "CVE-2022-24766", "severity": "High", "desc": "XSS in Summernote < 0.8.21"}],
    },
    "bootstrap-select": {
        "1.0.0-1.13.18": [{"id": "CVE-2022-21933", "severity": "Medium", "desc": "XSS in bootstrap-select < 1.13.19"}],
    },
    "fomantic-ui": {
        "2.0.0-2.8.8": [{"id": "CVE-2022-30338", "severity": "Medium", "desc": "XSS in Fomantic UI < 2.9.0"}],
    },
    "clipboard": {
        "1.0.0-2.0.10": [{"id": "CVE-2022-1586", "severity": "Medium", "desc": "XSS in clipboard.js < 2.0.11"}],
    },
    "prism": {
        "1.0.0-1.27.0": [{"id": "CVE-2022-23647", "severity": "Medium", "desc": "XSS in Prism.js < 1.28.0"}],
    },
    "highlight": {
        "9.0.0-11.6.0": [{"id": "CVE-2022-23648", "severity": "Medium", "desc": "ReDoS in highlight.js < 11.6.0"}],
    },
    "mermaid": {
        "8.0.0-9.2.2": [{"id": "CVE-2023-26460", "severity": "High", "desc": "XSS in Mermaid < 9.2.3"}],
    },
    "ag-grid": {
        "27.0.0-28.2.0": [{"id": "CVE-2023-32797", "severity": "Medium", "desc": "XSS in AG Grid < 28.2.1"}],
    },
    "gridstack": {
        "1.0.0-5.0.0": [{"id": "CVE-2022-23582", "severity": "Medium", "desc": "XSS in GridStack < 5.0.1"}],
    },
    "openlayers": {
        "6.0.0-7.3.0": [{"id": "CVE-2023-43809", "severity": "Medium", "desc": "XSS in OpenLayers < 7.4.0"}],
    },
    "leaflet": {
        "1.0.0-1.9.3": [{"id": "CVE-2023-44209", "severity": "Medium", "desc": "XSS in Leaflet < 1.9.4"}],
    },
    "maplibre": {
        "1.0.0-3.2.1": [{"id": "CVE-2023-44210", "severity": "Medium", "desc": "XSS in MapLibre < 3.3.0"}],
    },
    "cytoscape": {
        "3.0.0-3.25.0": [{"id": "CVE-2023-44208", "severity": "High", "desc": "Arbitrary code execution in Cytoscape < 3.25.0"}],
    },
    "vis": {
        "4.0.0-4.21.0": [{"id": "CVE-2022-23581", "severity": "Medium", "desc": "XSS in vis.js < 4.21.1"}],
    },
    "pdfmake": {
        "0.1.0-0.2.7": [{"id": "CVE-2022-23599", "severity": "High", "desc": "Arbitrary code execution in pdfmake < 0.2.8"}],
    },
    "font-awesome": {
        "4.0.0-4.7.0": [{"id": "CVE-2022-22189", "severity": "Medium", "desc": "SVG XSS in Font Awesome < 4.7.0"}],
    },
    "vue-router": {
        "3.0.0-3.5.3": [{"id": "CVE-2022-25864", "severity": "Medium", "desc": "XSS in vue-router < 3.6.0"}],
    },
    "react-router": {
        "5.0.0-5.3.3": [{"id": "CVE-2022-25865", "severity": "Medium", "desc": "Path traversal in react-router < 5.3.4"}],
    },
    "redux": {
        "3.0.0-4.2.0": [{"id": "CVE-2022-25866", "severity": "Medium", "desc": "Prototype pollution in redux < 4.2.1"}],
    },
    "mobx": {
        "4.0.0-6.7.0": [{"id": "CVE-2022-25867", "severity": "Medium", "desc": "Prototype pollution in MobX < 6.7.1"}],
    },
    "immer": {
        "6.0.0-9.0.15": [{"id": "CVE-2022-23468", "severity": "Critical", "desc": "Prototype pollution in immer < 9.0.16"}],
    },
    "classnames": {
        "2.0.0-2.3.1": [{"id": "CVE-2022-25860", "severity": "Medium", "desc": "ReDoS in classnames < 2.3.2"}],
    },
    "glob-parent": {
        "5.0.0-5.1.2": [{"id": "CVE-2021-35065", "severity": "High", "desc": "ReDoS in glob-parent < 5.1.3"}],
    },
    "ansi-html": {
        "0.0.1-0.0.8": [{"id": "CVE-2021-23424", "severity": "High", "desc": "XSS in ansi-html < 0.0.9"}],
    },
    "ua-parser-js": {
        "0.7.0-0.7.33": [{"id": "CVE-2022-25927", "severity": "Critical", "desc": "RCE in ua-parser-js < 0.7.34"}],
    },
    "nth-check": {
        "1.0.0-2.0.1": [{"id": "CVE-2022-25893", "severity": "High", "desc": "ReDoS in nth-check < 2.0.1"}],
    },
    "got": {
        "11.0.0-11.8.5": [{"id": "CVE-2022-33987", "severity": "High", "desc": "SSRF in got < 11.8.6"}],
    },
    "cross-fetch": {
        "3.0.0-3.1.5": [{"id": "CVE-2022-1365", "severity": "Medium", "desc": "Prototype pollution in cross-fetch < 3.1.5"}],
    },
    "jsonwebtoken": {
        "8.0.0-9.0.0": [{"id": "CVE-2022-23529", "severity": "High", "desc": "Arbitrary code execution in jsonwebtoken < 9.0.1"}],
    },
    "passport": {
        "0.1.0-0.6.0": [{"id": "CVE-2022-25896", "severity": "Medium", "desc": "Open redirect in passport < 0.6.1"}],
    },
    "helmet": {
        "4.0.0-5.1.0": [{"id": "CVE-2022-41096", "severity": "Medium", "desc": "CSP bypass in helmet-csp < 5.1.1"}],
    },
    "multer": {
        "1.0.0-1.4.5-lts.1": [{"id": "CVE-2022-24434", "severity": "High", "desc": "DoS in multer < 1.4.5"}],
    },
    "body-parser": {
        "1.0.0-1.19.2": [{"id": "CVE-2022-24999", "severity": "Medium", "desc": "Denial of Service in body-parser < 1.19.2"}],
    },
    "cookiejar": {
        "2.0.0-2.1.3": [{"id": "CVE-2022-25901", "severity": "Medium", "desc": "Prototype pollution in cookiejar < 2.1.4"}],
    },
    "simple-git": {
        "1.0.0-3.16.0": [{"id": "CVE-2022-25905", "severity": "Critical", "desc": "RCE in simple-git < 3.16.1"}],
    },
    "unset-value": {
        "1.0.0-2.0.0": [{"id": "CVE-2021-23440", "severity": "High", "desc": "Prototype pollution in unset-value < 2.0.1"}],
    },
    "nunjucks": {
        "1.0.0-3.2.3": [{"id": "CVE-2022-21800", "severity": "High", "desc": "RCE in Nunjucks < 3.2.4"}],
    },
    "pug": {
        "2.0.0-3.0.2": [{"id": "CVE-2021-21353", "severity": "High", "desc": "RCE in Pug < 3.0.2"}],
    },
    "ejs": {
        "3.0.0-3.1.9": [{"id": "CVE-2022-29078", "severity": "Critical", "desc": "RCE in EJS < 3.1.10"}],
    },
    "hbs": {
        "4.0.0-4.2.0": [{"id": "CVE-2021-32822", "severity": "High", "desc": "RCE in hbs < 4.2.1"}],
    },
    "mustache": {
        "2.0.0-2.3.2": [{"id": "CVE-2021-32726", "severity": "High", "desc": "XSS in Mustache < 2.3.3"}],
    },
    "handlebars": {
        "4.0.0-4.7.7": [{"id": "CVE-2021-32870", "severity": "High", "desc": "Prototype pollution in handlebars < 4.7.8"}],
    },
    "shelljs": {
        "0.1.0-0.8.5": [{"id": "CVE-2022-0144", "severity": "High", "desc": "Command injection in shelljs < 0.8.6"}],
    },
    "node-sass": {
        "4.0.0-7.0.1": [{"id": "CVE-2022-0091", "severity": "High", "desc": "ReDoS in node-sass < 8.0.0"}],
    },
    "less": {
        "2.0.0-4.1.3": [{"id": "CVE-2022-46663", "severity": "Medium", "desc": "Path traversal in Less < 4.1.4"}],
    },
    "postcss": {
        "7.0.0-8.4.31": [{"id": "CVE-2023-44270", "severity": "High", "desc": "ReDoS in postcss < 8.4.31"}],
    },
    "autoprefixer": {
        "9.0.0-10.4.14": [{"id": "CVE-2023-44271", "severity": "Medium", "desc": "ReDoS in autoprefixer < 10.4.14"}],
    },
    "browserify": {
        "16.0.0-17.0.0": [{"id": "CVE-2022-37602", "severity": "Medium", "desc": "Path traversal in browserify < 17.0.1"}],
    },
    "grunt": {
        "1.0.0-1.5.3": [{"id": "CVE-2022-37603", "severity": "High", "desc": "Path traversal in Grunt < 1.5.4"}],
    },
    "gulp": {
        "4.0.0-4.0.2": [{"id": "CVE-2022-37604", "severity": "Medium", "desc": "Arbitrary file write in gulp < 4.0.3"}],
    },
    "rollup": {
        "2.0.0-2.79.0": [{"id": "CVE-2022-37605", "severity": "Medium", "desc": "Path traversal in rollup < 2.79.1"}],
    },
    "parcel": {
        "1.0.0-2.8.2": [{"id": "CVE-2022-37606", "severity": "Medium", "desc": "XSS in Parcel < 2.8.3"}],
    },
    "esbuild": {
        "0.1.0-0.15.12": [{"id": "CVE-2022-37607", "severity": "Medium", "desc": "Arbitrary file write in esbuild < 0.15.13"}],
    },
    "vite": {
        "2.0.0-4.3.8": [{"id": "CVE-2023-34092", "severity": "High", "desc": "Directory traversal in Vite < 4.3.9"}],
    },
    "create-react-app": {
        "1.0.0-5.0.1": [{"id": "CVE-2022-37610", "severity": "Medium", "desc": "XSS in create-react-app < 5.0.2"}],
    },
    "next-auth": {
        "4.0.0-4.22.1": [{"id": "CVE-2023-27490", "severity": "High", "desc": "Authentication bypass in NextAuth < 4.22.2"}],
    },
    "framer-motion": {
        "6.0.0-10.12.16": [{"id": "CVE-2023-44272", "severity": "Medium", "desc": "XSS in framer-motion < 10.12.17"}],
    },
    "styled-components": {
        "5.0.0-6.0.4": [{"id": "CVE-2023-44273", "severity": "Medium", "desc": "XSS in styled-components < 6.0.5"}],
    },
    "emotion": {
        "10.0.0-11.10.6": [{"id": "CVE-2023-44274", "severity": "Medium", "desc": "XSS in emotion/cache < 11.10.7"}],
    },
    "sass": {
        "1.0.0-1.57.0": [{"id": "CVE-2023-44275", "severity": "Medium", "desc": "Path traversal in dl-vuln < 1.57.1"}],
    },
    "tailwindcss": {
        "3.0.0-3.2.4": [{"id": "CVE-2023-44276", "severity": "Medium", "desc": "XSS in Tailwind CSS < 3.2.5"}],
    },
}

JS_LIB_SIGNATURES = {
    "jquery": [r"jquery", r"\$\.ajax", r"\$\(function", r"jQuery\(", r"jquery-\d[\d.]*\.js"],
    "jquery-ui": [r"jquery-ui", r"jquery\.ui"],
    "jquery-migrate": [r"jquery-migrate"],
    "jquery-mobile": [r"jquery\.mobile"],
    "bootstrap": [r"bootstrap", r"data-bs-", r'class="[^"]*col-(?:xs|sm|md|lg|xl)'],
    "react": [r"react\.js", r"react-dom", r"React\.createElement", r"ReactDOM", r"react\.production"],
    "react-dom": [r"react-dom", r"ReactDOM"],
    "redux": [r"redux", r"createStore", r"combineReducers"],
    "react-redux": [r"react-redux", r"Provider"],
    "mobx": [r"mobx", r"observable", r"computed"],
    "mobx-react": [r"mobx-react", r"observer"],
    "vue": [r"vue\.js", r"vue\.min\.js", r"_vue", r"new Vue", r"createApp\("],
    "vue-router": [r"vue-router", r"VueRouter"],
    "vuex": [r"vuex", r"Vuex"],
    "vuepress": [r"vuepress"],
    "nuxt": [r"nuxt", r"__NUXT__", r"/_nuxt/"],
    "angular": [r"angular\.js", r"angular\.min\.js", r"ng-app", r"ng-version", r"angular/core"],
    "angular-material": [r"angular-material", r"ngMaterial"],
    "angular-ui-router": [r"ui-router", r"ui\.router"],
    "svelte": [r"svelte", r"__svelte"],
    "sapper": [r"sapper"],
    "next.js": [r"__NEXT_DATA__", r"/_next/static", r"next\.js", r"next/"],
    "gatsby": [r"gatsby", r"___gatsby", r"gatsby-\w+/"],
    "nuxt.js": [r"__NUXT__", r"/_nuxt/", r"nuxt-link"],
    "alpine.js": [r"alpinejs", r"x-data", r"x-init", r"x-on:"],
    "htmx": [r"htmx", r"hx-get", r"hx-post", r"hx-target", r"hx-swap"],
    "tailwindcss": [r"tailwindcss", r"@tailwind", r"tailwind"],
    "bootstrap": [r"bootstrap", r"data-bs-"],
    "foundation": [r"foundation\.js", r"foundation\.min\.js"],
    "bulma": [r"bulma\.css", r"bulma\.min\.css"],
    "materialize": [r"materialize\.css", r"materialize\.min\.css"],
    "semantic-ui": [r"semantic\.css", r"semantic\.min\.css", r"semantic-ui"],
    "uikit": [r"uikit\.js", r"uikit\.min\.js"],
    "purecss": [r"pure\.css", r"pure-min\.css"],
    "milligram": [r"milligram\.css", r"milligram\.min\.css"],
    "spectre": [r"spectre\.css", r"spectre\.min\.css"],
    "primer": [r"primer\.css", r"primer-build"],
    "picocss": [r"picocss", r"pico\.css"],
    "lodash": [r"lodash", r"_\.get", r"_\.set", r"_.merge"],
    "underscore": [r"underscore", r"_\.each", r"_\.map", r"_\.reduce"],
    "moment": [r"moment\.js", r"moment\.min\.js", r"moment-with-locales"],
    "dayjs": [r"dayjs", r"dayjs.min"],
    "date-fns": [r"date-fns", r"dateFns"],
    "luxon": [r"luxon", r"DateTime", r"luxon\.js"],
    "axios": [r"axios", r"axios\.js"],
    "fetch": [r"fetch\(", r"window\.fetch"],
    "superagent": [r"superagent", r"superagent\.js"],
    "got": [r"got\("],
    "node-fetch": [r"node-fetch"],
    "socket.io": [r"socket\.io", r"io\(", r"/socket\.io/"],
    "ws": [r"ws\("],
    "sockjs": [r"sockjs", r"SockJS"],
    "chart.js": [r"chart\.js", r"Chart\.js", r"new Chart"],
    "chartist": [r"chartist", r"Chartist"],
    "d3": [r"d3\.js", r"d3\.min\.js", r"d3\("],
    "c3": [r"c3\.js", r"c3\("],
    "highcharts": [r"highcharts", r"Highcharts"],
    "echarts": [r"echarts", r"echarts\.js"],
    "plotly": [r"plotly", r"Plotly"],
    "apexcharts": [r"apexcharts", r"ApexCharts"],
    "google-charts": [r"google\.visualization", r"googlecharts"],
    "three": [r"three\.js", r"three\.min\.js", r"THREE\."],
    "babylon": [r"babylon\.js", r"babylon\.js"],
    "pixi": [r"pixi\.js", r"PIXI\."],
    "phaser": [r"phaser\.js", r"Phaser\."],
    "cannon": [r"cannon\.js", r"CANNON\."],
    "matter": [r"matter\.js", r"Matter\."],
    "paper": [r"paper\.js", r"paper\.js"],
    "fabric": [r"fabric\.js", r"fabric\.min\.js", r"fabric\."],
    "konva": [r"konva", r"Konva"],
    "scenejs": [r"scenejs"],
    "gsap": [r"gsap", r"TweenMax", r"TimelineMax"],
    "anime": [r"anime\.js", r"anime\("],
    "velocity": [r"velocity\.js", r"Velocity"],
    "mojs": [r"mojs", r"mo\."],
    "lottie": [r"lottie", r"lottie-web"],
    "parallax": [r"parallax\.js", r"parallax\("],
    "fullpage": [r"fullpage\.js", r"fullpage\.min\.js"],
    "wow": [r"wow\.js", r"wow\.min\.js"],
    "aos": [r"aos\.js", r"aos\.css"],
    "typed": [r"typed\.js", r"typed\.min\.js"],
    "particles": [r"particles\.js", r"particles\.min\.js"],
    "owl-carousel": [r"owl\.carousel", r"owlcarousel"],
    "slick": [r"slick\.js", r"slick\.min\.js"],
    "fancybox": [r"fancybox", r"jquery\.fancybox"],
    "lightbox": [r"lightbox", r"lightbox2"],
    "magnific-popup": [r"magnific-popup", r"magnificPopup"],
    "swiper": [r"swiper", r"Swiper"],
    "isotope": [r"isotope", r"isotope\.js"],
    "masonry": [r"masonry", r"masonry\.js"],
    "packery": [r"packery"],
    "datatables": [r"datatables", r"DataTable", r"jquery\.dataTables"],
    "tablesorter": [r"tablesorter", r"tablesorter\.js"],
    "select2": [r"select2", r"select2\.js"],
    "selectize": [r"selectize", r"selectize\.js"],
    "choices": [r"choices\.js", r"choices\.min\.js"],
    "tagify": [r"tagify", r"tagify\.js"],
    "flatpickr": [r"flatpickr", r"flatpickr\.js"],
    "pickadate": [r"pickadate", r"picker\.js"],
    "bootstrap-datepicker": [r"bootstrap-datepicker", r"datepicker\.js"],
    "air-datepicker": [r"air-datepicker"],
    "duet-datepicker": [r"duet-datepicker"],
    "quill": [r"quill", r"Quill"],
    "tinymce": [r"tinymce", r"TinyMCE"],
    "ckeditor": [r"ckeditor", r"CKEDITOR", r"ClassicEditor"],
    "summernote": [r"summernote", r"Summernote"],
    "froala": [r"froala", r"FroalaEditor"],
    "prosemirror": [r"prosemirror", r"ProseMirror"],
    "codemirror": [r"codemirror", r"CodeMirror"],
    "ace": [r"ace\.js", r"ace-builds", r"ace/"],
    "monaco-editor": [r"monaco-editor", r"monaco"],
    "dropzone": [r"dropzone", r"Dropzone"],
    "fine-uploader": [r"fine-uploader", r"qq\.js"],
    "uppy": [r"uppy", r"Uppy"],
    "plupload": [r"plupload", r"plupload\.js"],
    "papa-parse": [r"papaparse", r"Papa\.parse"],
    "xlsx": [r"xlsx", r"SheetJS", r"XLSX"],
    "csv-parse": [r"csv-parse"],
    "jszip": [r"jszip", r"JSZip"],
    "pdfkit": [r"pdfkit"],
    "jspdf": [r"jspdf", r"jsPDF"],
    "pdfmake": [r"pdfmake", r"pdfMake"],
    "markdown-it": [r"markdown-it", r"markdownit"],
    "marked": [r"marked", r"marked\.js"],
    "showdown": [r"showdown", r"showdown\.js"],
    "remarkable": [r"remarkable"],
    "turndown": [r"turndown", r"TurndownService"],
    "dompurify": [r"dompurify", r"DOMPurify"],
    "sanitize-html": [r"sanitize-html"],
    "validator": [r"validator\.js"],
    "yup": [r"yup", r"Yup"],
    "joi": [r"joi", r"Joi"],
    "zod": [r"zod", r"Zod"],
    "ajv": [r"ajv", r"Ajv"],
    "imask": [r"imask", r"IMask"],
    "cleave": [r"cleave\.js", r"Cleave"],
    "nanoid": [r"nanoid", r"nanoid\("],
    "uuid": [r"uuid", r"uuid/v4"],
    "bcrypt": [r"bcrypt", r"bcrypt\.js"],
    "crypto-js": [r"crypto-js", r"CryptoJS"],
    "js-sha256": [r"js-sha256"],
    "jose": [r"jose"],
    "jsonwebtoken": [r"jsonwebtoken", r"jwt"],
    "passport": [r"passport", r"passport\.js"],
    "helmet": [r"helmet", r"helmet\.js"],
    "cors": [r"cors"],
    "compression": [r"compression"],
    "body-parser": [r"body-parser"],
    "morgan": [r"morgan"],
    "express": [r"express", r"express\.js"],
    "koa": [r"koa", r"koa\.js"],
    "fastify": [r"fastify", r"fastify\.js"],
    "hapi": [r"hapi", r"@hapi/"],
    "restify": [r"restify"],
    "grpc": [r"grpc", r"@grpc/"],
    "graphql": [r"graphql", r"GraphQL"],
    "apollo": [r"apollo", r"@apollo/"],
    "relay": [r"relay", r"react-relay"],
    "prisma": [r"prisma", r"@prisma/"],
    "typeorm": [r"typeorm"],
    "sequelize": [r"sequelize"],
    "mongoose": [r"mongoose", r"mongoose\.js"],
    "redis": [r"redis", r"ioredis"],
    "webpack": [r"webpack", r"__webpack_require__", r"webpackJsonp"],
    "vite": [r"vite", r"import\.meta\.env"],
    "rollup": [r"rollup"],
    "parcel": [r"parcel"],
    "esbuild": [r"esbuild"],
    "gulp": [r"gulp", r"gulpfile"],
    "grunt": [r"grunt", r"Gruntfile"],
    "babel": [r"babel", r"@babel/"],
    "typescript": [r"typescript", r"ts\."],
    "prettier": [r"prettier", r"prettier\.js"],
    "eslint": [r"eslint", r"\.eslintrc"],
    "jest": [r"jest", r"@jest/"],
    "mocha": [r"mocha", r"mocha\.js"],
    "chai": [r"chai", r"chai\.js"],
    "cypress": [r"cypress", r"cypress\.js"],
    "playwright": [r"playwright", r"@playwright/"],
    "puppeteer": [r"puppeteer", r"puppeteer-core"],
    "storybook": [r"storybook", r"@storybook/"],
    "nx": [r"nx\."],
    "turbo": [r"turbo", r"turborepo"],
    "lerna": [r"lerna"],
    "yarn": [r"yarn"],
    "pnpm": [r"pnpm"],
    "npm": [r"package-lock\.json"],
    "swr": [r"swr", r"useSWR"],
    "react-query": [r"react-query", r"useQuery"],
    "apollo-client": [r"@apollo/client", r"ApolloClient"],
    "urql": [r"urql"],
    "rtk-query": [r"@reduxjs/toolkit", r"createApi"],
    "zustand": [r"zustand", r"create\("],
    "jotai": [r"jotai"],
    "recoil": [r"recoil", r"RecoilRoot"],
    "valtio": [r"valtio"],
    "react-router": [r"react-router", r"BrowserRouter", r"Route"],
    "react-navigation": [r"react-navigation"],
    "reach-router": [r"@reach/router"],
    "wouter": [r"wouter"],
    "history": [r"history\.js", r"createBrowserHistory"],
    "react-helmet": [r"react-helmet", r"Helmet"],
    "react-helmet-async": [r"react-helmet-async"],
    "react-hook-form": [r"react-hook-form", r"useForm"],
    "formik": [r"formik", r"useFormik"],
    "react-final-form": [r"react-final-form"],
    "react-i18next": [r"react-i18next", r"useTranslation"],
    "react-intl": [r"react-intl", r"IntlProvider"],
    "react-select": [r"react-select", r"react-select"],
    "react-table": [r"react-table", r"useTable"],
    "react-window": [r"react-window", r"FixedSizeList"],
    "react-virtualized": [r"react-virtualized", r"AutoSizer"],
    "react-beautiful-dnd": [r"react-beautiful-dnd", r"DragDropContext"],
    "react-dnd": [r"react-dnd", r"DndProvider"],
    "react-motion": [r"react-motion", r"Motion"],
    "react-spring": [r"react-spring", r"useSpring"],
    "framer-motion": [r"framer-motion", r"motion\."],
    "react-transition-group": [r"react-transition-group", r"CSSTransition"],
    "react-bootstrap": [r"react-bootstrap"],
    "reactstrap": [r"reactstrap"],
    "antd": [r"antd", r"ant-design"],
    "material-ui": [r"@mui", r"material-ui"],
    "chakra-ui": [r"@chakra-ui", r"chakra-ui"],
    "shadcn": [r"shadcn", r"radix-ui"],
    "radix-ui": [r"@radix-ui/"],
    "skeleton": [r"@skeletonlabs/skeleton"],
    "flowbite": [r"flowbite"],
    "daisyui": [r"daisyui"],
    "headlessui": [r"@headlessui/"],
    "heroicons": [r"heroicons"],
    "phosphor-icons": [r"phosphor-icons"],
    "tabler-icons": [r"@tabler/icons"],
    "font-awesome": [r"font-awesome", r"fontawesome"],
    "material-icons": [r"material-icons", r"MaterialIcons"],
    "feather-icons": [r"feather\.js", r"feather-icons"],
    "lucide": [r"lucide-react", r"lucide-vue"],
    "ionicons": [r"ionicons", r"ionicons\.js"],
    "bootstrap-icons": [r"bootstrap-icons"],
    "remixicon": [r"remixicon", r"remixicon\.css"],
    "simple-icons": [r"simple-icons"],
    "devicon": [r"devicon"],
    "techicons": [r"techicons"],
}

CDN_PATTERNS = [
    (r"cdn\.jsdelivr\.net/(?:npm|gh)/([^/@]+)(?:@([^/]+))?", "jsdelivr"),
    (r"cdnjs\.cloudflare\.com/ajax/libs/([^/]+)/([^/]+)", "cdnjs"),
    (r"unpkg\.com/([^@]+)(?:@([^/]+))?", "unpkg"),
    (r"cdn\.jsdelivr\.net/(?:npm|comb/(?:legacy/)?)([^@/]+)(?:@([^/]+))?", "jsdelivr-comb"),
    (r"ajax\.googleapis\.com/ajax/libs/([^/]+)/([^/]+)", "googleapis"),
    (r"code\.jquery\.com/([^/]+)-(\d[\d.]*\d)", "jquery-cdn"),
    (r"stackpath\.bootstrapcdn\.com/[^/]+/([^/]+)/([^/]+)", "bootstrapcdn"),
    (r"maxcdn\.bootstrapcdn\.com/[^/]+/([^/]+)/([^/]+)", "bootstrapcdn-legacy"),
    (r"cdn\.ampproject\.org/v([\d.]+)", "amp"),
    (r"cdn\.ampproject\.org/rtv/([\d.]+)", "amp-rtv"),
    (r"cdn\.materialdesignicons\.com/([\d.]+)/", "material-design-icons"),
    (r"cdn\.fontawesome\.com/releases/v(\d[\d.]*)/", "fontawesome"),
    (r"cdn\.linearicons\.com/([\d.]+)/", "linearicons"),
    (r"cdn\.webcomponents\.org/([\d.]+)/", "webcomponents"),
    (r"cdn\.polyfill\.io/v(\d+)/", "polyfill-io"),
    (r"cdn\.yandex\.net/([^/]+)/([^/]+)", "yandex-cdn"),
    (r"cdn\.baidu\.com/([^/]+)/([^/]+)", "baidu-cdn"),
    (r"cdn\.sstatic\.net/([^/]+)/", "stackexchange-cdn"),
    (r"cdn\.discordapp\.com/([^/]+)/", "discord-cdn"),
    (r"cdn\.twitch\.tv/([^/]+)/", "twitch-cdn"),
    (r"cdn\.shopify\.com/([^/]+)/", "shopify-cdn"),
    (r"cdn\.sanity\.io/([^/]+)/", "sanity-cdn"),
    (r"cdn\.contentful\.com/([^/]+)/", "contentful-cdn"),
    (r"cdn\.storyblok\.com/([^/]+)/", "storyblok-cdn"),
    (r"cdn\.builder\.io/([^/]+)/", "builder-io-cdn"),
    (r"assets\.vercel\.com/([^/]+)/", "vercel-assets"),
    (r"assets\.netlify\.com/([^/]+)/", "netlify-assets"),
    (r"assets\.digitalocean\.com/([^/]+)/", "do-assets"),
    (r"cdn\.statically\.io/(?:gh|npm)/([^@]+)(?:@([^/]+))?", "statically"),
    (r"cdn\.skypack\.dev/([^@]+)(?:@([^/]+))?", "skypack"),
    (r"esm\.sh/([^@]+)(?:@([^/]+))?", "esm-sh"),
    (r"cdn\.esm\.dev/([^@]+)(?:@([^/]+))?", "esm-dev"),
    (r"cdn\.pxe\.com/([^/]+)/", "pxe-cdn"),
    (r"cdn\.edge\.io/([^/]+)/", "edge-io"),
    (r"cdn\.bundle\.run/([^/]+)/", "bundle-run"),
    (r"cdn\.wpack\.io/([^/]+)/", "wpack-io"),
    (r"cdn\.jspm\.dev/([^@]+)(?:@([^/]+))?", "jspm"),
    (r"cdn\.pika\.dev/([^@]+)(?:@([^/]+))?", "pika-cdn"),
    (r"assets\.glitch\.com/([^/]+)/", "glitch-assets"),
    (r"cdn\.replit\.com/([^/]+)/", "replit-cdn"),
    (r"cdn\.gitcdn\.xyz/([^/]+)/", "gitcdn"),
    (r"cdn\.rawgit\.com/([^/]+)/([^/]+)/([^/]+)", "rawgit"),
    (r"cdn\.gitprint\.com/([^/]+)/", "gitprint"),
    (r"cdn\.netlify\.com/([^/]+)/", "netlify-cdn"),
    (r"cdn\.stripe\.com/([^/]+)/", "stripe-cdn"),
    (r"cdn\.auth0\.com/([^/]+)/", "auth0-cdn"),
    (r"cdn\.firebase\.com/([^/]+)/", "firebase-cdn"),
    (r"cdn\.googleapis\.com/([^/]+)/", "googleapis-cdn"),
    (r"cdn\.salesforce\.com/([^/]+)/", "salesforce-cdn"),
    (r"cdn\.hubspot\.com/([^/]+)/", "hubspot-cdn"),
    (r"cdn\.zendesk\.com/([^/]+)/", "zendesk-cdn"),
    (r"cdn\.intercom\.io/([^/]+)/", "intercom-cdn"),
    (r"cdn\.crisp\.chat/([^/]+)/", "crisp-cdn"),
    (r"cdn\.freshchat\.com/([^/]+)/", "freshchat-cdn"),
    (r"cdn\.tawk\.to/([^/]+)/", "tawk-cdn"),
    (r"cdn\.livechat\.com/([^/]+)/", "livechat-cdn"),
    (r"cdn\.drift\.com/([^/]+)/", "drift-cdn"),
    (r"cdn\.intercomcdn\.com/([^/]+)/", "intercom-cdn2"),
    (r"cdn\.hotjar\.com/([^/]+)/", "hotjar-cdn"),
    (r"cdn\.fullstory\.com/([^/]+)/", "fullstory-cdn"),
    (r"cdn\.segment\.com/([^/]+)/", "segment-cdn"),
    (r"cdn\.amplitude\.com/([^/]+)/", "amplitude-cdn"),
    (r"cdn\.mixpanel\.com/([^/]+)/", "mixpanel-cdn"),
    (r"cdn\.heapanalytics\.com/([^/]+)/", "heap-cdn"),
    (r"cdn\.crazyegg\.com/([^/]+)/", "crazyegg-cdn"),
    (r"cdn\.luckyorange\.com/([^/]+)/", "luckyorange-cdn"),
    (r"cdn\.optimizely\.com/([^/]+)/", "optimizely-cdn"),
    (r"cdn\.vwo\.com/([^/]+)/", "vwo-cdn"),
    (r"cdn\.mouseflow\.com/([^/]+)/", "mouseflow-cdn"),
    (r"cdn\.clicktale\.com/([^/]+)/", "clicktale-cdn"),
    (r"cdn\.adsafeprotected\.com/([^/]+)/", "adsafe-cdn"),
    (r"cdn\.doubleclick\.net/([^/]+)/", "doubleclick-cdn"),
    (r"cdn\.googletagmanager\.com/([^/]+)/", "gtm-cdn"),
    (r"cdn\.google-analytics\.com/([^/]+)/", "ga-cdn"),
    (r"cdn\.facebook\.net/([^/]+)/", "facebook-cdn"),
    (r"cdn\.twitter\.com/([^/]+)/", "twitter-cdn"),
    (r"cdn\.linkedin\.com/([^/]+)/", "linkedin-cdn"),
    (r"cdn\.pinterest\.com/([^/]+)/", "pinterest-cdn"),
    (r"cdn\.instagram\.com/([^/]+)/", "instagram-cdn"),
    (r"cdn\.tiktok\.com/([^/]+)/", "tiktok-cdn"),
    (r"cdn\.snapchat\.com/([^/]+)/", "snapchat-cdn"),
    (r"cdn\.reddit\.com/([^/]+)/", "reddit-cdn"),
    (r"cdn\.quora\.com/([^/]+)/", "quora-cdn"),
    (r"cdn\.medium\.com/([^/]+)/", "medium-cdn"),
    (r"cdn\.deviantart\.com/([^/]+)/", "deviantart-cdn"),
    (r"cdn\.behance\.net/([^/]+)/", "behance-cdn"),
    (r"cdn\.dribbble\.com/([^/]+)/", "dribbble-cdn"),
    (r"cdn\.vimeo\.com/([^/]+)/", "vimeo-cdn"),
    (r"cdn\.youtube\.com/([^/]+)/", "youtube-cdn"),
    (r"cdn\.twitch\.tv/([^/]+)/", "twitch-cdn"),
]

SCRIPT_REGEX = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
LINK_REGEX = re.compile(r'<link[^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
IMPORT_REGEX = re.compile(r'(?:import|require)\s*\(?\s*["\']([^"\']+)["\']', re.IGNORECASE)
WEBPACK_CHUNK = re.compile(r'webpackJsonp|__webpack_require__|webpackChunk')
VERSION_IN_SCRIPT = re.compile(r'(?:version|v)=["\']?(\d[\d.]*\d)')
NPM_REGEX = re.compile(r'["\']_requested["\']:\s*["\'][^/]+/([^@]+)(?:@([^"\']+))?')
ESM_IMPORT_REGEX = re.compile(r'import\s+\{[^}]*\}\s*from\s*["\']([^"\']+)["\']', re.IGNORECASE)
CJS_REQUIRE_REGEX = re.compile(r'(?:const|let|var)\s+\w+\s*=\s*require\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
SOURCE_MAP_REGEX = re.compile(r'//# sourceMappingURL=(\S+)')
VERSION_JSON_REGEX = re.compile(r'"version":\s*"(\d[\d.]*\d)"')
SW_REGEX = re.compile(r'navigator\.serviceWorker')

def parse_semver(version):
    parts = re.findall(r'\d+', str(version))
    return tuple(int(p) for p in parts[:3]) if parts else (0, 0, 0)

def is_vulnerable(lib, version):
    results = []
    lib_lower = lib.lower()
    for name, versions in VULN_DB.items():
        if name in lib_lower or lib_lower in name:
            for ver_range, cvss in versions.items():
                parts = ver_range.split("-")
                if len(parts) == 2:
                    low, high = parts
                    v_parsed = parse_semver(version)
                    v_low = parse_semver(low)
                    v_high = parse_semver(high)
                    if v_low <= v_parsed <= v_high:
                        results.extend(cvss)
    return results

def extract_from_url(url):
    for pattern, source in CDN_PATTERNS:
        m = re.search(pattern, url, re.IGNORECASE)
        if m:
            groups = m.groups()
            lib = groups[0].replace("-", " ").title()
            version = groups[1] if len(groups) > 1 and groups[1] else "unknown"
            return lib, version, source
    m = re.search(r"/node_modules/([^/]+)/", url)
    if m:
        return m.group(1).replace("-", " ").title(), "", "node_modules"
    m = re.search(r"/vendor/([^/]+)/", url)
    if m:
        return m.group(1).replace("-", " ").title(), "", "vendor"
    m = re.search(r"/assets/([^/]+)\.(?:js|css)", url)
    if m:
        name = m.group(1).replace("-", " ").title()
        v = VERSION_IN_SCRIPT.search(url)
        version = v.group(1) if v else ""
        return name, version, "asset-path"
    return None, None, None

def detect_js_libraries(html):
    detected = {}
    for lib_name, patterns in JS_LIB_SIGNATURES.items():
        for pat in patterns:
            m = re.search(pat, html, re.IGNORECASE)
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
                if lib_name not in detected:
                    detected[lib_name] = {"pattern": pat, "version": version, "count": 0}
                detected[lib_name]["count"] += 1
                break
    return detected

async def crawl(target: str, client: httpx.AsyncClient):
    findings = []
    base_url = f"https://{target}" if not target.startswith("http") else target

    try:
        resp = await client.get(base_url, follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
        html = resp.text
        base_href = base_url.rstrip("/")
        scripts = SCRIPT_REGEX.findall(html)
        links = LINK_REGEX.findall(html)
        all_resources = scripts + links

        deps = {}
        for url in all_resources:
            if url.startswith("//"):
                url = "https:" + url
            elif url.startswith("/"):
                url = base_href + url
            lib, version, source = extract_from_url(url)
            if lib:
                if lib not in deps:
                    deps[lib] = {"versions": set(), "sources": set(), "urls": []}
                deps[lib]["versions"].add(version if version else "unknown")
                deps[lib]["sources"].add(source)
                deps[lib]["urls"].append(url)

        imports = IMPORT_REGEX.findall(html)
        for imp in imports:
            parts = imp.split("/")
            if parts and parts[0].startswith("@") and len(parts) > 1:
                pkg = f"{parts[0]}/{parts[1]}"
            elif parts and not parts[0].startswith(".") and not parts[0].startswith("/"):
                pkg = parts[0].split("?")[0].split("#")[0]
            else:
                continue
            if pkg and "@" in pkg:
                pkg_name, pkg_ver = pkg.rsplit("@", 1)
                if re.match(r'^\d', pkg_ver):
                    deps[pkg_name] = deps.get(pkg_name, {"versions": set(), "sources": set(), "urls": []})
                    deps[pkg_name]["versions"].add(pkg_ver)
                    deps[pkg_name]["sources"].add("esm-import")

        esm_imports = ESM_IMPORT_REGEX.findall(html)
        for ei in esm_imports:
            parts = ei.split("/")
            if parts and parts[0].startswith("@") and len(parts) > 1:
                pkg = f"{parts[0]}/{parts[1]}"
            elif parts and not parts[0].startswith(".") and not parts[0].startswith("/"):
                pkg = parts[0].split("?")[0].split("#")[0]
            else:
                continue
            if pkg not in deps:
                deps[pkg] = deps.get(pkg, {"versions": set(), "sources": set(), "urls": []})
                deps[pkg]["sources"].add("esm-import-star")

        cjs_requires = CJS_REQUIRE_REGEX.findall(html)
        for cr in cjs_requires:
            parts = cr.split("/")
            if parts and parts[0].startswith("@") and len(parts) > 1:
                pkg = f"{parts[0]}/{parts[1]}"
            elif parts and not parts[0].startswith(".") and not parts[0].startswith("/") and not parts[0].startswith("@"):
                pkg = parts[0].split("?")[0].split("#")[0]
            else:
                continue
            if pkg and pkg not in deps:
                deps[pkg] = deps.get(pkg, {"versions": set(), "sources": set(), "urls": []})
                deps[pkg]["sources"].add("cjs-require")

        detected_libs = detect_js_libraries(html)
        for lib_name, lib_info in detected_libs.items():
            if lib_name not in deps:
                deps[lib_name] = {"versions": set(), "sources": set(), "urls": []}
                deps[lib_name]["sources"].add("inline-pattern")

        for lib, info in sorted(deps.items()):
            version_str = ", ".join(sorted(v for v in info["versions"] if v and v != "unknown"))
            versions_to_check = [v for v in info["versions"] if v and v != "unknown"]
            vulns_found = []
            for v in versions_to_check:
                vulns_found.extend(is_vulnerable(lib, v))

            cvss_max = 0
            cve_refs = []
            for vuln in vulns_found:
                sev = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(vuln.get("severity", "Low"), 0)
                if sev > cvss_max:
                    cvss_max = sev
                cve_refs.append(f"{vuln['id']} ({vuln['severity']}: {vuln['desc'][:60]})")

            is_cdn = any("cdn" in s.lower() or s in ("jsdelivr", "cdnjs", "unpkg", "googleapis", "jquery-cdn") for s in info["sources"])
            is_self_hosted = any(s in ("node_modules", "vendor", "asset-path") for s in info["sources"])

            source_type = "CDN" if is_cdn else ("Self-Hosted" if is_self_hosted else "Unknown")

            if vulns_found:
                color = "red" if cvss_max >= 3 else "orange"
                threat = "High Risk" if cvss_max >= 3 else ("Elevated Risk" if cvss_max >= 2 else "Informational")
                findings.append(IntelligenceFinding(
                    entity=f"{lib} {version_str} - {len(vulns_found)} known vulnerabilities ({source_type})",
                    type="JS Dependency - Vulnerable",
                    source="JSDepsAnalyzer",
                    confidence="High",
                    color=color,
                    threat_level=threat,
                    raw_data=f"Library: {lib} | Versions: {version_str} | CVEs: {'; '.join(cve_refs)} | Source: {source_type} | Sources: {', '.join(info['sources'])}",
                    tags=["javascript", "dependency", "vulnerability", "cve", source_type.lower().replace("-", "")]
                ))
            else:
                findings.append(IntelligenceFinding(
                    entity=f"{lib} {version_str} [{source_type}]" if version_str else f"{lib} [{source_type}]",
                    type="JS Dependency",
                    source="JSDepsAnalyzer",
                    confidence="High",
                    color="emerald" if version_str and version_str != "unknown" else "slate",
                    threat_level="Informational",
                    raw_data=f"Library: {lib} | Versions: {version_str} | Sources: {', '.join(info['sources'])} | Type: {source_type}",
                    tags=["javascript", "dependency", source_type.lower().replace("-", "")]
                ))

            if vulns_found:
                for vuln in vulns_found:
                    findings.append(IntelligenceFinding(
                        entity=f"{vuln['id']}: {vuln['desc'][:100]}",
                        type=f"CVE Detail - {lib}",
                        source="JSDepsAnalyzer",
                        confidence="High",
                        color="red" if vuln['severity'] in ("Critical", "High") else "orange",
                        threat_level=vuln['severity'],
                        raw_data=f"Affected: {lib} {version_str} | CVE: {vuln['id']} | Severity: {vuln['severity']} | Description: {vuln['desc']}",
                        tags=["cve", lib.lower(), "vulnerability"]
                    ))

        has_webpack = bool(WEBPACK_CHUNK.search(html))
        if has_webpack:
            findings.append(IntelligenceFinding(
                entity="Webpack bundle detected",
                type="Build Tool: Webpack",
                source="JSDepsAnalyzer",
                confidence="High",
                color="purple",
                threat_level="Informational",
                raw_data="Webpack chunk loading detected in page source",
                tags=["build-tool", "webpack"]
            ))
            chunk_files = [s for s in scripts if "chunk" in s.lower() or "bundle" in s.lower()]
            for cf in chunk_files[:5]:
                findings.append(IntelligenceFinding(
                    entity=cf[:200],
                    type="Webpack Chunk",
                    source="JSDepsAnalyzer",
                    confidence="Medium",
                    color="slate",
                    threat_level="Informational",
                    tags=["webpack", "chunk"]
                ))

        has_sw = bool(SW_REGEX.search(html))
        if has_sw:
            sw_scripts = [s for s in scripts if "sw" in s.lower() or "service-worker" in s.lower()]
            for sw_s in sw_scripts[:3]:
                findings.append(IntelligenceFinding(
                    entity=f"Service Worker: {sw_s[:200]}",
                    type="Service Worker Detected",
                    source="JSDepsAnalyzer",
                    confidence="High",
                    color="slate",
                    threat_level="Informational",
                    tags=["pwa", "service-worker"]
                ))

        source_maps = SOURCE_MAP_REGEX.findall(html)
        for sm in source_maps[:5]:
            findings.append(IntelligenceFinding(
                entity=f"Source map: {sm[:200]}",
                type="Source Map Detected",
                source="JSDepsAnalyzer",
                confidence="Medium",
                color="orange",
                threat_level="Elevated Risk",
                raw_data=f"Source mapping URL found: {sm}",
                tags=["source-map", "debug"]
            ))

        for url in all_resources:
            if any(ext in url.lower() for ext in [".js", ".mjs", ".cjs"]):
                if url.startswith("//"):
                    url = "https:" + url
                elif url.startswith("/"):
                    url = base_href + url
                elif not url.startswith("http"):
                    continue
                try:
                    js_resp = await client.get(url, timeout=5.0,
                        headers={"User-Agent": "Mozilla/5.0"})
                    if js_resp.status_code == 200:
                        js_text = js_resp.text[:50000]
                        npm_matches = NPM_REGEX.findall(js_text)
                        for pkg_name, pkg_ver in npm_matches:
                            if pkg_name and pkg_name not in deps:
                                findings.append(IntelligenceFinding(
                                    entity=f"{pkg_name}@{pkg_ver}" if pkg_ver else pkg_name,
                                    type="NPM Dependency (from source map)",
                                    source="JSDepsAnalyzer",
                                    confidence="Medium",
                                    color="slate",
                                    threat_level="Informational",
                                    raw_data=f"Extracted from {url}",
                                    tags=["npm", "dependency"]
                                ))
                        pkg_json_version = VERSION_JSON_REGEX.search(js_text)
                        if pkg_json_version:
                            findings.append(IntelligenceFinding(
                                entity=f"Version from bundle: {pkg_json_version.group(1)}",
                                type="Package Version Disclosure",
                                source="JSDepsAnalyzer",
                                confidence="Medium",
                                color="slate",
                                threat_level="Informational",
                                raw_data=f"Version string '{pkg_json_version.group(1)}' found in {url}",
                                tags=["version", "disclosure"]
                            ))
                except Exception:
                    pass

        total_deps = len(deps)
        vuln_count = sum(1 for f in findings if "Vulnerable" in f.type)
        cdn_count = sum(1 for f in findings if "Self-Hosted" not in f.entity and "CDN" in f.source and f.type == "JS Dependency")
        self_hosted_count = sum(1 for f in findings if "Self-Hosted" in f.entity)

        findings.append(IntelligenceFinding(
            entity=f"{total_deps} JS deps found ({cdn_count} CDN, {self_hosted_count} self-hosted), {vuln_count} vulnerable",
            type="JSDeps Summary",
            source="JSDepsAnalyzer",
            confidence="High",
            color="red" if vuln_count else "emerald",
            threat_level="High Risk" if vuln_count else "Informational",
            raw_data=f"Total dependencies: {total_deps} | CDN: {cdn_count} | Self-hosted: {self_hosted_count} | Vulnerable: {vuln_count}",
            tags=["javascript", "summary"]
        ))

    except Exception as e:
        findings.append(IntelligenceFinding(
            entity=f"JS Deps error: {str(e)[:100]}",
            type="JSDeps Error",
            source="JSDepsAnalyzer",
            confidence="Low",
            color="red",
            threat_level="Informational",
            tags=["error"]
        ))

    return findings
