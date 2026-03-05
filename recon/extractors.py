import regex as re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


# -----------------------------------------------------
# Regex patterns
# -----------------------------------------------------

ABSOLUTE_URL_REGEX = re.compile(r'https?://[^\s"\']+')
PROTOCOL_RELATIVE_REGEX = re.compile(r'//[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,}[^\s"\']*')

JS_ENDPOINT_REGEX = re.compile(
    r'''
    fetch\(["'](.*?)["']|
    axios\.(?:get|post|put|delete|patch)\(["'](.*?)["']|
    url:\s*["'](.*?)["']
    ''',
    re.VERBOSE
)

RELATIVE_PATH_REGEX = re.compile(
    r'["\'](\/(?:api|v\d+|auth|admin|graphql|rest)[^"\']+)["\']'
)


# -----------------------------------------------------
# HTML URL Extraction
# -----------------------------------------------------

def extract_html_links(base_url, html):

    links = set()
    soup = BeautifulSoup(html, "html.parser")

    attributes = [
        "href",
        "src",
        "action",
        "data-src",
        "data-url",
        "data-href",
        "poster"
    ]

    tags = [
        "a",
        "link",
        "script",
        "iframe",
        "source",
        "track",
        "embed",
        "object",
        "form"
    ]

    for tag in soup.find_all(tags):

        # -------------------------
        # Standard attributes
        # -------------------------

        for attr in attributes:

            val = tag.get(attr)

            if not val:
                continue

            val = val.strip()

            if val.startswith("//"):
                val = "https:" + val

            try:
                links.add(urljoin(base_url, val))
            except Exception:
                pass

        # -------------------------
        # srcset parsing
        # -------------------------

        srcset = tag.get("srcset")

        if srcset:

            for part in srcset.split(","):

                try:
                    url = part.strip().split(" ")[0]
                    links.add(urljoin(base_url, url))
                except Exception:
                    pass

        # -------------------------
        # data-* attributes
        # -------------------------

        for attr_name, attr_val in tag.attrs.items():

            if attr_name.startswith("data-"):

                if isinstance(attr_val, str):

                    if "/" in attr_val or "http" in attr_val:

                        try:
                            links.add(urljoin(base_url, attr_val.strip()))
                        except Exception:
                            pass

    # -------------------------
    # Meta refresh redirects
    # -------------------------

    meta_refresh = soup.find_all("meta", attrs={"http-equiv": "refresh"})

    for tag in meta_refresh:

        content = tag.get("content", "")

        match = re.search(r'url=(.*)', content, re.IGNORECASE)

        if match:

            try:
                links.add(urljoin(base_url, match.group(1).strip()))
            except Exception:
                pass

    # -------------------------
    # Inline script URL extraction
    # -------------------------

    for script in soup.find_all("script"):

        if script.string:

            matches = ABSOLUTE_URL_REGEX.findall(script.string)

            for m in matches:
                links.add(m)

    return clean_links(links)


# -----------------------------------------------------
# JavaScript URL Extraction
# -----------------------------------------------------

def extract_js_urls(content):

    urls = set()

    # Absolute URLs
    urls.update(ABSOLUTE_URL_REGEX.findall(content))

    # Protocol relative
    for m in PROTOCOL_RELATIVE_REGEX.findall(content):
        urls.add("https:" + m)

    # JS fetch / axios patterns
    matches = JS_ENDPOINT_REGEX.findall(content)

    for match in matches:

        for m in match:
            if m:
                urls.add(m)

    # API-like relative paths
    rel = RELATIVE_PATH_REGEX.findall(content)
    urls.update(rel)

    # Template literals
    template_pattern = r'`([^`]+)`'

    templates = re.findall(template_pattern, content)

    for tpl in templates:

        if "/" in tpl or "http" in tpl:
            urls.add(tpl)

    return clean_links(urls)


# -----------------------------------------------------
# Link Cleaning
# -----------------------------------------------------

def clean_links(links):

    cleaned = set()

    for u in links:

        if not u:
            continue

        if any(x in u for x in [
            "javascript:",
            "mailto:",
            "tel:",
            "data:"
        ]):
            continue

        if len(u) < 5:
            continue

        cleaned.add(u.strip())

    return cleaned


# -----------------------------------------------------
# Structural Template (for clustering)
# -----------------------------------------------------

def structural_template(url):

    if not isinstance(url, str):
        return None

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        return None

    try:
        parsed = urlparse(url)
    except ValueError:
        return None

    path = parsed.path

    if not path:
        path = "/"

    # normalize numbers
    path = re.sub(r'/\d+', '/{int}', path)

    # normalize hashes
    path = re.sub(r'/[0-9a-fA-F]{8,}', '/{hash}', path)

    return path