import regex as re
import html
import tomllib
from urllib.parse import unquote
from urllib.parse import urljoin

# --------------------------------------------------
# Load Gitleaks rules from local TOML
# --------------------------------------------------

class GitleaksRuleEngine:

    def __init__(self, rules_path="leaks.toml"):
        self.rules = []
        self.load_rules(rules_path)

    def load_rules(self, path):

        try:

            with open(path, "rb") as f:
                parsed = tomllib.load(f)

            for rule in parsed.get("rules", []):

                regex = rule.get("regex")
                rule_id = rule.get("id")
                keywords = rule.get("keywords", [])

                if not regex:
                    continue

                try:

                    compiled = re.compile(regex, re.MULTILINE)

                    self.rules.append({
                        "id": rule_id,
                        "regex": compiled,
                        "keywords": keywords
                    })

                except re.error as e:
                    print(f"[!] Skipping rule {rule_id}: {e}")
                continue

        except Exception as e:
            print(f"[!] Failed loading Gitleaks rules: {e}")

    # ------------------------------------------------
    # Scan content
    # ------------------------------------------------

    def scan(self, content):

        findings = {}

        content_lower = content.lower()

        for rule in self.rules:

            rule_id = rule["id"]
            regex = rule["regex"]
            keywords = rule["keywords"]

            # Keyword pre-filter
            if keywords:
                if not any(k.lower() in content_lower for k in keywords):
                    continue

            matches = regex.findall(content)

            if matches:

                if isinstance(matches[0], tuple):
                    matches = ["".join(m) for m in matches]

                findings.setdefault(rule_id, set()).update(matches)

        return findings


# --------------------------------------------------
# Content normalization
# --------------------------------------------------

def normalize(content):

    content = html.unescape(content)
    content = unquote(content)

    return content


# --------------------------------------------------
# Email detection
# --------------------------------------------------

EMAIL_REGEX = re.compile(
    r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
)

def detect_emails(content):

    content = normalize(content)

    return set(EMAIL_REGEX.findall(content))


# --------------------------------------------------
# Advanced URL detection
# --------------------------------------------------

URL_REGEX = re.compile(r'https?://[^\s"\']+')

def detect_advanced_urls(content):

    return set(URL_REGEX.findall(content))

def detect_api_endpoints(content, base_url=None):


    results = set()

    # ----------------------------
    # 1️⃣ Direct Path-Based APIs
    # ----------------------------
    path_patterns = [
        r'/api(?:/v?\d+)?/[^\s"\'<>`]+',
        r'/v\d+/[^\s"\'<>`]+',
        r'/graphql[^\s"\'<>`]*',
        r'/graphiql[^\s"\'<>`]*',
        r'/oauth[^\s"\'<>`]*',
        r'/auth[^\s"\'<>`]*',
        r'/admin[^\s"\'<>`]*',
        r'/internal/[^\s"\'<>`]+',
        r'/private/[^\s"\'<>`]+',
        r'/backend/[^\s"\'<>`]+',
        r'/service/[^\s"\'<>`]+',
        r'/rest/[^\s"\'<>`]+',
        r'/webhook/[^\s"\'<>`]+',
        r'/callback/[^\s"\'<>`]+'
    ]

    for pattern in path_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for m in matches:
            try:
                if base_url:
                    results.add(urljoin(base_url, m))
                else:
                    results.add(m)
            except:
                continue

    # ----------------------------
    # 2️⃣ Full API URLs
    # ----------------------------
    full_url_pattern = r'https?://[a-zA-Z0-9\.-]+(?:/api|/v\d+|/graphql|/auth|/admin)[^\s"\']*'
    matches = re.findall(full_url_pattern, content, re.IGNORECASE)

    for m in matches:
        results.add(m)

    # ----------------------------
    # 3️⃣ JS Fetch / Axios / XHR
    # ----------------------------
    js_patterns = [
        r'fetch\(\s*[\'"`](.*?)[\'"`]',
        r'axios\.(?:get|post|put|delete|patch)\(\s*[\'"`](.*?)[\'"`]',
        r'open\(\s*[\'"`](GET|POST|PUT|DELETE|PATCH)[\'"`]\s*,\s*[\'"`](.*?)[\'"`]',
        r'url\s*:\s*[\'"`](.*?)[\'"`]'
    ]

    for pattern in js_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)

        for match in matches:
            if isinstance(match, tuple):
                for m in match:
                    if m and "/" in m:
                        try:
                            if base_url:
                                results.add(urljoin(base_url, m))
                            else:
                                results.add(m)
                        except:
                            continue
            else:
                if match and "/" in match:
                    try:
                        if base_url:
                            results.add(urljoin(base_url, match))
                        else:
                            results.add(match)
                    except:
                        continue

    # ----------------------------
    # 4️⃣ WebSocket APIs
    # ----------------------------
    ws_pattern = r'wss?://[^\s"\']+'
    ws_matches = re.findall(ws_pattern, content)

    for ws in ws_matches:
        results.add(ws)

    # ----------------------------
    # 5️⃣ Dev / Staging / Internal Subdomains
    # ----------------------------
    subdomain_api_pattern = r'https?://(?:api|dev|staging|internal|backend)\.[a-zA-Z0-9\.-]+[^\s"\']*'
    matches = re.findall(subdomain_api_pattern, content, re.IGNORECASE)

    for m in matches:
        results.add(m)

    # ----------------------------
    # 6️⃣ Clean & Deduplicate
    # ----------------------------
    cleaned = set()

    for url in results:
        if not url:
            continue

        if len(url) < 6:
            continue

        if any(noise in url for noise in [
            "__webpack",
            "node_modules",
            ".map",
            "webpackChunk"
        ]):
            continue

        cleaned.add(url.strip())

    return cleaned

# --------------------------------------------------
# Sensitive artifact detection
# --------------------------------------------------

def detect_sensitive_artifacts(content,base_url=None):

    findings = {
        "sensitive_files": set(),
        "cloud_exposures": set()
    }

    sensitive_patterns = [

    # ENV / configuration
    r'[\w\-/\.]*\.env',
    r'[\w\-/\.]*\.env\.local',
    r'[\w\-/\.]*\.env\.dev',
    r'[\w\-/\.]*\.env\.prod',
    r'[\w\-/\.]*\.env\.staging',
    r'[\w\-/\.]*\.env\.backup',
    r'[\w\-/\.]*\.env\.example',

    # Git / source control
    r'[\w\-/\.]*\.git/config',
    r'[\w\-/\.]*\.gitignore',
    r'[\w\-/\.]*\.gitmodules',
    r'[\w\-/\.]*\.gitattributes',

    # SSH / keys
    r'id_rsa',
    r'id_dsa',
    r'id_ecdsa',
    r'id_ed25519',
    r'authorized_keys',
    r'known_hosts',
    r'[\w\-/\.]*\.ssh/config',

    # WordPress
    r'wp-config\.php',
    r'wp-config\.php\.bak',
    r'wp-config\.php\.backup',
    r'wp-config\.php\.old',

    # Backup files
    r'[\w\-/\.]*\.bak',
    r'[\w\-/\.]*\.backup',
    r'[\w\-/\.]*\.old',
    r'[\w\-/\.]*\.orig',
    r'[\w\-/\.]*\.save',
    r'[\w\-/\.]*\.swp',

    # Database dumps
    r'[\w\-/\.]*\.sql',
    r'[\w\-/\.]*\.sqlite',
    r'[\w\-/\.]*\.db',
    r'[\w\-/\.]*\.dump',

    # Config files
    r'[\w\-/\.]*\.ini',
    r'[\w\-/\.]*\.conf',
    r'[\w\-/\.]*\.config',
    r'[\w\-/\.]*\.cfg',
    r'[\w\-/\.]*\.yml',
    r'[\w\-/\.]*\.yaml',
    r'[\w\-/\.]*\.toml',

    # Cloud credentials
    r'aws_credentials',
    r'credentials\.json',
    r'gcloud_credentials',
    r'[\w\-/\.]*\.aws/credentials',
    r'[\w\-/\.]*\.azure/credentials',

    # Docker / container
    r'docker-compose\.yml',
    r'docker-compose\.yaml',
    r'Dockerfile',
    r'[\w\-/\.]*\.docker/config\.json',

    # Kubernetes
    r'kubeconfig',
    r'[\w\-/\.]*\.kube/config',
    r'kubernetes\.yml',
    r'kubernetes\.yaml',

    # Private keys
    r'[\w\-/\.]*\.pem',
    r'[\w\-/\.]*\.key',
    r'[\w\-/\.]*\.crt',
    r'[\w\-/\.]*\.p12',
    r'[\w\-/\.]*\.pfx',

    # Logs
    r'[\w\-/\.]*\.log',

    # CI/CD
    r'[\w\-/\.]*\.github/workflows',
    r'[\w\-/\.]*\.gitlab-ci\.yml',
    r'jenkinsfile',

    # Package configs
    r'package-lock\.json',
    r'composer\.json',
    r'composer\.lock',
    r'Gemfile\.lock',
    r'requirements\.txt',

    # Framework configs
    r'settings\.py',
    r'config\.php',
    r'appsettings\.json',
    r'web\.config',

    # Misc sensitive
    r'passwd',
    r'shadow',
    r'[\w\-/\.]*\.htpasswd',
    r'[\w\-/\.]*\.htaccess',
    r'[\w\-/\.]*\.DS_Store',
    r'[\w\-/\.]*\.npmrc',
    r'[\w\-/\.]*\.pypirc',
    ]

    for pattern in sensitive_patterns:

        matches = re.findall(pattern, content, re.IGNORECASE)

        for match in matches:

            match = match.strip()

            # Skip empty junk
            if len(match) < 3:
                continue

            # If it's already a full URL keep it
            if match.startswith(("http://", "https://")):
                findings["sensitive_files"].add(match)
                continue

            # If relative path resolve using base_url
            if base_url:
                try:
                    full_url = urljoin(base_url, match)
                    findings["sensitive_files"].add(full_url)
                except Exception:
                    findings["sensitive_files"].add(match)
            else:
                findings["sensitive_files"].add(match)

    # ----------------------------
    # Cloud exposure detection
    # ----------------------------

    cloud_patterns = [
        r'https?://[a-z0-9.-]+\.s3\.amazonaws\.com/[^\s"\']+',
        r'https?://storage\.googleapis\.com/[^\s"\']+',
        r'https?://[a-z0-9.-]+\.blob\.core\.windows\.net/[^\s"\']+'
    ]

    for pattern in cloud_patterns:

        matches = re.findall(pattern, content, re.IGNORECASE)

        for m in matches:
            findings["cloud_exposures"].add(m)

    return findings


# --------------------------------------------------
# Initialize rule engine
# --------------------------------------------------

gitleaks_engine = GitleaksRuleEngine("leaks.toml")


# --------------------------------------------------
# Unified secret detection
# --------------------------------------------------

def detect_secrets(content):

    content = normalize(content)

    return gitleaks_engine.scan(content)