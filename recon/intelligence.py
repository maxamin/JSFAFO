import regex as re
import html
import tomllib
from urllib.parse import unquote


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


# --------------------------------------------------
# Sensitive artifact detection
# --------------------------------------------------

def detect_sensitive_artifacts(content):

    findings = {
        "sensitive_files": set(),
        "cloud_exposures": set()
    }

    sensitive_patterns = [

    # ENV / configuration
    r'\.env',
    r'\.env\.local',
    r'\.env\.dev',
    r'\.env\.prod',
    r'\.env\.staging',
    r'\.env\.backup',
    r'\.env\.example',

    # Git / source control
    r'\.git/config',
    r'\.gitignore',
    r'\.gitmodules',
    r'\.gitattributes',

    # SSH / keys
    r'id_rsa',
    r'id_dsa',
    r'id_ecdsa',
    r'id_ed25519',
    r'authorized_keys',
    r'known_hosts',
    r'\.ssh/config',

    # WordPress
    r'wp-config\.php',
    r'wp-config\.php\.bak',
    r'wp-config\.php\.backup',
    r'wp-config\.php\.old',

    # Backup files
    r'\.bak',
    r'\.backup',
    r'\.old',
    r'\.orig',
    r'\.save',
    r'\.swp',

    # Database dumps
    r'\.sql',
    r'\.sqlite',
    r'\.db',
    r'\.dump',

    # Config files
    r'\.ini',
    r'\.conf',
    r'\.config',
    r'\.cfg',
    r'\.yml',
    r'\.yaml',
    r'\.toml',

    # Cloud credentials
    r'aws_credentials',
    r'credentials\.json',
    r'gcloud_credentials',
    r'\.aws/credentials',
    r'\.azure/credentials',

    # Docker / container
    r'docker-compose\.yml',
    r'docker-compose\.yaml',
    r'Dockerfile',
    r'\.docker/config\.json',

    # Kubernetes
    r'kubeconfig',
    r'\.kube/config',
    r'kubernetes\.yml',
    r'kubernetes\.yaml',

    # Private keys
    r'\.pem',
    r'\.key',
    r'\.crt',
    r'\.p12',
    r'\.pfx',

    # Logs
    r'\.log',

    # CI/CD
    r'\.github/workflows',
    r'\.gitlab-ci\.yml',
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
    r'\.htpasswd',
    r'\.htaccess',
    r'\.DS_Store',
    r'\.npmrc',
    r'\.pypirc',
    ]

    for pattern in sensitive_patterns:

        matches = re.findall(pattern, content, re.IGNORECASE)

        for m in matches:
            findings["sensitive_files"].add(m)

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