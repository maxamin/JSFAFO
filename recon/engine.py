import asyncio
import os

from .crawler import AsyncCrawler
from .dedupe import BloomDeduplicator
from .extractors import extract_html_links, extract_js_urls
from .clustering import cluster_urls

from recon.intelligence import (
    detect_emails,
    detect_secrets,
    detect_sensitive_artifacts,
    detect_advanced_urls
)

from playwright.sync_api import sync_playwright


# ----------------------------------------------------
# Dynamic Analyzer
# ----------------------------------------------------

class DynamicSecurityAnalyzer:

    def __init__(self, target, headless=True):
        self.target = target
        self.headless = headless
        self.endpoints = set()

    def dynamic_scan(self):

        with sync_playwright() as p:

            browser = p.chromium.launch(headless=self.headless)
            page = browser.new_page()

            page.on("request", lambda req: self.endpoints.add(req.url))

            page.goto(self.target, wait_until="domcontentloaded", timeout=150000)
            page.wait_for_timeout(40000)

            browser.close()

    def run(self):
        self.dynamic_scan()


# ----------------------------------------------------
# Recon Engine
# ----------------------------------------------------

class ReconEngine:

    def __init__(self, base_url, output, args=None):

        self.base_url = base_url
        self.output = output
        self.args = args

        self.dedupe = BloomDeduplicator()
        self.visited = set()

        os.makedirs(output, exist_ok=True)

        self.urls_file = os.path.join(output, "urls.txt")
        self.emails_file = os.path.join(output, "emails.txt")
        self.secrets_file = os.path.join(output, "secrets.txt")
        self.artifacts_file = os.path.join(output, "artifacts.txt")

    # ------------------------------------------------
    # Scope Validation
    # ------------------------------------------------

    def in_scope(self, url):

        if not self.args or not self.args.scope:
            return True

        try:
            return self.args.scope.lower() in url.lower()
        except:
            return False

    # ------------------------------------------------

    async def run(self):

        crawler = AsyncCrawler(concurrency=20)
        await crawler.start()

        queue = []

        if self.in_scope(self.base_url):
            queue.append(self.base_url)

        all_urls = set()
        all_emails = set()
        all_secrets = set()
        all_artifacts = set()

        while queue:

            batch = [u for u in queue[:20] if self.in_scope(u)]
            queue = queue[20:]

            results = await crawler.crawl(batch)

            for url, content, content_type in results:

                if not content:
                    continue

                if not self.in_scope(url):
                    continue

                if url not in self.visited:
                    self.visited.add(url)
                    all_urls.add(url)

                # ----------------------------------
                # Static Intelligence
                # ----------------------------------

                emails = detect_emails(content)
                all_emails.update(emails)

                secrets = detect_secrets(content)
                for k in secrets:
                    all_secrets.update(secrets[k])

                artifacts = detect_sensitive_artifacts(content,url)
                all_artifacts.update(artifacts["sensitive_files"])
                all_artifacts.update(artifacts["cloud_exposures"])

                adv_urls = detect_advanced_urls(content)

                for u in adv_urls:
                    if self.in_scope(u):
                        all_urls.add(u)

                # ----------------------------------
                # HTML extraction
                # ----------------------------------

                if "html" in content_type:

                    links = extract_html_links(url, content)

                    for link in links:

                        if not self.in_scope(link):
                            continue

                        if not self.dedupe.seen(link):

                            self.dedupe.add(link)
                            queue.append(link)

                # ----------------------------------
                # JS extraction
                # ----------------------------------

                if "javascript" in content_type or url.endswith(".js"):

                    js_urls = extract_js_urls(content)

                    for js in js_urls:

                        if self.in_scope(js):
                            all_urls.add(js)

                # ----------------------------------
                # Dynamic discovery (Playwright)
                # ----------------------------------

                if "html" in content_type:

                    try:

                        analyzer = DynamicSecurityAnalyzer(url)

                        analyzer.run()

                        for ep in analyzer.endpoints:

                            if not self.in_scope(ep):
                                continue

                            if not self.dedupe.seen(ep):

                                self.dedupe.add(ep)
                                all_urls.add(ep)

                    except Exception:
                        pass
                self.save_results(all_urls, all_emails, all_secrets, all_artifacts)
        await crawler.close()

        

    # ------------------------------------------------

    def save_results(self, urls, emails, secrets, artifacts):

        with open(self.urls_file, "w") as f:
            for u in sorted(urls):
                f.write(u + "\n")

        with open(self.emails_file, "w") as f:
            for e in sorted(emails):
                f.write(e + "\n")

        with open(self.secrets_file, "w") as f:
            for s in sorted(secrets):
                f.write(s + "\n")

        with open(self.artifacts_file, "w") as f:
            for a in sorted(artifacts):
                f.write(a + "\n")

        # ----------------------------------
        # Endpoint clustering
        # ----------------------------------

        clusters = cluster_urls(urls)

        with open(os.path.join(self.output, "clusters.txt"), "w") as f:

            for template, group in clusters.items():

                f.write(f"\n[{template}] ({len(group)})\n")

                for u in group:
                    f.write(f"  {u}\n")