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

    def __init__(self, base_url, output):

        self.base_url = base_url
        self.output = output

        self.dedupe = BloomDeduplicator()
        self.visited = set()

        os.makedirs(output, exist_ok=True)

        self.urls_file = os.path.join(output, "urls.txt")
        self.emails_file = os.path.join(output, "emails.txt")
        self.secrets_file = os.path.join(output, "secrets.txt")
        self.artifacts_file = os.path.join(output, "artifacts.txt")

    # ------------------------------------------------

    async def run(self):

        crawler = AsyncCrawler()

        queue = [self.base_url]

        all_urls = set()
        all_emails = set()
        all_secrets = set()
        all_artifacts = set()

        while queue:

            batch = queue[:20]
            queue = queue[20:]

            results = await crawler.crawl(batch)
            for url, content, content_type in results:
                if not content:
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

                artifacts = detect_sensitive_artifacts(content)
                all_artifacts.update(artifacts["sensitive_files"])
                all_artifacts.update(artifacts["cloud_exposures"])

                adv_urls = detect_advanced_urls(content)
                all_urls.update(adv_urls)

                # ----------------------------------
                # HTML extraction
                # ----------------------------------

                if "html" in content_type:

                    links = extract_html_links(url, content)

                    for link in links:

                        if not self.dedupe.seen(link):

                            self.dedupe.add(link)
                            queue.append(link)

                # ----------------------------------
                # JS extraction
                # ----------------------------------

                if "javascript" in content_type or url.endswith(".js"):

                    js_urls = extract_js_urls(content)
                    all_urls.update(js_urls)

                # ----------------------------------
                # Dynamic discovery (Playwright)
                # ----------------------------------

                if "html" in content_type:

                    try:

                        analyzer = DynamicSecurityAnalyzer(url)

                        analyzer.run()

                        for ep in analyzer.endpoints:

                            if not self.dedupe.seen(ep):

                                self.dedupe.add(ep)
                                all_urls.add(ep)

                    except Exception:
                        pass

        self.save_results(all_urls, all_emails, all_secrets, all_artifacts)

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