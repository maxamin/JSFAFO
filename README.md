# JS FAFO

## JavaScript Framework for Automated Footprinting & Observation

**JS FAFO** is an advanced reconnaissance framework designed to
automatically discover web assets, JavaScript endpoints, API routes,
sensitive artifacts, and intelligence signals from target web
applications.

The project combines **asynchronous crawling**, **JavaScript static
analysis**, **dynamic browser instrumentation**, and **security
intelligence extraction** to build a comprehensive map of a target's
attack surface.

JS FAFO is designed for **security researchers, bug bounty hunters, and
penetration testers** who need a powerful and extensible reconnaissance
engine.

------------------------------------------------------------------------

# Features

## Advanced Crawling

-   Asynchronous high-performance crawler using `aiohttp`
-   Intelligent queue-based crawling
-   URL deduplication using Bloom filters
-   Automatic scope control
-   Depth-based crawling

## JavaScript Intelligence Extraction

-   Endpoint discovery inside JS
-   API route detection
-   Template literal reconstruction
-   Dynamic endpoint inference

## HTML Asset Discovery

-   Extract links from:
    -   `href`
    -   `src`
    -   `srcset`
    -   `data-*` attributes
    -   forms
    -   meta refresh
-   DOM link extraction

## Dynamic Analysis

Using Playwright instrumentation:

-   Capture API calls
-   Capture XHR/fetch requests
-   Detect WebSocket endpoints
-   Discover dynamically loaded routes

## Security Intelligence Engine

Extracts valuable security signals from responses:

-   Emails
-   API keys
-   JWT tokens
-   OAuth tokens
-   Cloud storage exposure
-   Secrets using **Gitleaks rules**

## Sensitive Artifact Detection

Detects exposed infrastructure artifacts such as:

.env\
.git/config\
id_rsa\
docker-compose.yml\
kubeconfig\
credentials.json\
backup.sql\
wp-config.php\
.htpasswd

## Attack Surface Mapping

Automatically identifies:

-   API endpoints
-   GraphQL routes
-   WebSockets
-   Versioned APIs
-   Internal services
-   Hidden backend paths

------------------------------------------------------------------------

# Architecture

JS-FAFO │ ├── crawler\
│ └── async crawler engine\
│ ├── extractors\
│ ├── HTML link extraction\
│ └── JS endpoint extraction\
│ ├── intelligence\
│ ├── secret detection\
│ ├── artifact detection\
│ └── gitleaks rule engine\
│ ├── clustering\
│ └── endpoint structure grouping\
│ ├── dynamic\
│ └── Playwright dynamic scanner\
│ └── recon engine\
└── orchestration layer

------------------------------------------------------------------------

# Installation

Clone the repository:

git clone https://github.com/yourname/js-fafo.git\
cd js-fafo

Install dependencies:

pip install -r requirements.txt

Install Playwright browsers:

playwright install

------------------------------------------------------------------------

# Usage

## Scan a single target

python main.py -u https://target.com

## Scan multiple targets

python main.py -l targets.txt

## Advanced scan

python main.py -u https://target.com -d 3 -s target.com

------------------------------------------------------------------------

# CLI Options

-u --url Target URL\
-l --list File containing target URLs\
-d --depth Crawl depth (default: 2)\
-s --scope Domain scope restriction\
-o --output Output directory

------------------------------------------------------------------------

# Output Structure

results/ │ ├── target.com/ │ ├── urls.txt │ ├── emails.txt │ ├──
secrets.txt │ ├── sensitive.txt │ └── clusters.txt

urls.txt → discovered endpoints\
emails.txt → extracted emails\
secrets.txt → detected credentials\
sensitive.txt → exposed artifacts\
clusters.txt → endpoint structure clusters

------------------------------------------------------------------------

# Intelligence Detection

JS FAFO integrates **Gitleaks rules** to detect secrets such as:

-   Twitter tokens
-   Stripe API keys
-   GitHub tokens
-   Slack tokens
-   OAuth secrets
-   Cloud provider credentials

Rules are loaded from:

leaks.toml

Reference:\
https://github.com/gitleaks/gitleaks

------------------------------------------------------------------------

# Dynamic Security Analysis

JS FAFO includes a dynamic browser scanner powered by Playwright.

It captures:

-   Fetch calls
-   XHR requests
-   WebSocket connections
-   dynamically generated endpoints

This allows detection of **hidden APIs not visible in static analysis**.

------------------------------------------------------------------------

# Example Workflow

1.  Start crawl\
2.  Discover HTML links\
3.  Extract JS endpoints\
4.  Parse JavaScript routes\
5.  Run dynamic browser scan\
6.  Extract secrets and artifacts\
7.  Cluster endpoints\
8.  Save intelligence report

------------------------------------------------------------------------

# Project Goals

JS FAFO aims to become a **next-generation reconnaissance framework**
capable of:

-   automated attack surface discovery
-   intelligent endpoint detection
-   infrastructure intelligence extraction
-   scalable asynchronous scanning

------------------------------------------------------------------------

# Roadmap

Future improvements planned:

-   AST-based JavaScript parsing
-   HAR traffic parsing
-   automatic fuzz seed generation
-   parameter type inference
-   endpoint graph visualization
-   distributed scanning
-   WAF fingerprinting

------------------------------------------------------------------------

# Ethical Use

This tool is intended for:

-   authorized penetration testing
-   bug bounty research
-   security auditing

Do **not** use this tool against systems without permission.

------------------------------------------------------------------------

# License

MIT License

------------------------------------------------------------------------

# FAFO

**Framework for Automated Footprinting & Observation**

A reconnaissance engine built to reveal the hidden attack surface of
modern web applications.
