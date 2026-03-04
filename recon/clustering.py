from collections import defaultdict
from .extractors import structural_template

def cluster_urls(urls):
    clusters = defaultdict(list)

    for url in urls:
        clusters[structural_template(url)].append(url)

    return clusters