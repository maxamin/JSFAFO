from pybloom_live import BloomFilter
from .config import BLOOM_CAPACITY, ERROR_RATE

class BloomDeduplicator:
    def __init__(self):
        self.bloom = BloomFilter(
            capacity=BLOOM_CAPACITY,
            error_rate=ERROR_RATE
        )

    def seen(self, item):
        return item in self.bloom

    def add(self, item):
        self.bloom.add(item)