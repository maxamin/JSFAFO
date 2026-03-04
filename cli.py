import argparse
import asyncio
import os
from urllib.parse import urlparse

from recon.engine import ReconEngine


def load_targets(args):

    targets = []

    if args.url:
        targets.append(args.url.strip())

    if args.list:
        with open(args.list, "r") as f:
            targets.extend([x.strip() for x in f if x.strip()])

    return list(set(targets))


async def process_target(target, args):

    if not target.startswith("http"):
        target = "https://" + target

    domain = urlparse(target).netloc.replace(":", "_")

    target_dir = os.path.join(args.output, domain)
    os.makedirs(target_dir, exist_ok=True)

    print(f"[+] Processing: {target}")

    engine = ReconEngine(
        base_url=target,
        output=target_dir,
        args=args
    )

    await engine.run()

    print(f"[+] Completed: {target}")


async def runner(targets, args):

    for target in targets:
        if args.scope in target:
            await process_target(target, args)


def main():

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "-u",
        "--url",
        help="Single target URL"
    )

    group.add_argument(
        "-l",
        "--list",
        help="File containing list of targets"
    )

    parser.add_argument(
        "-d",
        "--depth",
        type=int,
        default=2,
        help="Crawl depth"
    )

    parser.add_argument(
        "-s",
        "--scope",
        help="Restrict crawling to domains containing keyword"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="results",
        help="Output directory"
    )

    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    targets = load_targets(args)

    print(f"[+] Loaded {len(targets)} targets")

    asyncio.run(runner(targets, args))

    print("\n[+] All targets processed successfully.")


if __name__ == "__main__":
    main()