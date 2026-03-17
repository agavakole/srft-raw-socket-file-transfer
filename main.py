import argparse
from config import load_config
from src.server import run_server
from src.client import run_client


def main():
    parser = argparse.ArgumentParser(description="Secure Reliable File Transfer")

    parser.add_argument(
        "--mode",
        choices=["client", "server"],
        required=True,
        help="Run as client or server"
    )
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--file",
        help="Filename to transfer (client mode only)"
    )

    args = parser.parse_args()
    cfg = load_config(args.config)

    if args.mode == "server":
        run_server(cfg)
    elif args.mode == "client":
        if not args.file:
            parser.error("--file is required in client mode")
        run_client(cfg, args.file)


if __name__ == "__main__":
    main()