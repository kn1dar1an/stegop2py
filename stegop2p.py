#!/usr/bin/python
import sys
import getpass
from client import Client


def main():
    if len(sys.argv) != 3:
        print("Missing parameters")
        return

    password = getpass.getpass(prompt="Enter password for decoding: ")
    client = Client(password, sys.argv[1], sys.argv[2])
    # Run Client
    try:
        # Client startup
        client.start()
    except KeyboardInterrupt:
        print("\nReceived ^C. stopping...")
        client.stop()

    return 0


if __name__ == "__main__":
    main()
