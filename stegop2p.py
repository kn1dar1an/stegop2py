#!/usr/bin/python

from client import Client


def main():
    client = Client("Some_password#%@", "192.168.8.117", "192.168.8.113")
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
