import argparse
from src.Client import Client


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='pfa',
        description='src part of the final project of python security module at ESGI Paris'
    )
    parser.add_argument('host', type=str, help='client target ip')
    parser.add_argument('port', type=int, help='client target port')
    args = parser.parse_args()
    client = Client(host=args.host, port=args.port)
    client.run()
