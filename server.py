import argparse
from src.Server import ServerLinux
import signal
import logging


class ServiceExit(Exception):
    """
    Custom exception which is used to trigger the clean exit
    of all running threads and the main program.
    """
    pass


def service_shutdown(signum, frame):
    logging.info('[SERVER IS SHUTTING DOWN]')
    raise ServiceExit


def main():
    parser = argparse.ArgumentParser(
        prog='pfa',
        description='src part of the final projet of python security module at ESGI Paris'
    )
    parser.add_argument('host', type=str, help='client target ip')
    parser.add_argument('port', type=int, help='client target port')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()
    server = ServerLinux(args.host, args.port)
    signal.signal(signal.SIGINT, service_shutdown)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO
    )
    try:
        server.run()
    except ServiceExit:
        server.stop()


if __name__ == '__main__':
    main()
