import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

with open("flag.txt", "rb") as flagfile:
    FLAG = flagfile.read().strip()

class MyServer:
    def __init__(self, ip, port, max_conn):
        self.tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_server.bind((ip, port))
        self.max_conn = max_conn
        self.clients = {}
        self.tcp_server.listen(self.max_conn)

    def accept_clients(self):
        while len(self.clients) <= self.max_conn:
            client_socket, client_address = self.tcp_server.accept()
            self.clients[client_address] = client_socket
            client_thread = threading.Thread(target=self.serve_client, args=(client_socket,))
            client_thread.start()

    def serve_client(self, client_socket):
        welcome = """Bienvenue sur ce service de chiffrement AES ECB !!!
Vous pouvez envoyer votre texte, il sera suivi de notre secret avant d'être chiffré !\n
"""
        client_socket.send(welcome.encode())
        key = get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_ECB)
        # Récupérer l'adresse du client
        client_address = client_socket.getpeername()
        try:
            while True:
                client_socket.send(b">>> ")
                user_input = client_socket.recv(1024).strip()
                try:
                    user_input = bytes.fromhex(user_input.decode())
                except ValueError:
                    client_socket.send("Valeur hexadécimale attendue. Fermeture de la connexion...\n".encode())
                    break
                enciphered = cipher.encrypt(pad(user_input + FLAG, 16))
                client_socket.send(enciphered.hex().encode() + b"\n")
                if not user_input:
                    continue
                

        except ConnectionResetError:
            # Gestion des erreurs de connexion
            pass
        finally:
            self.clients.pop(client_address)
            client_socket.close()


if __name__ == "__main__":
    server_socket = MyServer("0.0.0.0", 8000, max_conn=20)
    server_socket.accept_clients()
