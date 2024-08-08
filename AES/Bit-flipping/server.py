import socket
import threading
from pwn import b64e, b64d
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

with open("flag.txt", "r") as flagfile:
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
        welcome = """
Bienvenue sur le service d'activation de l'appareil !!!
Vous devez vous connecter pour accéder au tableau de bord !
Vous pouvez dès à présent réclamer votre jeton unique de connexion
Commandes :
> t : token, pour obtenir votre jeton d'identification (OBLIGATOIRE)
> a : action, pour effectuer une action sur le tableau de bord
> q : quit, pour fermer l'application\n
"""
        client_socket.send(welcome.encode())
        key = get_random_bytes(32)
        # Récupérez l'adresse du client
        client_address = client_socket.getpeername()
        try:
            while True:
                client_socket.send(b">>> ")
                cmd = client_socket.recv(1024).decode().strip()
                if not cmd:
                    continue
                if cmd == "t":
                    token = b"role=invite&p=00"
                    iv = get_random_bytes(16)
                    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
                    enc_token = cipher.encrypt(token)
                    client_socket.send(f"Votre jeton : {b64e(iv)}:{b64e(enc_token)}\n".encode())
                elif cmd == "a":
                    client_socket.send(b"Entrez votre jeton d'authentification: ")
                    try:
                        enc_token = client_socket.recv(2048).decode().strip().split(":")
                        iv_client = b64d(enc_token[0])
                        cipher_client = AES.new(key=key, mode=AES.MODE_CBC, iv=iv_client)
                        token = cipher_client.decrypt(b64d(enc_token[1]))
                    except:
                        client_socket.send(b"Jeton invalide\n")
                    else:
                        if token == b"role=admin&p=000":
                            client_socket.send(f"Votre jeton déchiffré : {token}\nAccès autorisé, voici votre flag : {FLAG}\n".encode())
                        else:
                            client_socket.send(f"Votre jeton déchiffré : {token}\nAccès non autorisé\n".encode())
                elif cmd == "q":
                    client_socket.send(b"Bye\n")
                    break
                else:
                    client_socket.send(b"La commande n'existe pas\n")
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
