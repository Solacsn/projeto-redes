import socket
import json
import threading
import time
from statistics import mean
from crypto_handler import CryptoHandler

# --- Configurações ---
# A chave DEVE ser a mesma do cliente.
SECRET_KEY = b'minha_chave_super_secreta_12345!' # Chave de 32 bytes para AES-256
DISCOVERY_PORT = 6000
DATA_PORT = 6001

class Server:
    """Classe principal do servidor."""
    def __init__(self, crypto_handler):
        self.crypto_handler = crypto_handler
        self.clients = {}  # Dicionário para armazenar {ip: {data: {}, last_seen: timestamp}}
        self.lock = threading.Lock()

    def _discover_clients(self):
        """Thread para ouvir anúncios de clientes e adicioná-los à lista."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('', DISCOVERY_PORT))
            print(f"[+] Servidor de descoberta iniciado na porta UDP {DISCOVERY_PORT}.")
            while True:
                data, addr = s.recvfrom(1024)
                if data == b'CLIENT_DISCOVERY_MSG':
                    client_ip = addr[0]
                    with self.lock:
                        if client_ip not in self.clients:
                            print(f"[+] Novo cliente descoberto: {client_ip}")
                        self.clients[client_ip] = {
                            'data': self.clients.get(client_ip, {}).get('data'), # Mantém dados antigos se existirem
                            'last_seen': time.time()
                        }

    def _request_data_from_client(self, ip: str) -> bool:
        """Conecta a um cliente específico para solicitar e receber seus dados."""
        print(f"[*] Solicitando dados de {ip}...")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5) # Evita travamentos longos
                s.connect((ip, DATA_PORT))
                
                # Recebe os dados em partes
                encrypted_data = b''
                while True:
                    part = s.recv(4096)
                    if not part:
                        break
                    encrypted_data += part
                
                if not encrypted_data:
                    print(f"[!] Cliente {ip} não enviou dados.")
                    return False

            decrypted_data_bytes = self.crypto_handler.decrypt(encrypted_data)
            if not decrypted_data_bytes:
                print(f"[!] Falha ao descriptografar dados de {ip}. A chave secreta pode estar incorreta.")
                return False

            data = json.loads(decrypted_data_bytes.decode('utf-8'))

            with self.lock:
                self.clients[ip]['data'] = data
            print(f"[*] Dados de {ip} atualizados com sucesso.")
            return True

        except socket.timeout:
            print(f"[!] Timeout ao conectar com {ip}. O cliente está ocupado ou offline?")
            return False
        except ConnectionRefusedError:
            print(f"[!] Conexão recusada por {ip}. O cliente está rodando?")
            return False
        except Exception as e:
            print(f"[!] Erro ao comunicar com {ip}: {e}")
            return False

    def _refresh_all_data(self):
        """Solicita a atualização dos dados de todos os clientes conhecidos."""
        with self.lock:
            client_ips = list(self.clients.keys())

        if not client_ips:
            print("[!] Nenhum cliente descoberto para atualizar.")
            return

        print("\n--- ATUALIZANDO DADOS DE TODOS OS CLIENTES ---")
        threads = []
        for ip in client_ips:
            thread = threading.Thread(target=self._request_data_from_client, args=(ip,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        print("--- ATUALIZAÇÃO CONCLUÍDA ---")

    def _list_clients(self):
        """Exibe uma lista dos clientes descobertos."""
        with self.lock:
            if not self.clients:
                print("\nNenhum cliente descoberto. Aguardando anúncios...")
                return

            print("\n--- CLIENTES DISPONÍVEIS ---")
            for ip, info in self.clients.items():
                status = "Com dados" if info['data'] else "Sem dados (descoberto)"
                print(f"  - IP: {ip:<15} | Status: {status}")

    def _show_client_details(self):
        """Mostra os dados detalhados de um cliente escolhido."""
        client_ip = input("Digite o IP do cliente para detalhar: ").strip()
        with self.lock:
            client_info = self.clients.get(client_ip)

        if not client_info:
            print("[!] IP não encontrado na lista de clientes.")
            return
        
        # Garante que os dados estejam atualizados antes de mostrar
        if not client_info['data']:
             if not self._request_data_from_client(client_ip):
                 return # Não mostra detalhes se a atualização falhar
        
        with self.lock:
            data = self.clients[client_ip]['data']

        print(f"\n--- DETALHES DO CLIENTE: {client_ip} ---")
        print(f"  - Processadores (cores lógicos): {data['cpu_count']}")
        print(f"  - Memória RAM Livre: {data['ram_free_gb']} GB")
        print(f"  - Espaço em Disco Livre (raiz): {data['disk_free_gb']} GB")
        
        print("\n  - Interfaces de Rede:")
        for name, iface in data['interfaces'].items():
            ips = ", ".join(iface['ips']) if iface['ips'] else "Nenhum IP v4"
            print(f"    * {name:<15} | Status: {iface['status']:<10} | IPs: {ips}")
            
        print("\n  - Portas Abertas (Listen):")
        print(f"    * TCP: {data['open_ports']['tcp']}")
        print(f"    * UDP: {data['open_ports']['udp']}")
        print("--------------------------------------")

    def _show_consolidated_averages(self):
        """Calcula e exibe a média simples dos dados numéricos de todos os clientes."""
        with self.lock:
            clients_with_data = [info['data'] for info in self.clients.values() if info['data']]
        
        if not clients_with_data:
            print("\n[!] Não há dados de clientes para calcular médias. Atualize os dados primeiro.")
            return

        print(f"\n--- MÉDIA CONSOLIDADA DE {len(clients_with_data)} CLIENTE(S) ---")
        try:
            avg_cpu = mean([d['cpu_count'] for d in clients_with_data])
            avg_ram = mean([d['ram_free_gb'] for d in clients_with_data])
            avg_disk = mean([d['disk_free_gb'] for d in clients_with_data])

            print(f"  - Média de Processadores: {avg_cpu:.2f}")
            print(f"  - Média de RAM Livre: {avg_ram:.2f} GB")
            print(f"  - Média de Disco Livre: {avg_disk:.2f} GB")
        except Exception as e:
            print(f"[!] Erro ao calcular médias: {e}")
        print("-------------------------------------------------")


    def start_ui(self):
        """Inicia a interface de usuário do servidor."""
        # Inicia a thread de descoberta
        discovery_thread = threading.Thread(target=self._discover_clients, daemon=True)
        discovery_thread.start()

        time.sleep(1) # Dá um tempo para a thread de descoberta iniciar
        
        while True:
            print("\n===== PAINEL DE CONTROLE DO SERVIDOR =====")
            print("1. Listar clientes descobertos")
            print("2. Detalhar um cliente")
            print("3. Atualizar dados de todos os clientes")
            print("4. Mostrar médias consolidadas")
            print("5. Sair")
            choice = input("Escolha uma opção: ").strip()

            if choice == '1':
                self._list_clients()
            elif choice == '2':
                self._show_client_details()
            elif choice == '3':
                self._refresh_all_data()
            elif choice == '4':
                self._show_consolidated_averages()
            elif choice == '5':
                print("[-] Encerrando servidor...")
                break
            else:
                print("[!] Opção inválida. Tente novamente.")

if __name__ == "__main__":
    try:
        crypto = CryptoHandler(SECRET_KEY)
        server = Server(crypto)
        server.start_ui()
    except ValueError as e:
        print(f"Erro de inicialização: {e}")
    except KeyboardInterrupt:
        print("\n[-] Servidor encerrado pelo usuário.")
