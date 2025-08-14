import socket
import psutil
import json
import time
import threading
import os
import logging
import signal
from typing import Dict, Any, Optional
from crypto_handler import CryptoHandler

# --- Configurações ---
SECRET_KEY = os.environ.get('SECRET_KEY', 'minha_chave_super_secreta_12345!').encode()  # Should be securely set!
DISCOVERY_PORT = int(os.environ.get('DISCOVERY_PORT', 6000))
DATA_PORT = int(os.environ.get('DATA_PORT', 6001))
BROADCAST_INTERVAL = int(os.environ.get('BROADCAST_INTERVAL', 10))  # Segundos

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class SystemDataCollector:
    """Classe responsável por coletar os dados do sistema."""

    def _bytes_to_gb(self, b: int) -> float:
        return round(b / (1024**3), 2)

    def get_data(self) -> Dict[str, Any]:
        """Coleta e formata todos os dados requeridos."""
        data = {
            'cpu_count': psutil.cpu_count(logical=True),
            'ram_free_gb': self._bytes_to_gb(psutil.virtual_memory().available),
            'disk_free_gb': self._bytes_to_gb(psutil.disk_usage('/').free),
            'interfaces': self._get_network_info(),
            'open_ports': self._get_open_ports()
        }
        return data

    def _get_network_info(self) -> Dict[str, Dict[str, Any]]:
        """Coleta informações de rede, incluindo IPv4/IPv6 e status das interfaces."""
        interfaces: Dict[str, Dict[str, Any]] = {}
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        for name, snicaddrs in addrs.items():
            is_up = stats[name].isup if name in stats else False
            ipv4s = [snic.address for snic in snicaddrs if snic.family == socket.AF_INET]
            ipv6s = [snic.address for snic in snicaddrs if snic.family == socket.AF_INET6]
            interfaces[name] = {
                'status': 'Ativa' if is_up else 'Desativada',
                'ipv4s': ipv4s,
                'ipv6s': ipv6s
            }
        return interfaces

    def _get_open_ports(self) -> Dict[str, list]:
        """Lista portas TCP e UDP abertas (em estado de escuta)."""
        open_ports = {'tcp': [], 'udp': []}
        try:
            connections = psutil.net_connections()
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN and conn.type == socket.SOCK_STREAM:
                    if conn.laddr.port not in open_ports['tcp']:
                        open_ports['tcp'].append(conn.laddr.port)
                elif conn.type == socket.SOCK_DGRAM and conn.laddr.port:
                    if conn.laddr.port not in open_ports['udp']:
                        open_ports['udp'].append(conn.laddr.port)
            open_ports['tcp'].sort()
            open_ports['udp'].sort()
        except Exception as e:
            logging.warning(f"Erro ao coletar portas abertas: {e}")
        return open_ports

class Client:
    """Classe principal do cliente."""

    def __init__(self, crypto_handler: CryptoHandler):
        self.crypto_handler = crypto_handler
        self.data_collector = SystemDataCollector()
        self.shutdown_event = threading.Event()

    def _discovery_thread(self):
        """Thread que anuncia a presença do cliente na rede via UDP Broadcast."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                logging.info(f"Anunciando presença na porta UDP {DISCOVERY_PORT}")
                while not self.shutdown_event.is_set():
                    message = b'CLIENT_DISCOVERY_MSG'
                    # No cliente (client.py), dentro de _discovery_thread
                    s.sendto(message, ('255.255.255.255', DISCOVERY_PORT))
                    self.shutdown_event.wait(BROADCAST_INTERVAL)
        except Exception as e:
            logging.error(f"Erro na thread de descoberta: {e}")

    def _listen_for_server(self):
        """Thread que ouve por requisições do servidor e envia os dados."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', DATA_PORT))
                s.listen()
                logging.info(f"Ouvindo por conexões do servidor na porta TCP {DATA_PORT}")
                s.settimeout(1.0)
                while not self.shutdown_event.is_set():
                    try:
                        conn, addr = s.accept()
                        with conn:
                            logging.info(f"Conexão recebida de {addr[0]} (servidor)")
                            system_data = self.data_collector.get_data()
                            json_data = json.dumps(system_data, indent=2).encode('utf-8')
                            encrypted_data = self.crypto_handler.encrypt(json_data)
                            conn.sendall(encrypted_data)
                            logging.info("Dados enviados para o servidor.")
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(f"Erro no envio de dados ao servidor: {e}")
        except Exception as e:
            logging.error(f"Erro na thread de escuta: {e}")

    def start(self):
        """Inicia as threads do cliente e aguarda encerramento gracioso."""
        threads = [
            threading.Thread(target=self._discovery_thread, daemon=True),
            threading.Thread(target=self._listen_for_server, daemon=True),
        ]
        for t in threads:
            t.start()
        logging.info("Cliente iniciado. Pressione Ctrl+C para sair.")
        try:
            while not self.shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Encerrando cliente...")
            self.shutdown_event.set()
            for t in threads:
                t.join(timeout=2)
            logging.info("Cliente encerrado.")

def main():
    # Permitir encerramento gracioso via sinal SIGTERM
    client_instance: Optional[Client] = None

    def handle_signal(signum, frame):
        if client_instance:
            logging.info("Recebido sinal de término. Encerrando cliente...")
            client_instance.shutdown_event.set()

    signal.signal(signal.SIGTERM, handle_signal)

    try:
        crypto = CryptoHandler(SECRET_KEY)
        client_instance = Client(crypto)
        client_instance.start()
    except ValueError as e:
        logging.error(f"Erro de inicialização: {e}")
    except Exception as e:
        logging.error(f"Erro inesperado: {e}")

if __name__ == "__main__":
    main()

