import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoHandler:
    """
    Encapsula a lógica de criptografia e descriptografia usando AES-GCM.
    Requer uma chave de 16, 24 ou 32 bytes (para AES-128, AES-192 ou AES-256).
    """
    def __init__(self, key: bytes):
        if len(key) not in [16, 24, 32]:
            raise ValueError("A chave de criptografia deve ter 16, 24 ou 32 bytes.")
        self.key = key
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Criptografa os dados.
        Gera um 'nonce' (número usado uma vez) de 12 bytes, que é necessário
        para a segurança do AES-GCM e o anexa ao início do texto cifrado.
        """
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Descriptografa os dados.
        Extrai o 'nonce' dos primeiros 12 bytes e usa o restante para
        descriptografar.
        """
        if len(ciphertext) < 13:
            raise ValueError("Texto cifrado inválido ou corrompido.")
        nonce = ciphertext[:12]
        encrypted_data = ciphertext[12:]
        try:
            return self.aesgcm.decrypt(nonce, encrypted_data, None)
        except Exception as e:
            print(f"Erro ao descriptografar: {e}")
            return b'' # Retorna bytes vazios em caso de falha na autenticação
