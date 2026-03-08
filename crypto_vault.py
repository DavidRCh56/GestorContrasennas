"""
╔══════════════════════════════════════════════════════════════╗
║  MÓDULO DE SEGURIDAD - CryptoVault v3.0                      ║
║  Cifrado AES-256-GCM + PBKDF2-HMAC-SHA256                   ║
║  + Categorías + Export/Import + Estadísticas                 ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import json
import hashlib
import logging
import secrets
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("PasswordManager.CryptoVault")

# Constantes de seguridad
PBKDF2_ITERATIONS = 600_000  # Recomendación OWASP 2024+
SALT_SIZE = 32               # 256 bits
NONCE_SIZE = 12              # 96 bits (estándar AES-GCM)
KEY_SIZE = 32                # 256 bits (AES-256)
VAULT_VERSION = 1

# Categorías predefinidas
CATEGORIES = [
    "🌐 Social",
    "🏦 Banco",
    "💼 Trabajo",
    "📧 Email",
    "🎮 Gaming",
    "🛒 Compras",
    "📱 Apps",
    "🔧 Desarrollo",
    "📚 Educación",
    "🏥 Salud",
    "📁 Otros",
]


class CryptoVault:
    """
    Bóveda cifrada con AES-256-GCM.
    
    Flujo de seguridad:
    1. El usuario proporciona una contraseña maestra
    2. Se deriva una clave AES-256 con PBKDF2-HMAC-SHA256 (600k iter + salt)
    3. Los datos se cifran con AES-256-GCM (autenticado)
    4. Se almacena: version + salt + verification_hash + nonce + ciphertext
    """

    def __init__(self, vault_path: str):
        self.vault_path = vault_path
        self._derived_key = None
        self._salt = None
        self._credentials = []
        logger.info(f"CryptoVault inicializado. Ruta: {vault_path}")

    @property
    def is_vault_created(self) -> bool:
        """Comprueba si existe un archivo de bóveda."""
        exists = os.path.isfile(self.vault_path)
        logger.debug(f"¿Vault existe?: {exists}")
        return exists

    @property
    def is_unlocked(self) -> bool:
        """Comprueba si la bóveda está desbloqueada."""
        return self._derived_key is not None

    @property
    def credentials(self) -> list:
        """Retorna las credenciales (solo si está desbloqueada)."""
        if not self.is_unlocked:
            logger.warning("Intento de acceso a credenciales con vault bloqueado")
            return []
        return list(self._credentials)

    # ── Derivación de clave ──

    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Deriva una clave AES-256 de la contraseña maestra usando PBKDF2."""
        logger.info(f"Derivando clave con PBKDF2 ({PBKDF2_ITERATIONS} iteraciones)...")
        start = time.perf_counter()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        key = kdf.derive(master_password.encode("utf-8"))

        elapsed = (time.perf_counter() - start) * 1000
        logger.info(f"Clave derivada en {elapsed:.0f} ms ✓")
        return key

    def _compute_verification_hash(self, key: bytes) -> bytes:
        """Genera un hash de verificación de la clave (para comprobar contraseña sin descifrar)."""
        return hashlib.sha256(b"vault_verify_" + key).digest()

    # ── Cifrado / Descifrado ──

    def _encrypt(self, plaintext: bytes, key: bytes) -> tuple:
        """Cifra datos con AES-256-GCM. Retorna (nonce, ciphertext)."""
        logger.debug(f"Cifrando {len(plaintext)} bytes con AES-256-GCM...")
        nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        logger.debug(f"Cifrado completado: {len(ciphertext)} bytes (nonce={len(nonce)})")
        return nonce, ciphertext

    def _decrypt(self, nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
        """Descifra datos con AES-256-GCM."""
        logger.debug(f"Descifrando {len(ciphertext)} bytes...")
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        logger.debug(f"Descifrado completado: {len(plaintext)} bytes ✓")
        return plaintext

    # ── Crear vault ──

    def create_vault(self, master_password: str) -> bool:
        """Crea una nueva bóveda con la contraseña maestra proporcionada."""
        logger.info("=" * 50)
        logger.info("CREANDO NUEVA BÓVEDA")
        logger.info("=" * 50)

        if len(master_password) < 8:
            logger.error("Contraseña maestra demasiado corta (mínimo 8)")
            raise ValueError("La contraseña maestra debe tener al menos 8 caracteres.")

        try:
            # Generar salt aleatorio
            self._salt = secrets.token_bytes(SALT_SIZE)
            logger.debug(f"Salt generado: {len(self._salt)} bytes")

            # Derivar clave
            self._derived_key = self._derive_key(master_password, self._salt)

            # Hash de verificación
            verify_hash = self._compute_verification_hash(self._derived_key)

            # Datos iniciales vacíos
            self._credentials = []
            plaintext = json.dumps(self._credentials).encode("utf-8")

            # Cifrar
            nonce, ciphertext = self._encrypt(plaintext, self._derived_key)

            # Escribir archivo
            self._write_vault_file(self._salt, verify_hash, nonce, ciphertext)

            logger.info("Bóveda creada exitosamente ✓")
            return True

        except Exception as e:
            logger.critical(f"Error al crear bóveda: {e}", exc_info=True)
            self._derived_key = None
            self._salt = None
            raise

    # ── Desbloquear vault ──

    def unlock(self, master_password: str) -> bool:
        """Desbloquea la bóveda con la contraseña maestra."""
        logger.info("=" * 50)
        logger.info("DESBLOQUEANDO BÓVEDA")
        logger.info("=" * 50)

        try:
            salt, stored_hash, nonce, ciphertext = self._read_vault_file()
            self._salt = salt

            # Derivar clave
            key = self._derive_key(master_password, salt)

            # Verificar contraseña
            computed_hash = self._compute_verification_hash(key)
            if not secrets.compare_digest(computed_hash, stored_hash):
                logger.warning("Contraseña maestra incorrecta — hash no coincide")
                return False

            # Descifrar
            plaintext = self._decrypt(nonce, ciphertext, key)
            self._credentials = json.loads(plaintext.decode("utf-8"))
            
            # Migrar credenciales antiguas (añadir campo category si no existe)
            for cred in self._credentials:
                if "category" not in cred:
                    cred["category"] = "📁 Otros"
            
            self._derived_key = key

            logger.info(f"Bóveda desbloqueada: {len(self._credentials)} credenciales cargadas ✓")
            return True

        except Exception as e:
            logger.error(f"Error al desbloquear bóveda: {e}", exc_info=True)
            self._derived_key = None
            return False

    # ── Lock vault ──

    def lock(self):
        """Bloquea la bóveda, limpiando datos sensibles de memoria."""
        logger.info("Bloqueando bóveda...")
        self._derived_key = None
        self._credentials = []
        logger.info("Bóveda bloqueada ✓")

    # ── CRUD de credenciales ──

    def add_credential(self, title: str, site: str, email: str, password: str,
                       notes: str = "", category: str = "📁 Otros") -> dict:
        """Añade una credencial y guarda la bóveda."""
        if not self.is_unlocked:
            raise RuntimeError("La bóveda debe estar desbloqueada.")

        credential = {
            "id": secrets.token_hex(8),
            "title": title,
            "site": site,
            "email": email,
            "password": password,
            "notes": notes,
            "category": category,
            "created_at": datetime.now().isoformat(),
            "modified_at": datetime.now().isoformat(),
        }

        self._credentials.append(credential)
        self._save()
        logger.info(f"Credencial añadida: '{title}' [{category}] (ID: {credential['id']}) ✓")
        return credential

    def update_credential(self, cred_id: str, **kwargs) -> bool:
        """Actualiza una credencial existente."""
        if not self.is_unlocked:
            raise RuntimeError("La bóveda debe estar desbloqueada.")

        for cred in self._credentials:
            if cred["id"] == cred_id:
                for key in ("title", "site", "email", "password", "notes", "category"):
                    if key in kwargs:
                        cred[key] = kwargs[key]
                cred["modified_at"] = datetime.now().isoformat()
                self._save()
                logger.info(f"Credencial {cred_id} actualizada ✓")
                return True

        logger.warning(f"Credencial {cred_id} no encontrada")
        return False

    def delete_credential(self, cred_id: str) -> bool:
        """Elimina una credencial."""
        if not self.is_unlocked:
            raise RuntimeError("La bóveda debe estar desbloqueada.")

        before = len(self._credentials)
        self._credentials = [c for c in self._credentials if c["id"] != cred_id]

        if len(self._credentials) < before:
            self._save()
            logger.info(f"Credencial {cred_id} eliminada ✓")
            return True

        logger.warning(f"Credencial {cred_id} no encontrada para eliminar")
        return False

    # ── Estadísticas ──

    def get_statistics(self) -> dict:
        """Retorna estadísticas de la bóveda."""
        if not self.is_unlocked:
            return {"total": 0, "weak_passwords": 0, "categories": {}}

        total = len(self._credentials)
        
        # Contraseñas débiles (< 10 caracteres o sin variedad)
        weak = 0
        for cred in self._credentials:
            pw = cred.get("password", "")
            if len(pw) < 10:
                weak += 1
            elif pw.isalpha() or pw.isdigit():
                weak += 1
        
        # Conteo por categorías
        cat_counts = {}
        for cred in self._credentials:
            cat = cred.get("category", "📁 Otros")
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        # Última modificación
        last_modified = None
        for cred in self._credentials:
            mod = cred.get("modified_at")
            if mod and (last_modified is None or mod > last_modified):
                last_modified = mod

        return {
            "total": total,
            "weak_passwords": weak,
            "categories": cat_counts,
            "last_modified": last_modified,
        }

    # ── Export / Import cifrados ──

    def export_encrypted(self, export_path: str, export_password: str) -> bool:
        """Exporta las credenciales a un archivo cifrado independiente."""
        if not self.is_unlocked:
            raise RuntimeError("La bóveda debe estar desbloqueada.")

        logger.info(f"Exportando {len(self._credentials)} credenciales...")

        try:
            salt = secrets.token_bytes(SALT_SIZE)
            key = self._derive_key(export_password, salt)

            export_data = {
                "version": VAULT_VERSION,
                "exported_at": datetime.now().isoformat(),
                "credentials": self._credentials,
            }
            plaintext = json.dumps(export_data).encode("utf-8")
            nonce, ciphertext = self._encrypt(plaintext, key)

            with open(export_path, "wb") as f:
                f.write(b"PMEX")  # Magic bytes for Password Manager Export
                f.write(VAULT_VERSION.to_bytes(1, "big"))
                f.write(salt)
                f.write(nonce)
                f.write(ciphertext)

            logger.info(f"Exportación completada: {export_path} ✓")
            return True

        except Exception as e:
            logger.error(f"Error exportando: {e}", exc_info=True)
            raise

    def import_encrypted(self, import_path: str, import_password: str,
                         merge: bool = True) -> int:
        """
        Importa credenciales desde un archivo cifrado.
        
        Args:
            import_path: Ruta del archivo a importar
            import_password: Contraseña del archivo de exportación
            merge: Si True, añade las credenciales. Si False, reemplaza todas.
        
        Returns:
            Número de credenciales importadas.
        """
        if not self.is_unlocked:
            raise RuntimeError("La bóveda debe estar desbloqueada.")

        logger.info(f"Importando credenciales desde {import_path}...")

        try:
            with open(import_path, "rb") as f:
                data = f.read()

            # Verificar magic bytes
            if data[:4] != b"PMEX":
                raise ValueError("El archivo no es una exportación válida del gestor.")

            version = data[4]
            offset = 5
            salt = data[offset:offset + SALT_SIZE]
            offset += SALT_SIZE
            nonce = data[offset:offset + NONCE_SIZE]
            offset += NONCE_SIZE
            ciphertext = data[offset:]

            key = self._derive_key(import_password, salt)
            plaintext = self._decrypt(nonce, ciphertext, key)
            export_data = json.loads(plaintext.decode("utf-8"))

            imported_creds = export_data.get("credentials", [])
            
            if not merge:
                self._credentials = []

            # Importar con nuevos IDs para evitar conflictos
            count = 0
            for cred in imported_creds:
                cred["id"] = secrets.token_hex(8)  # Nuevo ID
                cred["modified_at"] = datetime.now().isoformat()
                if "category" not in cred:
                    cred["category"] = "📁 Otros"
                self._credentials.append(cred)
                count += 1

            self._save()
            logger.info(f"Importación completada: {count} credenciales ✓")
            return count

        except Exception as e:
            logger.error(f"Error importando: {e}", exc_info=True)
            raise

    # ── Persistencia ──

    def _save(self):
        """Cifra y guarda todas las credenciales."""
        logger.debug("Guardando bóveda cifrada...")
        plaintext = json.dumps(self._credentials).encode("utf-8")
        nonce, ciphertext = self._encrypt(plaintext, self._derived_key)
        verify_hash = self._compute_verification_hash(self._derived_key)
        self._write_vault_file(self._salt, verify_hash, nonce, ciphertext)
        logger.debug("Bóveda guardada ✓")

    def _write_vault_file(self, salt: bytes, verify_hash: bytes,
                          nonce: bytes, ciphertext: bytes):
        """Escribe el archivo de bóveda con formato binario."""
        logger.debug(f"Escribiendo vault: salt={len(salt)}B, hash={len(verify_hash)}B, "
                     f"nonce={len(nonce)}B, data={len(ciphertext)}B")
        with open(self.vault_path, "wb") as f:
            # Header: version (1 byte)
            f.write(VAULT_VERSION.to_bytes(1, "big"))
            # Salt (32 bytes)
            f.write(salt)
            # Verification hash (32 bytes)
            f.write(verify_hash)
            # Nonce (12 bytes)
            f.write(nonce)
            # Ciphertext (variable)
            f.write(ciphertext)

    def _read_vault_file(self) -> tuple:
        """Lee y parsea el archivo de bóveda."""
        logger.debug("Leyendo archivo de bóveda...")
        with open(self.vault_path, "rb") as f:
            data = f.read()

        version = data[0]
        if version != VAULT_VERSION:
            raise ValueError(f"Versión de vault no soportada: {version}")

        offset = 1
        salt = data[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        verify_hash = data[offset:offset + 32]
        offset += 32
        nonce = data[offset:offset + NONCE_SIZE]
        offset += NONCE_SIZE
        ciphertext = data[offset:]

        logger.debug(f"Vault leído: v{version}, salt={len(salt)}B, "
                     f"nonce={len(nonce)}B, data={len(ciphertext)}B")
        return salt, verify_hash, nonce, ciphertext
