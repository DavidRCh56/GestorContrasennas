"""
╔══════════════════════════════════════════════════════════════╗
║  MÓDULO DE SEGURIDAD - CryptoVault v4.0                      ║
║  Argon2id + AES-256-GCM + historial + vencimiento           ║
║  + Notas seguras + detección de duplicados                   ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import json
import hashlib
import logging
import secrets
import shutil
import time
from datetime import datetime, date

# ── Argon2id (preferido) con fallback a PBKDF2 ──
try:
    from argon2.low_level import hash_secret_raw, Type as Argon2Type
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("PasswordManager.CryptoVault")

# ── Constantes de seguridad ──
PBKDF2_ITERATIONS  = 600_000
SALT_SIZE          = 32
NONCE_SIZE         = 12
KEY_SIZE           = 32

# Versiones: 1=PBKDF2 (legado), 2=Argon2id
VAULT_VERSION_PBKDF2 = 1
VAULT_VERSION_ARGON2 = 2

# Argon2id params (OWASP 2024)
ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4

PASSWORD_HISTORY_LIMIT = 5

CATEGORIES = [
    "🌐 Social", "🏦 Banco", "💼 Trabajo", "📧 Email",
    "🎮 Gaming", "🛒 Compras", "📱 Apps", "🔧 Desarrollo",
    "📚 Educación", "🏥 Salud", "📁 Otros",
]


class CryptoVault:
    def __init__(self, vault_path: str):
        self.vault_path   = vault_path
        self._derived_key = None
        self._salt        = None
        self._vault_ver   = None
        self._credentials = []
        self._notes       = []
        logger.info(f"CryptoVault v4.0. Ruta: {vault_path}")

    # ── Propiedades ──────────────────────────────────

    @property
    def is_vault_created(self): return os.path.isfile(self.vault_path)
    @property
    def is_unlocked(self): return self._derived_key is not None
    @property
    def credentials(self): return list(self._credentials) if self.is_unlocked else []
    @property
    def notes(self): return list(self._notes) if self.is_unlocked else []
    @property
    def using_argon2(self): return self._vault_ver == VAULT_VERSION_ARGON2

    # ── KDF ──────────────────────────────────────────

    def _derive_key_pbkdf2(self, password: str, salt: bytes) -> bytes:
        logger.info(f"PBKDF2 {PBKDF2_ITERATIONS} iter…")
        t0 = time.perf_counter()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_SIZE,
                         salt=salt, iterations=PBKDF2_ITERATIONS)
        key = kdf.derive(password.encode("utf-8"))
        logger.info(f"PBKDF2 {(time.perf_counter()-t0)*1000:.0f}ms ✓")
        return key

    def _derive_key_argon2(self, password: str, salt: bytes) -> bytes:
        logger.info(f"Argon2id t={ARGON2_TIME_COST} m={ARGON2_MEMORY_COST}…")
        t0 = time.perf_counter()
        key = hash_secret_raw(
            secret=password.encode("utf-8"), salt=salt,
            time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM, hash_len=KEY_SIZE, type=Argon2Type.ID,
        )
        logger.info(f"Argon2id {(time.perf_counter()-t0)*1000:.0f}ms ✓")
        return key

    def _derive_key(self, password: str, salt: bytes, version: int = None) -> bytes:
        ver = version if version is not None else self._vault_ver
        if ver == VAULT_VERSION_ARGON2 and ARGON2_AVAILABLE:
            return self._derive_key_argon2(password, salt)
        return self._derive_key_pbkdf2(password, salt)

    def _compute_verify_hash(self, key: bytes) -> bytes:
        return hashlib.sha256(b"vault_verify_v4_" + key).digest()

    # ── AES-256-GCM ──────────────────────────────────

    def _encrypt(self, plaintext: bytes, key: bytes) -> tuple:
        nonce = secrets.token_bytes(NONCE_SIZE)
        return nonce, AESGCM(key).encrypt(nonce, plaintext, None)

    def _decrypt(self, nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    # ── Crear / Abrir / Cerrar ────────────────────────

    def create_vault(self, master_password: str) -> bool:
        if len(master_password) < 8:
            raise ValueError("La contraseña maestra debe tener al menos 8 caracteres.")
        logger.info("CREANDO BÓVEDA")
        self._salt      = secrets.token_bytes(SALT_SIZE)
        self._vault_ver = VAULT_VERSION_ARGON2 if ARGON2_AVAILABLE else VAULT_VERSION_PBKDF2
        self._derived_key = self._derive_key(master_password, self._salt, self._vault_ver)
        self._credentials = []
        self._notes       = []
        self._save_full(self._vault_ver, self._salt)
        logger.info(f"Bóveda v{self._vault_ver} creada ✓")
        return True

    def unlock(self, master_password: str) -> bool:
        logger.info("DESBLOQUEANDO BÓVEDA")
        try:
            ver, salt, stored_hash, nonce, ct = self._read_vault_file()
            self._vault_ver = ver
            key = self._derive_key(master_password, salt, ver)
            if not secrets.compare_digest(self._compute_verify_hash(key), stored_hash):
                logger.warning("Contraseña incorrecta")
                return False
            plaintext = self._decrypt(nonce, ct, key)
            data = json.loads(plaintext.decode("utf-8"))
            if isinstance(data, list):   # vault v1 legado
                self._credentials = data; self._notes = []
            else:
                self._credentials = data.get("credentials", [])
                self._notes       = data.get("notes", [])
            for c in self._credentials:
                c.setdefault("category",   "📁 Otros")
                c.setdefault("history",    [])
                c.setdefault("expires_at", None)
                c.setdefault("notes",      "")
            self._derived_key = key
            self._salt        = salt
            logger.info(f"Bóveda v{ver} desbloqueada: {len(self._credentials)} creds ✓")
            return True
        except Exception as e:
            logger.error(f"Error unlock: {e}", exc_info=True)
            self._derived_key = None
            return False

    def lock(self):
        self._derived_key = None
        self._credentials = []
        self._notes       = []
        logger.info("Bóveda bloqueada ✓")

    # ── CRUD credenciales ─────────────────────────────

    def add_credential(self, title: str, site: str, email: str, password: str,
                       notes: str = "", category: str = "📁 Otros",
                       expires_at: str = None) -> str:
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        cred_id = secrets.token_hex(8)
        self._credentials.append({
            "id": cred_id, "title": title, "site": site, "email": email,
            "password": password, "notes": notes, "category": category,
            "expires_at": expires_at, "history": [],
            "created_at": datetime.now().isoformat(),
            "modified_at": datetime.now().isoformat(),
        })
        self._save()
        return cred_id

    def update_credential(self, cred_id: str, **kwargs) -> bool:
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        for cred in self._credentials:
            if cred["id"] == cred_id:
                if "password" in kwargs and kwargs["password"] != cred["password"]:
                    hist = cred.get("history", [])
                    hist.insert(0, {"password": cred["password"],
                                    "saved_at": cred.get("modified_at", datetime.now().isoformat())})
                    cred["history"] = hist[:PASSWORD_HISTORY_LIMIT]
                for k in ("title","site","email","password","notes","category","expires_at"):
                    if k in kwargs: cred[k] = kwargs[k]
                cred["modified_at"] = datetime.now().isoformat()
                self._save()
                return True
        return False

    def delete_credential(self, cred_id: str) -> bool:
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        before = len(self._credentials)
        self._credentials = [c for c in self._credentials if c["id"] != cred_id]
        if len(self._credentials) < before:
            self._save(); return True
        return False

    # ── Análisis de seguridad ─────────────────────────

    def find_duplicates(self) -> dict:
        """Retorna {sha256_hash: [cred_id,...]} para contraseñas repetidas."""
        buckets: dict = {}
        for c in self._credentials:
            h = hashlib.sha256(c["password"].encode()).hexdigest()
            buckets.setdefault(h, []).append(c["id"])
        return {h: ids for h, ids in buckets.items() if len(ids) > 1}

    def get_expiring_soon(self, days: int = 30) -> list:
        today  = date.today()
        result = []
        for c in self._credentials:
            exp = c.get("expires_at")
            if exp:
                try:
                    delta = (date.fromisoformat(exp) - today).days
                    if delta <= days:
                        result.append((c, delta))
                except ValueError: pass
        return sorted(result, key=lambda x: x[1])

    def get_statistics(self) -> dict:
        if not self.is_unlocked:
            return {"total":0,"weak":0,"duplicates":0,"expiring":0,
                    "categories":{},"notes_count":0,"kdf":"—"}
        total = len(self._credentials)
        weak  = sum(1 for c in self._credentials
                    if len(c["password"])<10 or c["password"].isalpha() or c["password"].isdigit())
        dup_creds = sum(len(v) for v in self.find_duplicates().values())
        expiring  = len(self.get_expiring_soon(30))
        cat_counts: dict = {}
        for c in self._credentials:
            k = c.get("category","📁 Otros")
            cat_counts[k] = cat_counts.get(k,0)+1
        last_mod = None
        for c in self._credentials:
            m = c.get("modified_at")
            if m and (last_mod is None or m > last_mod): last_mod = m
        return {
            "total": total, "weak": weak, "duplicates": dup_creds,
            "expiring": expiring, "categories": cat_counts,
            "last_modified": last_mod, "notes_count": len(self._notes),
            "kdf": "Argon2id" if self._vault_ver == VAULT_VERSION_ARGON2 else "PBKDF2",
        }

    # ── Notas seguras ─────────────────────────────────

    def add_note(self, title: str, content: str, color: str = "#7c5cfc",
                 tags: str = "", pinned: bool = False) -> str:
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        nid = secrets.token_hex(8)
        self._notes.append({
            "id": nid, "title": title, "content": content, "color": color,
            "tags": tags, "pinned": pinned,
            "created_at": datetime.now().isoformat(),
            "modified_at": datetime.now().isoformat(),
        })
        self._save(); return nid

    def update_note(self, note_id: str, **kwargs) -> bool:
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        for n in self._notes:
            if n["id"] == note_id:
                for k in ("title", "content", "color", "tags", "pinned"):
                    if k in kwargs: n[k] = kwargs[k]
                n["modified_at"] = datetime.now().isoformat()
                self._save(); return True
        return False

    def delete_note(self, note_id: str) -> bool:
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        before = len(self._notes)
        self._notes = [n for n in self._notes if n["id"] != note_id]
        if len(self._notes) < before:
            self._save(); return True
        return False

    # ── Cambiar contraseña maestra ────────────────────

    def change_master_password(self, current_password: str, new_password: str) -> bool:
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        if len(new_password) < 8: raise ValueError("Mínimo 8 caracteres.")
        test_key = self._derive_key(current_password, self._salt, self._vault_ver)
        if not secrets.compare_digest(self._compute_verify_hash(test_key),
                                      self._compute_verify_hash(self._derived_key)):
            return False
        self.create_backup()
        new_ver  = VAULT_VERSION_ARGON2 if ARGON2_AVAILABLE else VAULT_VERSION_PBKDF2
        new_salt = secrets.token_bytes(SALT_SIZE)
        new_key  = self._derive_key(new_password, new_salt, new_ver)
        self._derived_key = new_key
        self._salt        = new_salt
        self._vault_ver   = new_ver
        self._save()
        logger.info(f"Contraseña maestra cambiada → KDF v{new_ver} ✓")
        return True

    # ── Export / Import ───────────────────────────────

    def export_encrypted(self, export_path: str, export_password: str) -> bool:
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        salt = secrets.token_bytes(SALT_SIZE)
        ver  = VAULT_VERSION_ARGON2 if ARGON2_AVAILABLE else VAULT_VERSION_PBKDF2
        key  = self._derive_key(export_password, salt, ver)
        payload = json.dumps({
            "version": 4, "exported_at": datetime.now().isoformat(),
            "credentials": self._credentials, "notes": self._notes,
        }).encode()
        nonce, ct = self._encrypt(payload, key)
        with open(export_path, "wb") as f:
            f.write(b"PMEX"); f.write(ver.to_bytes(1,"big"))
            f.write(salt); f.write(nonce); f.write(ct)
        logger.info(f"Export: {export_path} ✓")
        return True

    def import_encrypted(self, import_path: str, import_password: str,
                         merge: bool = True) -> int:
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        with open(import_path,"rb") as f: data = f.read()
        if data[:4] != b"PMEX": raise ValueError("Archivo no válido.")
        ver    = data[4]; offset = 5
        salt   = data[offset:offset+SALT_SIZE]; offset+=SALT_SIZE
        nonce  = data[offset:offset+NONCE_SIZE]; offset+=NONCE_SIZE
        ct     = data[offset:]
        key    = self._derive_key(import_password, salt, ver)
        parsed = json.loads(self._decrypt(nonce, ct, key).decode())
        if not merge: self._credentials=[]; self._notes=[]
        count  = 0
        for cred in parsed.get("credentials",[]):
            cred["id"]          = secrets.token_hex(8)
            cred["modified_at"] = datetime.now().isoformat()
            cred.setdefault("category","📁 Otros")
            cred.setdefault("history",[])
            cred.setdefault("expires_at",None)
            self._credentials.append(cred); count+=1
        for note in parsed.get("notes",[]):
            note["id"]          = secrets.token_hex(8)
            note["modified_at"] = datetime.now().isoformat()
            self._notes.append(note)
        self._save()
        return count

    def import_csv(self, csv_path: str, source: str = "generic") -> int:
        """Importa CSV de Chrome, Firefox, Bitwarden, LastPass, 1Password."""
        if not self.is_unlocked: raise RuntimeError("Vault bloqueado.")
        import csv as csv_mod
        MAPS = {
            "chrome":    {"name":"name",    "url":"url",       "user":"username",       "pw":"password"},
            "firefox":   {"name":"url",     "url":"url",       "user":"username",       "pw":"password"},
            "bitwarden": {"name":"name",    "url":"login_uri", "user":"login_username", "pw":"login_password"},
            "lastpass":  {"name":"name",    "url":"url",       "user":"username",       "pw":"password"},
            "1password": {"name":"Title",   "url":"URL",       "user":"Username",       "pw":"Password"},
            "generic":   {"name":"name",    "url":"url",       "user":"username",       "pw":"password"},
        }
        col = MAPS.get(source, MAPS["generic"])
        count = 0
        with open(csv_path, encoding="utf-8-sig", newline="") as f:
            for row in csv_mod.DictReader(f):
                pw = row.get(col["pw"],"").strip()
                if not pw: continue
                title    = row.get(col["name"],"").strip() or "Sin nombre"
                site     = row.get(col["url"],"").strip()
                username = row.get(col["user"],"").strip()
                notes_v  = row.get("notes", row.get("Notes", row.get("extra",""))).strip()
                self._credentials.append({
                    "id": secrets.token_hex(8), "title": title, "site": site,
                    "email": username, "password": pw, "notes": notes_v,
                    "category": "📁 Otros", "history": [], "expires_at": None,
                    "created_at": datetime.now().isoformat(),
                    "modified_at": datetime.now().isoformat(),
                })
                count += 1
        if count: self._save()
        logger.info(f"CSV ({source}): {count} importadas ✓")
        return count

    # ── Backup ────────────────────────────────────────

    def create_backup(self, backup_dir: str = None) -> str:
        if not os.path.isfile(self.vault_path): return None
        if backup_dir is None:
            backup_dir = os.path.join(os.path.dirname(self.vault_path), "backups")
        os.makedirs(backup_dir, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = os.path.join(backup_dir, f"vault_backup_{ts}.enc")
        shutil.copy2(self.vault_path, dest)
        logger.info(f"Backup: {dest} ✓")
        return dest

    # ── Persistencia ──────────────────────────────────

    def _save(self):
        payload = json.dumps({"credentials":self._credentials,"notes":self._notes}).encode("utf-8")
        nonce, ct = self._encrypt(payload, self._derived_key)
        self._write_vault_file(self._vault_ver, self._salt,
                               self._compute_verify_hash(self._derived_key), nonce, ct)

    def _save_full(self, ver, salt):
        payload = json.dumps({"credentials":[],"notes":[]}).encode("utf-8")
        nonce, ct = self._encrypt(payload, self._derived_key)
        self._write_vault_file(ver, salt, self._compute_verify_hash(self._derived_key), nonce, ct)

    def _write_vault_file(self, version, salt, verify_hash, nonce, ciphertext):
        with open(self.vault_path, "wb") as f:
            f.write(version.to_bytes(1,"big")); f.write(salt)
            f.write(verify_hash); f.write(nonce); f.write(ciphertext)

    def _read_vault_file(self) -> tuple:
        with open(self.vault_path,"rb") as f: data = f.read()
        ver=data[0]; off=1
        salt  = data[off:off+SALT_SIZE];  off+=SALT_SIZE
        vh    = data[off:off+32];          off+=32
        nonce = data[off:off+NONCE_SIZE];  off+=NONCE_SIZE
        return ver, salt, vh, nonce, data[off:]
