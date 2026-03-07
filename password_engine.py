"""
╔══════════════════════════════════════════════════════════════╗
║  MOTOR DE GENERACIÓN DE CONTRASEÑAS                         ║
║  Generación criptográficamente segura con múltiples capas   ║
╚══════════════════════════════════════════════════════════════╝
"""

import secrets
import string
import hashlib
import math
import time
import logging

logger = logging.getLogger("PasswordManager.PasswordEngine")


class PasswordEngine:
    """Motor de generación de contraseñas con múltiples capas de aleatoriedad."""

    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    DEFAULT_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:',.<>?/~`"
    SHUFFLE_ROUNDS = 7

    def __init__(self):
        logger.info("PasswordEngine inicializado ✓")

    def _secure_shuffle(self, char_list: list) -> list:
        """Fisher-Yates shuffle con secrets.randbelow(), múltiples rondas."""
        result = list(char_list)
        for rnd in range(self.SHUFFLE_ROUNDS):
            for i in range(len(result) - 1, 0, -1):
                j = secrets.randbelow(i + 1)
                result[i], result[j] = result[j], result[i]
        logger.debug(f"Mezcla segura: {self.SHUFFLE_ROUNDS} rondas completadas")
        return result

    def _build_charset(self, use_lower, use_upper, use_digits, use_symbols, custom_symbols) -> str:
        charset = ""
        if use_lower:
            charset += self.LOWERCASE
        if use_upper:
            charset += self.UPPERCASE
        if use_digits:
            charset += self.DIGITS
        if use_symbols:
            charset += (custom_symbols.strip() if custom_symbols.strip() else self.DEFAULT_SYMBOLS)
        # Eliminar duplicados
        seen = set()
        unique = ""
        for c in charset:
            if c not in seen:
                seen.add(c)
                unique += c
        if not unique:
            raise ValueError("Debes seleccionar al menos un tipo de carácter.")
        logger.debug(f"Charset construido: {len(unique)} caracteres únicos")
        return unique

    def generate(self, length: int, use_lower=True, use_upper=True,
                 use_digits=True, use_symbols=True, custom_symbols="") -> dict:
        start_time = time.perf_counter()
        logger.info(f"Generando contraseña de {length} caracteres...")

        if length < 4:
            raise ValueError("La longitud mínima es 4 caracteres.")
        if length > 256:
            raise ValueError("La longitud máxima es 256 caracteres.")

        charset = self._build_charset(use_lower, use_upper, use_digits, use_symbols, custom_symbols)

        # Caracteres garantizados (uno de cada tipo seleccionado)
        guaranteed = []
        if use_lower:
            guaranteed.append(secrets.choice(self.LOWERCASE))
        if use_upper:
            guaranteed.append(secrets.choice(self.UPPERCASE))
        if use_digits:
            guaranteed.append(secrets.choice(self.DIGITS))
        if use_symbols:
            syms = custom_symbols.strip() if custom_symbols.strip() else self.DEFAULT_SYMBOLS
            guaranteed.append(secrets.choice(syms))

        # Generar resto con triple selección aleatoria
        remaining = []
        for _ in range(length - len(guaranteed)):
            candidates = [secrets.choice(charset) for _ in range(3)]
            remaining.append(secrets.choice(candidates))

        # Triple mezcla
        all_chars = guaranteed + remaining
        shuffled = self._secure_shuffle(all_chars)
        for _ in range(length * 2):
            a, b = secrets.randbelow(length), secrets.randbelow(length)
            shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
        shuffled = self._secure_shuffle(shuffled)

        password = "".join(shuffled)
        entropy = length * math.log2(len(charset))
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        if entropy >= 128:
            strength = "🟢 MUY FUERTE"
        elif entropy >= 80:
            strength = "🟡 FUERTE"
        elif entropy >= 50:
            strength = "🟠 MODERADA"
        else:
            strength = "🔴 DÉBIL"

        result = {
            "password": password,
            "length": len(password),
            "charset_size": len(charset),
            "entropy_bits": round(entropy, 2),
            "strength": strength,
            "hash_prefix": hashlib.sha256(password.encode()).hexdigest()[:16],
            "generation_time_ms": round(elapsed_ms, 2),
        }

        logger.info(f"Contraseña generada: {result['length']} chars, "
                    f"{result['entropy_bits']} bits, {result['strength']}, "
                    f"{result['generation_time_ms']} ms ✓")
        return result
