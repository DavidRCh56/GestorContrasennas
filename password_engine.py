"""
╔══════════════════════════════════════════════════════════════╗
║  MOTOR DE GENERACIÓN DE CONTRASEÑAS v3.0                     ║
║  Generación criptográficamente segura con múltiples capas    ║
║  + Passphrases + Verificación HIBP                           ║
╚══════════════════════════════════════════════════════════════╝
"""

import secrets
import string
import hashlib
import math
import time
import logging
import urllib.request
import ssl

logger = logging.getLogger("PasswordManager.PasswordEngine")

# ═══════════════════════════════════════════════════════════════
#  DICCIONARIO ESPAÑOL PARA PASSPHRASES
# ═══════════════════════════════════════════════════════════════

SPANISH_WORDS = [
    "agua", "aire", "alto", "amor", "angel", "arbol", "arena", "azul",
    "barco", "bello", "bosque", "bravo", "brisa", "bueno", "burro",
    "cable", "campo", "carro", "casa", "cielo", "cinco", "claro", "cobre",
    "cola", "color", "comer", "costa", "crudo", "cruz", "cubo",
    "dado", "danza", "delta", "disco", "dolor", "dormir", "dulce", "duro",
    "eco", "edad", "elfo", "ente", "error", "espada", "estrella", "eterno",
    "faro", "feliz", "feria", "fiero", "final", "flor", "fuego", "fuente",
    "gallo", "gato", "genio", "globo", "golpe", "gordo", "gota", "grama",
    "hada", "hecho", "hielo", "hilo", "hoja", "horno", "humo", "hueso",
    "idea", "igloo", "impar", "indio", "iris", "isla", "ivory",
    "jabon", "jade", "jardin", "joven", "juego", "jugo", "justo",
    "karma", "kilo", "koala",
    "lago", "lava", "leon", "libro", "lima", "lobo", "luna", "luz",
    "madre", "mango", "mapa", "marco", "mesa", "miel", "monte", "mundo",
    "nada", "nave", "nieve", "ninja", "noble", "noche", "nota", "nube",
    "oasis", "ojo", "olivo", "onda", "opaco", "orden", "orilla", "oso",
    "padre", "palma", "pan", "pasto", "perro", "piano", "piedra", "pluma",
    "queso", "quinto",
    "rayo", "reina", "reloj", "rio", "roca", "rosa", "rubi", "rueda",
    "sabio", "sal", "santo", "selva", "silla", "sol", "sombra", "suave",
    "tabla", "tango", "tarde", "tigre", "torre", "trigo", "tubo", "turco",
    "uva", "union",
    "vaca", "valle", "vela", "verde", "vida", "vino", "vital", "vuelo",
    "wifi",
    "yoga", "yunque",
    "zafiro", "zarza", "zen", "zinc", "zona", "zorro",
]


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

    # ═══════════════════════════════════════════════════════════════
    #  GENERADOR DE PASSPHRASES
    # ═══════════════════════════════════════════════════════════════

    def generate_passphrase(self, word_count: int = 5, separator: str = "-",
                            capitalize: bool = False, add_number: bool = True) -> dict:
        """
        Genera una passphrase tipo Diceware con palabras en español.
        
        Args:
            word_count: Número de palabras (mínimo 4)
            separator: Separador entre palabras
            capitalize: Si poner primera letra en mayúscula
            add_number: Si añadir un número aleatorio al final
        """
        start_time = time.perf_counter()
        logger.info(f"Generando passphrase de {word_count} palabras...")

        if word_count < 3:
            raise ValueError("Mínimo 3 palabras para una passphrase segura.")
        if word_count > 12:
            raise ValueError("Máximo 12 palabras.")

        # Seleccionar palabras aleatorias
        words = [secrets.choice(SPANISH_WORDS) for _ in range(word_count)]

        if capitalize:
            words = [w.capitalize() for w in words]

        if add_number:
            words.append(str(secrets.randbelow(100)))

        passphrase = separator.join(words)

        # Entropía: log2(len(SPANISH_WORDS)) por palabra
        word_entropy = word_count * math.log2(len(SPANISH_WORDS))
        if add_number:
            word_entropy += math.log2(100)  # 2 dígitos
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        if word_entropy >= 100:
            strength = "🟢 MUY FUERTE"
        elif word_entropy >= 70:
            strength = "🟡 FUERTE"
        elif word_entropy >= 50:
            strength = "🟠 MODERADA"
        else:
            strength = "🔴 DÉBIL"

        result = {
            "password": passphrase,
            "length": len(passphrase),
            "word_count": word_count,
            "dictionary_size": len(SPANISH_WORDS),
            "entropy_bits": round(word_entropy, 2),
            "strength": strength,
            "generation_time_ms": round(elapsed_ms, 2),
            "charset_size": len(SPANISH_WORDS),
        }

        logger.info(f"Passphrase generada: {word_count} palabras, "
                    f"{result['entropy_bits']} bits, {result['strength']} ✓")
        return result

    # ═══════════════════════════════════════════════════════════════
    #  VERIFICACIÓN HIBP (Have I Been Pwned)
    # ═══════════════════════════════════════════════════════════════

    def check_hibp(self, password: str) -> dict:
        """
        Verifica si una contraseña ha sido comprometida usando la API
        k-Anonymity de Have I Been Pwned.
        
        Solo envía los primeros 5 caracteres del hash SHA-1.
        La contraseña NUNCA sale del dispositivo.
        """
        logger.info("Verificando contraseña en HIBP (k-Anonymity)...")
        
        try:
            # SHA-1 de la contraseña
            sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix = sha1[:5]
            suffix = sha1[5:]

            # Consultar API (solo envía prefix de 5 chars)
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={
                "User-Agent": "PasswordManager-v3.0",
                "Add-Padding": "true"
            })
            
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                body = response.read().decode("utf-8")

            # Buscar nuestro suffix en la respuesta
            count = 0
            for line in body.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    count = int(parts[1])
                    break

            result = {
                "compromised": count > 0,
                "breach_count": count,
                "message": (
                    f"⚠️ Esta contraseña apareció en {count:,} filtraciones de datos."
                    if count > 0 else
                    "✅ Esta contraseña NO aparece en filtraciones conocidas."
                )
            }

            logger.info(f"HIBP resultado: {'COMPROMETIDA' if count > 0 else 'SEGURA'} "
                        f"(apariciones: {count})")
            return result

        except Exception as e:
            logger.warning(f"Error consultando HIBP: {e}")
            return {
                "compromised": None,
                "breach_count": -1,
                "message": f"❌ No se pudo verificar (sin conexión a internet o error): {e}"
            }
