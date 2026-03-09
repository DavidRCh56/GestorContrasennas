"""
╔══════════════════════════════════════════════════════════════╗
║  MOTOR DE GENERACIÓN DE CONTRASEÑAS v4.0                     ║
║  Contraseñas + Passphrases + PINs + Verificación HIBP        ║
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

SPANISH_WORDS = [
    "agua","aire","alto","amor","angel","arbol","arena","azul",
    "barco","bello","bosque","bravo","brisa","bueno","burro",
    "cable","campo","carro","casa","cielo","cinco","claro","cobre",
    "cola","color","comer","costa","crudo","cruz","cubo",
    "dado","danza","delta","disco","dolor","dormir","dulce","duro",
    "eco","edad","elfo","ente","error","espada","estrella","eterno",
    "faro","feliz","feria","fiero","final","flor","fuego","fuente",
    "gallo","gato","genio","globo","golpe","gordo","gota","grama",
    "hada","hecho","hielo","hilo","hoja","horno","humo","hueso",
    "idea","igloo","impar","indio","iris","isla","ivory",
    "jabon","jade","jardin","joven","juego","jugo","justo",
    "karma","kilo","koala",
    "lago","lava","leon","libro","lima","lobo","luna","luz",
    "madre","mango","mapa","marco","mesa","miel","monte","mundo",
    "nada","nave","nieve","ninja","noble","noche","nota","nube",
    "oasis","ojo","olivo","onda","opaco","orden","orilla","oso",
    "padre","palma","pan","pasto","perro","piano","piedra","pluma",
    "queso","quinto",
    "rayo","reina","reloj","rio","roca","rosa","rubi","rueda",
    "sabio","sal","santo","selva","silla","sol","sombra","suave",
    "tabla","tango","tarde","tigre","torre","trigo","tubo","turco",
    "uva","union",
    "vaca","valle","vela","verde","vida","vino","vital","vuelo",
    "wifi","yoga","yunque",
    "zafiro","zarza","zen","zinc","zona","zorro",
]


class PasswordEngine:
    LOWERCASE        = string.ascii_lowercase
    UPPERCASE        = string.ascii_uppercase
    DIGITS           = string.digits
    DEFAULT_SYMBOLS  = "!@#$%^&*()-_=+[]{}|;:',.<>?/~`"
    SHUFFLE_ROUNDS   = 7

    def __init__(self):
        logger.info("PasswordEngine v4.0 inicializado ✓")

    # ── Shuffle seguro ────────────────────────────────

    def _secure_shuffle(self, lst: list) -> list:
        result = list(lst)
        for _ in range(self.SHUFFLE_ROUNDS):
            for i in range(len(result)-1, 0, -1):
                j = secrets.randbelow(i+1)
                result[i], result[j] = result[j], result[i]
        return result

    def _build_charset(self, use_lower, use_upper, use_digits, use_symbols, custom_symbols) -> str:
        charset = ""
        if use_lower:   charset += self.LOWERCASE
        if use_upper:   charset += self.UPPERCASE
        if use_digits:  charset += self.DIGITS
        if use_symbols: charset += (custom_symbols.strip() if custom_symbols.strip() else self.DEFAULT_SYMBOLS)
        seen = set(); unique = ""
        for c in charset:
            if c not in seen: seen.add(c); unique += c
        if not unique: raise ValueError("Selecciona al menos un tipo de carácter.")
        return unique

    # ── Contraseña ────────────────────────────────────

    def generate(self, length: int, use_lower=True, use_upper=True,
                 use_digits=True, use_symbols=True, custom_symbols="") -> dict:
        t0 = time.perf_counter()
        if length < 4:   raise ValueError("Longitud mínima: 4 caracteres.")
        if length > 256: raise ValueError("Longitud máxima: 256 caracteres.")
        charset = self._build_charset(use_lower, use_upper, use_digits, use_symbols, custom_symbols)

        guaranteed = []
        if use_lower:   guaranteed.append(secrets.choice(self.LOWERCASE))
        if use_upper:   guaranteed.append(secrets.choice(self.UPPERCASE))
        if use_digits:  guaranteed.append(secrets.choice(self.DIGITS))
        if use_symbols:
            syms = custom_symbols.strip() if custom_symbols.strip() else self.DEFAULT_SYMBOLS
            guaranteed.append(secrets.choice(syms))

        remaining = [secrets.choice([secrets.choice(charset) for _ in range(3)])
                     for _ in range(length - len(guaranteed))]

        all_chars = guaranteed + remaining
        shuffled  = self._secure_shuffle(all_chars)
        for _ in range(length*2):
            a, b = secrets.randbelow(length), secrets.randbelow(length)
            shuffled[a], shuffled[b] = shuffled[b], shuffled[a]
        shuffled = self._secure_shuffle(shuffled)

        password = "".join(shuffled)
        entropy  = length * math.log2(len(charset))
        elapsed  = (time.perf_counter()-t0)*1000

        strength = ("🟢 MUY FUERTE" if entropy>=128 else
                    "🟡 FUERTE"     if entropy>=80  else
                    "🟠 MODERADA"   if entropy>=50  else "🔴 DÉBIL")

        return {"password": password, "length": len(password),
                "charset_size": len(charset), "entropy_bits": round(entropy,2),
                "strength": strength, "generation_time_ms": round(elapsed,2),
                "hash_prefix": hashlib.sha256(password.encode()).hexdigest()[:16]}

    # ── Passphrase ────────────────────────────────────

    def generate_passphrase(self, word_count: int = 5, separator: str = "-",
                            capitalize: bool = False, add_number: bool = True) -> dict:
        t0 = time.perf_counter()
        if word_count < 3:  raise ValueError("Mínimo 3 palabras.")
        if word_count > 12: raise ValueError("Máximo 12 palabras.")

        words = [secrets.choice(SPANISH_WORDS) for _ in range(word_count)]
        if capitalize: words = [w.capitalize() for w in words]
        if add_number: words.append(str(secrets.randbelow(100)))
        passphrase = separator.join(words)

        entropy = word_count * math.log2(len(SPANISH_WORDS))
        if add_number: entropy += math.log2(100)
        elapsed = (time.perf_counter()-t0)*1000

        strength = ("🟢 MUY FUERTE" if entropy>=100 else
                    "🟡 FUERTE"     if entropy>=70  else
                    "🟠 MODERADA"   if entropy>=50  else "🔴 DÉBIL")

        return {"password": passphrase, "length": len(passphrase),
                "word_count": word_count, "dictionary_size": len(SPANISH_WORDS),
                "entropy_bits": round(entropy,2), "strength": strength,
                "generation_time_ms": round(elapsed,2), "charset_size": len(SPANISH_WORDS)}

    # ── PIN numérico ──────────────────────────────────

    def generate_pin(self, length: int = 6, avoid_sequences: bool = True,
                     avoid_repeats: bool = True, add_separator: bool = False,
                     group_size: int = 3) -> dict:
        """
        Genera un PIN numérico criptográficamente seguro.

        Args:
            length:           Longitud del PIN (4-12)
            avoid_sequences:  Rechaza secuencias como 1234, 4321
            avoid_repeats:    Rechaza PINs con todos los dígitos iguales (1111)
            add_separator:    Añade guión cada group_size dígitos (p.ej. 123-456)
            group_size:       Tamaño de los grupos si add_separator=True
        """
        t0 = time.perf_counter()
        if length < 4:  raise ValueError("Longitud mínima: 4 dígitos.")
        if length > 12: raise ValueError("Longitud máxima: 12 dígitos.")

        max_attempts = 1000
        for _ in range(max_attempts):
            digits = [str(secrets.randbelow(10)) for _ in range(length)]
            pin    = "".join(digits)

            if avoid_repeats and len(set(digits)) == 1:
                continue

            if avoid_sequences:
                is_seq = True
                for i in range(len(digits)-1):
                    if int(digits[i+1]) - int(digits[i]) != 1:
                        is_seq = False; break
                if is_seq and len(digits) > 2: continue

                is_rev = True
                for i in range(len(digits)-1):
                    if int(digits[i]) - int(digits[i+1]) != 1:
                        is_rev = False; break
                if is_rev and len(digits) > 2: continue

            break
        else:
            pin = "".join(str(secrets.randbelow(10)) for _ in range(length))

        display_pin = pin
        if add_separator:
            groups = [pin[i:i+group_size] for i in range(0, length, group_size)]
            display_pin = "-".join(groups)

        entropy = length * math.log2(10)
        elapsed = (time.perf_counter()-t0)*1000

        strength = ("🟢 FUERTE" if length>=8 else
                    "🟡 ACEPTABLE" if length>=6 else "🟠 CORTO")

        return {"password": display_pin, "pin_raw": pin, "length": length,
                "entropy_bits": round(entropy,2), "strength": strength,
                "generation_time_ms": round(elapsed,2), "charset_size": 10}

    # ── HIBP ──────────────────────────────────────────

    def check_hibp(self, password: str) -> dict:
        logger.info("Verificando HIBP (k-Anonymity)…")
        try:
            sha1   = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix = sha1[:5]; suffix = sha1[5:]
            url    = f"https://api.pwnedpasswords.com/range/{prefix}"
            ctx    = ssl.create_default_context()
            req    = urllib.request.Request(url, headers={
                "User-Agent": "PasswordManager-v4.0", "Add-Padding": "true"})
            with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
                body = r.read().decode("utf-8")
            count = 0
            for line in body.splitlines():
                parts = line.strip().split(":")
                if len(parts)==2 and parts[0]==suffix:
                    count = int(parts[1]); break
            result = {
                "compromised": count>0, "breach_count": count,
                "message": (f"⚠️ Aparece en {count:,} filtraciones." if count>0
                            else "✅ No aparece en filtraciones conocidas."),
            }
            logger.info(f"HIBP: {'COMPROMETIDA' if count>0 else 'SEGURA'} (n={count})")
            return result
        except Exception as e:
            logger.warning(f"HIBP error: {e}")
            return {"compromised": None, "breach_count": -1,
                    "message": f"❌ Sin conexión o error: {e}"}
