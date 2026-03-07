# 🔐 Gestor de Contraseñas Seguro v2.0

Aplicación de escritorio para **generar y gestionar contraseñas** con cifrado AES-256-GCM, protección anti-captura de pantalla y bóveda cifrada con contraseña maestra.

---

## 📦 Descarga y Uso

### Opción 1: Ejecutable (recomendado)

Descarga **`GestorContraseñas.exe`** de la carpeta `dist/` y ejecútalo directamente. No necesitas instalar Python ni nada más.

```
dist/
└── GestorContraseñas.exe   ← Doble clic para ejecutar
```

> El archivo `vault.enc` (tu bóveda cifrada) y la carpeta `logs/` se crearán automáticamente junto al .exe.

### Opción 2: Desde el código fuente

```bash
# Instalar dependencia
pip install cryptography

# Ejecutar
python generador_contraseñas.py
```

### Compilar el .exe tú mismo

```bash
python build_exe.py
```
Se generará `dist/GestorContraseñas.exe` (~13 MB). Puedes copiarlo a cualquier carpeta.

---

## 📋 Estructura del Proyecto

```
📁 Código fuente (open source)
├── generador_contraseñas.py   # App principal (GUI con pestañas)
├── password_engine.py         # Motor de generación de contraseñas
├── crypto_vault.py            # Cifrado AES-256-GCM y bóveda
├── build_exe.py               # Script para compilar como .exe
└── README.md

📁 Generados automáticamente (no se suben a GitHub)
├── dist/GestorContraseñas.exe # Ejecutable compilado
├── build/                     # Archivos temporales de compilación
├── vault.enc                  # Tu bóveda cifrada (PRIVADO)
└── logs/                      # Logs de ejecución
```

---

## ⚡ Pestaña: Generador

- **Longitud** ajustable (4–256) con slider o entrada manual
- **Tipos de caracteres**: minúsculas, mayúsculas, dígitos, símbolos personalizables
- **Triple aleatoriedad**: `secrets` (CSPRNG) + Fisher-Yates ×7 + intercambios extra
- **Indicador de fortaleza** con entropía en bits + barra visual
- **📋 Copiar** al portapapeles
- **💾 Guardar en Bóveda** — con nombre personalizado, URL y email

---

## 🔑 Pestaña: Mis Contraseñas

### Primera vez
Crea una **contraseña maestra** (mín. 8 caracteres).
**⚠️ Si la olvidas, NO hay recuperación posible.**

### Gestión de credenciales
Cada entrada tiene:
- **🌐 Nombre** personalizado (ej: "GitHub", "Mi Banco")
- **🔗 URL** del sitio web
- **📧 Email/usuario** — con botón copiar
- **🔑 Contraseña** oculta — 👁 para revelar 5 seg, 📋 para copiar

### Acciones
| Botón | Acción |
|---|---|
| **🚀 Quick Login** | Abre la web + copia email → 4 seg después copia contraseña |
| **✏️ Editar** | Modifica nombre, URL, email, contraseña, notas |
| **🗑 Eliminar** | Elimina credencial (con confirmación) |
| **➕ Añadir** | Nueva credencial manual |
| **🔒 Bloquear** | Cierra la bóveda |

---

## 🛡️ Seguridad

| Componente | Tecnología |
|---|---|
| Cifrado | **AES-256-GCM** (autenticado) |
| Derivación de clave | **PBKDF2-HMAC-SHA256**, 600.000 iteraciones |
| Sal | 32 bytes aleatorios (única por bóveda) |
| Nonce | 12 bytes aleatorios (único por operación de cifrado) |
| RNG | `secrets` (CSPRNG del sistema operativo) |

### Protecciones
- ✅ **Anti-captura de pantalla** — `SetWindowDisplayAffinity` (Windows 10 v2004+)
- ✅ **Contraseñas siempre ocultas** — se muestran como `●●●●●●` (revelar máx. 5 seg)
- ✅ **Cifrado autenticado** — AES-GCM detecta cualquier manipulación del archivo
- ✅ **Sin datos sensibles en logs** — nunca se registran contraseñas ni emails
- ✅ **Anti timing attacks** — `secrets.compare_digest()` para comparar hashes
- ✅ **Limpieza de memoria** — datos se borran de la RAM al bloquear la bóveda
- ✅ **Archivo indescifrable** — `vault.enc` es binario cifrado, inútil sin la contraseña

---

## 🧪 Cómo Verificar que la App es Segura

### 1. Verificar que el vault está cifrado
```bash
# Abre vault.enc con un editor de texto → verás datos binarios ilegibles
# Si ves texto legible como emails o contraseñas, algo está MAL
notepad vault.enc
```

### 2. Verificar protección anti-captura
1. Abre la app y ve a la pestaña **Mis Contraseñas**
2. Desbloquea la bóveda
3. Haz una captura de pantalla (Win+Shift+S o PrintScreen)
4. **Resultado esperado**: la ventana aparece como un rectángulo negro en la captura

### 3. Verificar contraseña maestra incorrecta
1. Cierra y reabre la app
2. Escribe una contraseña incorrecta en el login
3. **Resultado esperado**: "Contraseña incorrecta" — no se muestran datos

### 4. Verificar que los logs no filtran datos
```bash
# Busca tus contraseñas o emails en los logs — NO deben aparecer
findstr /i "tu_email@example.com" logs\*.log
findstr /i "tu_contraseña" logs\*.log
```

### 5. Verificar integridad del archivo
1. Cierra la app
2. Abre `vault.enc` con un editor hexadecimal y cambia 1 byte cualquiera
3. Reabre la app e intenta desbloquear
4. **Resultado esperado**: falla el desbloqueo (AES-GCM detecta la manipulación)

### 6. Revisar el código fuente
Todo el código es **open source** en este repositorio:
- `crypto_vault.py` — revisa el cifrado y la derivación de clave
- `password_engine.py` — revisa la generación de contraseñas
- `generador_contraseñas.py` — revisa la interfaz y protección anti-captura

---

## 📝 Logs

Se guardan en `logs/` con un archivo por ejecución (`pm_YYYYMMDD_HHMMSS.log`). Contienen:
- Acciones del usuario (generar, guardar, copiar)
- Tiempos de ejecución y métricas
- **Nunca** contraseñas, emails ni datos personales

---

## ⚠️ Importante

- **No olvides tu contraseña maestra** — no hay forma de recuperarla
- **Haz backup** de `vault.enc` periódicamente
- **No subas** `vault.enc` a GitHub (ya está en `.gitignore`)
- La protección anti-captura no es infalible ante software de muy bajo nivel

---

## 📄 Licencia

Código fuente abierto. Úsalo, modifícalo y compártelo libremente.
