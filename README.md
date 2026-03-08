# 🔐 Gestor de Contraseñas Seguro v3.0

Aplicación de escritorio para **generar y gestionar contraseñas** con cifrado AES-256-GCM, protección anti-captura de pantalla, bóveda cifrada con contraseña maestra, y UI moderna con animaciones dinámicas.

---

## 📦 Descarga y Uso

### Opción 1: Ejecutable (recomendado)

Descarga **`GestorContraseñas.exe`** de la carpeta `dist/` y ejecútalo directamente. No necesitas instalar Python ni nada más.

```
dist/
└── GestorContraseñas.exe   ← Doble clic para ejecutar
```

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

## 💾 Almacenamiento de Datos del .exe

> **¿Dónde guarda los datos el `.exe` cuando lo ejecutas?**

### Archivos que se crean

| Archivo | Descripción | Ubicación |
|---|---|---|
| `vault.enc` | Tu bóveda cifrada con todas las contraseñas | `%LOCALAPPDATA%\GestorContraseñas\` |
| `logs/` | Carpeta con logs de ejecución | `%LOCALAPPDATA%\GestorContraseñas\logs\` |

La ruta completa típica es: `C:\Users\TU_USUARIO\AppData\Local\GestorContraseñas\`

### ¿Cómo funciona?

1. **Primera ejecución**: Al abrir el `.exe` por primera vez, te pedirá crear una **contraseña maestra**. Se crea la carpeta `GestorContraseñas` en AppData con `vault.enc` dentro.

2. **Ejecuciones siguientes**: El `.exe` busca `vault.enc` en AppData para cargar tus contraseñas. Solo necesitas tu contraseña maestra.

3. **Portabilidad**: Puedes mover el `.exe` a cualquier carpeta o USB. Tus datos están seguros en AppData y se cargan desde cualquier ubicación del `.exe`.

4. **Migración automática**: Si tienes un `vault.enc` antiguo junto al `.exe` (versión anterior), se moverá automáticamente a la nueva ubicación en AppData.

5. **Protección de datos**: La carpeta de datos tiene atributos **oculta + sistema** para evitar borrado accidental. Solo se puede eliminar desde la propia app (pestaña 🛡️ Seguridad → Eliminar Datos) o manualmente con permisos de administrador.

6. **Desinstalar la app**: Desde la pestaña 🛡️ Seguridad puedes eliminar **todos** los datos (triple confirmación). Luego solo borras el `.exe`. No quedan archivos residuales.

### ¿Se conecta a internet?

El `.exe` funciona **100% offline** excepto por funciones opcionales:
- **🛡️ Verificar HIBP**: Consulta la API de [Have I Been Pwned](https://haveibeenpwned.com/) para comprobar si tu contraseña ha sido filtrada. Envía solo los **primeros 5 caracteres del hash SHA-1**, nunca la contraseña completa. Es **opcional**.
- **📊 Auditoría de bóveda**: Comprueba todas tus contraseñas guardadas contra HIBP. También opcional.

### ¿Qué NO hace?

- ❌ NO envía datos a servidores (excepto HIBP si lo activas)
- ❌ NO escribe en el registro de Windows
- ❌ NO requiere permisos de administrador
- ❌ NO deja rastro si usas la función de desinstalación

---

## 📋 Estructura del Proyecto

```
📁 Código fuente (open source)
├── generador_contraseñas.py   # App principal (GUI con pestañas)
├── password_engine.py         # Motor de generación + passphrases + HIBP
├── crypto_vault.py            # Cifrado AES-256-GCM, categorías, export/import
├── ui_engine.py               # Motor de UI: animaciones, toasts, tooltips
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

### Modo Contraseña
- **Longitud** ajustable (4–256) con slider o entrada manual
- **Tipos de caracteres**: minúsculas, mayúsculas, dígitos, símbolos personalizables
- **Triple aleatoriedad**: `secrets` (CSPRNG) + Fisher-Yates ×7 + intercambios extra
- **Indicador de fortaleza** con entropía en bits + barra visual animada
- **📋 Copiar** al portapapeles
- **💾 Guardar en Bóveda** — con nombre, categoría, URL y email
- **🛡️ Verificar HIBP** — comprueba si la contraseña ha sido filtrada

### Modo Passphrase
- Genera frases tipo **Diceware** con palabras en español
- Configurable: número de palabras (3–10), separador, capitalización, número al final
- Diccionario de ~180 palabras en español
- Ejemplo: `tigre-luna-bosque-coral-42`

---

## 🔑 Pestaña: Mis Contraseñas

### Primera vez
Crea una **contraseña maestra** (mín. 8 caracteres).
**⚠️ Si la olvidas, NO hay recuperación posible.**

### Gestión de credenciales
Cada entrada tiene:
- **�️ Categoría** (Social, Banco, Trabajo, Email, Gaming, Compras, etc.)
- **�🌐 Nombre** personalizado (ej: "GitHub", "Mi Banco")
- **🔗 URL** del sitio web
- **📧 Email/usuario** — con botón copiar
- **🔑 Contraseña** oculta — 👁 para revelar 5 seg, 📋 para copiar

### Funcionalidades
| Función | Descripción |
|---|---|
| **🔍 Búsqueda** | Filtra credenciales en tiempo real por nombre, URL o email |
| **🏷️ Filtro por categoría** | Filtra por Social, Banco, Trabajo, etc. |
| **� Estadísticas** | Total de credenciales y contraseñas débiles detectadas |
| **�🚀 Quick Login** | Abre la web + copia email → 4 seg después copia contraseña |
| **✏️ Editar** | Modifica todos los campos incluida la categoría |
| **🗑 Eliminar** | Elimina credencial (con confirmación) |
| **➕ Añadir** | Nueva credencial manual con categoría |
| **📤 Exportar** | Exporta credenciales cifradas a un archivo `.pmex` |
| **📥 Importar** | Importa credenciales desde un archivo `.pmex` |
| **⏰ Auto-bloqueo** | Se bloquea tras 5 min de inactividad |
| **🔒 Bloquear** | Cierra la bóveda manualmente |

---

## 🎨 Interfaz Moderna

- **Paleta oscura sofisticada** con gradientes morado-azul
- **Animaciones dinámicas**: barras de progreso animadas, pulsos de color, fade-in
- **Toast notifications** elegantes en vez de ventanas modales
- **Efectos hover** con glow y cambio de borde en cards y botones
- **Tooltips** informativos en los botones
- **Focus glow** en los campos de entrada
- **Transiciones suaves** de color con smoothstep

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
- ✅ **Auto-bloqueo** — la bóveda se bloquea tras 5 minutos de inactividad
- ✅ **HIBP k-Anonymity** — nunca envía tu contraseña completa, solo 5 chars del hash

---

## 🧪 Cómo Verificar que la App es Segura

### 1. Verificar que el vault está cifrado
```bash
# Abre vault.enc con un editor de texto → verás datos binarios ilegibles
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
- `crypto_vault.py` — cifrado, categorías, export/import
- `password_engine.py` — generación de contraseñas y passphrases
- `ui_engine.py` — motor de animaciones y estilos
- `generador_contraseñas.py` — interfaz y lógica principal

---

## 📝 Logs

Se guardan en `logs/` con un archivo por ejecución (`pm_YYYYMMDD_HHMMSS.log`). Contienen:
- Acciones del usuario (generar, guardar, copiar)
- Tiempos de ejecución y métricas
- **Nunca** contraseñas, emails ni datos personales

---

## ⚠️ Importante

- **No olvides tu contraseña maestra** — no hay forma de recuperarla
- **Haz backup** de `vault.enc` periódicamente (o usa 📤 Exportar)
- **No subas** `vault.enc` a GitHub (ya está en `.gitignore`)
- La protección anti-captura no es infalible ante software de muy bajo nivel
- El auto-bloqueo se activa tras 5 minutos de inactividad

---

## 📄 Licencia

Código fuente abierto. Úsalo, modifícalo y compártelo libremente.
