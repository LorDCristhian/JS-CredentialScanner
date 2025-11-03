
<p align="center">
  <img width="526" height="290" alt="image" src="https://github.com/user-attachments/assets/0576895b-50be-4a9f-893f-44cb3c5cc81f" />
</p>

# JS-CredentialScanner

JS-CredentialScanner es una herramienta profesional de seguridad diseñada para auditores, pentesters y equipos de seguridad ofensiva. Realiza análisis exhaustivo de archivos JavaScript en aplicaciones web para identificar información sensible, credenciales filtradas, tokens de API y configuraciones de seguridad expuestas.

### ¿Por qué usar JS-CredentialScanner?

- **Análisis en 3 Fases**: Búsqueda estática, dinámica (Selenium) y análisis de patrones
- **Detección de 30+ patrones** de seguridad críticos
- **Alto rendimiento**: Procesamiento asíncrono masivo con hasta 50 conexiones concurrentes
- **Clasificación por severidad**: Alta, Media y Baja
- **Sin duplicados**: Sistema inteligente de eliminación de URLs y patrones repetidos
- **Thread-safe**: Operaciones seguras en entornos multi-hilo

## Características

1. **Fase 1 - Búsqueda Estática**
   - Extracción de archivos JS mediante parsing HTML
   - Procesamiento paralelo con ThreadPoolExecutor
   - Soporte para 30 workers concurrentes

2. **Fase 2 - Búsqueda Dinámica**
   - Renderizado con Selenium + ChromeDriver
   - Extracción desde Network Performance Logs
   - Detección de JS cargados dinámicamente
   - Scroll automático para trigger de lazy loading

3. **Fase 3 - Análisis de Patrones**
   - Procesamiento asíncrono con aiohttp
   - 50 conexiones HTTP concurrentes
   - Análisis de contenido con 30+ patrones regex


## 🔧 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/LorDCristhian/JS-CredentialScanner.git
cd JS-CredentialScanner
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

**En sistemas Linux (si es necesario):**
```bash
pip install -r requirements.txt --break-system-packages
```

### 3. Verificar instalación de Chrome

```bash
google-chrome --version
# O en macOS:
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --version
```

## 🚀 Uso

### Recopilación de activos.
```bash
subfinder -dL dominios_proof.txt -silent | httprobe -prefer-https | tee urls.txt

Donde:
1. dominios_proof.txt contiene la lista de dominios que serán analizados.
2. urls.txt es el archivo resultante que almacenará las direcciones activas, las cuales serán empleadas posteriormente por el programa para la búsqueda de archivos JavaScript y la detección de patrones.

```

### Ejecución Básica

```bash
python JS-CredentialScanner.py
```


## 🎮 Modos de Operación

### Modo 1: Búsqueda Completa + Análisis

**Ideal para**: Auditorías completas desde cero

**Proceso**:
```
URLs de entrada → Búsqueda estática → Búsqueda dinámica → Análisis de patrones
```

**Archivo de entrada**: `url.txt` (una URL por línea)

**Ejemplo de url.txt**:
```
https://example.com
https://target-site.com/app
https://api.company.com
```

**Salidas**:
- `checar.txt` - Lista de todos los archivos JS encontrados (sin duplicados)
- `resultados_detallados.json` - Hallazgos con severidad y contexto

---

### Modo 2: Análisis Directo de JS

**Ideal para**: Análisis rápido de archivos JS conocidos

**Proceso**:
```
Archivo JS → Análisis de patrones → Resultados
```

**Archivo de entrada**: Archivo con URLs de archivos JS

**Ejemplo**:
```
https://site.com/static/app.min.js
https://site.com/assets/bundle.js
https://cdn.example.com/libs/auth.js
```

---

## 🔐 Patrones Detectados

### Severidad ALTA 🔴

| Patrón | Descripción | Impacto |
|--------|-------------|---------|
| AWS Access Key ID | `AKIA[0-9A-Z]{16}` | Acceso a infraestructura AWS |
| AWS Secret Access Key | Claves secretas de AWS | Compromiso total de cuenta |
| Azure Storage Account Key | Claves de almacenamiento Azure | Acceso a blobs y archivos |
| Token JWT | Tokens de autenticación | Suplantación de identidad |
| Authorization Headers | Basic/Bearer tokens | Acceso no autorizado |
| Passwords Hardcoded | Contraseñas en código | Compromiso de cuentas |
| Azure Client Secret | Secretos de aplicación | Acceso a recursos Azure |
| Azure SAS Token | Tokens de acceso compartido | Acceso temporal a recursos |

### Severidad MEDIA 🟡

| Patrón | Descripción | Impacto |
|--------|-------------|---------|
| GitHub Access Token | `ghp_`, `gho_`, `ghu_`, `ghs_` | Acceso a repositorios |
| Generic Secret Base64 | Secretos codificados | Posible exposición de credenciales |
| Azure Container Registry | URLs de registros | Acceso a imágenes Docker |
| Azure KeyVault URIs | URIs de secretos | Ubicación de secretos |

### Severidad BAJA 🟢

| Patrón | Descripción | Impacto |
|--------|-------------|---------|
| Google API Key | Claves de API pública | Uso no autorizado de servicios |
| Base64 Text | Texto codificado | Posible información sensible |
| Azure Authority URLs | Endpoints de autenticación | Información de configuración |
| Host | Subdominios internos | Descubrimiento de activos |

---
## 🔥 Notas:
- Es posible agregar nuevas expresiones regular, si imcorporacion se realiza en el metodo
- Es posible agregar nuevos dominios para ser omitidos en el analisis, su incorportacion se realiza en el metodo
