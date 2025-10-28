import concurrent.futures
import requests
import re
import os
import json
import time
import threading
import logging
from typing import List, Dict, Set, Tuple, Optional
import asyncio
import aiohttp
from dataclasses import dataclass
import itertools

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
import urllib3

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# ===================== CONFIGURACIÓN DE LOGGING =====================
# Configurar logging para suprimir mensajes de WebDriver Manager
logging.getLogger('WDM').setLevel(logging.WARNING)
logging.getLogger('selenium').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# Configurar nuestro logger principal
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Si no hay handlers, agregar uno
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

# ===================== CONFIGURACIÓN MEJORADA =====================
@dataclass
class Config:
    MAX_STATIC_WORKERS: int = 30
    MAX_SELENIUM_WORKERS: int = 10
    MAX_PATTERN_WORKERS: int = 20
    MAX_ASYNC_WORKERS: int = 50
    REQUEST_TIMEOUT: int = 15
    WAIT_TIME: int = 6
    SCROLL_STEPS: int = 3
    CHECAR_FILE: str = "checar.txt"
    RESULTS_FILE: str = "resultados_detallados.json"

# ===================== BANNER MEJORADO =====================
def mostrar_banner():
    banner = """
    
 ██▀███  ▓█████ ▓█████▄ ▄▄▄█████▓▓█████ ▄▄▄       ███▄ ▄███▓
▓██ ▒ ██▒▓█   ▀ ▒██▀ ██▌▓  ██▒ ▓▒▓█   ▀▒████▄    ▓██▒▀█▀ ██▒
▓██ ░▄█ ▒▒███   ░██   █▌▒ ▓██░ ▒░▒███  ▒██  ▀█▄  ▓██    ▓██░
▒██▀▀█▄  ▒▓█  ▄ ░▓█▄   ▌░ ▓██▓ ░ ▒▓█  ▄░██▄▄▄▄██ ▒██    ▒██ 
░██▓ ▒██▒░▒████▒░▒████▓   ▒██▒ ░ ░▒████▒▓█   ▓██▒▒██▒   ░██▒
░ ▒▓ ░▒▓░░░ ▒░ ░ ▒▒▓  ▒   ▒ ░░   ░░ ▒░ ░▒▒   ▓▒█░░ ▒░   ░  ░
  ░▒ ░ ▒░ ░ ░  ░ ░ ▒  ▒     ░     ░ ░  ░ ▒   ▒▒ ░░  ░      ░
  ░░   ░    ░    ░ ░  ░   ░         ░    ░   ▒   ░      ░   
   ░        ░  ░   ░                ░  ░     ░  ░       ░    
LordCristhian - Mejorado con IA
"""
    print(f"{Fore.RED}{Style.BRIGHT}{banner}{Style.RESET_ALL}")

# ===================== INICIALIZACIÓN =====================
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class JSAnalyzer:
    def __init__(self, config: Config):
        self.config = config
        self.patrones_busqueda = self._cargar_patrones_mejorados()
        self.resultados = []
        
    def _cargar_patrones_mejorados(self) -> Dict[str, str]:
        """Patrones mejorados con IA para detectar secrets más efectivamente"""
        return {
            "Conexion_aks": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net",
            "Token_JWT": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            "Google-api-key": r"(?i)AIza[0-9A-Za-z\-_]{35}",
            "Authorization-Basic": r"(?i)(Authorization:\sbasic\s+[a-z0-9=:_\-+/]{5,100})",
            "Authorization-Bearer": r"(?i)(Authorization:\sbearer\s+[a-z0-9=:_\-\.+/]{5,100})",
            "Passwords": r"(?i)(?:password|passwd|pwd|passphrase)\s*(?:=|:)\s*['\"][^'\"]{8,}['\"]",
            "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Access Key": r"(?i)aws_secret_access_key\s*(?:=|:)\s*['\"]?[A-Za-z0-9\/+=]{40,}['\"]?",
            "Github Access Token": r"gh[pous]_[A-Za-z0-9_]{36,}",
            "Azure Storage Account Key": r"(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{88}",
            "Base64 Secret": r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{10,}==(?=\b|[^A-Za-z0-9+/=])",
            "Generic_Secret_Base64": r"(?i)(?:secret|key|token)\s*(?:=|:)\s*['\"]?[A-Za-z0-9+/=]{20,}['\"]?",
            "Activos_movistar.com.pe": r"\b(?:[a-z0-9-]+\.)*movistar\.com\.pe\b",
            "Activos_telefonica.com.pe": r"\b(?:[a-z0-9-]+\.)*telefonica\.com\.pe\b",
            "Activos_serviciosmovistar.com": r"\b(?:[A-Za-z0-9-]+\.)*serviciosmovistar\.com\b",
        }

    async def procesar_url_async(self, session: aiohttp.ClientSession, url: str) -> Tuple[str, Dict]:
        """Procesamiento asíncrono con reintentos, mejor manejo de errores y exclusión de dominios"""
        
        # Lista de dominios a excluir
        dominios_excluidos = [
            "doubleclick.net",
            "googletagmanager.com", 
            "mediarithmics.com",
            "retargetly.com",
            "facebook.net",
            "google-analytics.com",
            "gstatic.com",
            "google.com",
            "facebook.com",
            "twitter.com",
            "onesignal.com",
            "boomtrain.com",
            "static.microsoft",
            "tiktok.com",
            "ubembed.com",
            "womtp.com",
            "walmeric.com",
            "msftauth.net",
            "crossattachmedia.serviciosmovistar.com",
            "jsdelivr.net",
            "wsimg.com",
            "clickcease.com",
            "afternic.com",
            "unbounce.com",
            "msauth.net",
            "linkedin.com"
        ]
        
        # Verificar si la URL pertenece a un dominio excluido
        try:
            dominio = urlparse(url).netloc.lower()
            for dominio_excluido in dominios_excluidos:
                if dominio.endswith(dominio_excluido):
                    logger.debug(f"URL excluida por dominio: {url}")
                    return url, {}  # Devolver diccionario vacío para indicar que no hay patrones
        except Exception as e:
            logger.debug(f"Error al parsear URL {url}: {e}")
        
        max_reintentos = 2
        reintento = 0
        
        while reintento < max_reintentos:
            try:
                async with session.get(url, ssl=False, 
                                     timeout=aiohttp.ClientTimeout(total=self.config.REQUEST_TIMEOUT),
                                     allow_redirects=False) as response:
                    
                    if response.status == 200:
                        contenido = await response.text()
                        patrones_encontrados = self._buscar_patrones_inteligente(contenido, url)
                        return url, patrones_encontrados
                    else:
                        # Si no es 200, no reintentar - es respuesta definitiva del servidor
                        return url, {}
                        
            except asyncio.TimeoutError:
                reintento += 1
                logger.debug(f"Timeout en {url}, reintento {reintento}/{max_reintentos}")
                await asyncio.sleep(1)  # Esperar antes de reintentar
                
            except aiohttp.ClientConnectorError:
                reintento += 1
                logger.debug(f"Error de conexión en {url}, reintento {reintento}/{max_reintentos}")
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.debug(f"Error inesperado en {url}: {e}")
                break  # No reintentar para otros errores
        
        return url, {}

    def _buscar_patrones_inteligente(self, contenido: str, url: str) -> Dict:
        """Búsqueda inteligente de patrones"""
        patrones_encontrados = {}
        
        for nombre, patron in self.patrones_busqueda.items():
            try:
                coincidencias = re.findall(patron, contenido)
                if coincidencias:
                    # Eliminar duplicados manteniendo el orden
                    coincidencias_unicas = []
                    vistas = set()
                    for coincidencia in coincidencias:
                        if coincidencia not in vistas:
                            vistas.add(coincidencia)
                            coincidencias_unicas.append(coincidencia)
                    
                    patrones_encontrados[nombre] = coincidencias_unicas
            except Exception as e:
                logger.warning(f"Error en patrón {nombre}: {e}")
                
        return patrones_encontrados

    async def analizar_urls_masivo(self, urls: List[str]):
        """Análisis masivo asíncrono con procesamiento por lotes"""
        print(f"{Fore.CYAN}{Style.BRIGHT}Iniciando análisis asíncrono de {len(urls)} URLs (solo códigos 200)...{Style.RESET_ALL}")
        
        # Configuración optimizada para lotes
        connector = aiohttp.TCPConnector(limit=30, limit_per_host=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.config.REQUEST_TIMEOUT)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # Procesar en lotes para mayor estabilidad
            batch_size = 100
            resultados_totales = []
            total_lotes = (len(urls) - 1) // batch_size + 1
            
            for i in range(0, len(urls), batch_size):
                batch = urls[i:i + batch_size]
                lote_actual = i // batch_size + 1
                print(f"{Fore.BLUE}Procesando lote {lote_actual}/{total_lotes} ({len(batch)} URLs){Style.RESET_ALL}")
                
                tasks = [self.procesar_url_async(session, url) for url in batch]
                resultados = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Procesar resultados del lote - SOLO agregar si hay patrones encontrados
                for resultado in resultados:
                    if isinstance(resultado, tuple) and resultado[1]:  # Solo si hay patrones
                        resultados_totales.append(resultado)
                
                # Pequeña pausa entre lotes para evitar sobrecarga
                if lote_actual < total_lotes:  # No esperar después del último lote
                    await asyncio.sleep(0.5)
            
            self.resultados = resultados_totales
            
            # Estadísticas detalladas
            urls_con_patrones = len(self.resultados)
            total_patrones = sum(len(patrones) for _, patrones in self.resultados)
            
            print(f"{Fore.GREEN}Análisis completado. {urls_con_patrones}/{len(urls)} URLs con patrones.{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total de patrones encontrados: {total_patrones}{Style.RESET_ALL}")

    def guardar_resultados(self):
        """Guarda resultados en formato estructurado"""
        if self.resultados:
            datos_guardar = {
                "timestamp": time.time(),
                "total_urls_analizadas": len(self.resultados),
                "resultados": [
                    {
                        "url": url,
                        "patrones": patrones,
                        "severity": self._calcular_severidad(patrones)
                    } for url, patrones in self.resultados
                ]
            }
            
            with open(self.config.RESULTS_FILE, 'w', encoding='utf-8') as f:
                json.dump(datos_guardar, f, indent=2, ensure_ascii=False)
                
            print(f"{Fore.GREEN}Resultados guardados en {self.config.RESULTS_FILE}{Style.RESET_ALL}")

    def _calcular_severidad(self, patrones: Dict) -> str:
        """Calcula la severidad basada en los patrones encontrados - CORREGIDO"""
        
        # PATRONES DE ALTA severidad - CREDENCIALES EXPLÍCITAS
        severidad_alta = {
            "AWS Access Key ID", 
            "AWS Secret Access Key", 
            "Azure Storage Account Key",
            "Token_JWT", 
            "Conexion_aks",
            "Authorization-Bearer",
            "Authorization-Basic",
            "Passwords"  # Las contraseñas deberían ser ALTA
        }
        
        # PATRONES DE MEDIA severidad - Posibles secrets que requieren revisión
        severidad_media = {
            "Github Access Token",
            "Generic_Secret_Base64",
            "Base64 Secret"
        }
        
        # PATRONES DE BAJA severidad - Información no crítica
        severidad_baja = {
            "Activos_movistar.com.pe",
            "Activos_telefonica.com.pe", 
            "Activos_serviciosmovistar.com",
            "Google-api-key"  # Dependiendo del contexto, podría ser baja
        }
        
        # Verificar por orden de prioridad
        for patron in patrones.keys():
            if patron in severidad_alta:
                return "ALTA"
        
        for patron in patrones.keys():
            if patron in severidad_media:
                return "MEDIA"
        
        for patron in patrones.keys():
            if patron in severidad_baja:
                return "BAJA"
        
        # Si no coincide con ninguna categoría conocida, clasificar como MEDIA por precaución
        return "BAJA"

    def mostrar_resumen_completo(self):
        """Muestra un resumen ejecutivo completo de los resultados"""
        if not self.resultados:
            print(f"{Fore.YELLOW}No se encontraron patrones sensibles.{Style.RESET_ALL}")
            return
            
        # Separar resultados por severidad - CORREGIDO
        resultados_alta = [(url, patrones) for url, patrones in self.resultados if self._calcular_severidad(patrones) == "ALTA"]
        resultados_media = [(url, patrones) for url, patrones in self.resultados if self._calcular_severidad(patrones) == "MEDIA"]
        resultados_baja = [(url, patrones) for url, patrones in self.resultados if self._calcular_severidad(patrones) == "BAJA"]
        
        total_patrones = sum(len(patrones) for _, patrones in self.resultados)
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== RESUMEN EJECUTIVO COMPLETO ==={Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total URLs analizadas: {len(self.resultados)}")
        print(f"{Fore.YELLOW}Total de patrones encontrados: {total_patrones}")
        print(f"{Fore.RED}URLs con severidad ALTA: {len(resultados_alta)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}URLs con severidad MEDIA: {len(resultados_media)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}URLs con severidad BAJA: {len(resultados_baja)}{Style.RESET_ALL}")
        
        # Mostrar resultados por severidad
        self._mostrar_resultados_por_severidad("ALTA", resultados_alta, Fore.RED)
        self._mostrar_resultados_por_severidad("MEDIA", resultados_media, Fore.YELLOW)
        self._mostrar_resultados_por_severidad("BAJA", resultados_baja, Fore.GREEN)

    def _mostrar_resultados_por_severidad(self, severidad: str, resultados: List, color: str):
        """Muestra resultados agrupados por severidad"""
        if resultados:
            print(f"\n{color}{Style.BRIGHT}=== URLs CON SEVERIDAD {severidad} ({len(resultados)}) ==={Style.RESET_ALL}")
            for url, patrones in resultados:
                print(f"\n{color}🔍 {url}{Style.RESET_ALL}")
                for nombre, coincidencias in patrones.items():
                    print(f"   \033[1m\033[97m⚠ {nombre}:\033[0m{Style.RESET_ALL}")
                    # Mostrar como lista entre llaves
                    if coincidencias:
                        # Formatear cada elemento de la lista
                        elementos_formateados = [f"'{coincidencia}'" for coincidencia in coincidencias]
                        lista_str = "[" + ", ".join(elementos_formateados) + "]"
                        print(f"     \033[37m{lista_str}{Style.RESET_ALL}")

# ===================== FUNCIONES ORIGINALES MEJORADAS =====================
def procesar_linea_mejorada(linea: str, contador_global: list) -> List[str]:
    """Versión mejorada del procesamiento de líneas"""
    try:
        url = linea.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        response = requests.get(url, timeout=15, verify=False)
        response.raise_for_status()
        
        # Suprimir el warning de XML
        import warnings
        from bs4 import XMLParsedAsHTMLWarning
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        
        soup = BeautifulSoup(response.text, 'html.parser')

        rutas = []
        # Buscar en scripts y enlaces
        for tag in soup.find_all(['script', 'link'], src=True):
            src = tag.get('src', '')
            if src.lower().endswith('.js'):
                ruta_absoluta = urljoin(url, src)
                rutas.append(ruta_absoluta)

        # Actualizar contador
        contador_global[0] += 1
        return rutas
        
    except Exception as e:
        # Actualizar contador incluso en error
        contador_global[0] += 1
        logger.debug(f"Error procesando línea {linea[:50]}...: {e}")
        return []

# ===================== FUNCIONES SELENIUM MEJORADAS =====================
def iniciar_driver_optimizado() -> Optional[webdriver.Chrome]:
    """Inicialización optimizada del driver de Selenium"""
    try:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-images")
        options.add_argument("--blink-settings=imagesEnabled=false")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        
        # Habilitar network logging (como en tu versión original)
        try:
            driver.execute_cdp_cmd("Network.enable", {})
        except Exception:
            pass
            
        return driver
    except Exception as e:
        logger.debug(f"Error iniciando driver: {e}")
        return None

def extract_js_from_logs(logs):
    """Extrae URLs de JavaScript de los logs de performance - VERSIÓN ORIGINAL CORREGIDA"""
    js_urls = set()
    for entry in logs:
        try:
            message = json.loads(entry["message"])["message"]
        except Exception:
            continue
        method = message.get("method", "")
        params = message.get("params", {})
        if method in ("Network.responseReceived", "Network.requestWillBeSent"):
            url = params.get("response", {}).get("url") or params.get("request", {}).get("url")
            if not url:
                continue
            path = urlparse(url).path.lower()
            if path.endswith(".js"):
                js_urls.add(url)
            else:
                mime = params.get("response", {}).get("mimeType", "")
                if "javascript" in str(mime).lower() or params.get("type") == "Script":
                    js_urls.add(url)
    return js_urls

def obtener_js_dinamicos_para_url(url: str, contador_global: list, total_urls: int) -> Set[str]:
    """Obtiene JavaScript de forma dinámica usando Selenium - VERSIÓN ORIGINAL MEJORADA"""
    found = set()
    driver = iniciar_driver_optimizado()
    
    if not driver:
        # Actualizar contador incluso en error
        contador_global[0] += 1
        return found

    try:
        driver.get(url)
        time.sleep(WAIT_TIME)
        
        # Scroll para cargar contenido dinámico (como en tu versión original)
        for i in range(SCROLL_STEPS):
            try:
                driver.execute_script("window.scrollBy(0, document.body.scrollHeight/3);")
            except Exception as e:
                logger.debug(f"Error en scroll: {e}")
            time.sleep(1)

        # Obtener logs de performance (como en tu versión original)
        try:
            logs = driver.get_log("performance")
        except Exception as e:
            logger.debug(f"Error obteniendo logs: {e}")
            logs = []

        found = extract_js_from_logs(logs)
        
    except Exception as e:
        logger.debug(f"Error en Selenium para {url}: {e}")
    finally:
        try:
            driver.quit()
        except Exception:
            pass
            
    # Actualizar contador
    contador_global[0] += 1
    return found

# ===================== FUNCIONES DE FLUJO COMPLETO =====================
async def ejecutar_flujo_completo(analyzer: JSAnalyzer):
    """Ejecuta el flujo completo de búsqueda y análisis"""
    archivo_entrada = input(f"{Fore.YELLOW}Ingrese el nombre del archivo con las URLs (ejemplo: url.txt): {Style.RESET_ALL}").strip()

    try:
        with open(archivo_entrada, "r") as archivo:
            lineas = archivo.readlines()
        print(f"{Fore.GREEN}Leídas {len(lineas)} URLs del archivo.{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"{Fore.RED}El archivo {archivo_entrada} no existe.{Style.RESET_ALL}")
        return

    # Limpiar archivo de resultados previos
    if os.path.exists(analyzer.config.CHECAR_FILE):
        os.remove(analyzer.config.CHECAR_FILE)

    # ===================== FASE 1: BÚSQUEDA ESTÁTICA =====================
    print(f"{Fore.CYAN}{Style.BRIGHT}=== FASE 1: BÚSQUEDA ESTÁTICA DE ARCHIVOS JS ==={Style.RESET_ALL}")
    
    # Usar una lista para contador mutable
    contador_estatico = [0]
    total_js_encontrados = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=analyzer.config.MAX_STATIC_WORKERS) as executor:
        # Preparar todas las tareas
        futures = []
        for linea in lineas:
            future = executor.submit(procesar_linea_mejorada, linea, contador_estatico)
            futures.append(future)
        
        # Procesar resultados a medida que completan
        for future in concurrent.futures.as_completed(futures):
            try:
                rutas = future.result()
                if rutas:
                    with open(analyzer.config.CHECAR_FILE, "a") as archivo_checar:
                        for ruta in rutas:
                            archivo_checar.write(f"{ruta}\n")
                    total_js_encontrados += len(rutas)
                    # Mostrar el formato exacto que prefieres
                    print(f"{Fore.GREEN}[✓] Procesada URL {contador_estatico[0]}/{len(lineas)} - Encontrados {len(rutas)} JS{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[✓] Procesada URL {contador_estatico[0]}/{len(lineas)} - Encontrados 0 JS{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.GREEN}[✓] Procesada URL {contador_estatico[0]}/{len(lineas)} - Error: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}Fase 1 completada. {len(lineas)} URLs procesadas, {total_js_encontrados} JS encontrados.{Style.RESET_ALL}")

    # ===================== FASE 2: BÚSQUEDA DINÁMICA CON SELENIUM =====================
    print(f"{Fore.CYAN}{Style.BRIGHT}=== FASE 2: BÚSQUEDA DINÁMICA CON SELENIUM ==={Style.RESET_ALL}")
    
    urls_to_process = [l.strip() for l in lineas if l.strip()]
    
    # Leer URLs ya encontradas para evitar duplicados
    urls_existentes = set()
    if os.path.exists(analyzer.config.CHECAR_FILE):
        with open(analyzer.config.CHECAR_FILE, "r") as f:
            urls_existentes = set(line.strip() for line in f if line.strip())

    # Usar una lista para contador mutable
    contador_dinamico = [0]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=analyzer.config.MAX_SELENIUM_WORKERS) as executor:
        # Preparar todas las tareas
        futures_dyn = {}
        for url in urls_to_process:
            future = executor.submit(obtener_js_dinamicos_para_url, url, contador_dinamico, len(urls_to_process))
            futures_dyn[future] = url

        # Procesar resultados a medida que completan
        for future in concurrent.futures.as_completed(futures_dyn):
            url = futures_dyn[future]
            try:
                js_set = future.result()
            except Exception as e:
                logger.debug(f"Error en Selenium para {url}: {e}")
                js_set = set()

            nuevos_js = js_set - urls_existentes
            if nuevos_js:
                with open(analyzer.config.CHECAR_FILE, "a") as f:
                    for js in sorted(nuevos_js):
                        f.write(js + "\n")
                        urls_existentes.add(js)

            # Mostrar el formato exacto que prefieres
            print(f"{Fore.CYAN}[✓] Procesada URL {contador_dinamico[0]}/{len(urls_to_process)} - Encontrados {len(nuevos_js)} JS{Style.RESET_ALL}")

    # ===================== FASE 3: ANÁLISIS DE PATRONES =====================
    print(f"{Fore.CYAN}{Style.BRIGHT}=== FASE 3: ANÁLISIS DE PATRONES EN ARCHIVOS JS ==={Style.RESET_ALL}")
    
    # Leer todas las URLs JS encontradas
    try:
        with open(analyzer.config.CHECAR_FILE, "r") as file:
            urls_js = [line.strip() for line in file if line.strip()]
        print(f"{Fore.GREEN}Encontrados {len(urls_js)} archivos JS para analizar.{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"{Fore.RED}No se encontraron archivos JS para analizar.{Style.RESET_ALL}")
        return

    if urls_js:
        await analyzer.analizar_urls_masivo(urls_js)
        analyzer.mostrar_resumen_completo()
        analyzer.guardar_resultados()
    else:
        print(f"{Fore.YELLOW}No se encontraron archivos JS para analizar.{Style.RESET_ALL}")

# ===================== MENÚ INTERACTIVO MEJORADO =====================
def mostrar_menu() -> str:
    """Menú interactivo mejorado"""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== SELECCIONE EL MODO DE EJECUCIÓN ==={Style.RESET_ALL}")
    opciones = [
        "1. Búsqueda completa de JS + Análisis de patrones",
        "2. Análisis directo de archivos JS existentes", 
        "3. Salir"
    ]
    
    for opcion in opciones:
        print(f"{Fore.YELLOW}{opcion}{Style.RESET_ALL}")
    
    while True:
        modo = input(f"\n{Fore.CYAN}Ingrese su opción (1-3): {Style.RESET_ALL}").strip()
        if modo in ['1', '2', '3']:
            return modo
        print(f"{Fore.RED}Opción inválida. Intente nuevamente.{Style.RESET_ALL}")

# ===================== VARIABLES GLOBALES =====================
WAIT_TIME = 6
SCROLL_STEPS = 3

# ===================== FUNCIÓN PRINCIPAL =====================
async def main():
    mostrar_banner()
    config = Config()
    analyzer = JSAnalyzer(config)
    
    modo = mostrar_menu()
    
    if modo == '3':
        print(f"{Fore.YELLOW}Saliendo...{Style.RESET_ALL}")
        return
        
    try:
        if modo == '1':
            await ejecutar_flujo_completo(analyzer)
            
        elif modo == '2':
            archivo_js = input(f"{Fore.YELLOW}Ingrese el archivo con rutas JS: {Style.RESET_ALL}").strip()
            
            if os.path.exists(archivo_js):
                with open(archivo_js, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    
                print(f"{Fore.CYAN}Analizando {len(urls)} URLs...{Style.RESET_ALL}")
                await analyzer.analizar_urls_masivo(urls)
                analyzer.mostrar_resumen_completo()
                analyzer.guardar_resultados()
            else:
                print(f"{Fore.RED}Archivo no encontrado.{Style.RESET_ALL}")
                
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Interrumpido por el usuario.{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Error en ejecución: {e}")

if __name__ == "__main__":
    asyncio.run(main())
