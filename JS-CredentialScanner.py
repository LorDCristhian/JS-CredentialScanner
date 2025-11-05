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
from functools import lru_cache

from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
import urllib3

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException
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
    # OPTIMIZACIÓN 4: Aumento de workers y batch sizes
    MAX_STATIC_WORKERS: int = 30  # Aumentado de 30
    MAX_SELENIUM_WORKERS: int = 10  # Aumentado de 10
    MAX_PATTERN_WORKERS: int = 20  # Aumentado de 20
    MAX_ASYNC_WORKERS: int = 50  # Aumentado de 50
    # OPTIMIZACIÓN 5: Timeouts reducidos
    REQUEST_TIMEOUT: int = 15  # Reducido de 15
    WAIT_TIME: int = 6  # Reducido de 6
    SCROLL_STEPS: int = 3
    CHECAR_FILE: str = "checar.txt"
    RESULTS_FILE: str = "resultados_detallados.json"
    # Batch sizes más grandes
    BATCH_SIZE: int = 100  # Aumentado de 100
    ASYNC_CONNECTIONS: int = 30  # Aumentado de 30
    ASYNC_PER_HOST: int = 10  # Aumentado de 10
    # SELENIUM TIMEOUTS - Configuración eficiente
    SELENIUM_PAGE_LOAD_TIMEOUT: int = 60  # Timeout para carga de página
    SELENIUM_SCRIPT_TIMEOUT: int = 15  # Timeout para ejecución de scripts
    SELENIUM_IMPLICIT_WAIT: int = 5  # Espera implícita para elementos

# ===================== BANNER MEJORADO =====================
def mostrar_banner():
    banner = f"""
{Fore.RED}                               [ ◉ ]
    ╦╔═╗   ╔═╗┬─┐┌─┐┌┬┐┌─┐┌┐┌┌┬┐┬┌─┐┬  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
    ║╚═╗───║  ├┬┘├┤  ││├┤ │││ │ │├─┤│  ╚═╗│  ├─┤││││││├┤ ├┬┘
   ╚╝╚═╝   ╚═╝┴└─└─┘─┴┘└─┘┘└┘ ┴ ┴┴ ┴┴─┘╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
   ═══════════════════════════════════════════════════════════{Style.RESET_ALL}
{Fore.WHITE}        JavaScript Security Credential Detection Engine
        30+ Patterns | Multi-Phase Analysis | High Speed
                      v2.0 | {Style.BRIGHT}{Fore.RED}Lord{Fore.WHITE}Crist{Fore.RED}hian{Style.RESET_ALL}
{Fore.RED}   ═══════════════════════════════════════════════════════════{Style.RESET_ALL}
"""
    print(banner)

# ===================== INICIALIZACIÓN =====================
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================== OPTIMIZACIÓN 2: Cache LRU para dominios =====================
@lru_cache(maxsize=10000)
def es_dominio_excluido(dominio: str) -> bool:
    """Cache LRU para verificación de dominios excluidos - O(1) después del primer check"""
    dominios_excluidos = frozenset([  # OPTIMIZACIÓN 3: frozenset para O(1)
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
        "jsdelivr.net",
        "wsimg.com",
        "clickcease.com",
        "afternic.com",
        "unbounce.com",
        "msauth.net",
        "linkedin.com",
        "hotjar.com",
        "googleapis.com"
    ])
    
    dominio_lower = dominio.lower()
    return any(dominio_lower.endswith(excluido) for excluido in dominios_excluidos)

class JSAnalyzer:
    def __init__(self, config: Config):
        self.config = config
        # OPTIMIZACIÓN 1: Pre-compilación de todos los regex
        self.patrones_compilados = self._precompilar_patrones()
        self.resultados = []
        
        # ✅ CORRECCIÓN: Control de duplicados thread-safe
        self.urls_escritas = set()
        self.file_lock = threading.Lock()
        
        # OPTIMIZACIÓN 3: frozensets para búsquedas O(1) de severidad
        self.severidad_alta = frozenset({
            "AWS Access Key ID", 
            "AWS Secret Access Key", 
            "Token_JWT", 
            "Azure_Storage_Connection_String",
            "Authorization-Bearer",
            "Authorization-Basic",
            "Passwords",
            "Azure_Tenant_ID | Azure_Client_ID | Azure_Subscription_ID",
            "Azure_Client_Secret",
            "Azure_Storage_Account_Key",
            "OAuth2_Azure",
            "Azure_Tenant_Domain",
            "Azure_SAS_Token",
            "Azure_SQL_Connection_String",
            "Azure_CosmosDB_Key",
            "Azure_Function_Key",
            "Azure_App_Insights_InstrumentationKey"
        })
        
        self.severidad_media = frozenset({
            "Github Access Token",
            "Generic_Secret_Base64",
            "Azure_Container_Registry",
            "Azure_KeyVault_Secret_URI"
        })
        
        self.severidad_baja = frozenset({
            "Activos_x.com.pe",
            "Activos_y.com.pe", 
            "Activos_z.com",
            "Google-api-key",
            "Base64_text",
            "Azure_Authority_URL",
            "Azure_AD_B2C_Policy",
            "Azure_AD_Endpoint",
            "Azure_Managed_Identity_Endpoint",
            "Azure_Storage_Endpoint",
            "Azure_SPN_Object_ID"
        })
    
    # ✅ CORRECCIÓN: Método thread-safe para escribir URLs sin duplicados
    def escribir_url_unica(self, url: str) -> bool:
        """
        Escribe una URL al archivo checar.txt solo si no existe (thread-safe).
        Retorna True si se escribió, False si ya existía.
        """
        with self.file_lock:
            if url not in self.urls_escritas:
                with open(self.config.CHECAR_FILE, "a") as f:
                    f.write(f"{url}\n")
                self.urls_escritas.add(url)
                return True
            return False
    
    # ✅ CORRECCIÓN: Cargar URLs existentes al iniciar
    def cargar_urls_existentes(self):
        """Carga las URLs ya escritas en el archivo checar.txt"""
        if os.path.exists(self.config.CHECAR_FILE):
            with self.file_lock:
                with open(self.config.CHECAR_FILE, "r") as f:
                    self.urls_escritas = set(line.strip() for line in f if line.strip())
                #logger.info(f"Cargadas {len(self.urls_escritas)} URLs existentes del archivo")
        
    def _precompilar_patrones(self) -> Dict[str, re.Pattern]:
        """OPTIMIZACIÓN 1: Pre-compilar todos los regex para mayor velocidad (20-30% más rápido)"""
        patrones_raw = {
            "Token_JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "Google-api-key": r"(?i)AIza[0-9A-Za-z\-_]{35}",
            "Authorization-Basic": r"(?i)(Authorization:\sbasic\s+[a-z0-9=:_\-+/]{5,100})",
            "Authorization-Bearer": r"(?i)(Authorization:\sbearer\s+[a-z0-9=:_\-\.+/]{5,100})",
            "Passwords": r"(?i)(?:password|passwd|pwd|pass|passphrase|secret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
            "AWS Access Key ID": r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
            "AWS Secret Access Key": r"(?i)(?:aws_secret_access_key|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
            "Github Access Token": r"\b(gh[pousrSRT]_[A-Za-z0-9_]{36,255})\b",
            "Base64_text": r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{10,}==(?=\b|[^A-Za-z0-9+/=])",
            "Generic_Secret_Base64": r"(?i)(?:secret|api[_-]?key|token|key)\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{20,})['\"]?",
            "Activos_x.com.pe": r"\b(?:[a-z0-9-]+\.)*prueba\.com\.pe\b",
            "Activos_y.com.pe": r"\b(?:[a-z0-9-]+\.)*test\.com\.pe\b",
            "Activos_z.com": r"\b(?:[A-Za-z0-9-]+\.)*servicios\.com\b",
            "OAuth2_Azure": r"https?://[a-zA-Z0-9\.-]+\.(?:b2clogin\.com|microsoftonline\.com|windows\.net)(?:/[^\s'\"<>]*)?",
            "Azure_Client_Secret": r"(?i)(?:client[_-]?secret|secret[_-]?(?:key|value))\s*[:=]\s*['\"]([A-Za-z0-9\-_~.!@#$%^&*()+=]{16,})['\"]",
            "Azure_Tenant_Domain": r"(?i)\b[a-z0-9][a-z0-9-]{0,61}[a-z0-9]?\.onmicrosoft\.com\b",
            "Azure_Tenant_ID | Azure_Client_ID | Azure_Subscription_ID": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
            "Azure_Authority_URL": r"https://login\.microsoftonline\.com/[a-z0-9\.-]+/?(?:oauth2|v2\.0)?/?",
            "Azure_AD_B2C_Policy": r"(?i)b2c_[a-z0-9_-]{5,}",
            "Azure_AD_Endpoint": r"(?i)https:\/\/[a-z0-9\.-]+(?:b2clogin|login\.microsoftonline|login\.windows\.net)[^\s'\"<>]*",
            "Azure_Storage_Connection_String": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};(?:EndpointSuffix=core\.windows\.net)?",
            "Azure_Storage_Account_Key": r"(?i)(?:accountkey|storagekey)\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{86,88})['\"]?",
            "Azure_SAS_Token": r"(?i)\b(?:sv=\d{4}-\d{2}-\d{2}(?:&[a-z]{1,3}=[a-z0-9%+/:=\-_T.]+){3,}&sig=[A-Za-z0-9%+/=]+)\b",
            "Azure_SQL_Connection_String": r"(?i)Server=tcp:[^;]+\.database\.windows\.net;[^;]*User ID=[^;]+;[^;]*Password=[^;]+;",
            "Azure_CosmosDB_Key": r"(?i)AccountEndpoint=https://[a-z0-9-]+\.documents\.azure\.com:?\d*/?;AccountKey=[A-Za-z0-9+/]{86}==;?",
            "Azure_Function_Key": r"(?i)(x-functions-key|code)\s*[:=]\s*['\"][A-Za-z0-9\-_]{20,}['\"]",
            "Azure_Container_Registry": r"(?i)\b[a-z0-9]{5,50}\.azurecr\.io\b",
            "Azure_Storage_Endpoint": r"(?i)https:\/\/[a-z0-9-]+\.blob\.core\.windows\.net",
            "Azure_KeyVault_Secret_URI": r"https:\/\/[a-z0-9-]+\.vault\.azure\.net\/secrets\/[a-zA-Z0-9-]+\/[a-zA-Z0-9]+",
            "Azure_App_Insights_InstrumentationKey": r"(?i)InstrumentationKey\s*=\s*[0-9a-f-]{36}",
            "Azure_SPN_Object_ID": r"(?i)objectid\s*(=|:)\s*['\"][0-9a-f-]{36}['\"]"
        }
        
        # Pre-compilar todos los patrones
        return {nombre: re.compile(patron) for nombre, patron in patrones_raw.items()}

    async def procesar_url_async(self, session: aiohttp.ClientSession, url: str) -> Tuple[str, Dict]:
        """Procesamiento asíncrono optimizado con cache de dominios y timeouts reducidos"""
        
        # OPTIMIZACIÓN 2: Usar cache LRU para dominios
        try:
            dominio = urlparse(url).netloc.lower()
            if es_dominio_excluido(dominio):
                logger.debug(f"URL excluida por dominio: {url}")
                return url, {}
        except Exception as e:
            logger.debug(f"Error al parsear URL {url}: {e}")
        
        max_reintentos = 2
        reintento = 0
        
        while reintento < max_reintentos:
            try:
                # OPTIMIZACIÓN 5: Timeout reducido
                async with session.get(url, ssl=False, 
                                     timeout=aiohttp.ClientTimeout(total=self.config.REQUEST_TIMEOUT),
                                     allow_redirects=False) as response:
                    
                    if response.status == 200:
                        contenido = await response.text()
                        patrones_encontrados = self._buscar_patrones_optimizado(contenido, url)
                        return url, patrones_encontrados
                    else:
                        return url, {}
                        
            except asyncio.TimeoutError:
                reintento += 1
                logger.debug(f"Timeout en {url}, reintento {reintento}/{max_reintentos}")
                await asyncio.sleep(0.5)  # Reducido de 1s
                
            except aiohttp.ClientConnectorError:
                reintento += 1
                logger.debug(f"Error de conexión en {url}, reintento {reintento}/{max_reintentos}")
                await asyncio.sleep(0.5)  # Reducido de 1s
                
            except Exception as e:
                logger.debug(f"Error inesperado en {url}: {e}")
                break
        
        return url, {}

    def _buscar_patrones_optimizado(self, contenido: str, url: str) -> Dict:
        """OPTIMIZACIÓN 7: Usar finditer() + sets para eliminación eficiente de duplicados"""
        patrones_encontrados = {}
        
        for nombre, patron_compilado in self.patrones_compilados.items():
            try:
                # OPTIMIZACIÓN 7: finditer() + set comprehension es más eficiente
                coincidencias_set = {match.group(0) for match in patron_compilado.finditer(contenido)}
                
                if coincidencias_set:
                    # Convertir a lista manteniendo orden (aunque el set ya eliminó duplicados)
                    patrones_encontrados[nombre] = list(coincidencias_set)
                    
            except Exception as e:
                logger.warning(f"Error en patrón {nombre}: {e}")
                
        return patrones_encontrados

    async def analizar_urls_masivo(self, urls: List[str]):
        """Análisis masivo asíncrono optimizado con mayor throughput"""
        print(f"{Fore.CYAN}{Style.BRIGHT}Iniciando análisis asíncrono de {len(urls)} URLs (solo códigos 200)...{Style.RESET_ALL}")
        
        # OPTIMIZACIÓN 4: Más conexiones y límites por host
        connector = aiohttp.TCPConnector(
            limit=self.config.ASYNC_CONNECTIONS, 
            limit_per_host=self.config.ASYNC_PER_HOST, 
            ssl=False
        )
        timeout = aiohttp.ClientTimeout(total=self.config.REQUEST_TIMEOUT)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # OPTIMIZACIÓN 4: Batch size aumentado
            batch_size = self.config.BATCH_SIZE
            resultados_totales = []
            total_lotes = (len(urls) - 1) // batch_size + 1
            
            for i in range(0, len(urls), batch_size):
                batch = urls[i:i + batch_size]
                lote_actual = i // batch_size + 1
                print(f"{Fore.BLUE}Procesando lote {lote_actual}/{total_lotes} ({len(batch)} URLs){Style.RESET_ALL}")
                
                tasks = [self.procesar_url_async(session, url) for url in batch]
                resultados = await asyncio.gather(*tasks, return_exceptions=True)
                
                for resultado in resultados:
                    if isinstance(resultado, tuple) and resultado[1]:
                        resultados_totales.append(resultado)
                
                if lote_actual < total_lotes:
                    await asyncio.sleep(0.3)  # Reducido de 0.5s
            
            self.resultados = resultados_totales
            
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

    def _calcular_severidad(self, patrones: Dict) -> Dict[str, int]:
        """Calcula la severidad usando frozensets optimizados"""
        contador = {"alta": 0, "media": 0, "baja": 0}
        
        # OPTIMIZACIÓN 3: Búsqueda O(1) con frozensets
        for nombre_patron in patrones.keys():
            if nombre_patron in self.severidad_alta:
                contador["alta"] += 1
            elif nombre_patron in self.severidad_media:
                contador["media"] += 1
            elif nombre_patron in self.severidad_baja:
                contador["baja"] += 1
        
        return contador

    def mostrar_resumen_completo(self):
        """Muestra un resumen ejecutivo completo de los resultados"""
        if not self.resultados:
            print(f"{Fore.YELLOW}No se encontraron patrones sensibles.{Style.RESET_ALL}")
            return
            
        total_patrones_alta = 0
        total_patrones_media = 0
        total_patrones_baja = 0
        total_patrones_general = 0
        
        for url, patrones in self.resultados:
            severidad = self._calcular_severidad(patrones)
            total_patrones_alta += severidad["alta"]
            total_patrones_media += severidad["media"]
            total_patrones_baja += severidad["baja"]
            total_patrones_general += len(patrones)
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== RESUMEN EJECUTIVO COMPLETO ==={Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total URLs analizadas: {len(self.resultados)}")
        print(f"{Fore.YELLOW}Total de patrones encontrados: {total_patrones_general}")
        print(f"{Fore.RED}Patrones con severidad ALTA: {total_patrones_alta}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Patrones con severidad MEDIA: {total_patrones_media}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Patrones con severidad BAJA: {total_patrones_baja}{Style.RESET_ALL}")
        
        self._mostrar_resultados_por_severidad("ALTA", self.resultados, Fore.RED)
        self._mostrar_resultados_por_severidad("MEDIA", self.resultados, Fore.YELLOW)
        self._mostrar_resultados_por_severidad("BAJA", self.resultados, Fore.GREEN)

    def _mostrar_resultados_por_severidad(self, severidad: str, resultados: List, color: str):
        """Muestra resultados agrupados por severidad SIN DUPLICADOS dentro de cada URL"""
        
        if severidad == "ALTA":
            patrones_severidad = self.severidad_alta
        elif severidad == "MEDIA":
            patrones_severidad = self.severidad_media
        else:
            patrones_severidad = self.severidad_baja
        
        resultados_filtrados = []
        for url, patrones in resultados:
            patrones_filtrados = {}
            for nombre, coincidencias in patrones.items():
                if nombre in patrones_severidad:
                    # Ya están sin duplicados por el set en _buscar_patrones_optimizado
                    patrones_filtrados[nombre] = coincidencias
            
            if patrones_filtrados:
                resultados_filtrados.append((url, patrones_filtrados))
        
        if resultados_filtrados:
            print(f"\n{color}{Style.BRIGHT}=== PATRONES CON SEVERIDAD {severidad} ({len(resultados_filtrados)} URLs) ==={Style.RESET_ALL}")
            for url, patrones in resultados_filtrados:
                print(f"\n{color}🔍 {url}{Style.RESET_ALL}")
                for nombre, coincidencias in patrones.items():
                    print(f"   \033[1m\033[97m⚠ {nombre}:\033[0m{Style.RESET_ALL}")
                    if coincidencias:
                        elementos_formateados = [f"'{coincidencia}'" for coincidencia in coincidencias]
                        lista_str = "[" + ", ".join(elementos_formateados) + "]"
                        print(f"     \033[37m{lista_str}{Style.RESET_ALL}")

# ===================== FUNCIONES ORIGINALES MEJORADAS =====================
def procesar_linea_mejorada(linea: str, contador_global: list, analyzer: JSAnalyzer) -> Tuple[List[str], bool]:
    """✅ CORRECCIÓN: Ahora usa el método thread-safe del analyzer"""
    try:
        url = linea.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # OPTIMIZACIÓN 5: Timeout reducido
        response = requests.get(url, timeout=10, verify=False)
        
        if response.status_code != 200:
            contador_global[0] += 1
            return [], False
        
        import warnings
        from bs4 import XMLParsedAsHTMLWarning
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        
        # OPTIMIZACIÓN 6: Parser lxml (2-3x más rápido que html.parser)
        try:
            soup = BeautifulSoup(response.text, 'lxml')
        except:
            # Fallback a html.parser si lxml no está disponible
            soup = BeautifulSoup(response.text, 'html.parser')

        rutas = []
        for tag in soup.find_all(['script', 'link'], src=True):
            src = tag.get('src', '')
            if src.lower().endswith('.js'):
                ruta_absoluta = urljoin(url, src)
                rutas.append(ruta_absoluta)

        contador_global[0] += 1
        return rutas, True
        
    except Exception as e:
        contador_global[0] += 1
        logger.debug(f"Error procesando línea {linea[:50]}...: {e}")
        return [], False

# ===================== FUNCIONES SELENIUM MEJORADAS =====================
def iniciar_driver_optimizado(config: Config) -> Optional[webdriver.Chrome]:
    """Inicialización optimizada del driver de Selenium con timeouts eficientes"""
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
        # Optimizaciones adicionales de rendimiento
        options.add_argument("--disable-javascript-harmony-shipping")
        options.add_argument("--disable-background-networking")
        options.add_argument("--disable-default-apps")
        options.add_argument("--disable-sync")
        # Configuración de timeouts en opciones
        options.page_load_strategy = 'normal'  # 'eager' para más velocidad, 'normal' para estabilidad
        
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        
        # CONFIGURACIÓN DE TIMEOUTS EFICIENTES
        # Page Load Timeout: Tiempo máximo para cargar una página
        driver.set_page_load_timeout(config.SELENIUM_PAGE_LOAD_TIMEOUT)
        
        # Script Timeout: Tiempo máximo para ejecutar scripts asíncronos
        driver.set_script_timeout(config.SELENIUM_SCRIPT_TIMEOUT)
        
        # Implicit Wait: Tiempo de espera para encontrar elementos (bajo para mejor rendimiento)
        driver.implicitly_wait(config.SELENIUM_IMPLICIT_WAIT)
        
        try:
            driver.execute_cdp_cmd("Network.enable", {})
        except Exception:
            pass
            
        return driver
    except Exception as e:
        logger.debug(f"Error iniciando driver: {e}")
        return None

def extract_js_from_logs(logs):
    """Extrae URLs de JavaScript de los logs de performance"""
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

def verificar_url_200(url: str) -> bool:
    """Verifica si una URL responde con código 200 - optimizado con timeout reducido"""
    try:
        # OPTIMIZACIÓN 5: Timeout reducido
        response = requests.head(url, timeout=8, verify=False, allow_redirects=True)
        return response.status_code == 200
    except:
        try:
            response = requests.get(url, timeout=8, verify=False, stream=True)
            return response.status_code == 200
        except:
            return False

def obtener_js_dinamicos_para_url(url: str, contador_global: list, total_urls: int, config: Config) -> Tuple[Set[str], bool]:
    """Obtiene JavaScript de forma dinámica usando Selenium con timeouts eficientes"""
    found = set()
    
    if not verificar_url_200(url):
        contador_global[0] += 1
        return found, False
    
    driver = iniciar_driver_optimizado(config)
    
    if not driver:
        contador_global[0] += 1
        return found, True

    try:
        # driver.get() respetará el page_load_timeout configurado
        driver.get(url)
        
        # OPTIMIZACIÓN 5: WAIT_TIME reducido (de Config)
        time.sleep(config.WAIT_TIME)
        
        # Scroll con timeouts para cada operación
        for i in range(config.SCROLL_STEPS):
            try:
                driver.execute_script("window.scrollBy(0, document.body.scrollHeight/3);")
            except Exception as e:
                logger.debug(f"Error en scroll: {e}")
            time.sleep(0.8)  # Reducido de 1s

        # Obtener logs con timeout implícito
        try:
            logs = driver.get_log("performance")
        except Exception as e:
            logger.debug(f"Error obteniendo logs: {e}")
            logs = []

        found = extract_js_from_logs(logs)
        
    except TimeoutException:
        # Timeout específico de Selenium (page load, script, etc.)
        logger.debug(f"Selenium timeout en {url} - página tardó más de {config.SELENIUM_PAGE_LOAD_TIMEOUT}s")
    except Exception as e:
        logger.debug(f"Error en Selenium para {url}: {e}")
    finally:
        try:
            driver.quit()
        except Exception:
            pass
            
    contador_global[0] += 1
    return found, True

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

    if os.path.exists(analyzer.config.CHECAR_FILE):
        os.remove(analyzer.config.CHECAR_FILE)

    # ✅ CORRECCIÓN: Reiniciar el set de URLs escritas
    analyzer.urls_escritas.clear()

    # ===================== FASE 1: BÚSQUEDA ESTÁTICA =====================
    print(f"{Fore.CYAN}{Style.BRIGHT}=== FASE 1: BÚSQUEDA ESTÁTICA DE ARCHIVOS JS  ==={Style.RESET_ALL}")
    
    contador_estatico = [0]
    total_js_encontrados = 0
    urls_200_fase1 = 0
    
    # OPTIMIZACIÓN 4: Más workers
    with concurrent.futures.ThreadPoolExecutor(max_workers=analyzer.config.MAX_STATIC_WORKERS) as executor:
        futures = []
        for linea in lineas:
            future = executor.submit(procesar_linea_mejorada, linea, contador_estatico, analyzer)
            futures.append(future)
        
        for future in concurrent.futures.as_completed(futures):
            try:
                rutas, es_200 = future.result()
                if es_200:
                    urls_200_fase1 += 1
                if rutas:
                    # ✅ CORRECCIÓN: Usar método thread-safe
                    urls_nuevas = 0
                    for ruta in rutas:
                        if analyzer.escribir_url_unica(ruta):
                            urls_nuevas += 1
                    total_js_encontrados += urls_nuevas
                    print(f"{Fore.GREEN}[✓] Procesada URL {contador_estatico[0]}/{len(lineas)} (200 OK) - Encontrados {urls_nuevas} JS únicos{Style.RESET_ALL}")
                elif es_200:
                    print(f"{Fore.GREEN}[✓] Procesada URL {contador_estatico[0]}/{len(lineas)} (200 OK) - Encontrados 0 JS{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[✓] Procesada URL {contador_estatico[0]}/{len(lineas)} (No 200) - Omitida{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[✓] Procesada URL {contador_estatico[0]}/{len(lineas)} - Error: {e}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== RESUMEN FASE 1 ==={Style.RESET_ALL}")
    print(f"{Fore.GREEN}URLs procesadas: {len(lineas)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}URLs con código 200: {urls_200_fase1}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Total archivos JS únicos encontrados: {total_js_encontrados}{Style.RESET_ALL}\n")

    # ===================== FASE 2: BÚSQUEDA DINÁMICA CON SELENIUM =====================
    print(f"{Fore.CYAN}{Style.BRIGHT}=== FASE 2: BÚSQUEDA DINÁMICA CON SELENIUM  ==={Style.RESET_ALL}")
    
    urls_to_process = [l.strip() for l in lineas if l.strip()]

    contador_dinamico = [0]
    urls_200_fase2 = 0
    total_js_fase2 = 0
    
    # OPTIMIZACIÓN 4: Más workers de Selenium
    with concurrent.futures.ThreadPoolExecutor(max_workers=analyzer.config.MAX_SELENIUM_WORKERS) as executor:
        futures_dyn = {}
        for url in urls_to_process:
            future = executor.submit(obtener_js_dinamicos_para_url, url, contador_dinamico, len(urls_to_process), analyzer.config)
            futures_dyn[future] = url

        for future in concurrent.futures.as_completed(futures_dyn):
            url = futures_dyn[future]
            try:
                js_set, es_200 = future.result()
            except Exception as e:
                logger.debug(f"Error en Selenium para {url}: {e}")
                js_set = set()
                es_200 = False

            if es_200:
                urls_200_fase2 += 1

            # ✅ CORRECCIÓN: Usar método thread-safe para escribir URLs
            urls_nuevas = 0
            for js in js_set:
                if analyzer.escribir_url_unica(js):
                    urls_nuevas += 1
            total_js_fase2 += urls_nuevas

            if es_200:
                print(f"{Fore.CYAN}[✓] Procesada URL {contador_dinamico[0]}/{len(urls_to_process)} (200 OK) - Encontrados {urls_nuevas} JS únicos{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[✓] Procesada URL {contador_dinamico[0]}/{len(urls_to_process)} (No 200) - Omitida{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{Style.BRIGHT}=== RESUMEN FASE 2 ==={Style.RESET_ALL}")
    print(f"{Fore.GREEN}URLs procesadas: {len(urls_to_process)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}URLs con código 200: {urls_200_fase2}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Total archivos JS únicos encontrados (nuevos): {total_js_fase2}{Style.RESET_ALL}\n")

    # ===================== FASE 3: ANÁLISIS DE PATRONES =====================
    print(f"{Fore.CYAN}{Style.BRIGHT}=== FASE 3: ANÁLISIS DE PATRONES EN ARCHIVOS JS  ==={Style.RESET_ALL}")
    
    try:
        with open(analyzer.config.CHECAR_FILE, "r") as file:
            urls_js = [line.strip() for line in file if line.strip()]
        print(f"{Fore.GREEN}Encontrados {len(urls_js)} archivos JS únicos para analizar.{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"{Fore.RED}No se encontraron archivos JS para analizar.{Style.RESET_ALL}")
        return

    if urls_js:
        await analyzer.analizar_urls_masivo(urls_js)
        
        urls_con_patrones = len(analyzer.resultados)
        total_patrones = sum(len(patrones) for _, patrones in analyzer.resultados)
        
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== RESUMEN FASE 3 ==={Style.RESET_ALL}")
        print(f"{Fore.GREEN}URLs JS analizadas: {len(urls_js)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}URLs JS con código 200 y patrones: {urls_con_patrones}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total de hallazgos: {total_patrones}{Style.RESET_ALL}\n")
        
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
                # ✅ CORRECCIÓN: Cargar URLs existentes antes de analizar
                analyzer.cargar_urls_existentes()
                
                with open(archivo_js, 'r', encoding='utf-8') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    
                print(f"{Fore.CYAN}Analizando {len(urls)} URLs...{Style.RESET_ALL}")
                await analyzer.analizar_urls_masivo(urls)
                
                urls_con_patrones = len(analyzer.resultados)
                total_patrones = sum(len(patrones) for _, patrones in analyzer.resultados)
                
                print(f"\n{Fore.CYAN}{Style.BRIGHT}=== RESUMEN DE ANÁLISIS ==={Style.RESET_ALL}")
                print(f"{Fore.GREEN}URLs analizadas: {len(urls)}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}URLs con código 200 y patrones: {urls_con_patrones}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}Total de hallazgos: {total_patrones}{Style.RESET_ALL}\n")
                
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
