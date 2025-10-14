import concurrent.futures
import requests
import re
import os
import json
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
import urllib3

# Selenium imports
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

# ===================== BANNER =====================
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
LordCristhian
"""
print(f"{Fore.RED}{Style.BRIGHT}{banner}{Style.RESET_ALL}")

# ===================== INIT =====================
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================== SETTINGS =====================
MAX_STATIC_WORKERS = 10
MAX_SELENIUM_WORKERS = 3
MAX_PATTERN_WORKERS = 10
REQUEST_TIMEOUT = 15
WAIT_TIME = 6
SCROLL_STEPS = 3
CHECAR_FILE = "checar.txt"

# ===================== FUNCIONES =====================
def procesar_linea(linea):
    try:
        url = linea.strip()
        response = requests.get(url, timeout=15, verify=False)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        rutas = []
        for script_tag in soup.find_all('script', src=True):
            src = script_tag['src']
            if src.lower().endswith('.js'):
                ruta_absoluta = urljoin(url, src)
                rutas.append(ruta_absoluta)

        with open(CHECAR_FILE, "a") as archivo_checar:
            for ruta in rutas:
                print(ruta)
                archivo_checar.write(f"{ruta}\n")

    except Exception:
        pass

def procesar_url(url):
    print(f"{Fore.GREEN}{Style.BRIGHT}[✓] Procesando URL: {Style.RESET_ALL}{url}")
    try:
        response = requests.get(url, timeout=20, verify=False)
        response.raise_for_status()
        contenido = response.text
        patrones_encontrados = {}
        for nombre, patron in patrones_busqueda.items():
            coincidencias = re.findall(patron, contenido)
            if coincidencias:
                patrones_encontrados[nombre] = coincidencias
        if patrones_encontrados:
            resultados.append((url, patrones_encontrados))
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}{Style.BRIGHT}[x] Error al procesar URL: {Style.RESET_ALL}{url}")

def iniciar_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    try:
        driver.execute_cdp_cmd("Network.enable", {})
    except Exception:
        pass
    return driver

def extract_js_from_logs(logs):
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

def obtener_js_dinamicos_para_url(url):
    found = set()
    try:
        driver = iniciar_driver()
    except Exception:
        return found

    try:
        driver.get(url)
        time.sleep(WAIT_TIME)
        for _ in range(SCROLL_STEPS):
            try:
                driver.execute_script("window.scrollBy(0, document.body.scrollHeight/3);")
            except Exception:
                pass
            time.sleep(1)

        try:
            logs = driver.get_log("performance")
        except Exception:
            logs = []

        found.update(extract_js_from_logs(logs))
    except Exception:
        pass
    finally:
        try:
            driver.quit()
        except Exception:
            pass
    return found

# ===================== PATRONES =====================
resultados = []
patrones_busqueda = {
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
    "Generic_Base64_Secret": r"(?i)(?:secret|key|token)\s*(?:=|:)\s*['\"]?[A-Za-z0-9+/=]{20,}['\"]?"
}

# ===================== MENÚ DE OPCIONES =====================
print(f"{Fore.CYAN}{Style.BRIGHT}Seleccione el modo de ejecución:{Style.RESET_ALL}")
print(f"{Fore.YELLOW}1.{Style.RESET_ALL} Buscar archivos JS desde URLs y luego analizar patrones.")
print(f"{Fore.YELLOW}2.{Style.RESET_ALL} Analizar directamente patrones desde un archivo con rutas .js")

modo = input(f"{Fore.CYAN}{Style.BRIGHT}Ingrese el número de opción (1 o 2): {Style.RESET_ALL}")

# ===================== OPCIÓN 1: flujo completo (como antes) =====================
if modo.strip() == "1":
    if os.path.exists(CHECAR_FILE):
        os.remove(CHECAR_FILE)

    archivo_entrada = input(f"{Fore.YELLOW}{Style.BRIGHT}Ingrese el nombre del archivo con las URLs (ejemplo: url.txt): {Style.RESET_ALL}")

    try:
        with open(archivo_entrada, "r") as archivo:
            lineas = archivo.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}{Style.BRIGHT}El archivo {archivo_entrada} no existe.{Style.RESET_ALL}")
        exit(1)

    print(f"{Fore.CYAN}{Style.BRIGHT}================= INICIO DE LA BUSQUEDA DE ARCHIVOS JS ================={Style.RESET_ALL}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_STATIC_WORKERS) as executor:
        futures_static = [executor.submit(procesar_linea, linea) for linea in lineas]
        concurrent.futures.wait(futures_static)

    print(f"{Fore.CYAN}{Style.BRIGHT}================= RECOLECCION DINAMICA (SELENIUM) ================={Style.RESET_ALL}")

    urls_to_process = [l.strip() for l in lineas if l.strip()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SELENIUM_WORKERS) as executor:
        futures_dyn = {executor.submit(obtener_js_dinamicos_para_url, url): url for url in urls_to_process}

        completed = 0
        for fut in concurrent.futures.as_completed(futures_dyn):
            url = futures_dyn[fut]
            try:
                js_set = fut.result()
            except Exception:
                js_set = set()

            if js_set:
                try:
                    existing = set()
                    if os.path.exists(CHECAR_FILE):
                        with open(CHECAR_FILE, "r") as fh:
                            existing = set([ln.strip() for ln in fh.readlines() if ln.strip()])
                except Exception:
                    existing = set()

                with open(CHECAR_FILE, "a") as fh:
                    for js in sorted(js_set):
                        if js not in existing:
                            print(js)
                            fh.write(js + "\n")

            completed += 1
            print(f"{Fore.CYAN}[{completed}/{len(urls_to_process)}] Completado: {url}{Style.RESET_ALL}")

    try:
        with open(CHECAR_FILE, "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Fore.RED}{Style.BRIGHT}No se encontró checar.txt para analizar patrones.{Style.RESET_ALL}")
        exit(1)

# ===================== OPCIÓN 2: solo análisis de patrones =====================
elif modo.strip() == "2":
    archivo_js = input(f"{Fore.YELLOW}{Style.BRIGHT}Ingrese el nombre del archivo que contiene las rutas .js: {Style.RESET_ALL}")
    try:
        with open(archivo_js, "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Fore.RED}{Style.BRIGHT}El archivo {archivo_js} no existe.{Style.RESET_ALL}")
        exit(1)

# ===================== BUSQUEDA DE PATRONES (común para ambos modos) =====================
print(f"{Fore.CYAN}{Style.BRIGHT}================= INICIO DE LA BUSQUEDA DE PATRONES ================={Style.RESET_ALL}")

with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PATTERN_WORKERS) as executor:
    futures_patterns = [executor.submit(procesar_url, url) for url in urls]
    concurrent.futures.wait(futures_patterns)

print(f"{Fore.CYAN}{Style.BRIGHT}================= PATRONES BUSCADOS ================={Style.RESET_ALL}")
for clave, valor in patrones_busqueda.items():
    print(f"{Fore.YELLOW}{Style.BRIGHT}[☀] {clave} : {valor}{Style.RESET_ALL}")

print(f"{Fore.CYAN}{Style.BRIGHT}================= RESULTADO DE LAS BUSQUEDAS ================={Style.RESET_ALL}")
for url, patrones_encontrados in resultados:
    print(f"{Fore.YELLOW}{Style.BRIGHT}[♥] Patrones encontrados en la URL {url}:{Style.RESET_ALL}")
    for nombre, coincidencias in patrones_encontrados.items():
        print(f"{Fore.MAGENTA}{Style.BRIGHT}     {nombre}:{Style.RESET_ALL} {coincidencias}")
