import concurrent.futures
import requests
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style, init
import urllib3

# Banner
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


if os.path.exists("checar.txt"):
    os.remove("checar.txt")


archivo_entrada = input(f"{Fore.YELLOW}{Style.BRIGHT}Por favor, ingrese el nombre del archivo con las URLs de búsqueda (ejemplo: url.txt): {Style.RESET_ALL}")


def procesar_linea(linea):
    try:
        
        url = linea.strip()
        response = requests.get(url, timeout=15, verify=False)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        
        rutas = []
        for script_tag in soup.find_all('script', src=True):
            src = script_tag['src']
            if src.lower().endswith(('.js')):
                ruta_absoluta = urljoin(url, src)
                rutas.append(ruta_absoluta)

       
        with open("checar.txt", "a") as archivo_checar:
            for ruta in rutas:
                print(ruta)
                archivo_checar.write(f"{ruta}\n")

    except Exception:
        
        pass


def procesar_url(url):
    print(f"{Fore.GREEN}{Style.BRIGHT}[✓] Procesando URL: {Style.RESET_ALL}{url}")
    try:
        response = requests.get(url, timeout=20,verify=False)
        response.raise_for_status()
        contenido = response.text
        patrones_encontrados = {}
        for nombre, patron in patrones_busqueda.items():
            coincidencias = re.findall(patron, contenido)
            if coincidencias:
                patrones_encontrados[nombre] = coincidencias
        if patrones_encontrados:
            resultados.append((url, patrones_encontrados))
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}{Style.BRIGHT}[x] Error al procesar URL: {Style.RESET_ALL}{url}")


resultados = []


patrones_busqueda = {
    "Conexion_aks": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net",
    "Token_JWT": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "Google-api-key": r"(?i)AIza[0-9A-Za-z\-_]{35}",
    "Authorization-Basic": r"(?i)(Authorization:\sbasic\s+[a-z0-9=:_\-+/]{5,100})",
    "Authorization-Bearer": r"(?i)(Authorization:\sbearer\s+[a-z0-9=:_\-\.+/]{5,100})",
}

if __name__ == "__main__":
    
    try:
        with open(archivo_entrada, "r") as archivo:
            lineas = archivo.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}{Style.BRIGHT}El archivo {archivo_entrada} no existe.{Style.RESET_ALL}")
        exit(1)

    
    print(f"{Fore.CYAN}{Style.BRIGHT}================= INICIO DE LA BUSQUEDA DE ARCHIVOS JS ================={Style.RESET_ALL}")

    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(procesar_linea, lineas)

    
    try:
        with open("checar.txt", "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Fore.RED}{Style.BRIGHT}El archivo checar.txt no existe o no se genero.{Style.RESET_ALL}")
        exit(1)

    
    print(f"{Fore.CYAN}{Style.BRIGHT}================= INICIO DE LA BUSQUEDA DE PATRONES ================={Style.RESET_ALL}")

    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(procesar_url, urls)

    # Imprimir los valores buscados
    print(f"{Fore.CYAN}{Style.BRIGHT}================= PATRONES BUSCADOS ================={Style.RESET_ALL}")
    for clave, valor in patrones_busqueda.items():
        print(f"{Fore.YELLOW}{Style.BRIGHT}[☀] {clave} : {valor}{Style.RESET_ALL}")

    print(f"{Fore.CYAN}{Style.BRIGHT}================= RESULTADO DE LAS BUSQUEDAS ================={Style.RESET_ALL}")

    # Imprimir resultados al final
    for url, patrones_encontrados in resultados:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[♥] Patrones encontrados en la URL {url}:{Style.RESET_ALL}")
        for nombre, coincidencias in patrones_encontrados.items():
            print(f"{Fore.MAGENTA}{Style.BRIGHT}     {nombre}:{Style.RESET_ALL} {coincidencias}")
