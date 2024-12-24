import concurrent.futures
import requests
import re
import os
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from colorama import Fore, Style, init

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

if os.path.exists("checar.txt"):
    os.remove("checar.txt")
# Banner INICIO PROCESO
#print(f"{Fore.CYAN}{Style.BRIGHT}================= INICIO DEL PROCESO ================={Style.RESET_ALL}")

# Solicitar el archivo de entrada para las URLs de búsqueda de JS
archivo_entrada = input(f"{Fore.YELLOW}{Style.BRIGHT}Por favor, ingrese el nombre del archivo con las URLs de búsqueda (ejemplo: url.txt): {Style.RESET_ALL}")

# Función para procesar las líneas de entrada y obtener las rutas de archivos JS
def procesar_linea(linea):
    try:
        # Realizar solicitud HTTP a la URL y parsear el contenido
        url = linea.strip()
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        # Iterar sobre las etiquetas <script> y extraer rutas
        rutas = []
        for script_tag in soup.find_all('script', src=True):
            src = script_tag['src']
            if src.lower().endswith(('.js')):
                ruta_absoluta = urljoin(url, src)
                rutas.append(ruta_absoluta)

        # Imprimir las rutas y almacenarlas en el archivo "checar.txt"
        with open("checar.txt", "a") as archivo_checar:
            for ruta in rutas:
                print(ruta)
                archivo_checar.write(f"{ruta}\n")

    except Exception:
        # Omitir cualquier error en la solicitud HTTP, el análisis HTML, o la escritura en el archivo
        pass

# Función para procesar una URL y buscar patrones
def procesar_url(url):
    print(f"{Fore.GREEN}{Style.BRIGHT}[✓] Procesando URL: {Style.RESET_ALL}{url}")
    try:
        response = requests.get(url, timeout=20)
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

# Lista para almacenar los resultados de patrones
resultados = []

# Diccionario de patrones a buscar
patrones_busqueda = {
    "Conexion_aks": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net",
    "Token_JWT": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "Google-api-key": r"(?i)AIza[0-9A-Za-z\-_]{35}",
    "Authorization-Basic": r"(?i)(Authorization:\sbasic\s+[a-z0-9=:_\-+/]{5,100})",
    "Authorization-Bearer": r"(?i)(Authorization:\sbearer\s+[a-z0-9=:_\-\.+/]{5,100})",
}

if __name__ == "__main__":
    # Verificar si el archivo de entrada existe
    try:
        with open(archivo_entrada, "r") as archivo:
            lineas = archivo.readlines()
    except FileNotFoundError:
        print(f"{Fore.RED}{Style.BRIGHT}El archivo {archivo_entrada} no existe.{Style.RESET_ALL}")
        exit(1)

    # Informar que el proceso de búsqueda de archivos JS ha comenzado
    print(f"{Fore.CYAN}{Style.BRIGHT}================= INICIO DE LA BUSQUEDA DE ARCHIVOS JS ================={Style.RESET_ALL}")

    # Utilizar ThreadPoolExecutor para procesar las líneas en paralelo
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(procesar_linea, lineas)

    # Leer las URLs del archivo "checar.txt" después de haber procesado todas las líneas
    try:
        with open("checar.txt", "r") as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Fore.RED}{Style.BRIGHT}El archivo checar.txt no existe o no se genero.{Style.RESET_ALL}")
        exit(1)

    # Informar que el proceso de búsqueda de patrones ha comenzado
    print(f"{Fore.CYAN}{Style.BRIGHT}================= INICIO DE LA BUSQUEDA DE PATRONES ================={Style.RESET_ALL}")

    # Usar ThreadPoolExecutor para procesar las URL en paralelo y buscar patrones
    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(procesar_url, urls)

    # Banner FIN PROCESO
    #print(f"{Fore.CYAN}{Style.BRIGHT}================= FIN DEL PROCESO ================={Style.RESET_ALL}")

    # Imprimir los valores buscados
    print(f"{Fore.CYAN}{Style.BRIGHT}================= PATRONES BUSCADOS ================={Style.RESET_ALL}")
    for clave, valor in patrones_busqueda.items():
        print(f"{Fore.YELLOW}{Style.BRIGHT}[☀] {clave} : {valor}{Style.RESET_ALL}")

    # Imprimir margen
    print(f"{Fore.CYAN}{Style.BRIGHT}================= RESULTADO DE LAS BUSQUEDAS ================={Style.RESET_ALL}")

    # Imprimir resultados al final
    for url, patrones_encontrados in resultados:
        print(f"{Fore.YELLOW}{Style.BRIGHT}[♥] Patrones encontrados en la URL {url}:{Style.RESET_ALL}")
        for nombre, coincidencias in patrones_encontrados.items():
            print(f"{Fore.MAGENTA}{Style.BRIGHT}     {nombre}:{Style.RESET_ALL} {coincidencias}")
