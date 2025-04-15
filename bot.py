import subprocess
import requests
import hashlib
import base64
import whois
import os
import json
import exifread
import tempfile
import shodan
import re
import random
import string
import time
from pathlib import Path
from scapy.all import ARP, Ether, srp
from urllib.parse import urlparse
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    CallbackQueryHandler, filters, ContextTypes, ConversationHandler
)
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configuration - load from environment variables
BOT_TOKEN = os.getenv('BOT_TOKEN')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
ALLOWED_USERS = [int(id) for id in os.getenv('ALLOWED_USERS', '').split(',') if id]

# State definitions for ConversationHandler
WAITING_FOR_INPUT = 1
WAITING_FOR_WORDLIST = 2
WAITING_FOR_WIFI_SCAN = 3
WAITING_FOR_WIFI_ATTACK = 4

# Initialize clients
shodan_client = shodan.Shodan(SHODAN_API_KEY) if SHODAN_API_KEY else None

# Helper functions
def is_valid_domain(domain):
    """Check if input is a valid domain."""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_ip(ip):
    """Check if input is a valid IP address."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split('.'))

def sanitize_input(text, operation):
    """Sanitize input based on operation type."""
    text = text.strip()
    
    if operation in ["nmap", "network_scan"]:
        # Only allow valid domains and IPs for nmap
        if not (is_valid_domain(text) or is_valid_ip(text) or text == "local"):
            raise ValueError("Input deve essere un dominio, IP valido o 'local'")
        
        # Check for command injection attempts
        if ';' in text or '&' in text or '|' in text or '>' in text or '<' in text:
            raise ValueError("Input non valido")
    
    elif operation in ["whois", "tech", "subdomains"]:
        # Domain validation
        if not is_valid_domain(text):
            raise ValueError("Input deve essere un dominio valido")
    
    elif operation in ["ipinfo", "geoip", "shodan"]:
        # IP validation
        if not is_valid_ip(text):
            raise ValueError("Input deve essere un indirizzo IP valido")
    
    return text

def scan_local_network():
    """Scan local network for devices using ARP."""
    # Create ARP request packets for the entire subnet
    target_ip = "192.168.1.0/24"  # Common home network range
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    result = srp(packet, timeout=3, verbose=0)[0]
    
    # List of available devices
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

def generate_password(length=12, complexity=3):
    """Generate a random password with specified complexity."""
    if complexity < 1 or complexity > 4:
        complexity = 3
    
    char_sets = [
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation
    ]
    
    chars = ''.join(char_sets[:complexity])
    
    # Ensure we have at least one character from each requested set
    password = [random.choice(char_set) for char_set in char_sets[:complexity]]
    
    # Fill the rest randomly
    remaining = length - complexity
    if remaining > 0:
        password.extend(random.choice(chars) for _ in range(remaining))
    
    # Shuffle the password characters
    random.shuffle(password)
    return ''.join(password)

async def is_authorized(update: Update) -> bool:
    """Check if user is authorized to use the bot."""
    user_id = update.effective_user.id
    if not ALLOWED_USERS or user_id not in ALLOWED_USERS:
        await update.message.reply_text("❌ Non sei autorizzato ad usare questo bot.")
        return False
    return True

# Command handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    await update.message.reply_text(
        "👋 Benvenuto al Bot di Security Tools Avanzato!\n\n"
        "Questo bot offre vari strumenti per l'analisi di sicurezza e informazioni.\n"
        "Usa /menu per visualizzare le opzioni disponibili."
    )
    return ConversationHandler.END

async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display the main menu of available operations."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    keyboard = [
        [KeyboardButton("🔍 WHOIS"), KeyboardButton("🌐 IP Info")],
        [KeyboardButton("📡 Nmap Scan"), KeyboardButton("🧬 Base64 Encode")],
        [KeyboardButton("🔐 Hash"), KeyboardButton("🌍 GeoIP")],
        [KeyboardButton("📂 Metadata"), KeyboardButton("🧠 Headers")],
        [KeyboardButton("🛰️ Shodan"), KeyboardButton("🔧 Tech Detect")],
        [KeyboardButton("🌐 Subdomains"), KeyboardButton("🔎 Network Scan")],
        [KeyboardButton("📶 WiFi Tools"), KeyboardButton("🔑 Password Tools")],
        [KeyboardButton("❓ Aiuto")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text(
        "📲 *Scegli un'operazione:*\n"
        "Dopo aver selezionato un'operazione, inserisci il dato da analizzare.", 
        reply_markup=reply_markup, 
        parse_mode='Markdown'
    )
    return ConversationHandler.END

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display help information."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    help_text = (
        "📚 *Guida all'uso del Bot*\n\n"
        "1. Usa /menu per visualizzare tutte le opzioni\n"
        "2. Seleziona un'operazione dal menu\n"
        "3. Fornisci l'input richiesto\n\n"
        "*Operazioni disponibili:*\n"
        "🔍 WHOIS - Informazioni di registrazione dominio\n"
        "🌐 IP Info - Dettagli su un indirizzo IP\n"
        "📡 Nmap Scan - Scansione porte di base\n"
        "🧬 Base64 - Codifica/decodifica testo\n"
        "🔐 Hash - Calcola valori hash\n"
        "🌍 GeoIP - Localizzazione geografica IP\n"
        "📂 Metadata - Estrai metadata da file\n"
        "🧠 Headers - Mostra headers HTTP\n"
        "🛰️ Shodan - Cerca informazioni su Shodan\n"
        "🔧 Tech Detect - Rileva tecnologie sito web\n"
        "🌐 Subdomains - Trova sottodomini\n"
        "🔎 Network Scan - Scansione dispositivi sulla rete\n"
        "📶 WiFi Tools - Strumenti per reti WiFi\n"
        "🔑 Password Tools - Generazione e cracking password\n\n"
        "Per metadata, invia un file dopo aver selezionato l'opzione"
    )
    await update.message.reply_text(help_text, parse_mode='Markdown')
    return ConversationHandler.END

async def wifi_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display WiFi tools menu."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    keyboard = [
        [KeyboardButton("📶 Scansione WiFi")],
        [KeyboardButton("🔐 Cracking WiFi WPA")],
        [KeyboardButton("🔄 Deauth Attack")],
        [KeyboardButton("📡 Monitor Mode")],
        [KeyboardButton("⬅️ Menu Principale")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text(
        "📶 *WiFi Tools*\n\n"
        "Seleziona un'operazione relativa alle reti WiFi.", 
        reply_markup=reply_markup, 
        parse_mode='Markdown'
    )
    return ConversationHandler.END

async def password_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display password tools menu."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    keyboard = [
        [KeyboardButton("🔑 Genera Password")],
        [KeyboardButton("🔓 Password Cracking Hash")],
        [KeyboardButton("📑 Dizionario Password")],
        [KeyboardButton("⬅️ Menu Principale")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text(
        "🔑 *Password Tools*\n\n"
        "Seleziona un'operazione relativa alle password.", 
        reply_markup=reply_markup, 
        parse_mode='Markdown'
    )
    return ConversationHandler.END

async def process_selection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process menu selection and prepare for input."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    text = update.message.text
    
    # Map button texts to operations
    operation_map = {
        "🔍 WHOIS": "whois",
        "🌐 IP Info": "ipinfo",
        "📡 Nmap Scan": "nmap",
        "🧬 Base64 Encode": "encode",
        "🔐 Hash": "hash",
        "🌍 GeoIP": "geoip",
        "📂 Metadata": "metadata",
        "🧠 Headers": "headers",
        "🛰️ Shodan": "shodan",
        "🔧 Tech Detect": "tech",
        "🌐 Subdomains": "subdomains",
        "🔎 Network Scan": "network_scan",
        "📶 WiFi Tools": "wifi_menu",
        "🔑 Password Tools": "password_menu",
        "⬅️ Menu Principale": "main_menu",
        "❓ Aiuto": "help",
        # WiFi submenu
        "📶 Scansione WiFi": "wifi_scan",
        "🔐 Cracking WiFi WPA": "wifi_crack",
        "🔄 Deauth Attack": "wifi_deauth",
        "📡 Monitor Mode": "wifi_monitor",
        # Password submenu
        "🔑 Genera Password": "password_generate",
        "🔓 Password Cracking Hash": "password_crack",
        "📑 Dizionario Password": "password_dict"
    }
    
    operation = operation_map.get(text)
    
    if not operation:
        await update.message.reply_text("❌ Operazione non valida. Usa /menu per visualizzare le opzioni.")
        return ConversationHandler.END
    
    if operation == "help":
        return await help_command(update, context)
    elif operation == "wifi_menu":
        return await wifi_menu(update, context)
    elif operation == "password_menu":
        return await password_menu(update, context)
    elif operation == "main_menu":
        return await menu(update, context)
    
    # Store the selected operation in user data
    context.user_data['operation'] = operation
    
    # Special handling for metadata
    if operation == "metadata":
        await update.message.reply_text("📄 Invia un file per estrarre i metadata.")
        return WAITING_FOR_INPUT
    
    # Special handling for WiFi operations
    elif operation == "wifi_scan":
        await update.message.reply_text(
            "📶 *Scansione WiFi*\n\n"
            "Questa funzione scansiona le reti WiFi nelle vicinanze.\n"
            "Digita 'scan' per avviare la scansione.",
            parse_mode='Markdown'
        )
        return WAITING_FOR_WIFI_SCAN
    
    elif operation == "wifi_crack":
        await update.message.reply_text(
            "🔐 *Cracking WiFi WPA*\n\n"
            "Inserisci il nome della rete WiFi (SSID) da analizzare:",
            parse_mode='Markdown'
        )
        return WAITING_FOR_WIFI_ATTACK
    
    elif operation == "wifi_deauth":
        await update.message.reply_text(
            "🔄 *Deauth Attack*\n\n"
            "Inserisci il BSSID (MAC) dell'access point e il MAC del client da deautenticare nel formato:\n"
            "`[BSSID AP] [MAC Client]`\n"
            "Esempio: `00:11:22:33:44:55 AA:BB:CC:DD:EE:FF`",
            parse_mode='Markdown'
        )
        return WAITING_FOR_INPUT
    
    elif operation == "wifi_monitor":
        await update.message.reply_text("📡 Invio disponibilità interfacce wireless...")
        try:
            result = subprocess.run(
                ['iwconfig'],
                capture_output=True, text=True, timeout=5
            )
            interfaces = result.stdout.strip()
            await update.message.reply_text(
                f"📡 *Interfacce Wireless*\n\n```\n{interfaces}\n```\n\n"
                "Per impostare un'interfaccia in modalità monitor, digita:\n"
                "`monitor [interfaccia]`\n"
                "Esempio: `monitor wlan0`",
                parse_mode='Markdown'
            )
        except Exception as e:
            await update.message.reply_text(f"⚠️ Errore nell'ottenere le interfacce: {str(e)}")
        return WAITING_FOR_INPUT
    
    # Special handling for password operations
    elif operation == "password_generate":
        await update.message.reply_text(
            "🔑 *Genera Password*\n\n"
            "Inserisci i parametri nel formato: `[lunghezza] [complessità]`\n"
            "- Lunghezza: numero di caratteri (8-64)\n"
            "- Complessità: 1-4 (1=min, 4=max)\n\n"
            "Esempio: `16 3`",
            parse_mode='Markdown'
        )
        return WAITING_FOR_INPUT
    
    elif operation == "password_crack":
        await update.message.reply_text(
            "🔓 *Password Cracking Hash*\n\n"
            "Inserisci l'hash da provare a craccare:",
            parse_mode='Markdown'
        )
        return WAITING_FOR_WORDLIST
    
    elif operation == "password_dict":
        await update.message.reply_text(
            "📑 *Dizionario Password*\n\n"
            "Inserisci la parola base per generare varianti:",
            parse_mode='Markdown'
        )
        return WAITING_FOR_INPUT
    
    # Standard operations
    instructions = {
        "whois": "🔍 Inserisci un dominio per la ricerca WHOIS:",
        "ipinfo": "🌐 Inserisci un indirizzo IP per ottenere informazioni:",
        "nmap": "📡 Inserisci un dominio o IP per la scansione Nmap:",
        "encode": "🧬 Inserisci il testo da codificare in Base64:",
        "hash": "🔐 Inserisci il testo di cui calcolare gli hash:",
        "geoip": "🌍 Inserisci un indirizzo IP per la geolocalizzazione:",
        "headers": "🧠 Inserisci un URL per analizzare gli headers HTTP:",
        "shodan": "🛰️ Inserisci un indirizzo IP per la ricerca su Shodan:",
        "tech": "🔧 Inserisci un URL per rilevare le tecnologie:",
        "subdomains": "🌐 Inserisci un dominio per trovare sottodomini:",
        "network_scan": "🔎 Inserisci 'local' per scansionare la rete locale o un IP/subnet (es. 192.168.1.0/24):"
    }
    
    await update.message.reply_text(instructions.get(operation, "Inserisci i dati:"))
    return WAITING_FOR_INPUT

async def process_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process user input based on previously selected operation."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    operation = context.user_data.get('operation')
    
    if not operation:
        await update.message.reply_text("❌ Nessuna operazione selezionata. Usa /menu per iniziare.")
        return ConversationHandler.END
    
    # Handle file upload for metadata
    if operation == "metadata" and update.message.document:
        return await process_metadata(update, context)
    
    # Handle text input for other operations
    if not update.message.text:
        await update.message.reply_text("⚠️ Inserisci un input valido.")
        return WAITING_FOR_INPUT
    
    text = update.message.text
    
    try:
        # Validate and sanitize input
        if operation not in ["encode", "hash", "password_generate", "password_dict", "wifi_monitor"]:
            text = sanitize_input(text, operation)
        
        # Process WiFi monitor mode command
        if operation == "wifi_monitor" and text.startswith("monitor "):
            interface = text.split()[1]
            await update.message.reply_text(f"📡 Tentativo di mettere {interface} in modalità monitor...")
            
            try:
                # Bring interface down
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'], check=True, timeout=5)
                # Set monitor mode
                subprocess.run(['sudo', 'iw', interface, 'set', 'monitor', 'none'], check=True, timeout=5)
                # Bring interface back up
                subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'], check=True, timeout=5)
                
                # Check if monitor mode was enabled
                result = subprocess.run(['iwconfig', interface], capture_output=True, text=True, timeout=5)
                if "Mode:Monitor" in result.stdout:
                    await update.message.reply_text(f"✅ {interface} è ora in modalità monitor!")
                else:
                    await update.message.reply_text(f"⚠️ Non è stato possibile attivare la modalità monitor su {interface}.")
            except Exception as e:
                await update.message.reply_text(f"❌ Errore: {str(e)}")
        
        # Process WiFi deauth attack
        elif operation == "wifi_deauth":
            parts = text.split()
            if len(parts) != 2:
                await update.message.reply_text("⚠️ Formato non valido. Usa: `[BSSID AP] [MAC Client]`", parse_mode='Markdown')
            else:
                ap_mac, client_mac = parts
                
                # Validate MAC address format with regex
                mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
                if not (re.match(mac_pattern, ap_mac) and re.match(mac_pattern, client_mac)):
                    await update.message.reply_text("❌ Formato MAC non valido.")
                else:
                    await update.message.reply_text(
                        f"🔄 *Deauth Attack*\n\n"
                        f"AP: `{ap_mac}`\n"
                        f"Client: `{client_mac}`\n\n"
                        f"Per eseguire l'attacco reale, usa aireplay-ng con un'interfaccia in modalità monitor:\n\n"
                        f"```\n"
                        f"sudo aireplay-ng --deauth 10 -a {ap_mac} -c {client_mac} [interfaccia]\n"
                        f"```",
                        parse_mode='Markdown'
                    )
        
        # Process password generation
        elif operation == "password_generate":
            parts = text.split()
            if len(parts) != 2:
                await update.message.reply_text("⚠️ Formato non valido. Usa: `[lunghezza] [complessità]`", parse_mode='Markdown')
            else:
                try:
                    length = int(parts[0])
                    complexity = int(parts[1])
                    
                    if length < 8 or length > 64:
                        await update.message.reply_text("⚠️ La lunghezza deve essere tra 8 e 64 caratteri.")
                    elif complexity < 1 or complexity > 4:
                        await update.message.reply_text("⚠️ La complessità deve essere tra 1 e 4.")
                    else:
                        password = generate_password(length, complexity)
                        await update.message.reply_text(
                            f"🔑 *Password Generata*\n\n"
                            f"```\n{password}\n```\n\n"
                            f"*Lunghezza*: {length} caratteri\n"
                            f"*Complessità*: {complexity}/4",
                            parse_mode='Markdown'
                        )
                except ValueError:
                    await update.message.reply_text("⚠️ I parametri devono essere numeri.")
        
        # Process dictionary generation
        elif operation == "password_dict":
            base_word = text.strip().lower()
            if len(base_word) < 3:
                await update.message.reply_text("⚠️ La parola base deve avere almeno 3 caratteri.")
            else:
                variations = []
                
                # Common variations
                variations.append(base_word)
                variations.append(base_word.capitalize())
                variations.append(base_word.upper())
                
                # Add numbers
                for i in range(10):
                    variations.append(f"{base_word}{i}")
                
                # Add year
                current_year = time.localtime().tm_year
                variations.append(f"{base_word}{current_year}")
                variations.append(f"{base_word}{current_year-1}")
                
                # Common substitutions
                substitutions = {
                    'a': '@', 'e': '3', 'i': '1', 
                    'o': '0', 's': '$', 't': '7'
                }
                
                # Apply substitutions
                subst_word = base_word
                for char, repl in substitutions.items():
                    if char in base_word:
                        subst_word = subst_word.replace(char, repl)
                
                if subst_word != base_word:
                    variations.append(subst_word)
                
                # Common suffixes
                for suffix in ['123', '1234', '!', '!!', '?', '.', '_123']:
                    variations.append(f"{base_word}{suffix}")
                
                # Make list unique and limit size
                unique_variations = list(set(variations))[:30]
                
                dict_text = "\n".join(unique_variations)
                await update.message.reply_text(
                    f"📑 *Dizionario Password*\n\n"
                    f"Parola base: `{base_word}`\n"
                    f"Varianti generate: {len(unique_variations)}\n\n"
                    f"```\n{dict_text}\n```",
                    parse_mode='Markdown'
                )
        
        # Process network scan
        elif operation == "network_scan":
            if text.lower() == "local":
                await update.message.reply_text("🔍 Scansione della rete locale in corso...")
                try:
                    devices = scan_local_network()
                    
                    if devices:
                        result = "🖥️ *Dispositivi trovati nella rete locale:*\n\n"
                        for i, device in enumerate(devices, 1):
                            result += f"{i}. IP: `{device['ip']}` - MAC: `{device['mac']}`\n"
                        
                        await update.message.reply_text(result, parse_mode='Markdown')
                    else:
                        await update.message.reply_text("⚠️ Nessun dispositivo trovato nella rete locale.")
                except Exception as e:
                    await update.message.reply_text(f"❌ Errore durante la scansione: {str(e)}")
            else:
                target = text.strip()
                await update.message.reply_text(f"🔍 Esecuzione scansione sulla rete {target}...")
                try:
                    # Use -sn for host discovery only
                    result = subprocess.run(
                        ['nmap', '-sn', target],
                        capture_output=True, text=True, timeout=60
                    )
                    await update.message.reply_text(f"🖥️ *Risultati scansione rete {target}*:\n\n```\n{result.stdout[:4000]}\n```", parse_mode='Markdown')
                except Exception as e:
                    await update.message.reply_text(f"❌ Errore durante la scansione: {str(e)}")
        
        # Standard operations from the original code
        elif operation == "whois":
            w = whois.whois(text)
            await update.message.reply_text(f"🔍 *WHOIS per {text}*\n\n```\n{json.dumps(w, indent=2, default=str)[:4000]}\n```", parse_mode='Markdown')
        
        elif operation == "ipinfo":
            response = requests.get(f"https://ipinfo.io/{text}/json")
            data = response.json()
            
            if 'bogon' in data and data['bogon']:
                await update.message.reply_text(f"⚠️ {text} è un indirizzo IP 'bogon', non valido per l'uso pubblico.")
            else:
                info = (
                    f"🖥️ *Dettagli IP: {text}*\n\n"
                    f"*IP*: {data.get('ip')}\n"
                    f"*Città*: {data.get('city', 'N/A')}\n"
                    f"*Regione*: {data.get('region', 'N/A')}\n"
                    f"*Paese*: {data.get('country', 'N/A')}\n"
                    f"*Localizzazione*: {data.get('loc', 'N/A')}\n"
                    f"*ISP*: {data.get('org', 'N/A')}\n"
                    f"*Hostname*: {data.get('hostname', 'N/A')}"
                )
                await update.message.reply_text(info, parse_mode='Markdown')
        
        elif operation == "nmap":
            await update.message.reply_text(f"🔄 Esecuzione scan su {text}. Potrebbe richiedere un minuto...")
            try:
                # Improved scan with service detection
                result = subprocess.run(
                    ['nmap', '-F', '-sV', '--host-timeout', '45s', text],
                    capture_output=True, text=True, timeout=60
                )
                await update.message.reply_text(f"📡 *Risultati Nmap per {text}*:\n\n```\n{result.stdout[:4000]}\n```", parse_mode='Markdown')
            except subprocess.TimeoutExpired:
                await update.message.reply_text("⏱️ Timeout durante la scansione. Prova un host più veloce da raggiungere.")
            except subprocess.CalledProcessError as e:
                await update.message.reply_text(f"⚠️ Errore durante la scansione: {e.stderr[:500]}")
        
        elif operation == "encode":
            encoded = base64.b64encode(text.encode()).decode()
            try:
                decoded = base64.b64decode(text.encode()).decode()
                is_valid_b64 = True
            except Exception:
                decoded = "[Input non valido come Base64]"
                is_valid_b64 = False
            
            response = f"🧬 *Base64*\n\n"
            response += f"*Input originale*: `{text}`\n"
            response += f"*Codificato*: `{encoded}`\n"
            
            if is_valid_b64:
                response += f"*Input decodificato*: `{decoded}`\n"
                response += "*Nota*: L'input fornito era già in formato Base64 valido"
            
            await update.message.reply_text(response, parse_mode='Markdown')
        
        elif operation == "hash":
            md5 = hashlib.md5(text.encode()).hexdigest()
            sha1 = hashlib.sha1(text.encode()).hexdigest()
            sha256 = hashlib.sha256(text.encode()).hexdigest()
            sha512 = hashlib.sha512(text.encode()).hexdigest()
            
            await update.message.reply_text(
                f"🔐 *Hash di '{text}'*\n\n"
                f"*MD5*: `{md5}`\n"
                f"*SHA1*: `{sha1}`\n"
                f"*SHA256*: `{sha256}`\n"
                f"*SHA512*: `{sha512}`", 
                parse_mode='Markdown'
            )
        
        elif operation == "geoip":
            data = requests.get(f"https://ipapi.co/{text}/json/").json()
            if 'error' in data:
                await update.message.reply_text(f"⚠️ Errore: {data.get('reason', 'Errore sconosciuto')}")
            else:
                info = (
                    f"🌍 *GeoIP per {text}*\n\n"
                    f"*Paese*: {data.get('country_name', 'N/A')} ({data.get('country', 'N/A')})\n"
                    f"*Regione*: {data.get('region', 'N/A')}\n"
                    f"*Città*: {data.get('city', 'N/A')}\n"
                    f"*Latitudine*: {data.get('latitude', 'N/A')}\n"
                    f"*Longitudine*: {data.get('longitude', 'N/A')}\n"
                    f"*ISP*: {data.get('org', 'N/A')}\n"
                    f"*ASN*: {data.get('asn', 'N/A')}"
                )
                await update.message.reply_text(info, parse_mode='Markdown')
        
        elif operation == "headers":
            # Ensure URL has a scheme
            if not text.startswith(('http://', 'https://')):
                text = 'https://' + text
            
            try:
                resp = requests.get(text, timeout=10, allow_redirects=True, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                })
                headers = '\n'.join(f'*{k}*: {v}' for k, v in resp.headers.items())
                
                # Check for security headers
                security_headers = {
                    'Strict-Transport-Security': 'HSTS non trovato - Possibile vulnerabilità di downgrade!',
                    'Content-Security-Policy': 'CSP non trovato - Possibile vulnerabilità XSS!',
                    'X-Content-Type-Options': 'X-Content-Type-Options non trovato - Possibile MIME sniffing!',
                    'X-Frame-Options': 'X-Frame-Options non trovato - Possibile clickjacking!'
                }
                
                security_analysis = "*Analisi di sicurezza degli header:*\n"
                for header, warning in security_headers.items():
                    if header not in resp.headers:
                        security_analysis += f"⚠️ {warning}\n"
                    else:
                        security_analysis += f"✅ {header} presente ({resp.headers[header]})\n"
                
                await update.message.reply_text(
                    f"🧠 *Headers per {text}*\n\n"
                    f"*Status Code*: {resp.status_code}\n"
                    f"*Redirects*: {len(resp.history)}\n\n"
                    f"{headers[:2000]}\n\n"
                    f"{security_analysis}", 
                    parse_mode='Markdown'
                )
            except requests.exceptions.RequestException as e:
                await update.message.reply_text(f"⚠️ Errore nella richiesta: {str(e)}")
        
        elif operation == "shodan":
            if not shodan_client:
                await update.message.reply_text("⚠️ API Shodan non configurata.")
            else:
                try:
                    result = shodan_client.host(text)
                    summary = (
                        f"🛰️ *Shodan per {text}*\n\n"
                        f"*IP*: {result.get('ip_str', 'N/A')}\n"
                        f"*Hostname*: {', '.join(result.get('hostnames', ['N/A']))}\n"
                        f"*Paese*: {result.get('country_name', 'N/A')}\n"
                        f"*ISP*: {result.get('isp', 'N/A')}\n"
                        f"*OS*: {result.get('os', 'N/A')}\n\n"
                        f"*Porte aperte*: {', '.join(str(p) for p in result.get('ports', []))}\n\n"
                    )
                    
                    if len(result.get('vulns', [])) > 0:
                        vulns = ', '.join(result.get('vulns', []))
                        summary += f"*Vulnerabilità*: {vulns}\n\n"
                    
                    # Add sample of services
                    if 'data' in result and result['data']:
                        summary += "*Servizi*:\n"
                        for i, service in enumerate(result['data'][:3]):
                            summary += f"- Porta {service.get('port', 'N/A')}: {service.get('product', 'N/A')} {service.get('version', '')}\n"
                        
                        if len(result['data']) > 3:
                            summary += f"...e altri {len(result['data']) - 3} servizi"
                    
                    await update.message.reply_text(summary[:4000], parse_mode='Markdown')
                except shodan.APIError as e:
                    await update.message.reply_text(f"⚠️ Errore Shodan: {str(e)}")
        
        elif operation == "tech":
            # Ensure URL has a scheme
            if not text.startswith(('http://', 'https://')):
                text = 'https://' + text
            
            await update.message.reply_text(f"🔧 Rilevamento tecnologie per {text} in corso...")
            
            try:
                # Get the page content
                response = requests.get(text, timeout=15, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                })
                html_content = response.text
                
                # Simple pattern detection
                tech_signatures = {
                    'WordPress': ['wp-content', 'wp-includes', 'WordPress'],
                    'Joomla': ['joomla', 'Joomla'],
                    'Drupal': ['drupal', 'Drupal'],
                    'Bootstrap': ['bootstrap.min.css', 'bootstrap.css'],
                    'jQuery': ['jquery.min.js', 'jquery.js'],
                    'React': ['react.min.js', 'react.js', 'reactjs'],
                    'Angular': ['angular.min.js', 'angular.js', 'ng-app'],
                    'Vue.js': ['vue.min.js', 'vue.js'],
                    'PHP': ['php'],
                    'ASP.NET': ['asp.net', '.aspx'],
                    'nginx': ['nginx'],
                    'Apache': ['apache'],
                    'Font Awesome': ['font-awesome'],
                    'Google Analytics': ['google-analytics.com', 'ga.js', 'analytics.js'],
                    'Cloudflare': ['cloudflare', '__cf'],
                    'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
                    'Laravel': ['laravel'],
                    'Google Fonts': ['fonts.googleapis.com'],
                }
                
                detected_tech = []
                for tech, patterns in tech_signatures.items():
                    if any(pattern.lower() in html_content.lower() for pattern in patterns):
                        detected_tech.append(tech)
                
                # Server header detection
                server = response.headers.get('Server', 'Non rilevato')
                
                # Header-based tech detection
                if 'X-Powered-By' in response.headers:
                    powered_by = response.headers.get('X-Powered-By')
                    detected_tech.append(f"X-Powered-By: {powered_by}")
                
                if detected_tech:
                    tech_list = '\n'.join(f"- {tech}" for tech in detected_tech)
                    await update.message.reply_text(
                        f"🔧 *Tecnologie rilevate su {text}*\n\n"
                        f"*Server*: {server}\n\n"
                        f"*Tecnologie*:\n{tech_list}",
                        parse_mode='Markdown'
                    )
                else:
                    await update.message.reply_text(
                        f"🔧 *Tecnologie rilevate su {text}*\n\n"
                        f"*Server*: {server}\n\n"
                        f"Non sono state rilevate altre tecnologie note.",
                        parse_mode='Markdown'
                    )
            except requests.exceptions.RequestException as e:
                await update.message.reply_text(f"⚠️ Errore nella richiesta: {str(e)}")
        
        elif operation == "subdomains":
            try:
                result = requests.get(f"https://crt.sh/?q=%25.{text}&output=json", timeout=15)
                
                if result.status_code == 200:
                    data = result.json()
                    subs = sorted({entry['name_value'] for entry in data})
                    
                    summary = f"🌐 *Sottodomini di {text}*\n\n"
                    for sub in subs[:30]:  # Limit to 30 results
                        summary += f"- {sub}\n"
                    
                    if len(subs) > 30:
                        summary += f"\n...e altri {len(subs) - 30} sottodomini"
                    
                    await update.message.reply_text(summary[:4000], parse_mode='Markdown')
                else:
                    await update.message.reply_text(f"⚠️ Errore API: {result.status_code}")
            except requests.exceptions.RequestException as e:
                await update.message.reply_text(f"⚠️ Errore richiesta: {str(e)}")
    
    except ValueError as e:
        await update.message.reply_text(f"⚠️ Input non valido: {str(e)}")
    except Exception as e:
        await update.message.reply_text(f"⚠️ Errore: {str(e)}")
    
    # Clear user data and return to initial state
    context.user_data.clear()
    return ConversationHandler.END

async def process_metadata(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Extract metadata from uploaded file."""
    try:
        file = await context.bot.get_file(update.message.document.file_id)
        file_name = update.message.document.file_name
        
        # Create temp file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            await file.download_to_drive(temp_file.name)
            temp_path = temp_file.name
        
        await update.message.reply_text(f"📄 Analisi di {file_name} in corso...")
        
        # Process file based on type
        if file_name.lower().endswith(('.jpg', '.jpeg', '.png', '.tiff', '.heic')):
            with open(temp_path, 'rb') as f:
                tags = exifread.process_file(f)
            
            if tags:
                output = "*📊 Metadata EXIF:*\n\n"
                for tag, value in sorted(tags.items()):
                    # Filter out binary data and some common uninteresting tags
                    if not tag.startswith('JPEGThumbnail') and not str(value).startswith('[Binary data'):
                        output += f"*{tag}*: {value}\n"
            else:
                output = "⚠️ Nessun metadata EXIF trovato."
                
            # Try to get GPS data
            gps_coords = []
            for tag in tags.keys():
                if tag.startswith('GPS GPSLatitude'):
                    gps_coords.append(f"*GPS Latitudine*: {tags[tag]}")
                if tag.startswith('GPS GPSLongitude'):
                    gps_coords.append(f"*GPS Longitudine*: {tags[tag]}")
            
            if gps_coords:
                output += "\n\n*Dati GPS trovati:*\n" + "\n".join(gps_coords)
                output += "\n\n⚠️ *Attenzione*: I dati GPS possono rivelare informazioni sensibili sulla località."
        
        elif file_name.lower().endswith(('.pdf')):
            try:
                # Try to extract PDF metadata using pdfinfo
                result = subprocess.run(
                    ['pdfinfo', temp_path],
                    capture_output=True, text=True, timeout=10
                )
                output = f"*📊 Metadata PDF:*\n\n```\n{result.stdout}\n```"
            except:
                output = "⚠️ Impossibile estrarre metadata PDF. Assicurati che pdfinfo sia installato."
        else:
            # Try to get metadata with exiftool for other files
            try:
                result = subprocess.run(
                    ['exiftool', temp_path],
                    capture_output=True, text=True, timeout=10
                )
                output = f"*📊 Metadata generici:*\n\n```\n{result.stdout[:3900]}\n```"
            except:
                output = "⚠️ Tipo di file non supportato per l'estrazione metadata o exiftool non installato."
        
        # Clean up
        os.unlink(temp_path)
        
        await update.message.reply_text(output[:4000], parse_mode='Markdown')
    
    except Exception as e:
        await update.message.reply_text(f"⚠️ Errore nell'elaborazione del file: {str(e)}")
    
    # Clear user data and return to initial state
    context.user_data.clear()
    return ConversationHandler.END

async def process_wifi_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process WiFi scanning commands."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    text = update.message.text.strip().lower()
    
    if text == "scan":
        await update.message.reply_text("📶 Scansione delle reti WiFi in corso...")
        
        try:
            # Try using iwlist for scanning
            result = subprocess.run(
                ['sudo', 'iwlist', 'wlan0', 'scan'],
                capture_output=True, text=True, timeout=15
            )
            
            if result.returncode == 0:
                # Process the output to get a cleaner view
                output = result.stdout
                networks = []
                
                # Parse networks - simplified approach
                essid_pattern = re.compile(r'ESSID:"(.*?)"')
                channel_pattern = re.compile(r'Channel:(\d+)')
                signal_pattern = re.compile(r'Signal level=(.*? dBm)')
                encryption_pattern = re.compile(r'Encryption key:(on|off)')
                
                for cell in output.split("Cell ")[1:]:
                    essid = essid_pattern.search(cell)
                    channel = channel_pattern.search(cell)
                    signal = signal_pattern.search(cell)
                    encryption = encryption_pattern.search(cell)
                    
                    if essid:
                        network = {
                            'essid': essid.group(1),
                            'channel': channel.group(1) if channel else "N/A",
                            'signal': signal.group(1) if signal else "N/A",
                            'encrypted': "Sì" if encryption and encryption.group(1) == "on" else "No"
                        }
                        networks.append(network)
                
                if networks:
                    response = "📶 *Reti WiFi trovate*\n\n"
                    for i, network in enumerate(networks, 1):
                        response += (
                            f"{i}. *{network['essid']}*\n"
                            f"   Canale: {network['channel']}\n"
                            f"   Segnale: {network['signal']}\n"
                            f"   Criptata: {network['encrypted']}\n\n"
                        )
                    await update.message.reply_text(response, parse_mode='Markdown')
                else:
                    await update.message.reply_text("❌ Nessuna rete WiFi trovata.")
            else:
                # If iwlist fails, try airmon-ng if available
                await update.message.reply_text("⚠️ iwlist non riuscito. Tentativo con airmon-ng...")
                
                # Check if airmon-ng is available
                try:
                    subprocess.run(['which', 'airmon-ng'], check=True, timeout=5)
                    
                    # Get wireless interfaces
                    interfaces = subprocess.run(
                        ['airmon-ng'], 
                        capture_output=True, text=True, timeout=5
                    )
                    
                    await update.message.reply_text(
                        f"🔄 Per utilizzare gli strumenti di scanning avanzati, esegui questi comandi:\n\n"
                        f"```\n"
                        f"sudo airmon-ng check kill\n"
                        f"sudo airmon-ng start wlan0\n"
                        f"sudo airodump-ng wlan0mon\n"
                        f"```\n\n"
                        f"*Interfacce disponibili:*\n```\n{interfaces.stdout[:1000]}\n```",
                        parse_mode='Markdown'
                    )
                except:
                    await update.message.reply_text("❌ Nessuno strumento di scanning WiFi disponibile (iwlist, airmon-ng).")
        except Exception as e:
            await update.message.reply_text(f"❌ Errore durante la scansione: {str(e)}")
    else:
        await update.message.reply_text("⚠️ Comando non riconosciuto. Digita 'scan' per avviare la scansione.")
    
    # Clear user data and return to initial state
    context.user_data.clear()
    return ConversationHandler.END

async def process_wifi_attack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process WiFi crack attempt."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    ssid = update.message.text.strip()
    context.user_data['ssid'] = ssid
    
    await update.message.reply_text(
        f"🔐 *Cracking WiFi WPA per '{ssid}'*\n\n"
        f"Per eseguire un attacco WPA/WPA2 su una rete WiFi di tua proprietà, segui questi passaggi:\n\n"
        f"1. Metti l'interfaccia in modalità monitor:\n"
        f"```\n"
        f"sudo airmon-ng check kill\n"
        f"sudo airmon-ng start wlan0\n"
        f"```\n\n"
        f"2. Cattura handshake (in un nuovo terminale):\n"
        f"```\n"
        f"sudo airodump-ng -c [canale] --bssid [mac_ap] -w {ssid.replace(' ', '_')}_capture wlan0mon\n"
        f"```\n\n"
        f"3. Forza deautenticazione per accelerare cattura handshake (in un altro terminale):\n"
        f"```\n"
        f"sudo aireplay-ng --deauth 10 -a [mac_ap] wlan0mon\n"
        f"```\n\n"
        f"4. Usa un dizionario per il cracking:\n"
        f"```\n"
        f"sudo aircrack-ng {ssid.replace(' ', '_')}_capture-01.cap -w [percorso_wordlist]\n"
        f"```\n\n"
        f"Invia un dizionario personalizzato o scrivi 'wordlist' per utilizzare un dizionario standard.",
        parse_mode='Markdown'
    )
    
    # Context will be maintained for the next step
    return WAITING_FOR_WORDLIST

async def process_wordlist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Process wordlist for WiFi cracking."""
    if not await is_authorized(update): 
        return ConversationHandler.END
    
    ssid = context.user_data.get('ssid', 'rete')
    
    if update.message.document:
        # User uploaded a wordlist file
        file = await context.bot.get_file(update.message.document.file_id)
        file_name = update.message.document.file_name
        
        await update.message.reply_text(
            f"📚 *Wordlist ricevuta: {file_name}*\n\n"
            f"Per utilizzarla con aircrack-ng, salva il file e poi esegui:\n\n"
            f"```\n"
            f"sudo aircrack-ng {ssid.replace(' ', '_')}_capture-01.cap -w /percorso/al/{file_name}\n"
            f"```\n\n"
            f"Assicurati di avere prima catturato un valido WPA handshake.",
            parse_mode='Markdown'
        )
    elif update.message.text.strip().lower() == "wordlist":
        # Suggest standard wordlists
        await update.message.reply_text(
            f"📚 *Wordlist standard*\n\n"
            f"Ecco alcune wordlist comunemente utilizzate:\n\n"
            f"1. *rockyou.txt* - Una delle più usate (13 milioni di password)\n"
            f"   Percorso: `/usr/share/wordlists/rockyou.txt` (Kali Linux)\n\n"
            f"2. *crackstation-human-only.txt* - Grande dizionario di password umane\n\n"
            f"3. *darkc0de.txt* - Combinazioni alfanumeriche comuni\n\n"
            f"Comando di esempio con rockyou:\n"
            f"```\n"
            f"sudo aircrack-ng {ssid.replace(' ', '_')}_capture-01.cap -w /usr/share/wordlists/rockyou.txt\n"
            f"```",
            parse_mode='Markdown'
        )
    else:
        # User typed a custom base password
        base_word = update.message.text.strip()
        
        if len(base_word) < 3:
            await update.message.reply_text("⚠️ La parola base deve avere almeno 3 caratteri.")
        else:
            # Generate a small custom wordlist with common variations
            variations = []
            
            # Common variations
            variations.append(base_word)
            variations.append(base_word.capitalize())
            variations.append(base_word.upper())
            
            # Add numbers
            for i in range(100):
                variations.append(f"{base_word}{i:02d}")
            
            # Common suffixes
            for suffix in ['123', '1234', '12345', '!', '@', '#', '!!', '123!', '2023', '2024', '2025']:
                variations.append(f"{base_word}{suffix}")
                variations.append(f"{base_word.capitalize()}{suffix}")
            
            # Save to temp file
            temp_dir = tempfile.gettempdir()
            wordlist_path = os.path.join(temp_dir, f"{base_word}_wordlist.txt")
            
            with open(wordlist_path, 'w', encoding='utf-8') as f:
                for word in variations:
                    f.write(f"{word}\n")

            
            await update.message.reply_text(
                f"📚 *Wordlist personalizzata creata*\n\n"
                f"Creato un dizionario con {len(variations)} variazioni basate su '{base_word}'.\n\n"
                f"Salvato temporaneamente come: `{wordlist_path}`\n\n"
                f"Comando di esempio:\n"
                f"```\n"
                f"sudo aircrack-ng {ssid.replace(' ', '_')}_capture-01.cap -w {wordlist_path}\n"
                f"```",
                parse_mode='Markdown'
            )
    
    # Clear user data and return to initial state
    context.user_data.clear()
    return ConversationHandler.END

async def handle_invalid_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle invalid input during conversation."""
    await update.message.reply_text(
        "❓ Non capisco questo comando.\n"
        "Usa /menu per visualizzare le opzioni disponibili."
    )
    return ConversationHandler.END

def main():
    """Start the bot."""
    # Check for required environment variables
    if not BOT_TOKEN:
        print("❌ BOT_TOKEN non trovato. Crea un file .env con le tue credenziali.")
        return
    
    try:
        # Create application
        app = ApplicationBuilder().token(BOT_TOKEN).build()
        
        # Add conversation handler
        conv_handler = ConversationHandler(
            entry_points=[
                CommandHandler("start", start),
                CommandHandler("menu", menu),
                CommandHandler("help", help_command),
                MessageHandler(filters.TEXT & ~filters.COMMAND, process_selection)
            ],
            states={
                WAITING_FOR_INPUT: [
                    MessageHandler(filters.TEXT | filters.Document.ALL, process_input)
                ],
                WAITING_FOR_WORDLIST: [
                    MessageHandler(filters.TEXT | filters.Document.ALL, process_wordlist)
                ],
                WAITING_FOR_WIFI_SCAN: [
                    MessageHandler(filters.TEXT, process_wifi_scan)
                ],
                WAITING_FOR_WIFI_ATTACK: [
                    MessageHandler(filters.TEXT, process_wifi_attack)
                ]
            },
            fallbacks=[
                MessageHandler(filters.ALL, handle_invalid_input)
            ]
        )
        
        app.add_handler(conv_handler)
        
        print("✅ Bot avviato con successo! Premi Ctrl+C per terminare.")
        app.run_polling()
    
    except Exception as e:
        print(f"❌ Errore di avvio: {e}")

if __name__ == '__main__':
    main()