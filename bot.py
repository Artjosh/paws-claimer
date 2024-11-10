import json
import asyncio
import aiohttp
import aiofiles
from fake_useragent import UserAgent
from colorama import init, Fore, Style
from aiohttp_socks import ProxyConnector
import time
from datetime import datetime
import random
import cloudscraper
from typing import List
from aiohttp import BasicAuth
from requests.auth import HTTPProxyAuth
import sys
import logging
import concurrent.futures
import threading
from queue import Queue

class PawsManager:
    
    def __init__(self, data=None, proxy=None, account_number=None, wallet=None):
        with open('configs.json', 'r') as f:
            self.config = json.loads(f.read())
            
        self.data = data.strip() if data else ''
        self.proxy = proxy.strip() if (proxy and self.config['USE_PROXY']) else ''
        self.account_number = account_number
        self.wallet = wallet.strip() if wallet else ''
        self.wallet_base = ''
        self.session = None
        self.headers = self._initialize_headers()
        self.colors = {
            'success': Fore.GREEN,
            'error': Fore.RED,
            'info': Fore.BLUE,
            'warning': Fore.YELLOW,
            'ann': Fore.YELLOW,
            'upd': Fore.CYAN
        }
        self.print_lock = threading.Lock()
        init()  # Inicializa colorama
        self.account_queue = Queue()
        self.active_threads = 0
        self.thread_lock = threading.Lock()

    async def make_request(self, method, url, **kwargs):
        """Sistema de requisições com retry e bypass"""
        max_retries = 3
        retry_delay = 2
        
        for attempt in range(max_retries):
            try:
                if not self.session:
                    await self.create_session()
                
                headers = {**kwargs.pop('headers', {}), **self.headers}
                kwargs['headers'] = headers
                
                timeout = aiohttp.ClientTimeout(total=30)
                
                async with aiohttp.ClientSession(timeout=timeout) as temp_session:
                    temp_session.headers.update(headers)
                    async with getattr(temp_session, method.lower())(url, **kwargs) as response:
                        if response.status == 403:
                            scraper = self._create_scraper()
                            cf_response = scraper.request(method, url, **kwargs)
                            
                            if cf_response.status_code not in [200, 201]:
                                self.log(f"Status Code Cloudflare: {cf_response.status_code}", "error")
                                self.log(f"Resposta Cloudflare: {cf_response.text}", "error")
                            
                            return cf_response.json()
                        
                        return await response.json()
                    
            except Exception as e:
                self.log(f"Erro na requisição: {str(e)}", "error")
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay * (attempt + 1))
                    continue
                raise
    
    async def tasks(self):
        """Executa e reivindica tasks"""
        self.log("Is doing tasks...", "info")
        try:
            tasks_list = await self.make_request("get", "https://api.paws.community/v1/quests/list")
            
            for task in tasks_list["data"]:
                try:
                    # Completa a task
                    await self.make_request("post", "https://api.paws.community/v1/quests/completed", 
                                          json={"questId": task["_id"]})
                    self.log(f"Completed tasks: {task['title']}", "success")
                except:
                    self.log(f"Failed to complete tasks: {task['title']}", "error")
                
                await asyncio.sleep(1)
                
                try:
                    # Reivindica a recompensa
                    await self.make_request("post", "https://api.paws.community/v1/quests/claim", 
                                          json={"questId": task["_id"]})
                    self.log(f"Claimed tasks: {task['title']}", "success")
                except:
                    self.log(f"Failed to claimed tasks: {task['title']}", "error")
                
                await asyncio.sleep(1)
                
        except Exception as e:
            self.log("Cannot get tasks data!", "error")
            
        self.log("Completed all tasks that are available!", "info")
    
    def _create_scraper(self):
        """Cria uma instância do cloudscraper com os headers corretos"""
        scraper = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'windows',
                'mobile': False
            }
        )
        scraper.headers.update(self._initialize_headers())
        return scraper
    
    async def wallet_connect(self):
        """Conecta a wallet"""
        try:
            await self.make_request("post", "https://api.paws.community/v1/user/wallet", 
                                  json={"wallet": self.wallet})
            
            if not self.wallet and self.wallet_base:
                self.log(f"Unlink the wallet: {self.wallet_base}", "info")
            elif not self.wallet and not self.wallet_base:
                self.log("Have no wallet to connect.", "warning")
            else:
                self.log(f"Wallet connected: {self.wallet}", "success")
                
        except Exception as e:
            self.log("Failed to connect to wallet. Please check your wallet address and try again!", "error")
    
    async def create_session(self):
        """Cria uma sessão HTTP com ou sem proxy"""
        if self.session:
            await self.session.close()
        
        timeout = aiohttp.ClientTimeout(total=30)
        
        if self.proxy:
            try:
                if 'socks' in self.proxy.lower():
                    connector = ProxyConnector.from_url(self.proxy)
                else:
                    connector = ProxyConnector.from_url(f'http://{self.proxy}')
                self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            except Exception as e:
                self.log(f'Erro ao configurar proxy: {e}', 'error')
                self.session = aiohttp.ClientSession(timeout=timeout)
        else:
            self.session = aiohttp.ClientSession(timeout=timeout)
            
        self.session.headers.update(self.headers)
    
    def _initialize_headers(self):
        """Inicializa os headers com plataforma consistente"""
        user_agent = UserAgent().random
        
        # Detecta a plataforma baseado no User-Agent
        platform = "Windows"  # default
        if "Linux" in user_agent:
            platform = "Linux"
        elif "Mac" in user_agent:
            platform = "macOS"
        elif "Android" in user_agent:
            platform = "Android"
        elif "iPhone" or "iPad" in user_agent:
            platform = "iOS"
        
        return {
            "accept": "application/json",
            "accept-language": "pt-PT,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "content-type": "application/json",
            "authority": "api.paws.community",
            "Origin": "https://app.paws.community",
            "Referer": "https://app.paws.community/",
            "User-Agent": user_agent,
            "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
            "sec-ch-ua-mobile": "?1" if ("Android" in user_agent or "iPhone" in user_agent or "iPad" in user_agent) else "?0",
            "sec-ch-ua-platform": f'"{platform}"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site"
        }
        
    async def login(self):
        """Login na plataforma"""
        try:
            data = {
                "data": self.data,
            }
            
            self.log("Tentando login...", "info")
            response = await self.make_request("post", "https://api.paws.community/v1/user/auth", json=data)
            
            if not isinstance(response, dict):
                raise Exception("Resposta inválida do servidor")
            
            if response.get('success', False) and 'data' in response:
                token = response['data'][0]
                user_data = response['data'][1]
                
                self.headers["authorization"] = f"Bearer {token}"
                self.wallet_base = user_data.get("userData", {}).get("wallet", "")
                
                self.log("Login successfully!", "success")
                
                # Lógica para pegar o nome do usuário
                user_info = user_data.get('userData', {})
                if 'username' in user_info:
                    name = user_info['username']
                elif 'firstname' in user_info:
                    name = user_info['firstname']
                else:
                    name = 'Unknown'
                    
                balance = user_data.get('gameData', {}).get('balance', 0)
                self.log(f"Name: {name} | Balance: {balance}", "info")
                
                return True
                
            else:
                raise Exception(response.get('error', {}).get('message', 'Unknown error'))
            
        except Exception as e:
            self.log(f"Login error: {str(e)}", "error")
            return False
    
    def format_proxy(self, proxy_info):
        """Formata proxy para uso com requests/aiohttp"""
        if not proxy_info:
            return None
            
        # Se tem autenticação
        if '@' in proxy_info:
            auth, proxy = proxy_info.split('@')
            username = auth.split(':')[1]
            password = auth.split(':')[2]
            host = proxy.split(':')[0]
            port = proxy.split(':')[1]
            return {
                'http': f'http://{host}:{port}',
                'https': f'http://{host}:{port}'
            }
        else:
            # Sem autenticação
            host = proxy_info.split(':')[0]
            port = proxy_info.split(':')[1]
            return {
                'http': f'http://{host}:{port}',
                'https': f'http://{host}:{port}'
            }
    
    async def check_ip(self, proxy_info):
        """Verifica IP usando o proxy"""
        url = "https://api.ipify.org?format=json"
        proxies = self.format_proxy(proxy_info)

        if "@" in proxy_info:
            proxy_credentials = proxy_info.split("@")[0]
            proxy_user = proxy_credentials.split(":")[1]
            proxy_pass = proxy_credentials.split(":")[2]
            auth = BasicAuth(proxy_user, proxy_pass)
        else:
            auth = None

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, proxy=proxies.get('http'), proxy_auth=auth) as response:
                    if response.status == 200:
                        data = await response.json()
                        actual_ip = data.get("ip")
                        self.log(f"Actual IP Address: {actual_ip}")
                        return actual_ip
                    else:
                        self.log(f"IP check failed with status {response.status}", "error")
                        return None
        except Exception as e:
            self.log(f"IP check failed: {str(e)}", "error")
            return None
    
    def log(self, message, level='info'):
        """Sistema de log com thread safety"""
        with self.print_lock:
            timestamp = datetime.now().strftime('%d/%m/%Y, %H:%M:%S')
            color = {
                'info': Fore.BLUE,
                'success': Fore.GREEN,
                'error': Fore.RED,
                'warning': Fore.YELLOW
            }.get(level, Fore.WHITE)
            
            symbol = {
                'info': '[+]',
                'success': '[>]',
                'error': '[!]',
                'warning': '[*]',
                'ann': '[*]',
                'upd': '[%]'
            }.get(level, '[#]')
            
            msg = f"{color}[{timestamp}] - {symbol} Account {self.account_number} | {message}{Style.RESET_ALL}"
            print(msg)
            logging.info(msg)

    async def process_account_async(self, account, account_number, total_accounts):
        """Versão assíncrona do processamento de conta"""
        try:
            self.session = None
            
            self.data = account['acc_info']
            self.proxy = account['proxy_info'] if self.config['USE_PROXY'] else None
            self.account_number = account_number
            self.wallet = account['wallet']
            
            self.log(f"Processing account {account_number}/{total_accounts}", "info")
            
            # Só verifica IP se USE_PROXY for True
            if self.config['USE_PROXY'] and self.proxy:
                actual_ip = await self.check_ip(self.proxy)
                expected_ip = self.proxy.split(":")[0]
                if not actual_ip or actual_ip != expected_ip:
                    self.log(f"Proxy IP mismatch or check failed. Skipping account {account_number}", "error")
                    return
            
            if await self.login():
                await self.wallet_connect()
                await self.tasks()
                
        except Exception as e:
            self.log(f"Error processing account {account_number}: {str(e)}", "error")
        finally:
            if self.session:
                await self.session.close()
                self.session = None

    def main(self):
        """Função principal com gerenciamento dinâmico de threads"""
        try:
            with open('data-proxy.json', 'r') as f:
                data = json.loads(f.read())
            
            accounts = data['accounts']
            total_accounts = len(accounts)
            self.log(f"Total accounts to process: {total_accounts}", "info")
            
            # Preenche a fila com todas as contas
            for i, account in enumerate(accounts):
                self.account_queue.put((i + 1, account))
            
            # Cria pool de threads
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['WORKERS']) as executor:
                futures = set()
                
                while not self.account_queue.empty() or futures:
                    # Adiciona novas tasks enquanto houver contas e threads disponíveis
                    while len(futures) < self.config['WORKERS'] and not self.account_queue.empty():
                        account_number, account = self.account_queue.get()
                        
                        account_manager = PawsManager(
                            data=account['acc_info'],
                            proxy=account['proxy_info'] if self.config['USE_PROXY'] else None,
                            account_number=account_number,
                            wallet=account['wallet']
                        )
                        
                        future = executor.submit(
                            lambda: asyncio.run(account_manager.process_account_async(
                                account, account_number, total_accounts
                            ))
                        )
                        futures.add(future)
                    
                    # Aguarda qualquer thread terminar
                    done, futures = concurrent.futures.wait(
                        futures, 
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    
                    # Remove as threads concluídas
                    futures = futures
                    
                    # Pequeno delay para evitar sobrecarga
                    time.sleep(0.1)
            
            self.log("All accounts have been processed. Exiting...", "info")
                
        except Exception as e:
            self.log(f"Critical error: {str(e)}", "error")

if __name__ == "__main__":
    # Configura logging
    logging.basicConfig(
        filename='paws_bot.log',
        level=logging.INFO,
        format='%(asctime)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    try:
        manager = PawsManager()
        manager.main()
    except KeyboardInterrupt:
        sys.exit()
