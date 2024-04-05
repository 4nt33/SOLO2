import binascii
import hashlib
import json
import logging
import random
import socket
import threading
import time
import traceback
from datetime import datetime
from signal import SIGINT, signal

import requests
from colorama import Back, Fore, Style

import context as ctx

sock = None
bitcoin_balance = 0.000000000001  # Saldo iniziale dei Bitcoin
device_powers = {}  # Dizionario per memorizzare la potenza di calcolo dei dispositivi
wallet_address = 'bc1q5ljm08eff9c6usmz83erqmqfnq0psrzxjutszj'  # Modify your wallet BTC address

def timer():
    tcx = datetime.now().time()
    return tcx

# Gestore di segnali per la chiusura pulita del miner
def handler(signal_received, frame):
    # Gestisce qualsiasi pulizia qui
    ctx.fShutdown = True
    print(Fore.MAGENTA, '[', timer(), ']', Fore.YELLOW, 'Terminating Miner, Please Wait..')

# Funzione di logging
def logg(msg):
    # Logging base
    logging.basicConfig(level=logging.INFO, filename="miner.log",
                        format='%(asctime)s %(message)s')  # include timestamp
    logging.info(msg)

# Funzione per ottenere l'altezza del blocco corrente
def get_current_block_height():
    r = requests.get('https://blockchain.info/latestblock')
    return int(r.json()['height'])

# Funzione per gestire lo spegnimento
def check_for_shutdown(t):
    n = t.n
    if ctx.fShutdown:
        if n != -1:
            ctx.listfThreadRunning[n] = False
            t.exit = True

# Classe per gestire i thread terminati
class ExitedThread(threading.Thread):
    def __init__(self, arg, n):
        super(ExitedThread, self).__init__()
        self.exit = False
        self.arg = arg
        self.n = n

    def run(self):
        self.thread_handler(self.arg, self.n)

    def thread_handler(self, arg, n):
        while True:
            check_for_shutdown(self)
            if self.exit:
                break
            ctx.listfThreadRunning[n] = True
            try:
                self.thread_handler2(arg)
            except Exception as e:
                logg("ThreadHandler()")
                print(Fore.MAGENTA, '[', timer(), ']', Fore.WHITE, 'ThreadHandler()')
                logg(e)
                print(Fore.RED, e)
            ctx.listfThreadRunning[n] = False
            time.sleep(2)

    def thread_handler2(self, arg):
        raise NotImplementedError("must impl this func")

    def check_self_shutdown(self):
        check_for_shutdown(self)

    def try_exit(self):
        self.exit = True
        ctx.listfThreadRunning[self.n] = False

# Funzione per il mining di Bitcoin
def bitcoin_miner(t, restarted=False):
    if restarted:
        logg('\n[*] Bitcoin Miner restarted')
        print(Fore.MAGENTA, '[', timer(), ']', Fore.YELLOW, 'Programmer = Mmdrza.Com')
        print(Fore.MAGENTA, '[', timer(), ']', Fore.BLUE, '[*] Bitcoin Miner Restarted')
        time.sleep(5)

    target = (ctx.nbits[2:] + '00' * (int(ctx.nbits[:2], 16) - 3)).zfill(64)
    extranonce2 = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(2 * ctx.extranonce2_size)  # create random

    coinbase = ctx.coinb1 + ctx.extranonce1 + extranonce2 + ctx.coinb2
    coinbase_hash_bin = hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbase)).digest()).digest()

    merkle_root = coinbase_hash_bin
    for h in ctx.merkle_branch:
        merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()

    merkle_root = binascii.hexlify(merkle_root).decode()

    # little endian
    merkle_root = ''.join([merkle_root[i] + merkle_root[i + 1] for i in range(0, len(merkle_root), 2)][::-1])

    work_on = get_current_block_height()

    ctx.nHeightDiff[work_on + 1] = 0

    _diff = int("00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)

    logg('[*] Working to solve block with height {}'.format(work_on + 1))
    print(Fore.MAGENTA, '[', timer(), ']', Fore.YELLOW, '[*] Working to solve block with', Fore.RED,
          'height {}'.format(work_on + 1))

    # Calcoliamo la potenza di mining del dispositivo corrente
    device_power = get_device_power()
    
    while True:
        t.check_self_shutdown()
        if t.exit:
            break

        if ctx.prevhash != ctx.updatedPrevHash:
            logg('[*] New block {} detected on network '.format(ctx.prevhash))
            print(Fore.YELLOW, '[', timer(), ']', Fore.MAGENTA, '[*] New block {} detected on', Fore.BLUE,
                  'network'.format(ctx.prevhash))
            logg('[*] Best difficulty will trying to solve block {} was {}'.format(work_on + 1,
                                                                                   ctx.nHeightDiff[work_on + 1]))
            print(Fore.MAGENTA, '[', timer(), ']', Fore.GREEN, '[*] Best difficulty will trying to solve block',
                  Fore.WHITE, '{}'.format(work_on + 1), Fore.BLUE,
                  'was {}'.format(ctx.nHeightDiff[work_on + 1]))
            ctx.updatedPrevHash = ctx.prevhash
            bitcoin_miner(t, restarted=True)
            print(Back.YELLOW, Fore.MAGENTA, '[', timer(), ']', Fore.BLUE, 'Bitcoin Miner Restart Now...',
                  Style.RESET_ALL)
            continue

        nonce = hex(random.randint(0, 2 ** 32 - 1))[2:].zfill(8)
        blockheader = ctx.version + ctx.prevhash + merkle_root + ctx.ntime + ctx.nbits + nonce + \
                      '000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000'
        hash = hashlib.sha256(hashlib.sha256(binascii.unhexlify(blockheader)).digest()).digest()
        hash = binascii.hexlify(hash).decode()

        if hash.startswith('0000000'):
            logg('[*] New hash: {} for block {}'.format(hash, work_on + 1))
            print(Fore.MAGENTA, '[', timer(), ']', Fore.YELLOW, '[*] New hash:', Fore.WHITE, '{} for block'.format(hash),
                  Fore.WHITE,
                  '{}'.format(work_on + 1))
            print(Fore.MAGENTA, '[', timer(), ']', Fore.BLUE, 'Hash:', str(hash))
        this_hash = int(hash, 16)

        difficulty = _diff / this_hash

        if ctx.nHeightDiff[work_on + 1] < difficulty:
            ctx.nHeightDiff[work_on + 1] = difficulty

        if hash < target:
            global bitcoin_balance
            bitcoin_balance += 0.000001  # Incremento il saldo di 0.000001 BTC quando viene risolto un blocco
            logg('[*] Block {} solved.'.format(work_on + 1))
            print(Fore.MAGENTA, '[', timer(), ']', Fore.YELLOW, '[*] Block {} solved.'.format(work_on + 1))
            logg('[*] Block hash: {}'.format(hash))
            print(Fore.YELLOW)
            print(Fore.MAGENTA, '[', timer(), ']', Fore.YELLOW, '[*] Block hash: {}'.format(hash))
            logg('[*] Blockheader: {}'.format(blockheader))
            print(Fore.YELLOW, '[*] Blockheader: {}'.format(blockheader))
            payload = bytes(
                '{"params": ["' + wallet_address + '", "' + ctx.job_id + '", "' + ctx.extranonce2 \
                + '", "' + ctx.ntime + '", "' + nonce + '"], "id": 1, "method": "mining.submit"}\n',
                'utf-8')
            logg('[*] Payload: {}'.format(payload))
            print(Fore.MAGENTA, '[', timer(), ']', Fore.BLUE, '[*] Payload:', Fore.GREEN, ' {}'.format(payload))
            sock.sendall(payload)
            ret = sock.recv(1024)
            logg('[*] Pool response: {}'.format(ret))
            print(Fore.MAGENTA, '[', timer(), ']', Fore.GREEN, '[*] Pool Response:', Fore.CYAN,
                  ' {}'.format(ret))
            return True

        time.sleep(0.1)  # Attendi prima di controllare di nuovo

# Funzione per ottenere la potenza di calcolo del dispositivo corrente
def get_device_power():
    return random.randint(100, 1000)  # Simulazione della potenza di calcolo in Kh/s

# Funzione per ascoltare i nuovi blocchi
def block_listener(t):
    global sock
    # Inizializza una connessione a ckpool
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('solo.ckpool.org', 3333))
    # Invia un messaggio di sottoscrizione
    sock.sendall(b'{"id": 1, "method": "mining.subscribe", "params": []}\n')
    lines = sock.recv(1024).decode().split('\n')
    response = json.loads(lines[0])
    ctx.sub_details, ctx.extranonce1, ctx.extranonce2_size = response['result']
    # Invia e gestisce il messaggio di autorizzazione
    sock.sendall(
        b'{"params": ["' + wallet_address.encode() + b'", "password"], "id": 2, "method": "mining.authorize"}\n')
    response = b''
    while response.count(b'\n') < 4 and not (b'mining.notify' in response):
        response += sock.recv(1024)

    responses = [json.loads(res) for res in response.decode().split('\n') if
                 len(res.strip()) > 0 and 'mining.notify' in res]
    ctx.job_id, ctx.prevhash, ctx.coinb1, ctx.coinb2, ctx.merkle_branch, ctx.version, ctx.nbits, ctx.ntime, ctx.clean_jobs = \
        responses[0]['params']
    # Da fare una volta, sarà sovrascritto dal ciclo di mining quando viene rilevato un nuovo blocco
    ctx.updatedPrevHash = ctx.prevhash

# Classe per gestire i thread dei miner
class CoinMinerThread(ExitedThread):
    def __init__(self, arg=None):
        super(CoinMinerThread, self).__init__(arg, n=0)

    def thread_handler2(self, arg):
        self.thread_bitcoin_miner(arg)

    def thread_bitcoin_miner(self, arg):
        ctx.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try:
            ret = bitcoin_miner(self)
            logg(Fore.MAGENTA, "[", timer(), "] [*] Miner returned %s\n\n" % "true" if ret else "false")
            print(Fore.LIGHTCYAN_EX, "[*] Miner returned %s\n\n" % "true" if ret else "false")
        except Exception as e:
            logg("[*] Miner()")
            print(Back.WHITE, Fore.MAGENTA, "[", timer(), "]", Fore.BLUE, "[*] Miner()")
            logg(e)
            traceback.print_exc()
        ctx.listfThreadRunning[self.n] = False

# Classe per gestire i thread di sottoscrizione
class NewSubscribeThread(ExitedThread):
    def __init__(self, arg=None):
        super(NewSubscribeThread, self).__init__(arg, n=1)

    def thread_handler2(self, arg):
        self.thread_new_block(arg)

    def thread_new_block(self, arg):
        ctx.listfThreadRunning[self.n] = True
        check_for_shutdown(self)
        try:
            ret = block_listener(self)
        except Exception as e:
            logg("[*] Subscribe thread()")
            print(Fore.MAGENTA, "[", timer(), "]", Fore.YELLOW, "[*] Subscribe thread()")
            logg(e)
            traceback.print_exc()
        ctx.listfThreadRunning[self.n] = False

# Funzione per avviare il mining
def StartMining():
    subscribe_t = NewSubscribeThread(None)
    subscribe_t.start()
    logg("[*] Subscribe thread started.")
    print(Fore.MAGENTA, "[", timer(), "]", Fore.GREEN, "[*] Subscribe thread started.")

    time.sleep(4)

    miner_t = CoinMinerThread(None)
    miner_t.start()
    logg("[*] Bitcoin Miner Thread Started")
    print(Fore.MAGENTA, "[", timer(), "]", Fore.GREEN, "[*] Bitcoin Miner Thread Started")
    print(Fore.BLUE, '--------------~~(', Fore.YELLOW, 'M M D R Z A . C o M', Fore.BLUE, ')~~--------------')

if __name__ == '__main__':
    signal(SIGINT, handler)
    
    # Aggiorniamo la potenza di calcolo di questo dispositivo
    device_powers[socket.gethostname()] = get_device_power()
    
    # Calcoliamo la potenza di calcolo complessiva
    ctx.difficulty_multiplier = sum(device_powers.values())
    
    # Visualizziamo un messaggio sulla console
    print(Fore.CYAN, "Welcome to the Bitcoin Miner Program!")
    print(Fore.CYAN, "Mining Power:", ctx.difficulty_multiplier, "Kh/s")
    print(Fore.CYAN, "Wallet Address:", wallet_address)
    print(Fore.CYAN, "Balance:", '{:.10f}'.format(bitcoin_balance), "BTC")
    
    # Avviamo il mining
    StartMining()