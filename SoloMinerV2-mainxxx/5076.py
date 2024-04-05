from flask import Flask, render_template
from threading import Thread
import time
import re
import subprocess

app = Flask(__name__)

# Funzione per ottenere il saldo dei Bitcoin
def get_bitcoin_balance():
    while True:
        try:
            process = subprocess.Popen(['python3', 'SoloMinerv3.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            output = process.stdout.readline().strip()
            if output:
                balance_match = re.search(r'Balance: (\d+\.\d+) BTC', output)
                if balance_match:
                    balance = float(balance_match.group(1))
                    return balance
        except Exception as e:
            print(f"Si è verificato un errore durante l'ottenimento del saldo Bitcoin: {e}")
        time.sleep(1)

# Pagina principale
@app.route('/')
def index():
    return render_template('index.html')

# Pagina di aggiornamento dei dati in tempo reale
@app.route('/data')
def data():
    balance = get_bitcoin_balance()
    return {'balance': balance}

if __name__ == '__main__':
    # Avvia l'applicazione Flask su un thread separato
    Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 8000}).start()