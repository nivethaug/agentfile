import smtplib
from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, jsonify, make_response, request
from flask_cors import CORS
import threading
import ccxt
import datetime
import sqlite3
import logging
import requests

from Telegramhandler import DatabaseHandler, ExchangeHandler, MenuHandler, TelegramBot, WebhookHandler

app = Flask(__name__)
CORS(app, origins="*")

# Your email credentials
hostinger_email = 'support@vnalert.tech'
hostinger_password = 'Nivetha@3117'

# Read the HTML template from a file (load it once)
#with open('mail.html', 'r') as file:
#    html_template = file.read()

processed_emails = set()
lock = threading.Lock()
sdb = '/root/vnalert.db'
ldb = '/root/vnalertpv.db'
DB_PATH = 'telecex.db'
BOT_TOKEN = "7139638501:AAHvIbe2nKbWkMJ7OSp2XcC5EjHn_h8u3Uo"


def addheader(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token'
    return response

def send_single_email(to_email, data, html_template):
    try:
        with smtplib.SMTP('smtp.hostinger.com', 587) as server:
            server.starttls()
            server.login(hostinger_email, hostinger_password)
            message = MIMEMultipart()
            message['From'] = hostinger_email
            message['To'] = to_email
            message['Subject'] = data.get('sub')
            html_template = html_template.replace("description", data.get('description'))
            html_template = html_template.replace("mid", data.get('email'))
            html_template = html_template.replace("name", data.get('name'))
            html_template = html_template.replace("pne", data.get('phone'))
            message.attach(MIMEText(html_template, 'html'))
            server.sendmail(hostinger_email, to_email, message.as_string())

            with lock:
                processed_emails.add(to_email)  # Add the processed email to the set in a thread-safe manner

        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

@app.route('/api/send-email', methods=['POST'])
def send_email():
    try:
        # Recipient email address
        to_email = 'support@vnalert.tech'
        data = request.get_json()
        temp = ''
        # Use ThreadPoolExecutor to limit concurrency
        with ThreadPoolExecutor(max_workers=1) as pool:
            futures = [pool.submit(send_single_email, to_email, data, temp) for _ in range(1)]
            results = [future.result() for future in futures]

        if all(results):
            response = make_response(jsonify(message="Sent Success!", success=True))
        else:
            failed_emails = [i + 1 for i, result in enumerate(results) if not result]
            error_message = f"Error sending emails {', '.join(map(str, failed_emails))}"
            response = make_response(jsonify(message=error_message))
            response.status_code = 500  # Set a 500 Internal Server Error status code

        response = addheader(response)
        return response

    except Exception as e:
        response = make_response(jsonify(message="Error"))
        response.status_code = 500  # Set a 500 Internal Server Error status code
        response = addheader(response)
        return response

@app.route('/api/todaytrade', methods=['GET'])
def todaytrade():
    response = make_response(jsonify(gettodayclosed()))
    response = addheader(response)
    return response
@app.route('/api/todaytradepv', methods=['GET'])
def todaytradepv():
    response = make_response(jsonify(gettodayclosedpv()))
    response = addheader(response)
    return response

@app.route('/api/opntrade', methods=['GET'])
def opntrade():
    response = make_response(jsonify(get_open_trades()))
    response = addheader(response)
    return response
@app.route('/api/opntradepv', methods=['GET'])
def opntradepv():
    response = make_response(jsonify(get_open_tradespv()))
    response = addheader(response)
    return response

@app.route('/api/todaypnl', methods=['GET'])
def todaypnl():
    response = make_response(jsonify(pnl=getTodayPnl()))
    response = addheader(response)
    return response

def gettodayclosed():
    # Get the current UTC time and the UTC time 24 hours ago
    conn = sqlite3.connect(sdb)
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc)
    last_24hr = now - datetime.timedelta(hours=24)

    # Execute the SQL query to get trades from the last 24 hours
    cursor.execute('''SELECT *
                      FROM trades
                      WHERE entry_time >= ? AND entry_time <= ?''', (last_24hr, now))
    last_24hr_trades = cursor.fetchall()
    conn.close()
    return last_24hr_trades
def gettodayclosedpv():
    # Get the current UTC time and the UTC time 24 hours ago
    conn = sqlite3.connect(ldb)
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc)
    last_24hr = now - datetime.timedelta(hours=24)

    # Execute the SQL query to get trades from the last 24 hours
    cursor.execute('''SELECT *
                      FROM trades
                      WHERE entry_time >= ? AND entry_time <= ?''', (last_24hr, now))
    last_24hr_trades = cursor.fetchall()
    conn.close()
    return last_24hr_trades

@app.route('/api/closetrade', methods=['GET'])
def closetrade():
    symbol = request.args.get('symbol', None)
    price = request.args.get('price', None)
    update_trade(symbol+'.P',price)
    response = make_response(jsonify(get_open_trades()))
    response = addheader(response)
    return response
@app.route('/api/closetradepv', methods=['GET'])
def closetradepv():
    symbol = request.args.get('symbol', None)
    price = request.args.get('price', None)
    update_tradepv(symbol+'.P',price)
    response = make_response(jsonify(get_open_trades()))
    response = addheader(response)
    return response

@app.route('/api/closetraden', methods=['GET'])
def closetraden():
    symbol = request.args.get('symbol', None)
    price = request.args.get('price', None)
    response = make_response(jsonify(get_open_trades()))
    revariablesponse = addheader(response)
    return response

@app.route('/api/createtrade', methods=['GET'])
def createtrade():
    symbol = request.args.get('symbol', None)
    price = request.args.get('price', None)
    opentrade(symbol, price)
    response = make_response(jsonify(get_open_trades()))
    response = addheader(response)
    return response

@app.route('/api/updateprice', methods=['GET'])
def updateprice():
    symbol = request.args.get('symbol', None)
    price = request.args.get('price', None)
    update_price(symbol, price)
    response = make_response(jsonify(get_open_trades()))
    response = addheader(response)
    return response

def opentrade(symbol,entry_price):
    conn = sqlite3.connect(sdb)
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO trades (symbol, entry_price, Qty,ACnt) VALUES (?, ?, ?, ?)''', (symbol, entry_price,10,0))
    conn.commit()

def update_trade(symbol, price=0):
    conn = sqlite3.connect(sdb)
    cursor = conn.cursor()
    cursor.execute('''SELECT id, entry_price, Qty FROM trades WHERE symbol=? AND exit_price IS NULL''', (symbol,))
    trade = cursor.fetchone()
    trade_id, entry_price, Qty = trade  # Unpack tuple elements correctly
    pnl = -(((float(price) - float(entry_price)) / float(entry_price)) * 100)
    try:
        cursor.execute('''UPDATE trades SET exit_price=?, exit_time=?, pnl=? WHERE id=?''', (price, datetime.datetime.utcnow(), pnl, trade_id))
        conn.commit()
    except Exception as e:
        print(e)
        # Handle any exceptions
def update_tradepv(symbol, price=0):
    conn = sqlite3.connect('/root/bot/vnalertpv.db')
    cursor = conn.cursor()
    cursor.execute('''SELECT id, entry_price, Qty FROM trades WHERE symbol=? AND exit_price IS NULL''', (symbol,))
    trade = cursor.fetchone()
    trade_id, entry_price, Qty = trade  # Unpack tuple elements correctly
    pnl = -(((float(price) - float(entry_price)) / float(entry_price)) * 100)
    try:
        cursor.execute('''UPDATE trades SET exit_price=?, exit_time=?, pnl=? WHERE id=?''', (price, datetime.datetime.utcnow(), pnl, trade_id))
        conn.commit()
    except Exception as e:
        # Handle any exceptions
            print("Error:", e)


def update_price(symbol, price):
    conn = sqlite3.connect(sdb)
    cursor = conn.cursor()
    cursor.execute('''SELECT id, entry_price, Qty FROM trades WHERE symbol=? AND exit_price IS NULL''', (symbol,))
    trade = cursor.fetchone()
    trade_id, entry_price, Qty = trade  # Unpack tuple elements correctly
    try:
        pnl = 0
        cursor.execute('''UPDATE trades SET entry_price=? WHERE id=?''', (price, trade_id))
        conn.commit()
    except Exception as e:
        # Handle any exceptions
            print("Error:", e)

def getTodayPnl():
    conn = sqlite3.connect(sdb)
    cursor = conn.cursor()
    today_date = datetime.datetime.now().strftime('%Y-%m-%d')

        # Get today's date
    today_date = datetime.datetime.now().strftime('%Y-%m-%d')

    # Execute the SQL query to get today's closed PnL
    cursor.execute('''SELECT SUM(pnl)
                    FROM trades
                    WHERE DATE(exit_time) = ?''', (today_date,))
    today_closed_pnl = cursor.fetchone()[0] or 0  # Get the sum of today's closed PnL, handle None if no trades closed today
    conn.close()
    return today_closed_pnl


@app.route('/api/ptodaytrade', methods=['GET'])
def ptodaytrade():
    response = make_response(jsonify(pgettodayclosed()))
    response = addheader(response)
    return response

@app.route('/api/ptodaypnl', methods=['GET'])
def ptodaypnl():
    response = make_response(jsonify(pnl=pgetTodayPnl()))
    response = addheader(response)
    return 
    
@app.route('/api/negativetodaypnl', methods=['GET'])
def negativetodaypnl():
    response = make_response(jsonify(pnl=getNegativePnl()))
    response = addheader(response)
    return response
# Function to get open trades from SQLite database
def get_open_trades():
    conn = sqlite3.connect(sdb)
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM trades WHERE exit_price IS NULL''')
    open_trades = cursor.fetchall()
    return open_trades

def get_open_tradespv():
    conn = sqlite3.connect(ldb)
    cursor = conn.cursor()
    cursor.execute('''SELECT * FROM trades WHERE exit_price IS NULL''')
    open_trades = cursor.fetchall()
    return open_trades

def pgettodayclosed():
        # Get today's date
    conn = sqlite3.connect(ldb)
    cursor = conn.cursor()
    today_date = datetime.datetime.now().strftime('%Y-%m-%d')

    # Execute the SQL query to get today's closed trades
    cursor.execute('''SELECT *
                    FROM trades
                    WHERE DATE(exit_time) = ?''', (today_date,))
    today_closed_trades = cursor.fetchall()
    conn.close()
    return today_closed_trades


def pgetTodayPnl():
    conn = sqlite3.connect(sdb)
    cursor = conn.cursor()
    today_date = datetime.datetime.now().strftime('%Y-%m-%d')

        # Get today's date
    today_date = datetime.datetime.now().strftime('%Y-%m-%d')

    # Execute the SQL query to get today's closed PnL
    cursor.execute('''SELECT SUM(pnl)
                    FROM trades
                    WHERE DATE(exit_time) = ?''', (today_date,))
    today_closed_trades = cursor.fetchall()  # Get the sum of today's closed PnL, handle None if no trades closed today
    conn.close()
    return today_closed_trades

def getNegativePnl():
    conn = sqlite3.connect(sdb)
    cursor = conn.cursor()


    # Execute the SQL query to get today's closed PnL
    cursor.execute('''SELECT * FROM trades WHERE pnl < 0''')
    today_closed_pnl = cursor.fetchall()  # Get the sum of today's closed PnL, handle None if no trades closed today
    conn.close()
    return today_closed_pnl
    
@app.route('/api/cltodaypnl', methods=['GET'])
def cltodaypnl():
    cleartrades()
    response = make_response(jsonify(pnl=getTodayPnl()))
    response = addheader(response)
    return response

def cleartrades():
    conn = sqlite3.connect(sdb)
    cursor = conn.cursor()
    cursor.execute('''DELETE FROM trades''')
    conn.commit()

@app.route('/api/pcltodaypnl', methods=['GET'])
def pcltodaypnl():
    pcleartrades()
    response = make_response(jsonify(pnl=pgetTodayPnl()))
    response = addheader(response)
    return response

def pcleartrades():
    conn = sqlite3.connect(ldb)
    cursor = conn.cursor()
    cursor.execute('''DELETE FROM trades''')
    conn.commit()
BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

########################### Tele bot ########################################
############################ Tele bot ########################################

@app.route("/api/set_webhook", methods=["GET"])
def set_webhook():
    webhook_url = f"https://vnapi.in/api/telebot"  # Replace with your public URL
    callback_url = f"{webhook_url}/callback"
    
    # Delete any existing webhook
    requests.get(f"{BASE_URL}/deleteWebhook")
    
    # Set the new webhook with callback URL
    payload = {
        "url": webhook_url,
        "allowed_updates": ["message", "callback_query"]
    }
    response = requests.post(f"{BASE_URL}/setWebhook", json=payload)
    
    if response.status_code == 200:
        return {
            "status": "success",
            "message": "Webhook set successfully",
            "webhook_url": webhook_url,
            "callback_url": callback_url
        }
    else:
        return {
            "status": "error",
            "message": "Failed to set webhook",
            "response": response.json()
        }



# Flask route
@app.route("/api/telebot", methods=["POST"])
def webhook():
        # Initialize components
    bot = TelegramBot(BASE_URL, DB_PATH)
    db = DatabaseHandler(DB_PATH)
    exchange_handler = ExchangeHandler(db)
    menu_handler = MenuHandler(bot)
    webhook_handler = WebhookHandler(bot, db, exchange_handler, menu_handler)
    return webhook_handler.handle_webhook(request.json)


if __name__ == '__main__':
   app.run(debug=True)
