#! /usr/bin/env python3

from flask import Flask, jsonify, send_from_directory, render_template, request, redirect, url_for, session, make_response
import robin_stocks.robinhood as rh
from flask_cors import CORS
import os
from getpass import getpass
import datetime
from functools import wraps
import logging
import sys
import traceback
import webbrowser
import psutil
import time
import signal
import threading
import ssl
import random
from news_scanner import NewsScanner

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

# Configure session cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Set to False for HTTP during development
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True
)

# Configure CORS and SSL
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Add static folder configuration
app.static_folder = 'static'
app.static_url_path = '/static'

# Create static directory if it doesn't exist
os.makedirs(app.static_folder, exist_ok=True)

# Global variables for session management
_session = None
_username = None
_password = None

# Add this near the top with other globals
RECOMMENDED_STOCKS = [
    'F',    # Ford
    'SOFI', # SoFi Technologies
    'PLTR', # Palantir
    'AMD',  # Advanced Micro Devices
    'VALE', # Vale SA
    'NIO',  # NIO Inc
    'PLUG', # Plug Power
    'SNAP', # Snap Inc
    'T',    # AT&T
    'UBER', # Uber
]

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def cleanup_previous_sessions():
    """Cleanup any previous Flask sessions running on port 5000."""
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmdline = proc.info['cmdline']
                if cmdline and 'python' in proc.info['name'].lower():
                    if any('app.py' in arg for arg in cmdline) and proc.pid != os.getpid():
                        logger.info(f"Found previous session (PID: {proc.pid}), terminating...")
                        os.kill(proc.pid, signal.SIGTERM)
                        time.sleep(1)  # Give it time to shutdown gracefully
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception as e:
        logger.error(f"Error cleaning up sessions: {str(e)}")

def open_browser():
    """Open the browser to the application URL."""
    try:
        url = "http://localhost:5000"
        logger.info(f"Opening browser to {url}")
        webbrowser.open(url)
    except Exception as e:
        logger.error(f"Error opening browser: {str(e)}")

def maintain_session(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _session
        try:
            logger.debug(f"Checking session before executing {func.__name__}")
            if not _session or not rh.authentication.get_token():
                logger.debug("Session invalid or expired, attempting to login")
                _session = login_to_robinhood()
            logger.debug(f"Executing {func.__name__}")
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Session error in {func.__name__}: {str(e)}")
            logger.error(traceback.format_exc())
            _session = login_to_robinhood()
            return func(*args, **kwargs)
    return wrapper

def login_to_robinhood():
    """Initialize Robinhood connection using secure credential input."""
    global _username, _password, _session
    
    try:
        logger.debug("Attempting Robinhood login")
        if not _username or not _password:
            _username = input("Enter Robinhood email: ")
            _password = getpass("Enter Robinhood password: ")
            mfa_code = input("Enter your MFA code from authenticator app: ")
            logger.debug("Credentials collected, attempting login")
            _session = rh.login(_username, _password, mfa_code=mfa_code)
            logger.debug("Login successful")
            return _session
        
        logger.debug("Using existing credentials for login")
        return rh.login(_username, _password)
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def check_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login requests."""
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            mfa_code = request.form.get('mfa_code')
            
            if not all([username, password, mfa_code]):
                return render_template('login.html', error="All fields are required")
            
            try:
                global _session, _username, _password
                _username = username
                _password = password
                _session = rh.login(username, password, mfa_code=mfa_code)
                
                if _session:
                    session.permanent = True
                    session['logged_in'] = True
                    
                    # Create response with loading page
                    response = make_response(render_template('loading.html'))
                    
                    # Set session cookie with proper attributes
                    response.headers.add(
                        'Set-Cookie',
                        'session={}; SameSite=Lax; HttpOnly; Path=/'.format(session.get('logged_in', ''))
                    )
                    
                    return response
                else:
                    return render_template('login.html', error="Login failed")
                    
            except Exception as e:
                logger.error(f"Login error: {str(e)}")
                return render_template('login.html', error=str(e))
        
        return render_template('login.html')
        
    except Exception as e:
        logger.error(f"Login route error: {str(e)}")
        return render_template('login.html', error="Server error occurred")

def analyze_options_batch(tickers):
    """Analyze options for a batch of tickers and return the best opportunities."""
    all_opportunities = []
    
    for symbol in tickers:
        try:
            logger.debug(f"Analyzing options for {symbol}")
            
            # Get current stock price
            stock_price = rh.stocks.get_latest_price(symbol)
            if not stock_price or not stock_price[0]:
                logger.warning(f"Could not get price for {symbol}")
                continue
            current_price = float(stock_price[0])
            
            # Get options chain info
            chain_data = rh.options.get_chains(symbol)
            if not chain_data or 'error' in chain_data:
                logger.warning(f"No options chain found for {symbol}")
                continue
                
            # Get expiration dates directly from the chain data
            exp_dates = rh.options.get_chains(symbol, info='expiration_dates')
            if not exp_dates:
                logger.warning(f"No expiration dates found for {symbol}")
                continue
            
            logger.debug(f"Found {len(exp_dates)} expiration dates for {symbol}")
            
            # Get call options data for each expiration date
            for exp_date in exp_dates[:3]:  # Limit to first 3 expiration dates to reduce API load
                try:
                    time.sleep(0.5)  # Add delay between API calls to avoid rate limiting
                    
                    # Try both API methods to get options data
                    try:
                        options = rh.options.find_options_for_stock_by_expiration(
                            symbol,
                            exp_date,
                            optionType='call'
                        )
                    except:
                        options = rh.options.find_options_by_expiration(
                            symbol,
                            expirationDate=exp_date,
                            optionType='call'
                        )
                    
                    if not options:
                        logger.debug(f"No options found for {symbol} exp {exp_date}")
                        continue
                        
                    # Process each option
                    for option in options:
                        try:
                            if not isinstance(option, dict):
                                continue
                                
                            strike_price = float(option.get('strike_price', 0))
                            ask_price = float(option.get('ask_price', 0))
                            bid_price = float(option.get('bid_price', 0))
                            
                            if strike_price <= 0 or (ask_price <= 0 and bid_price <= 0):
                                continue
                            
                            # Calculate days until expiration
                            try:
                                expiration_date = datetime.datetime.strptime(exp_date, '%Y-%m-%d')
                                days_until_expiration = (expiration_date - datetime.datetime.now()).days
                            except ValueError:
                                continue
                            
                            # Filter for reasonable prices and costs
                            if (ask_price > 0 or bid_price > 0) and ask_price <= 5.00:
                                option_price = ask_price if ask_price > 0 else bid_price
                                break_even_price = strike_price + option_price
                                break_even_percentage = ((break_even_price - current_price) / current_price) * 100
                                
                                # Only include promising opportunities
                                if break_even_percentage <= 50:
                                    opportunity = {
                                        'symbol': symbol,
                                        'current_price': round(current_price, 2),
                                        'expiration_date': exp_date,
                                        'days_until_expiration': days_until_expiration,
                                        'strike_price': round(strike_price, 2),
                                        'break_even_price': round(break_even_price, 2),
                                        'break_even_percentage': round(break_even_percentage, 2),
                                        'option_cost': round(option_price, 2),
                                        'volume': int(option.get('volume', 0) or 0),
                                        'open_interest': int(option.get('open_interest', 0) or 0),
                                        'implied_volatility': round(float(option.get('implied_volatility', 0) or 0) * 100, 2)
                                    }
                                    all_opportunities.append(opportunity)
                                    
                        except (ValueError, TypeError, KeyError) as e:
                            continue
                            
                except Exception as e:
                    logger.debug(f"Error fetching options for {symbol} exp {exp_date}: {str(e)}")
                    continue
                    
        except Exception as e:
            logger.debug(f"Error analyzing {symbol}: {str(e)}")
            continue
    
    # Sort opportunities by break even percentage and days until expiration
    all_opportunities.sort(key=lambda x: (x['break_even_percentage'], x['days_until_expiration']))
    return all_opportunities

@app.route('/')
@check_auth
def index():
    """Show the best options opportunities from trending and recommended stocks."""
    try:
        logger.info("\n=== Generating Options Report ===")
        
        # Get all tickers to analyze
        available_tickers = list(set(trending_tickers + RECOMMENDED_STOCKS))
        logger.info(f"Analyzing {len(available_tickers)} tickers: {', '.join(available_tickers)}")
        
        # Analyze options for all tickers
        opportunities = analyze_options_batch(available_tickers)
        logger.info(f"Found {len(opportunities)} valid opportunities")
        
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logger.info(f"Rendering template with {len(opportunities)} opportunities")
        
        # Create response with proper cookie settings
        response = make_response(render_template(
            'options_report.html',
            timestamp=timestamp,
            opportunities=opportunities,
            recommended_stocks=RECOMMENDED_STOCKS,
            trending_tickers=trending_tickers,
            last_scan_time=last_scan_time
        ))
        
        # Ensure session cookie is set properly
        response.headers.add('Set-Cookie', 'session={}; SameSite=Lax; HttpOnly; Path=/'.format(session.get('logged_in', '')))
        return response
        
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        logger.error(traceback.format_exc())
        return redirect(url_for('login'))

@app.route('/api/test', methods=['GET'])
@maintain_session
def test_connection():
    """Test the Robinhood connection."""
    try:
        logger.debug("Testing connection")
        profile = rh.profiles.load_account_profile()
        return jsonify({
            'success': True,
            'message': 'Connection successful',
            'profile': profile
        })
    except Exception as e:
        logger.error(f"Test connection error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/options/<symbol>/report', methods=['GET'])
@maintain_session
def generate_options_report(symbol):
    try:
        # Get query parameters
        expiration_date = request.args.get('expiration_date')
        strike_price = request.args.get('strike_price')
        option_type = request.args.get('option_type')
        
        if option_type and option_type not in ['call', 'put']:
            return jsonify({
                'success': False,
                'error': 'Option type must be either "call" or "put"'
            }), 400

        # Get current stock price
        current_price = float(rh.stocks.get_latest_price(symbol)[0])
        
        # Get options data with filters
        options_data = rh.options.find_tradable_options(
            symbol,
            expirationDate=expiration_date,
            strikePrice=strike_price,
            optionType=option_type
        )
        
        # Filter out options with no valid prices
        filtered_options = []
        for option in options_data:
            if (option.get('bid_price') != 'N/A' and float(option.get('bid_price', 0)) > 0) or \
               (option.get('ask_price') != 'N/A' and float(option.get('ask_price', 0)) > 0):
                filtered_options.append(option)
        
        # Sort options by expiration date and strike price
        filtered_options.sort(key=lambda x: (
            x.get('expiration_date', ''),
            float(x.get('strike_price', 0))
        ))
        
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        return render_template(
            'options_report.html',
            symbol=symbol,
            timestamp=timestamp,
            current_price=current_price,
            options_data=filtered_options,
            filters={
                'expiration_date': expiration_date,
                'strike_price': strike_price,
                'option_type': option_type
            }
        )
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/favicon.ico')
def favicon():
    """Serve the favicon."""
    return send_from_directory(
        app.static_folder,
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    )

@app.route('/installHook.js.map')
@app.route('/<path:filename>')
def handle_dev_tools_requests(filename=None):
    """Handle requests from browser developer tools gracefully."""
    # Return a complete source map for any request
    response = jsonify({
        'version': 3,
        'file': 'anonymous.js',
        'sourceRoot': '',
        'sources': ['anonymous.js'],
        'sourcesContent': ['console.log("debug");'],
        'names': ['console', 'log'],
        'mappings': 'AAAA,OAAOA,QAAQC,IAAI,QAAQ',
        'x_google_ignoreList': [],
        'sourceURL': 'anonymous.js'
    })
    response.headers['Content-Type'] = 'application/json'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/options')
@app.route('/options/<symbol>')
@check_auth
@maintain_session
def analyze_call_options(symbol=None):
    """Analyze call options and their break-even points."""
    try:
        # If no symbol provided, use a random trending or recommended stock
        available_tickers = trending_tickers if trending_tickers else RECOMMENDED_STOCKS
        if not symbol:
            symbol = random.choice(available_tickers)
        
        # Get news for the symbol
        news_items = news_scanner.get_ticker_news(symbol)
        
        logger.debug(f"Analyzing call options for {symbol}")
        
        # Get current stock price
        current_price = float(rh.stocks.get_latest_price(symbol)[0])
        logger.debug(f"Current price for {symbol}: ${current_price}")
        
        # Get all expiration dates first
        exp_dates = rh.options.get_chains(symbol)
        logger.debug(f"Found {len(exp_dates)} expiration dates")
        
        # Get call options data for each expiration date
        all_options = []
        for exp_date in exp_dates:
            logger.debug(f"Fetching options for expiration date: {exp_date}")
            options = rh.options.find_options_by_expiration(
                symbol,
                expirationDate=exp_date,
                optionType='call'
            )
            all_options.extend(options)
        
        logger.debug(f"Total options found: {len(all_options)}")
        
        # Calculate break-even analysis for each option
        analyzed_options = []
        for option in all_options:
            try:
                expiration_date = datetime.datetime.strptime(option['expiration_date'], '%Y-%m-%d')
                days_until_expiration = (expiration_date - datetime.datetime.now()).days
                strike_price = float(option['strike_price'])
                ask_price = float(option.get('ask_price', 0))
                bid_price = float(option.get('bid_price', 0))
                
                # Only include options with valid prices and reasonable cost (under $5.00)
                if (ask_price > 0 or bid_price > 0) and ask_price <= 5.00:
                    # Use mid price if both bid and ask are available
                    option_price = ask_price if ask_price > 0 else bid_price
                    break_even_price = strike_price + option_price
                    break_even_percentage = ((break_even_price - current_price) / current_price) * 100
                    
                    # Only include options with reasonable break-even percentage (under 50%)
                    if break_even_percentage <= 50:
                        analyzed_options.append({
                            'expiration_date': option['expiration_date'],
                            'days_until_expiration': days_until_expiration,
                            'strike_price': strike_price,
                            'break_even_price': round(break_even_price, 2),
                            'break_even_percentage': break_even_percentage,
                            'last_price': float(option.get('last_trade_price', 0)),
                            'bid_price': bid_price,
                            'ask_price': ask_price,
                            'volume': int(option.get('volume', 0) or 0),
                            'open_interest': int(option.get('open_interest', 0) or 0),
                            'implied_volatility': float(option.get('implied_volatility', 0) or 0)
                        })
            except (ValueError, TypeError) as e:
                logger.warning(f"Skipping option due to data error: {str(e)}")
                continue
        
        logger.debug(f"Analyzed {len(analyzed_options)} valid options")
        
        # Sort options by break even percentage and days until expiration
        analyzed_options.sort(key=lambda x: (x['break_even_percentage'], x['days_until_expiration']))
        
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        logger.debug("Rendering template with options data")
        return render_template(
            'options_report.html',
            symbol=symbol,
            timestamp=timestamp,
            current_price=current_price,
            options_data=analyzed_options,
            recommended_stocks=RECOMMENDED_STOCKS,
            trending_tickers=trending_tickers,
            last_scan_time=last_scan_time,
            news_items=news_items[:3]  # Show top 3 news items
        )
        
    except Exception as e:
        logger.error(f"Error analyzing options: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Add after other globals
news_scanner = NewsScanner()
trending_tickers = []
last_scan_time = None
SCAN_INTERVAL = 3600  # Scan for new tickers every hour

def update_trending_tickers():
    """Background task to update trending tickers periodically."""
    global trending_tickers, last_scan_time
    while True:
        try:
            logger.info("\n=== Scanning for trending tickers ===")
            new_tickers = news_scanner.get_trending_tickers(max_tickers=20)
            if new_tickers:
                trending_tickers = new_tickers
                last_scan_time = datetime.datetime.now()
                logger.info(f"Found {len(trending_tickers)} trending tickers:")
                for ticker in trending_tickers:
                    logger.info(f"- {ticker}")
            else:
                logger.info("No trending tickers found")
            time.sleep(SCAN_INTERVAL)
        except Exception as e:
            logger.error(f"Error updating trending tickers: {str(e)}")
            time.sleep(300)  # Wait 5 minutes on error

def initialize_app():
    """Initialize the application and ensure all components are ready."""
    global trending_tickers, last_scan_time
    
    logger.info("Initializing Options Finder...")
    
    # Create necessary directories
    os.makedirs('static', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    # Start the news scanner and wait for first scan
    try:
        logger.info("Starting initial news scan...")
        new_tickers = news_scanner.get_trending_tickers(max_tickers=20)
        if new_tickers:
            trending_tickers = new_tickers
            last_scan_time = datetime.datetime.now()
            logger.info(f"Initial scan found {len(trending_tickers)} trending tickers")
        else:
            logger.warning("No trending tickers found in initial scan")
    except Exception as e:
        logger.error(f"Error in initial news scan: {str(e)}")

if __name__ == '__main__':
    try:
        # Cleanup any previous sessions
        cleanup_previous_sessions()
        
        # Initialize the application
        initialize_app()
        
        # Start the periodic news scanner thread
        scanner_thread = threading.Thread(target=update_trending_tickers, daemon=True)
        scanner_thread.start()
        
        logger.info("Starting web server...")
        
        # Open browser after a short delay
        timer = threading.Timer(2.0, lambda: webbrowser.open('http://localhost:5000'))
        timer.daemon = True
        timer.start()
        
        # Run the Flask app
        app.run(
            debug=True, 
            host='0.0.0.0', 
            port=5000,
            use_reloader=False
        )
    except Exception as e:
        logger.error(f"Application error: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1)
