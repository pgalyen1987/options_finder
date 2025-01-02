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
import queue
from utils.rate_limiter import rate_limited

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

# Update logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('app.log', mode='w')
    ]
)

# Configure loggers
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Add log filter for Werkzeug
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.WARNING)

# Add log filter for urllib3
urllib3_logger = logging.getLogger('urllib3')
urllib3_logger.setLevel(logging.WARNING)

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
            # Check if we have a valid session by trying to load profile
            try:
                profile = rh.profiles.load_account_profile()
                if not profile:
                    logger.debug("Session invalid, attempting to login")
                    _session = login_to_robinhood()
            except Exception:
                logger.debug("Session expired, attempting to login")
                _session = login_to_robinhood()
                
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Session error in {func.__name__}: {str(e)}")
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
    """Handle Robinhood login and redirect to dashboard."""
    try:
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            mfa_code = request.form.get('mfa_code')
            
            if not all([username, password, mfa_code]):
                return render_template('login.html', error="All fields are required")
            
            try:
                global _session, _username, _password
                add_log('INFO', f'Attempting login for user: {username}')
                _username = username
                _password = password
                _session = rh.login(username, password, mfa_code=mfa_code)
                
                if _session:
                    add_log('INFO', f'Login successful for user: {username}')
                    session.permanent = True
                    session['logged_in'] = True
                    
                    # Redirect directly to dashboard
                    return redirect(url_for('index'))
                else:
                    return render_template('login.html', error="Login failed")
                    
            except Exception as e:
                error_msg = str(e)
                if "challenge type" in error_msg.lower():
                    error_msg = "Invalid MFA code. Please try again."
                elif "invalid_grant" in error_msg.lower():
                    error_msg = "Invalid username or password."
                return render_template('login.html', error=error_msg)
        
        return render_template('login.html')
        
    except Exception as e:
        return render_template('login.html', error="An unexpected error occurred. Please try again.")

# Add error handlers
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors by redirecting to index if logged in, or login if not."""
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    add_log('ERROR', f'Internal server error: {str(e)}')
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle all other exceptions."""
    add_log('ERROR', f'Unhandled exception: {str(e)}')
    if session.get('logged_in'):
        return redirect(url_for('index'))
    return redirect(url_for('login'))

def analyze_options_batch(tickers):
    """Find call options with zero or negative break-even percentage."""
    opportunities = []
    
    add_log('INFO', f'Starting analysis of {len(tickers)} tickers')
    update_processing_stats({
        'total': len(tickers),
        'processed': 0,
        'valid': 0,
        'status': 'analyzing',
        'last_update': datetime.datetime.now().strftime('%H:%M:%S')
    })
    
    for symbol in tickers:
        try:
            update_processing_stats({
                'current_ticker': symbol,
                'status': f'analyzing {symbol}',
                'last_update': datetime.datetime.now().strftime('%H:%M:%S')
            })
            
            # Get current stock price
            stock_price = float(rh.stocks.get_latest_price(symbol)[0])
            if stock_price <= 0:
                continue
                
            # Get expiration dates
            exp_dates = rh.options.get_chains(symbol, info='expiration_dates')
            if not exp_dates:
                continue
                
            # Check each expiration date
            for exp_date in exp_dates[:3]:  # Check first 3 expiration dates
                try:
                    # Get call options
                    options = rh.options.find_options_for_stock_by_expiration(
                        symbol,
                        exp_date,
                        optionType='call'
                    )
                    
                    if not options:
                        continue
                    
                    # Check each option
                    for option in options:
                        try:
                            strike_price = float(option.get('strike_price', 0))
                            ask_price = float(option.get('ask_price', 0))
                            bid_price = float(option.get('bid_price', 0))
                            
                            if strike_price <= 0 or (ask_price <= 0 and bid_price <= 0):
                                continue
                            
                            option_price = ask_price if ask_price > 0 else bid_price
                            break_even_price = strike_price + option_price
                            break_even_percentage = ((break_even_price - stock_price) / stock_price) * 100
                            
                            # Check for zero or negative break-even
                            if break_even_percentage <= 0:
                                opportunity = {
                                    'symbol': symbol,
                                    'current_price': round(stock_price, 2),
                                    'expiration_date': exp_date,
                                    'days_until_expiration': (datetime.datetime.strptime(exp_date, '%Y-%m-%d') - datetime.datetime.now()).days,
                                    'strike_price': round(strike_price, 2),
                                    'break_even_price': round(break_even_price, 2),
                                    'break_even_percentage': round(break_even_percentage, 2),
                                    'option_cost': round(option_price, 2),
                                    'volume': int(option.get('volume', 0) or 0),
                                    'open_interest': int(option.get('open_interest', 0) or 0),
                                    'implied_volatility': round(float(option.get('implied_volatility', 0) or 0) * 100, 2)
                                }
                                
                                opportunities.append(opportunity)
                                add_log('SUCCESS', f'Found opportunity on {symbol}: {break_even_percentage:.2f}% break-even')
                                
                                # Update stats and broadcast new opportunity
                                update_processing_stats({
                                    'valid': len(opportunities),
                                    'opportunities': sorted(opportunities, key=lambda x: x['break_even_percentage']),
                                    'last_update': datetime.datetime.now().strftime('%H:%M:%S')
                                })
                        except (ValueError, TypeError):
                            continue
                except Exception:
                    continue
                    
        except Exception:
            continue
            
        finally:
            # Update processed count
            update_processing_stats({
                'processed': processing_stats['processed'] + 1,
                'last_update': datetime.datetime.now().strftime('%H:%M:%S')
            })
    
    # Sort by break-even percentage (most negative first)
    opportunities.sort(key=lambda x: x['break_even_percentage'])
    
    # Final update with sorted opportunities
    update_processing_stats({
        'status': 'complete',
        'last_update': datetime.datetime.now().strftime('%H:%M:%S'),
        'opportunities': opportunities
    })
    
    return opportunities

def is_stock_rising(symbol):
    """Check if a stock is in an upward trend."""
    try:
        # Get historical data for the last 5 days
        historicals = rh.stocks.get_stock_historicals(symbol, interval='day', span='week')
        if not historicals or len(historicals) < 2:
            return False
        
        # Calculate price changes
        current_price = float(historicals[-1]['close_price'])
        prev_price = float(historicals[0]['close_price'])
        price_change_pct = ((current_price - prev_price) / prev_price) * 100
        
        # Check if stock is rising (positive price change)
        return price_change_pct > 0
    except Exception:
        return False

def has_potential_negative_breakeven(symbol):
    """Pre-check if a stock might have negative break-even opportunities."""
    try:
        # Get current stock price
        current_price = float(rh.stocks.get_latest_price(symbol)[0])
        if current_price <= 0:
            return False
        
        # Get nearest expiration options chain
        exp_dates = rh.options.get_chains(symbol, info='expiration_dates')
        if not exp_dates:
            return False
            
        # Check the first expiration date
        options = rh.options.find_options_for_stock_by_expiration(
            symbol,
            exp_dates[0],
            optionType='call'
        )
        
        if not options:
            return False
            
        # Look for options with strike prices near current price
        for option in options:
            try:
                strike_price = float(option.get('strike_price', 0))
                ask_price = float(option.get('ask_price', 0))
                
                # If strike price is within 5% of current price and ask price is reasonable
                if (abs(strike_price - current_price) / current_price) <= 0.05 and ask_price > 0:
                    # Calculate potential break-even
                    break_even_price = strike_price + ask_price
                    break_even_percentage = ((break_even_price - current_price) / current_price) * 100
                    
                    # If break-even is close to negative or negative
                    if break_even_percentage <= 1:
                        return True
            except Exception:
                continue
                
        return False
    except Exception:
        return False

def get_all_options_tickers():
    """Get ALL stock tickers that have options available."""
    try:
        add_log('INFO', 'Fetching ALL possible options tickers from Robinhood')
        
        # Get all instruments first
        all_tickers = []
        url = 'https://api.robinhood.com/instruments/'
        
        while url:
            try:
                # Add delay between requests to avoid rate limiting
                time.sleep(0.5)  # 500ms delay between requests
                
                response = rh.helper.request_get(url, 'regular')
                if not response or not isinstance(response, dict):
                    add_log('ERROR', 'Invalid response from Robinhood API')
                    break
                    
                # Process all instruments
                for instrument in response.get('results', []):
                    # Skip if instrument doesn't have required fields
                    if not instrument.get('tradeable') or not instrument.get('tradability') == 'tradable' or not instrument.get('symbol'):
                        continue
                        
                    # Skip if no chain ID in instrument data
                    if not instrument.get('tradable_chain_id'):
                        continue
                        
                    symbol = instrument['symbol']
                    all_tickers.append(symbol)
                    
                    if len(all_tickers) % 100 == 0:
                        add_log('INFO', f'Found {len(all_tickers)} options tickers so far')
                
                # Get next page URL
                url = response.get('next')
                if url:
                    add_log('INFO', f'Processing next page... Current total: {len(all_tickers)} tickers')
                    time.sleep(1)  # 1 second delay between pages
                    
            except Exception as e:
                if '429' in str(e):  # Rate limit hit
                    add_log('WARNING', 'Rate limit reached, waiting 60 seconds...')
                    time.sleep(60)  # Wait 60 seconds when rate limited
                    continue
                add_log('ERROR', f'Error fetching instruments: {str(e)}')
                break
        
        if not all_tickers:
            add_log('WARNING', 'No option tickers found, falling back to recommended stocks')
            return RECOMMENDED_STOCKS
        
        add_log('SUCCESS', f'Found {len(all_tickers)} total options tickers')
        return all_tickers
        
    except Exception as e:
        add_log('ERROR', f'Error getting tickers: {str(e)}')
        return RECOMMENDED_STOCKS  # Fallback to recommended stocks

@app.route('/')
@check_auth
def index():
    """Show the dashboard and start options search."""
    try:
        # Start the search process
        add_log('INFO', '\n=== Starting Options Search ===')
        add_log('INFO', 'Starting search for zero or negative break-even options')
        
        # Create initial response with empty data
        response = make_response(render_template(
            'options_report.html',
            timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            opportunities=[],
            recommended_stocks=RECOMMENDED_STOCKS,
            trending_tickers=[],
            last_scan_time=None,
            search_mode="complete",
            attempts=0,
            total_stocks=0,
            system_logs=system_logs,
            processing_stats=processing_stats
        ))
        
        # Start background processing
        def background_processing():
            try:
                # Get all tickers
                all_tickers = get_all_options_tickers()
                if len(all_tickers) > 100:
                    add_log('SUCCESS', f'Found {len(all_tickers)} option tickers to analyze')
                
                # Update initial stats
                update_processing_stats({
                    'total': len(all_tickers),
                    'processed': 0,
                    'valid': 0,
                    'status': 'analyzing',
                    'last_update': datetime.datetime.now().strftime('%H:%M:%S'),
                    'opportunities': []
                })
                
                # Process tickers
                analyze_options_batch(all_tickers)
                
            except Exception as e:
                add_log('ERROR', f'Background processing error: {str(e)}')
        
        # Start processing in background
        thread = threading.Thread(target=background_processing)
        thread.daemon = True
        thread.start()
        
        return response
        
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        logger.error(traceback.format_exc())
        return redirect(url_for('login'))

@app.route('/random_search')
@check_auth
@maintain_session
def random_search():
    """Continuous search for negative break-even options using random stocks."""
    try:
        add_log('INFO', 'Starting continuous random search for negative break-even options')
        
        opportunities = []
        max_attempts = 20  # Maximum number of batches to try
        batch_size = 10  # Tickers per batch
        total_tickers = 0
        
        for attempt in range(max_attempts):
            add_log('INFO', f'Search attempt {attempt + 1}/{max_attempts}')
            
            # Get random tickers
            random_tickers = get_random_tickers(batch_size)
            total_tickers += len(random_tickers)
            
            # Analyze options
            batch_opportunities = analyze_options_batch(random_tickers)
            
            if batch_opportunities:
                opportunities.extend(batch_opportunities)
                add_log('SUCCESS', f'Found {len(batch_opportunities)} opportunities!')
                break  # Stop if we found opportunities
            else:
                add_log('INFO', 'No opportunities in this batch, continuing search...')
        
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if not opportunities:
            add_log('WARNING', f'No opportunities found after checking {total_tickers} tickers')
        else:
            add_log('SUCCESS', f'Search complete. Found {len(opportunities)} opportunities after checking {total_tickers} tickers')
        
        return render_template(
            'options_report.html',
            timestamp=timestamp,
            opportunities=opportunities,
            search_mode="random",
            attempts=attempt + 1,
            total_stocks=total_tickers
        )
        
    except Exception as e:
        add_log('ERROR', f'Error in random search: {str(e)}')
        return redirect(url_for('index'))

@app.route('/api/test')
def test_connection():
    """Test the Robinhood connection and data readiness."""
    try:
        # Test Robinhood connection
        profile = rh.profiles.load_account_profile()
        if not profile:
            return jsonify({
                'success': False,
                'message': 'Robinhood connection not ready'
            })
            
        # Connection is ready, no need to wait for news scanning
        return jsonify({
            'success': True,
            'message': 'Connection ready',
            'profile': profile
        })
        
    except Exception as e:
        logger.error(f"Test connection error: {str(e)}")
        return jsonify({
            'success': False,
            'message': str(e)
        })

@app.route('/api/options/<symbol>/chains', methods=['GET'])
@check_auth
@maintain_session
def get_options_chains(symbol):
    """Get options chain data for a symbol."""
    try:
        # Get current stock price with retry
        for _ in range(3):  # Try up to 3 times
            try:
                current_price = float(rh.stocks.get_latest_price(symbol)[0])
                break
            except Exception:
                time.sleep(1)
        else:  # If all retries failed
            return jsonify({
                'success': False,
                'error': 'Unable to fetch current price'
            }), 503
        
        # Get options chain info with retry
        chain_info = None
        for _ in range(3):  # Try up to 3 times
            try:
                chain_info = rh.options.get_chains(symbol)
                if chain_info and isinstance(chain_info, dict) and chain_info.get('chain_id'):
                    break
                time.sleep(1)
            except Exception as e:
                if '429' in str(e):  # Rate limit hit
                    add_log('WARNING', 'Rate limit reached, waiting 30 seconds...')
                    time.sleep(30)
                else:
                    time.sleep(1)
        
        if not chain_info or not isinstance(chain_info, dict) or not chain_info.get('chain_id'):
            return jsonify({
                'success': False,
                'error': 'No options available for this symbol'
            }), 404
            
        # Get expiration dates with retry
        exp_dates = None
        for _ in range(3):  # Try up to 3 times
            try:
                exp_dates = rh.options.get_chains(symbol, info='expiration_dates')
                if exp_dates:
                    break
                time.sleep(1)
            except Exception as e:
                if '429' in str(e):  # Rate limit hit
                    add_log('WARNING', 'Rate limit reached, waiting 30 seconds...')
                    time.sleep(30)
                else:
                    time.sleep(1)
        
        if not exp_dates:
            return jsonify({
                'success': False,
                'error': 'No expiration dates available'
            }), 404
        
        # Get options data for each expiration date
        chains_data = []
        for exp_date in exp_dates[:3]:  # Limit to nearest 3 expiration dates for performance
            try:
                # Add delay between requests
                time.sleep(0.5)
                
                # Get call options for this expiration with retry
                options = None
                for _ in range(3):  # Try up to 3 times
                    try:
                        options = rh.options.find_options_for_stock_by_expiration(
                            symbol,
                            exp_date,
                            optionType='call'
                        )
                        if options:
                            break
                        time.sleep(1)
                    except Exception as e:
                        if '429' in str(e):  # Rate limit hit
                            add_log('WARNING', 'Rate limit reached, waiting 30 seconds...')
                            time.sleep(30)
                        else:
                            time.sleep(1)
                
                if options:
                    # Filter and format options data
                    formatted_options = []
                    for option in options:
                        try:
                            strike_price = float(option.get('strike_price', 0))
                            ask_price = float(option.get('ask_price', 0))
                            bid_price = float(option.get('bid_price', 0))
                            
                            if strike_price > 0 and (ask_price > 0 or bid_price > 0):
                                option_price = ask_price if ask_price > 0 else bid_price
                                break_even_price = strike_price + option_price
                                break_even_percentage = ((break_even_price - current_price) / current_price) * 100
                                
                                formatted_options.append({
                                    'strike_price': round(strike_price, 2),
                                    'ask_price': round(ask_price, 2),
                                    'bid_price': round(bid_price, 2),
                                    'break_even_price': round(break_even_price, 2),
                                    'break_even_percentage': round(break_even_percentage, 2),
                                    'volume': int(option.get('volume', 0) or 0),
                                    'open_interest': int(option.get('open_interest', 0) or 0),
                                    'implied_volatility': round(float(option.get('implied_volatility', 0) or 0) * 100, 2),
                                    'expiration_date': exp_date,
                                    'option_type': 'call',
                                    'symbol': symbol
                                })
                        except (ValueError, TypeError) as e:
                            add_log('WARNING', f'Error formatting option for {symbol}: {str(e)}')
                            continue
                    
                    if formatted_options:
                        chains_data.append({
                            'expiration_date': exp_date,
                            'days_until_expiration': (datetime.datetime.strptime(exp_date, '%Y-%m-%d') - datetime.datetime.now()).days,
                            'options': formatted_options
                        })
            except Exception as e:
                add_log('WARNING', f'Error fetching options for {symbol} expiring {exp_date}: {str(e)}')
                continue
        
        if not chains_data:
            return jsonify({
                'success': False,
                'error': 'No valid options data found'
            }), 404
        
        # Add logging for successful response
        add_log('INFO', f'Successfully retrieved options chains for {symbol}')
        
        return jsonify({
            'success': True,
            'symbol': symbol,
            'current_price': round(current_price, 2),
            'chains': chains_data
        })
        
    except Exception as e:
        error_msg = str(e)
        add_log('ERROR', f'Error getting options chains for {symbol}: {error_msg}')
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500

@rate_limited
def fetch_options_data(symbol, exp_date=None, option_type='call'):
    try:
        if exp_date:
            options = rh.options.find_options_by_expiration(
                symbol,
                expirationDate=exp_date,
                optionType=option_type
            )
        else:
            options = rh.options.find_tradable_options(
                symbol,
                optionType=option_type
            )
        return options
    except Exception as e:
        logger.error(f"Error fetching options for {symbol}: {str(e)}")
        return []

@app.route('/api/options/<symbol>/report', methods=['GET'])
@check_auth
@maintain_session
def get_options_report(symbol):
    try:
        # Get current stock price
        current_price = float(rh.stocks.get_latest_price(symbol)[0])
        
        # Get expiration dates with retry logic
        retries = 3
        exp_dates = None
        
        for attempt in range(retries):
            try:
                exp_dates = rh.options.get_chains(symbol, info='expiration_dates')
                if exp_dates:
                    break
                time.sleep(1)
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed: {str(e)}")
                if attempt < retries - 1:
                    time.sleep(2)
                    continue
                return jsonify({
                    'success': False,
                    'error': 'Unable to fetch options data'
                }), 503

        if not exp_dates:
            return jsonify({
                'success': False,
                'error': 'No options available for this symbol'
            }), 404

        # Fetch options data with rate limiting
        all_options = []
        for exp_date in exp_dates[:5]:  # Limit to first 5 expiration dates
            options = fetch_options_data(symbol, exp_date)
            if options:
                all_options.extend(options)
            time.sleep(0.2)  # Additional delay between requests

        # Rest of your existing analysis code...

        # Sort by break-even percentage
        analyzed_options.sort(key=lambda x: x['break_even_percentage'])
        
        return jsonify({
            'success': True,
            'symbol': symbol,
            'current_price': round(current_price, 2),
            'expiration_date': exp_dates[0],
            'days_until_expiration': (datetime.datetime.strptime(exp_dates[0], '%Y-%m-%d') - datetime.datetime.now()).days,
            'options': analyzed_options
        })
        
    except Exception as e:
        add_log('ERROR', f'Error generating options report for {symbol}: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/favicon.ico')
def favicon():
    """Serve the favicon with proper cache control."""
    response = send_from_directory(
        app.static_folder,
        'favicon.ico',
        mimetype='image/x-icon',
        etag=True,
        max_age=31536000,
        conditional=True
    )
    return response

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
ticker_queue = queue.Queue()
SCAN_INTERVAL = 3600  # Scan for new tickers every hour
processing_stats = {
    'processed': 0,
    'total': 0,
    'valid': 0,
    'current_ticker': None,
    'news_articles': 0,
    'status': 'initializing'
}

def update_processing_stats(stats_update):
    """Update the processing statistics."""
    global processing_stats
    processing_stats.update(stats_update)

@app.route('/api/progress')
@check_auth
def get_progress():
    """Get the current processing progress."""
    return jsonify({
        'processed': processing_stats['processed'],
        'total': processing_stats['total'],
        'valid': processing_stats['valid'],
        'current_ticker': processing_stats['current_ticker'],
        'news_articles': processing_stats['news_articles'],
        'status': processing_stats['status'],
        'last_scan': last_scan_time.strftime('%Y-%m-%d %H:%M:%S') if last_scan_time else None
    })

@app.route('/api/next_ticker')
@check_auth
def next_ticker():
    """Get the next ticker to analyze."""
    ticker = get_next_ticker()
    return jsonify({
        'ticker': ticker,
        'queue_size': ticker_queue.qsize(),
        'last_scan': last_scan_time.strftime('%Y-%m-%d %H:%M:%S') if last_scan_time else None,
        'processed': processing_stats['processed'],
        'total': processing_stats['total'],
        'valid': processing_stats['valid']
    })

def update_trending_tickers():
    """Background task to update trending tickers periodically."""
    global trending_tickers, last_scan_time
    while True:
        try:
            logger.info("\n=== Scanning for trending tickers ===")
            update_processing_stats({
                'status': 'scanning news',
                'processed': 0,
                'total': 0,
                'valid': 0
            })
            
            new_tickers = news_scanner.get_trending_tickers(max_tickers=20)
            if new_tickers:
                # Update the queue with new tickers
                while not ticker_queue.empty():
                    ticker_queue.get_nowait()  # Clear old tickers
                for ticker in new_tickers:
                    ticker_queue.put(ticker)
                
                trending_tickers = new_tickers
                last_scan_time = datetime.datetime.now()
                logger.info(f"Found {len(trending_tickers)} trending tickers:")
                for ticker in trending_tickers:
                    logger.info(f"- {ticker}")
                    
                update_processing_stats({
                    'status': 'ready',
                    'total': len(trending_tickers)
                })
            else:
                logger.info("No new trending tickers found, keeping current list")
            time.sleep(SCAN_INTERVAL)
        except Exception as e:
            logger.error(f"Error updating trending tickers: {str(e)}")
            if not trending_tickers:
                trending_tickers = RECOMMENDED_STOCKS[:5]  # Use recommended stocks as fallback
            time.sleep(300)  # Wait 5 minutes on error

def initialize_app():
    """Initialize the application with recommended stocks by default."""
    global trending_tickers, last_scan_time
    
    add_log('INFO', 'Starting application initialization')
    
    # Create necessary directories
    os.makedirs('static', exist_ok=True)
    os.makedirs('reports', exist_ok=True)
    
    # Start with recommended stocks
    trending_tickers = RECOMMENDED_STOCKS[:5]
    last_scan_time = datetime.datetime.now()
    
    # Initialize queue with recommended stocks
    for ticker in trending_tickers:
        ticker_queue.put(ticker)
    
    # Update status
    update_processing_stats({
        'status': 'ready',
        'total': len(trending_tickers),
        'news_articles': 0
    })
    
    add_log('INFO', 'Initialization complete')

@app.route('/api/scan_news', methods=['POST'])
@check_auth
def scan_news():
    """Endpoint to trigger news scanning on demand."""
    try:
        update_processing_stats({
            'status': 'scanning news',
            'processed': 0,
            'total': 0,
            'valid': 0,
            'news_articles': 0
        })
        
        # Clear existing queue
        while not ticker_queue.empty():
            ticker_queue.get_nowait()
        
        # Scan for new tickers
        new_tickers = news_scanner.get_trending_tickers(max_tickers=20)
        
        if new_tickers:
            global trending_tickers, last_scan_time
            trending_tickers = new_tickers
            last_scan_time = datetime.datetime.now()
            
            # Update queue with new tickers
            for ticker in trending_tickers:
                ticker_queue.put(ticker)
            
            update_processing_stats({
                'status': 'ready',
                'total': len(trending_tickers)
            })
            
            return jsonify({
                'success': True,
                'message': f'Found {len(trending_tickers)} trending tickers',
                'tickers': trending_tickers
            })
        else:
            # Fallback to recommended stocks
            trending_tickers = RECOMMENDED_STOCKS[:5]
            last_scan_time = datetime.datetime.now()
            
            for ticker in trending_tickers:
                ticker_queue.put(ticker)
            
            update_processing_stats({
                'status': 'ready (fallback)',
                'total': len(trending_tickers)
            })
            
            return jsonify({
                'success': False,
                'message': 'No trending tickers found, using recommended stocks',
                'tickers': trending_tickers
            })
            
    except Exception as e:
        logger.error(f"News scan error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error scanning news, using recommended stocks',
            'tickers': RECOMMENDED_STOCKS[:5]
        }), 500

def get_next_ticker():
    """Get the next ticker from the queue and put it back at the end."""
    try:
        ticker = ticker_queue.get_nowait()
        ticker_queue.put(ticker)  # Put it back at the end
        return ticker
    except queue.Empty:
        if trending_tickers:
            return trending_tickers[0]  # Return first ticker if queue is empty
        return RECOMMENDED_STOCKS[0]  # Fallback to first recommended stock

# Add to globals section
system_logs = []
MAX_LOGS = 50

def add_log(level, message):
    """Add a log entry to the system logs with timestamp."""
    global system_logs
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = {
        'timestamp': timestamp,
        'level': level,
        'message': message
    }
    system_logs.append(log_entry)
    
    # Keep only last MAX_LOGS entries
    if len(system_logs) > MAX_LOGS:
        system_logs = system_logs[-MAX_LOGS:]
    
    # Log to console and file
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.log(log_level, message)

@app.route('/api/status')
@check_auth
def get_status():
    """Get detailed system status including logs."""
    try:
        # Check Robinhood connection
        connected = False
        try:
            profile = rh.profiles.load_account_profile()
            connected = bool(profile)
        except Exception:
            pass
            
        # Calculate time since last update
        last_update = processing_stats.get('last_update')
        if last_update:
            now = datetime.datetime.now()
            last_update_time = datetime.datetime.strptime(last_update, '%H:%M:%S')
            last_update_time = last_update_time.replace(year=now.year, month=now.month, day=now.day)
            seconds_since_update = (now - last_update_time).total_seconds()
        else:
            seconds_since_update = 0
            
        return jsonify({
            'connected': connected,
            'status': processing_stats['status'],
            'processed': processing_stats['processed'],
            'total': processing_stats['total'],
            'valid': processing_stats['valid'],
            'current_ticker': processing_stats['current_ticker'],
            'logs': system_logs,
            'last_update': last_update,
            'seconds_since_update': int(seconds_since_update),
            'last_scan': last_scan_time.strftime('%Y-%m-%d %H:%M:%S') if last_scan_time else None
        })
    except Exception as e:
        add_log('ERROR', f"Error getting status: {str(e)}")
        return jsonify({
            'connected': False,
            'status': 'error',
            'logs': system_logs
        })

if __name__ == '__main__':
    try:
        # Cleanup any previous sessions
        cleanup_previous_sessions()
        add_log('INFO', 'Previous sessions cleaned up')
        
        # Initialize the application with recommended stocks
        initialize_app()
        
        # Open browser after a short delay
        timer = threading.Timer(1.0, lambda: webbrowser.open('http://localhost:5000/login'))
        timer.daemon = True
        timer.start()
        add_log('INFO', 'Starting web server on port 5000')
        
        # Run the Flask app
        app.run(
            debug=False,
            host='0.0.0.0', 
            port=5000,
            use_reloader=False
        )
    except Exception as e:
        add_log('ERROR', f'Application startup error: {str(e)}')
        sys.exit(1)
