import feedparser
import yfinance as yf
import robin_stocks.robinhood as rh
from bs4 import BeautifulSoup
import re
import logging
import requests
from datetime import datetime, timedelta
import time
import pandas as pd
from textblob import TextBlob

logger = logging.getLogger(__name__)

class NewsScanner:
    def __init__(self):
        """Initialize the news scanner with RSS feeds and regex patterns."""
        self.stock_news_url = "https://news.google.com/rss/search?q=stock+market+when:24h&hl=en-US&gl=US&ceid=US:en"
        self.business_news_url = "https://news.google.com/rss/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGx6TVdZU0FtVnVHZ0pWVXlnQVAB?hl=en-US&gl=US&ceid=US%3Aen"
        self.ticker_pattern = r'\$?([A-Z]{1,5})'  # Match potential stock tickers
        self.excluded_words = {
            'THE', 'AND', 'FOR', 'NEW', 'CEO', 'CFO', 'USA', 'NYSE', 'IPO', 'ETF',
            'API', 'AI', 'EPS', 'GDP', 'SEC', 'FBI', 'CEO', 'CTO', 'CFO', 'COO',
            'EST', 'PST', 'UTC', 'RSS', 'URL', 'TV', 'ICE', 'IRS', 'IRA', 'UK',
            'DOW', 'SPY', 'QQQ', 'VIX', 'WSJ', 'CNN', 'BBC', 'USD', 'EUR', 'JPY'
        }
        self.positive_sentiment_threshold = 0.2  # Increased threshold for more selective filtering
        self.min_news_age_hours = 48  # Only consider news from the last 48 hours
        self.min_daily_volume = 100000  # Minimum average daily volume
        self.min_option_volume = 10  # Minimum option volume
        self.max_days_to_expiration = 60  # Maximum days to expiration for options

    def analyze_sentiment(self, text):
        """Analyze the sentiment of a text using TextBlob."""
        try:
            analysis = TextBlob(text)
            return analysis.sentiment.polarity
        except Exception as e:
            logger.warning(f"Error analyzing sentiment: {str(e)}")
            return 0.0

    def check_options_availability(self, ticker):
        """Check if the ticker has valid options available in Robinhood."""
        try:
            # Get options chain info
            chain_data = rh.options.get_chains(ticker)
            if not chain_data or 'error' in chain_data:
                logger.debug(f"{ticker}: No options chain found")
                return False

            # Get expiration dates
            exp_dates = rh.options.get_chains(ticker, info='expiration_dates')
            if not exp_dates:
                logger.debug(f"{ticker}: No expiration dates found")
                return False

            # Get current date and max expiration date
            current_date = datetime.now()
            valid_options_found = False

            # Check the first few expiration dates
            for exp_date in exp_dates[:3]:  # Check first 3 expiration dates
                try:
                    # Calculate days until expiration
                    exp_datetime = datetime.strptime(exp_date, '%Y-%m-%d')
                    days_to_exp = (exp_datetime - current_date).days

                    # Skip if too far out
                    if days_to_exp > self.max_days_to_expiration:
                        continue

                    # Get call options for this expiration
                    options = rh.options.find_options_by_expiration(
                        ticker,
                        expirationDate=exp_date,
                        optionType='call'
                    )

                    if not options:
                        continue

                    # Check for valid options with sufficient volume
                    for option in options:
                        volume = int(option.get('volume', 0) or 0)
                        if volume >= self.min_option_volume:
                            valid_options_found = True
                            break

                    if valid_options_found:
                        break

                except Exception as e:
                    logger.debug(f"{ticker}: Error checking expiration {exp_date}: {str(e)}")
                    continue

            if not valid_options_found:
                logger.debug(f"{ticker}: No valid options found with sufficient volume")
                return False

            return True

        except Exception as e:
            logger.warning(f"Error checking options for {ticker}: {str(e)}")
            return False

    def validate_ticker(self, ticker):
        """Validate a ticker by checking for recent news, trading data, and options availability."""
        try:
            stock = yf.Ticker(ticker)
            
            # Check for recent news
            news = stock.news
            if not news:
                logger.debug(f"{ticker}: No recent news found")
                return False
                
            # Check if news is recent enough
            current_time = datetime.now().timestamp()
            recent_news = False
            for item in news:
                news_time = item.get('providerPublishTime', 0)
                hours_old = (current_time - news_time) / 3600
                if hours_old <= self.min_news_age_hours:
                    recent_news = True
                    break
                    
            if not recent_news:
                logger.debug(f"{ticker}: No news within last {self.min_news_age_hours} hours")
                return False
                
            # Check trading data
            hist = stock.history(period="5d")
            if hist.empty or hist['Close'].isnull().all():
                logger.debug(f"{ticker}: No valid trading data")
                return False
                
            # Check trading volume
            if hist['Volume'].mean() < self.min_daily_volume:
                logger.debug(f"{ticker}: Insufficient trading volume")
                return False

            # Check options availability
            if not self.check_options_availability(ticker):
                logger.debug(f"{ticker}: No valid options available")
                return False
                
            return True
            
        except Exception as e:
            logger.warning(f"Error validating {ticker}: {str(e)}")
            return False

    def get_trending_tickers(self, max_tickers=20):
        """Get trending stock tickers from news articles with positive sentiment."""
        try:
            logger.info("Fetching news feeds...")
            # Fetch news from both sources
            stock_feed = feedparser.parse(self.stock_news_url)
            business_feed = feedparser.parse(self.business_news_url)
            
            # Combine entries from both feeds
            all_entries = stock_feed.entries + business_feed.entries
            logger.info(f"Found {len(all_entries)} news articles")
            
            # Extract potential tickers and their sentiment scores
            ticker_sentiment = {}
            for entry in all_entries:
                title = entry.get('title', '')
                description = entry.get('description', '')
                content = f"{title} {description}"
                
                # Analyze sentiment of the content
                sentiment = self.analyze_sentiment(content)
                
                # Only process content with positive sentiment
                if sentiment > self.positive_sentiment_threshold:
                    # Find all potential ticker matches
                    matches = re.findall(self.ticker_pattern, content)
                    # Only include tickers that are 2-4 characters long and not in excluded words
                    valid_matches = [
                        m for m in matches 
                        if len(m) >= 2 and len(m) <= 4 and m not in self.excluded_words
                    ]
                    
                    # Update sentiment scores for tickers
                    for ticker in valid_matches:
                        if ticker in ticker_sentiment:
                            ticker_sentiment[ticker] = max(ticker_sentiment[ticker], sentiment)
                        else:
                            ticker_sentiment[ticker] = sentiment
            
            logger.info(f"Found {len(ticker_sentiment)} potential ticker symbols with positive sentiment")
            
            if not ticker_sentiment:
                logger.warning("No potential tickers found with positive sentiment")
                return []
                
            # Sort tickers by sentiment score
            sorted_tickers = sorted(ticker_sentiment.items(), key=lambda x: x[1], reverse=True)
            potential_tickers = [ticker for ticker, _ in sorted_tickers]
            
            # Validate tickers individually with enhanced validation
            valid_tickers = []
            logger.info(f"Validating {len(potential_tickers)} potential tickers...")
            
            for ticker in potential_tickers:
                if len(valid_tickers) >= max_tickers:
                    break
                    
                logger.info(f"Validating {ticker}...")
                if self.validate_ticker(ticker):
                    valid_tickers.append(ticker)
                    logger.info(f"✓ {ticker} validated successfully")
                else:
                    logger.debug(f"✗ {ticker} failed validation")
                    
                # Add small delay to avoid rate limiting
                time.sleep(0.5)
            
            logger.info(f"Validation complete. Found {len(valid_tickers)} valid tickers")
            return valid_tickers
            
        except Exception as e:
            logger.error(f"Error fetching trending tickers: {str(e)}")
            return []
            
    def get_ticker_news(self, ticker, max_items=5):
        """Get recent news items for a specific ticker."""
        try:
            # Use yfinance to get news
            stock = yf.Ticker(ticker)
            news = stock.news
            
            if not news:
                return []
                
            # Format news items and filter by age
            formatted_news = []
            current_time = datetime.now().timestamp()
            
            for item in news[:max_items]:
                news_time = item.get('providerPublishTime', 0)
                hours_old = (current_time - news_time) / 3600
                
                if hours_old <= self.min_news_age_hours:
                    formatted_news.append({
                        'title': item.get('title', ''),
                        'link': item.get('link', ''),
                        'publisher': item.get('publisher', ''),
                        'published': datetime.fromtimestamp(news_time).strftime('%Y-%m-%d %H:%M:%S'),
                        'hours_old': round(hours_old, 1)
                    })
                
            return formatted_news
            
        except Exception as e:
            logger.error(f"Error fetching news for {ticker}: {str(e)}")
            return []

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Test the scanner
    scanner = NewsScanner()
    trending = scanner.get_trending_tickers(max_tickers=10)
    
    print("\nTrending Tickers Found:")
    for ticker in trending:
        print(f"\n{ticker}:")
        news = scanner.get_ticker_news(ticker)
        if news:
            for item in news[:2]:
                print(f"- [{item['hours_old']}h ago] {item['title']}")
        else:
            print("No recent news found") 