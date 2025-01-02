import feedparser
import yfinance as yf
from bs4 import BeautifulSoup
import re
import logging
import requests
from datetime import datetime, timedelta
import time

class NewsScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.google_news_url = "https://news.google.com/rss/search?q=stock+market+when:24h&hl=en-US&gl=US&ceid=US:en"
        self.business_news_url = "https://news.google.com/rss/topics/CAAqJggKIiBDQkFTRWdvSUwyMHZNRGx6TVdZU0FtVnVHZ0pWVXlnQVAB?hl=en-US&gl=US&ceid=US%3Aen"
        self.known_tickers = set(self._get_nasdaq_tickers())
        
    def _get_nasdaq_tickers(self):
        """Get a list of valid NASDAQ tickers."""
        try:
            # Download NASDAQ ticker list
            url = "ftp://ftp.nasdaqtrader.com/SymbolDirectory/nasdaqlisted.txt"
            response = requests.get(url)
            lines = response.text.split('\n')
            # Extract tickers (first column)
            tickers = [line.split('|')[0] for line in lines[1:-1]]  # Skip header and last line
            return tickers
        except Exception as e:
            self.logger.error(f"Error fetching NASDAQ tickers: {str(e)}")
            return []

    def _extract_tickers(self, text):
        """Extract potential stock tickers from text."""
        # Pattern for stock tickers (1-5 capital letters)
        pattern = r'\b[A-Z]{1,5}\b'
        potential_tickers = set(re.findall(pattern, text))
        
        # Filter out common words and keep only known tickers
        common_words = {'A', 'I', 'CEO', 'CFO', 'US', 'GDP', 'IPO', 'NYSE', 'SEC', 'FBI', 'USA'}
        return {ticker for ticker in potential_tickers 
                if ticker in self.known_tickers and ticker not in common_words}

    def _validate_ticker(self, ticker):
        """Validate if a ticker is tradeable and has options."""
        try:
            stock = yf.Ticker(ticker)
            info = stock.info
            
            # Check if the stock has options
            if not stock.options:
                return False
                
            # Check if it's a valid stock (has a market price)
            if 'regularMarketPrice' not in info or info['regularMarketPrice'] is None:
                return False
                
            # Check if price is reasonable (between $1 and $500)
            price = info['regularMarketPrice']
            if price < 1 or price > 500:
                return False
            
            return True
        except Exception as e:
            self.logger.debug(f"Error validating ticker {ticker}: {str(e)}")
            return False

    def get_trending_tickers(self, max_tickers=20):
        """Get trending stock tickers from news articles."""
        trending_tickers = set()
        
        try:
            # Fetch business news
            feed = feedparser.parse(self.business_news_url)
            
            # Process each news item
            for entry in feed.entries:
                # Extract text from title and description
                text = f"{entry.title} {entry.description}"
                
                # Extract potential tickers
                tickers = self._extract_tickers(text)
                
                # Add to trending set
                trending_tickers.update(tickers)
                
                if len(trending_tickers) >= max_tickers:
                    break
                    
            # Validate tickers
            valid_tickers = []
            for ticker in trending_tickers:
                if self._validate_ticker(ticker):
                    valid_tickers.append(ticker)
                    if len(valid_tickers) >= max_tickers:
                        break
            
            return valid_tickers
            
        except Exception as e:
            self.logger.error(f"Error fetching trending tickers: {str(e)}")
            return []

    def get_ticker_news(self, ticker):
        """Get recent news for a specific ticker."""
        try:
            url = f"https://news.google.com/rss/search?q={ticker}+stock+when:24h&hl=en-US&gl=US&ceid=US:en"
            feed = feedparser.parse(url)
            
            news_items = []
            for entry in feed.entries[:5]:  # Get top 5 news items
                news_items.append({
                    'title': entry.title,
                    'link': entry.link,
                    'published': entry.published,
                    'summary': entry.description
                })
            
            return news_items
        except Exception as e:
            self.logger.error(f"Error fetching news for {ticker}: {str(e)}")
            return []

if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Test the scanner
    scanner = NewsScanner()
    trending = scanner.get_trending_tickers(max_tickers=10)
    
    print("\nTrending Tickers Found:")
    for ticker in trending:
        print(f"\n{ticker}:")
        news = scanner.get_ticker_news(ticker)
        for item in news[:2]:  # Show top 2 news items
            print(f"- {item['title']}") 