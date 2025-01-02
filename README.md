# Options Finder

A Flask-based web application that analyzes stock options data from Robinhood and identifies potential trading opportunities based on break-even analysis.

## Features

- Fetches real-time options data from Robinhood
- Analyzes call options for break-even potential
- Tracks trending stocks from Google News
- Displays options data in a user-friendly web interface
- Secure login with MFA support
- Automatic session management
- Background news scanning for trending tickers

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd options_finder
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file with your configuration:
```bash
touch .env
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your browser to http://localhost:5000
3. Log in with your Robinhood credentials and MFA code
4. View options analysis and trending stocks

## Security Notes

- The application uses secure session management
- MFA is required for Robinhood authentication
- All sensitive data is handled securely
- SSL certificates are optional for development

## Development

- Python 3.8+ required
- Uses Flask for web framework
- Robin-stocks for Robinhood API integration
- Supports both HTTP and HTTPS

## Directory Structure

```
options_finder/
├── app.py              # Main application file
├── news_scanner.py     # News scanning functionality
├── requirements.txt    # Python dependencies
├── static/            # Static files (favicon, etc.)
├── templates/         # HTML templates
├── reports/          # Generated reports
└── ssl/              # SSL certificates (optional)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - See LICENSE file for details 