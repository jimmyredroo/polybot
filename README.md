# Polymarket Insider Trading Detector

A Python-based monitoring system that detects potentially suspicious trading activity on Polymarket by analyzing wallet behavior patterns. Inspired by Discord bots that successfully flagged suspicious betting activity hours before major events.

## Overview

This tool monitors Polymarket's CLOB API for transaction patterns that may indicate insider knowledge, focusing on wallet-level behavioral analysis rather than simple price movement detection. The system generates real-time alerts via Discord webhooks when suspicious activity is detected.

### Why Wallet Behavior Matters

Traditional market surveillance focuses on price movements, but insider trading on prediction markets often reveals itself through wallet behavior:

- **Fresh wallets** making unusually large first bets
- **Low-activity accounts** suddenly placing significant positions
- **Market concentration** in niche events where insider knowledge provides advantages
- **Timing patterns** relative to wallet creation

## Key Features

- **Real-time monitoring** of Polymarket transactions via CLOB API
- **Wallet profiling** with historical trade analysis and behavior scoring
- **Radar score calculation** weighting multiple risk factors
- **Market categorization** (HIGH_VALUE, SPORTS, CRYPTO, GENERAL) with severity multipliers
- **Discord webhook integration** for instant alerts with market thumbnails
- **Polygonscan API integration** for accurate wallet creation timestamps
- **SQLite storage** for historical data and caching

## Alert Types

| Alert | Criteria |
|-------|----------|
| `LOW_ACTIVITY_LARGE_BET` | ≤10 lifetime trades + ≥$1,000 bet |
| `FRESH_WALLET_BET` | Wallet <30 days old + ≥$500 bet |
| `UNUSUAL_SIZE` | Trade 5x+ larger than wallet's average |

## Radar Score Calculation

The system calculates a composite "radar score" weighting five behavioral components:

| Component | Weight | Description |
|-----------|--------|-------------|
| Wallet Creation to Transaction Timing | 35% | Time between wallet creation and trade (key signal) |
| Trade Size | 20% | Absolute size of the position |
| Wallet Freshness | 15% | Age of the wallet |
| Market Concentration | 15% | How focused the wallet is on specific markets |
| Conviction vs History | 15% | Size relative to wallet's historical behavior |

### "Perfect Setup" Criteria

The highest-confidence alerts meet all six criteria:

1. Wallet age under 1 day
2. Participation in fewer than 3 markets
3. Trade size over $10,000
4. Radar score above 50%
5. Wallet creation to transaction time under 20%
6. Trade age under 5 hours

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/polymarket-insider-detector.git
cd polymarket-insider-detector

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DISCORD_WEBHOOK_URL="your_webhook_url"
export POLYGONSCAN_API_KEY="your_api_key"
```

## Usage

### Single Scan
```bash
python insider_detector.py
```

### Continuous Monitoring
```bash
python insider_detector.py --monitor --interval 30
```

### Configuration Options

- `--interval` - Polling interval in seconds (default: 30)
- `--min-severity` - Minimum severity threshold for alerts (default: 0.3)
- `--min-trade-size` - Minimum trade size to analyze (default: 1000)

## Filtering Strategy

To reduce false positives, the system:

- **Filters trades under $1,000** - Small bets rarely indicate insider activity
- **Excludes high-probability outcomes** - Obvious bets on near-certain events
- **Deprioritizes sports markets** - Public information, limited insider edge
- **Deprioritizes crypto markets** - High noise, public blockchain data
- **Prioritizes political/corporate events** - Highest signal for genuine insider knowledge

## API Integrations

| API | Purpose |
|-----|---------|
| Polymarket CLOB API | Transaction data and market information |
| Polymarket Gamma API | Market images for Discord embeds |
| Polygonscan API | Wallet creation timestamps |

## Discord Alerts

Alerts are sent to Discord with:

- Market name and thumbnail image
- Wallet address (linked to Polygonscan)
- Trade details (size, side, odds)
- Radar score breakdown
- Wallet profile summary
- Severity classification

## Roadmap

- [ ] Filter out all sports markets
- [ ] Refine severity level thresholds
- [ ] Focus alerts on high-severity likelihood only
- [ ] Additional filtering for low-notional noise

## Contributing

Contributions are welcome! Areas of particular interest:

- Improved wallet behavior heuristics
- Additional data sources for cross-referencing
- Backtesting framework improvements
- New alert type development

## Disclaimer

This tool is for research and educational purposes only. Detection of "suspicious" activity does not constitute proof of insider trading. Always conduct your own due diligence and comply with applicable laws and platform terms of service.

## License

MIT License

## Maintainer

Jimmy
