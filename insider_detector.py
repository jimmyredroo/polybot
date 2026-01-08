"""
Polymarket Insider Detection System

Tracks trades, profiles wallets, and flags suspicious activity:
- Fresh/low-activity wallets making large bets
- Unusual sizing relative to wallet history
- Concentrated betting on niche markets
"""

import requests
import sqlite3
import time
import os
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional, List, Dict
import json


@dataclass
class Trade:
    """A single trade from the Polymarket API"""
    wallet: str
    side: str  # BUY or SELL
    size: float  # number of shares
    price: float
    usdc_size: float  # dollar value
    timestamp: int
    market_id: str
    market_title: str
    outcome: str
    pseudonym: str
    tx_hash: str


@dataclass
class WalletProfile:
    """Aggregated stats about a wallet"""
    wallet: str
    total_trades: int
    unique_markets: int
    total_volume_usd: float
    first_seen: datetime
    last_seen: datetime
    avg_trade_size: float
    max_trade_size: float
    win_rate: Optional[float]  # if we can calculate it
    wc_tx_minutes: Optional[float] = None  # Minutes from wallet creation to first trade


@dataclass
class Alert:
    """A suspicious activity alert"""
    alert_type: str
    severity: float  # 0-1
    wallet: str
    trade: Trade
    wallet_profile: WalletProfile
    reason: str
    timestamp: datetime


class InsiderDetector:
    """Main detection engine"""
    
    def __init__(self, db_path: str = "insider_detection.db", discord_webhook: str = None, polygonscan_api_key: str = None):
        self.db_path = Path(db_path)
        self.data_api = "https://data-api.polymarket.com"
        self.gamma_api = "https://gamma-api.polymarket.com"
        self.polygonscan_api = "https://api.polygonscan.com/api"
        self.discord_webhook = discord_webhook or os.getenv("DISCORD_WEBHOOK_URL")
        self.polygonscan_api_key = polygonscan_api_key or os.getenv("POLYGONSCAN_API_KEY")
        self._init_db()
        
        # Cache for wallet creation times (avoid repeated API calls)
        self._wallet_creation_cache = {}
        
        # Cache for market images
        self._market_image_cache = {}
        
        # Track transactions we've already alerted on (prevent duplicates)
        self._alerted_tx_hashes = set()
        self._load_alerted_tx_hashes()
        
        # Detection thresholds
        self.thresholds = {
            "min_notional_usd": 1000,           # Minimum trade size to consider for any alert
            "high_favorite_threshold": 0.85,    # Skip alerts on outcomes >= this probability
            "min_alert_severity": 0.30,         # Don't send alerts below this severity
            "low_activity_max_trades": 10,      # Wallet with <= this many trades is "low activity"
            "low_activity_max_markets": 3,      # Wallet in <= this many markets is "low activity"
            "large_bet_usd": 1000,              # Bets >= this are "large"
            "whale_bet_usd": 5000,              # Bets >= this are "whale" territory
            "niche_market_volume": 50000,       # Markets with <= this volume are "niche"
            "fresh_wallet_days": 30,            # Wallet < this old is "fresh"
            "longshot_threshold": 0.20,         # Prices <= this are "longshots"
            "favorite_threshold": 0.50,         # Prices >= this are "favorites" (less suspicious)
            # Burner wallet detection
            "burner_wc_tx_minutes": 60,         # wc/tx threshold - wallet created to trade in <= this many minutes = suspicious
            "burner_wc_tx_critical": 15,        # wc/tx critical - under 15 mins is HIGHLY suspicious
            "burner_wallet_age_hours": 24,      # Only check wc/tx for wallets under this age
            "burner_min_markets": 3,            # Burner wallets typically have < this many markets
            "radar_score_threshold": 0.5,       # Minimum "radar score" to alert on
            # *** PERFECT SETUP criteria (from Polysights) ***
            "perfect_wallet_age_hours": 24,     # Wallet age under 1 day
            "perfect_max_markets": 3,           # Less than 3 total markets
            "perfect_min_size_usd": 10000,      # Size over $10k
            "perfect_min_radar": 0.5,           # Radar score above 50%
            "perfect_max_wc_tx_pct": 20,        # wc/tx under 20% (time from creation to first trade as % of wallet age)
            "perfect_max_trade_age_hours": 5,   # Less than 5 hours since the trade
        }
        
        # Sports-related keywords (deprioritize these markets)
        self.sports_keywords = [
            # Patterns
            "win on 20", "vs", "versus", "match", "game", "score",
            "spread:", "spread ", "moneyline", "over/under", "o/u",
            "playoffs", "playoff", "finals", "championship", "championship",
            "season", "regular season", "postseason",
            # Leagues
            "nba", "nfl", "mlb", "nhl", "ufc", "mls", "wnba",
            "premier league", "la liga", "bundesliga", "serie a", "ligue 1",
            "champions league", "europa league", "world cup", "euro 20",
            "super bowl", "world series", "stanley cup", "march madness",
            "ncaa", "college football", "college basketball",
            # Sports
            "boxing", "fight", "tennis", "golf", "f1", "formula 1",
            "grand prix", "racing", "nascar", "olympics", "medal",
            "basketball", "football", "soccer", "baseball", "hockey",
            "cricket", "rugby", "mma", "ufc",
            # Team name patterns (common suffixes)
            "lakers", "celtics", "warriors", "bulls", "heat", "knicks",
            "knights", "kings", "chiefs", "eagles", "cowboys", "patriots",
            "yankees", "dodgers", "red sox", "cubs", "braves",
            "maple leafs", "bruins", "rangers", "penguins", "oilers", "steelers",
            "ravens", "bucks",
            # Generic team words
            "fc ", " fc", "united", "city fc", "real madrid", "barcelona",
            "manchester", "liverpool", "chelsea", "arsenal", "tottenham"
        ]
        
        # Crypto/price keywords (deprioritize - public information)
        self.crypto_keywords = [
            "bitcoin", "btc", "ethereum", "eth", "solana", "sol",
            "crypto", "doge", "dogecoin", "xrp", "ripple",
            "price of", "reach $", "dip to $", "drop to $", "hit $",
            "above $", "below $", "between $", "under $", "over $",
            "all-time high", "ath", "market cap"
        ]
        
        # High-value keywords (prioritize these - more likely insider edge)
        self.high_value_keywords = [
            # Political figures & events
            "president", "prime minister", "election", "vote", "ballot",
            "resign", "impeach", "indicted", "arrested", "pardon",
            "dies", "dead", "death", "assassination", "assassinated",
            "coup", "overthrow", "exile", "flees", "flee",
            # Specific political names (add more as needed)
            "trump", "biden", "obama", "desantis", "newsom", "haley",
            "putin", "xi", "zelensky", "netanyahu", "maduro", "machado",
            "bolsonaro", "lula", "trudeau", "starmer", "macron", "scholz",
            # Countries with political instability
            "venezuela", "ukraine", "russia", "taiwan", "israel", "gaza",
            "iran", "north korea", "syria", "myanmar",
            # Corporate events
            "ceo", "cfo", "founder", "executive", "board",
            "acquisition", "acquire", "merger", "merge", "ipo",
            "bankrupt", "bankruptcy", "layoff", "layoffs",
            "sec ", "ftc ", "doj ", "investigation", "lawsuit", "settle",
            # Corporate names
            "openai", "anthropic", "google", "meta", "facebook", "amazon",
            "apple", "microsoft", "nvidia", "tesla", "spacex", "twitter",
            # Economic/Fed
            "fed ", "federal reserve", "rate cut", "rate hike", "inflation",
            "recession", "gdp", "jobs report", "unemployment",
            # Legal
            "verdict", "guilty", "not guilty", "sentenced", "trial",
            "supreme court", "ruling", "overturn",
            # Geopolitical
            "war", "invasion", "invade", "sanctions", "treaty",
            "nato", "ceasefire", "peace deal", "nuclear"
        ]
    
    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def _init_db(self):
        with self._get_conn() as conn:
            conn.executescript("""
                -- All trades we've seen
                CREATE TABLE IF NOT EXISTS trades (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wallet TEXT NOT NULL,
                    side TEXT NOT NULL,
                    size REAL NOT NULL,
                    price REAL NOT NULL,
                    usdc_size REAL,
                    timestamp INTEGER NOT NULL,
                    market_id TEXT NOT NULL,
                    market_title TEXT,
                    outcome TEXT,
                    pseudonym TEXT,
                    tx_hash TEXT UNIQUE,
                    fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX IF NOT EXISTS idx_trades_wallet ON trades(wallet);
                CREATE INDEX IF NOT EXISTS idx_trades_market ON trades(market_id);
                CREATE INDEX IF NOT EXISTS idx_trades_time ON trades(timestamp DESC);
                
                -- Wallet profiles (computed periodically)
                CREATE TABLE IF NOT EXISTS wallet_profiles (
                    wallet TEXT PRIMARY KEY,
                    total_trades INTEGER,
                    unique_markets INTEGER,
                    total_volume_usd REAL,
                    first_seen INTEGER,
                    last_seen INTEGER,
                    avg_trade_size REAL,
                    max_trade_size REAL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Alerts
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity REAL NOT NULL,
                    wallet TEXT NOT NULL,
                    market_id TEXT,
                    market_title TEXT,
                    trade_size REAL,
                    trade_price REAL,
                    reason TEXT,
                    tx_hash TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    dismissed INTEGER DEFAULT 0
                );
                
                CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity DESC);
                
                -- Market metadata
                CREATE TABLE IF NOT EXISTS markets (
                    market_id TEXT PRIMARY KEY,
                    title TEXT,
                    volume REAL,
                    liquidity REAL,
                    category TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
    
    def _load_alerted_tx_hashes(self):
        """Load tx_hashes of recent alerts from database to prevent duplicates"""
        with self._get_conn() as conn:
            # Load alerts from the last 24 hours
            rows = conn.execute("""
                SELECT DISTINCT tx_hash FROM alerts
                WHERE timestamp > datetime('now', '-24 hours')
                AND tx_hash IS NOT NULL
            """).fetchall()
            self._alerted_tx_hashes = {row[0] for row in rows}
            print(f"Loaded {len(self._alerted_tx_hashes)} alerted tx_hashes from database")
    
    def fetch_recent_trades(self, limit: int = 100, market_id: str = None) -> List[Trade]:
        """Fetch recent trades from Polymarket Data API"""
        params = {
            "limit": limit,
            "takerOnly": "true"
        }
        if market_id:
            params["market"] = market_id
            
        try:
            resp = requests.get(f"{self.data_api}/trades", params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            trades = []
            for t in data:
                # Calculate USDC size if not provided
                usdc_size = t.get("usdcSize") or (t.get("size", 0) * t.get("price", 0))
                
                trades.append(Trade(
                    wallet=t.get("proxyWallet", ""),
                    side=t.get("side", ""),
                    size=float(t.get("size", 0)),
                    price=float(t.get("price", 0)),
                    usdc_size=float(usdc_size),
                    timestamp=int(t.get("timestamp", 0)),
                    market_id=t.get("conditionId", ""),
                    market_title=t.get("title", ""),
                    outcome=t.get("outcome", ""),
                    pseudonym=t.get("pseudonym", ""),
                    tx_hash=t.get("transactionHash", "")
                ))
            return trades
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching trades: {e}")
            return []
    
    def fetch_wallet_activity(self, wallet: str, limit: int = 100) -> List[Trade]:
        """Fetch trade history for a specific wallet"""
        params = {
            "user": wallet,
            "limit": limit
        }
        
        try:
            resp = requests.get(f"{self.data_api}/activity", params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            trades = []
            for t in data:
                if t.get("type") != "TRADE":
                    continue
                    
                trades.append(Trade(
                    wallet=t.get("proxyWallet", wallet),
                    side=t.get("side", ""),
                    size=float(t.get("size", 0)),
                    price=float(t.get("price", 0)),
                    usdc_size=float(t.get("usdcSize", 0)),
                    timestamp=int(t.get("timestamp", 0)),
                    market_id=t.get("conditionId", ""),
                    market_title=t.get("title", ""),
                    outcome=t.get("outcome", ""),
                    pseudonym=t.get("pseudonym", ""),
                    tx_hash=t.get("transactionHash", "")
                ))
            return trades
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching wallet activity: {e}")
            return []
    
    def save_trades(self, trades: List[Trade]) -> int:
        """Save trades to database, returns count of new trades"""
        new_count = 0
        with self._get_conn() as conn:
            for t in trades:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO trades 
                        (wallet, side, size, price, usdc_size, timestamp, market_id, 
                         market_title, outcome, pseudonym, tx_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (t.wallet, t.side, t.size, t.price, t.usdc_size, t.timestamp,
                          t.market_id, t.market_title, t.outcome, t.pseudonym, t.tx_hash))
                    if conn.total_changes > 0:
                        new_count += 1
                except sqlite3.IntegrityError:
                    pass  # Duplicate tx_hash
            conn.commit()
        return new_count
    
    def fetch_wallet_creation_time(self, wallet: str) -> Optional[datetime]:
        """
        Fetch wallet's first transaction time from Polygonscan API.
        This gives us the actual on-chain wallet creation/first activity time.
        """
        # Check cache first
        if wallet in self._wallet_creation_cache:
            return self._wallet_creation_cache[wallet]
        
        if not self.polygonscan_api_key:
            return None
        
        try:
            # Get the first transaction for this wallet (sorted ascending by block)
            params = {
                "module": "account",
                "action": "txlist",
                "address": wallet,
                "startblock": 0,
                "endblock": 99999999,
                "page": 1,
                "offset": 1,  # Only need the first tx
                "sort": "asc",  # Oldest first
                "apikey": self.polygonscan_api_key
            }
            
            resp = requests.get(self.polygonscan_api, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("status") == "1" and data.get("result"):
                first_tx = data["result"][0]
                timestamp = int(first_tx.get("timeStamp", 0))
                if timestamp > 0:
                    creation_time = datetime.fromtimestamp(timestamp)
                    self._wallet_creation_cache[wallet] = creation_time
                    return creation_time
            
            # No transactions found - wallet might be brand new
            self._wallet_creation_cache[wallet] = None
            return None
            
        except requests.exceptions.RequestException as e:
            print(f"Polygonscan API error for {wallet[:10]}...: {e}")
            return None
        except (KeyError, ValueError, IndexError) as e:
            print(f"Error parsing Polygonscan response: {e}")
            return None
    
    def fetch_market_info(self, condition_id: str) -> Dict[str, Optional[str]]:
        """
        Fetch market info (image, slug, event slug) from Polymarket Gamma API.
        Returns dict with 'image', 'slug', 'event_slug' keys.
        """
        # Check cache first
        if condition_id in self._market_image_cache:
            return self._market_image_cache[condition_id]
        
        result = {"image": None, "slug": None, "event_slug": None}
        
        try:
            # Query Gamma API for market by condition ID
            params = {"condition_id": condition_id}
            resp = requests.get(f"{self.gamma_api}/markets", params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            
            if data and len(data) > 0:
                market = data[0]
                # Get image - try market image first, fall back to icon
                result["image"] = market.get("image") or market.get("icon")
                # Get slugs for URL building
                result["slug"] = market.get("slug")
                result["event_slug"] = market.get("event_slug") or market.get("groupItemTitle")
                
            self._market_image_cache[condition_id] = result
            return result
            
        except requests.exceptions.RequestException as e:
            print(f"Gamma API error for market {condition_id[:10]}...: {e}")
            self._market_image_cache[condition_id] = result
            return result
        except (KeyError, ValueError, IndexError) as e:
            print(f"Error parsing Gamma response: {e}")
            self._market_image_cache[condition_id] = result
            return result
    
    def fetch_market_image(self, condition_id: str) -> Optional[str]:
        """
        Fetch market image URL from Polymarket Gamma API.
        Returns the image URL or None if not found.
        (Wrapper for backwards compatibility)
        """
        info = self.fetch_market_info(condition_id)
        return info.get("image")
    
    def get_market_url(self, condition_id: str) -> Optional[str]:
        """
        Get the Polymarket URL for a market.
        Returns URL like https://polymarket.com/event/slug
        """
        info = self.fetch_market_info(condition_id)
        event_slug = info.get("event_slug")
        if event_slug:
            return f"https://polymarket.com/event/{event_slug}"
        return None
    
    def get_wallet_profile(self, wallet: str, force_refresh: bool = False) -> Optional[WalletProfile]:
        """Get or compute wallet profile"""
        with self._get_conn() as conn:
            # Check cache first
            if not force_refresh:
                cached = conn.execute("""
                    SELECT * FROM wallet_profiles 
                    WHERE wallet = ? AND updated_at > datetime('now', '-1 hour')
                """, (wallet,)).fetchone()
                
                if cached:
                    # Check if wc_tx_minutes column exists (for backwards compatibility)
                    try:
                        wc_tx_min = cached["wc_tx_minutes"]
                    except (IndexError, KeyError):
                        wc_tx_min = None
                    
                    return WalletProfile(
                        wallet=cached["wallet"],
                        total_trades=cached["total_trades"],
                        unique_markets=cached["unique_markets"],
                        total_volume_usd=cached["total_volume_usd"],
                        first_seen=datetime.fromtimestamp(cached["first_seen"]),
                        last_seen=datetime.fromtimestamp(cached["last_seen"]),
                        avg_trade_size=cached["avg_trade_size"],
                        max_trade_size=cached["max_trade_size"],
                        win_rate=None,
                        wc_tx_minutes=wc_tx_min
                    )
            
            # Compute from trades in DB
            stats = conn.execute("""
                SELECT 
                    COUNT(*) as total_trades,
                    COUNT(DISTINCT market_id) as unique_markets,
                    SUM(usdc_size) as total_volume,
                    MIN(timestamp) as first_seen,
                    MAX(timestamp) as last_seen,
                    AVG(usdc_size) as avg_size,
                    MAX(usdc_size) as max_size
                FROM trades
                WHERE wallet = ?
            """, (wallet,)).fetchone()
            
            if not stats or stats["total_trades"] == 0:
                # Fetch from API if we don't have data
                activity = self.fetch_wallet_activity(wallet, limit=100)
                if activity:
                    self.save_trades(activity)
                    # Recurse to get computed stats
                    return self.get_wallet_profile(wallet, force_refresh=True)
                return None
            
            first_seen_dt = datetime.fromtimestamp(stats["first_seen"])
            last_seen_dt = datetime.fromtimestamp(stats["last_seen"])
            
            # Calculate wc/tx (wallet creation to first transaction)
            # Use Polygonscan API to get actual wallet creation time
            wc_tx_minutes = None
            
            wallet_creation_time = self.fetch_wallet_creation_time(wallet)
            
            if wallet_creation_time:
                # We have actual on-chain creation time
                # wc/tx = time from wallet creation to first Polymarket trade
                time_diff = first_seen_dt - wallet_creation_time
                wc_tx_minutes = max(0, time_diff.total_seconds() / 60.0)
                
                # If wc/tx is negative (shouldn't happen) or very large, cap it
                if wc_tx_minutes > 10080:  # Cap at 1 week
                    wc_tx_minutes = 10080.0
            else:
                # Fallback: estimate based on trading pattern for fresh wallets
                wallet_age_hours = (datetime.now() - first_seen_dt).total_seconds() / 3600
                if wallet_age_hours <= self.thresholds["burner_wallet_age_hours"]:
                    if stats["total_trades"] <= 2:
                        # Very few trades on a fresh wallet - assume fast wc/tx (suspicious)
                        wc_tx_minutes = 30.0  # Conservative estimate
                    else:
                        # Get time gap between first two trades as proxy
                        first_trades = conn.execute("""
                            SELECT timestamp FROM trades 
                            WHERE wallet = ? 
                            ORDER BY timestamp ASC 
                            LIMIT 2
                        """, (wallet,)).fetchall()
                        
                        if len(first_trades) >= 2:
                            gap_seconds = first_trades[1]["timestamp"] - first_trades[0]["timestamp"]
                            wc_tx_minutes = gap_seconds / 60.0
                        else:
                            wc_tx_minutes = 60.0  # Default estimate
            
            profile = WalletProfile(
                wallet=wallet,
                total_trades=stats["total_trades"],
                unique_markets=stats["unique_markets"],
                total_volume_usd=stats["total_volume"] or 0,
                first_seen=first_seen_dt,
                last_seen=last_seen_dt,
                avg_trade_size=stats["avg_size"] or 0,
                max_trade_size=stats["max_size"] or 0,
                win_rate=None,
                wc_tx_minutes=wc_tx_minutes
            )
            
            # Cache it
            conn.execute("""
                INSERT OR REPLACE INTO wallet_profiles
                (wallet, total_trades, unique_markets, total_volume_usd, 
                 first_seen, last_seen, avg_trade_size, max_trade_size, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (wallet, profile.total_trades, profile.unique_markets,
                  profile.total_volume_usd, int(profile.first_seen.timestamp()),
                  int(profile.last_seen.timestamp()), profile.avg_trade_size,
                  profile.max_trade_size))
            conn.commit()
            
            return profile
    
    def classify_market(self, title: str) -> Dict:
        """Classify a market by type and calculate priority multiplier"""
        title_lower = title.lower()
        
        # Check if it's a sports market
        is_sports = any(keyword in title_lower for keyword in self.sports_keywords)
        
        # Check if it's a crypto/price market
        is_crypto = any(keyword in title_lower for keyword in self.crypto_keywords)
        
        # Check if it's a high-value market (politics, corporate, etc)
        is_high_value = any(keyword in title_lower for keyword in self.high_value_keywords)
        
        # Determine category (high-value overrides others)
        if is_high_value and not is_sports:
            category = "HIGH_VALUE"
            priority_multiplier = 1.5  # Boost priority
        elif is_sports:
            category = "SPORTS"
            priority_multiplier = 0.3  # Heavily deprioritize
        elif is_crypto:
            category = "CRYPTO"
            priority_multiplier = 0.4  # Deprioritize (public info)
        else:
            category = "GENERAL"
            priority_multiplier = 1.0
        
        return {
            "category": category,
            "is_sports": is_sports,
            "is_crypto": is_crypto,
            "is_high_value": is_high_value,
            "priority_multiplier": priority_multiplier
        }
    
    def calculate_longshot_multiplier(self, price: float) -> float:
        """
        Calculate severity multiplier based on how much of a longshot the bet is.
        Lower prices = higher multiplier (more suspicious to bet big on longshots)
        """
        if price <= 0.05:
            return 2.5  # Extreme longshot (5% or less)
        elif price <= 0.10:
            return 2.0  # Heavy longshot (10% or less)
        elif price <= self.thresholds["longshot_threshold"]:
            return 1.5  # Longshot (20% or less)
        elif price >= self.thresholds["favorite_threshold"]:
            return 0.5  # Favorite - less suspicious
        else:
            return 1.0  # Middle range
    
    def calculate_radar_score(self, trade: Trade, profile: WalletProfile) -> Dict:
        """
        Calculate "Radar Score" - quantifies anomalous confidence.
        Looking for: new actor with zero history acting with whale conviction.
        
        Returns dict with score (0-1) and component breakdown.
        """
        scores = {}
        
        # 1. Wallet freshness (0-1, fresher = higher)
        wallet_age_hours = (datetime.now() - profile.first_seen).total_seconds() / 3600
        if wallet_age_hours <= 1:
            scores["freshness"] = 1.0
        elif wallet_age_hours <= 24:
            scores["freshness"] = 0.8
        elif wallet_age_hours <= 72:
            scores["freshness"] = 0.5
        elif wallet_age_hours <= 168:  # 1 week
            scores["freshness"] = 0.3
        else:
            scores["freshness"] = 0.1
        
        # 2. Market concentration (0-1, fewer markets = higher)
        if profile.unique_markets <= 1:
            scores["concentration"] = 1.0
        elif profile.unique_markets <= 3:
            scores["concentration"] = 0.8
        elif profile.unique_markets <= 5:
            scores["concentration"] = 0.5
        else:
            scores["concentration"] = 0.2
        
        # 3. Trade conviction (0-1, larger relative to history = higher)
        if profile.avg_trade_size > 0:
            size_ratio = trade.usdc_size / profile.avg_trade_size
            if size_ratio >= 10:
                scores["conviction"] = 1.0
            elif size_ratio >= 5:
                scores["conviction"] = 0.8
            elif size_ratio >= 2:
                scores["conviction"] = 0.5
            else:
                scores["conviction"] = 0.3
        else:
            # No history - if this is a big trade, high conviction
            scores["conviction"] = min(1.0, trade.usdc_size / 5000)
        
        # 4. wc/tx score (0-1, faster = higher) - THE SMOKING GUN
        if profile.wc_tx_minutes is not None:
            if profile.wc_tx_minutes <= 15:
                scores["wc_tx"] = 1.0  # Critical - almost certainly a burner
            elif profile.wc_tx_minutes <= 60:
                scores["wc_tx"] = 0.8
            elif profile.wc_tx_minutes <= 240:  # 4 hours
                scores["wc_tx"] = 0.5
            else:
                scores["wc_tx"] = 0.2
        else:
            scores["wc_tx"] = 0.3  # Unknown, neutral
        
        # 5. Absolute size score (0-1, bigger = higher)
        if trade.usdc_size >= 10000:
            scores["size"] = 1.0
        elif trade.usdc_size >= 5000:
            scores["size"] = 0.7
        elif trade.usdc_size >= 2000:
            scores["size"] = 0.5
        elif trade.usdc_size >= 1000:
            scores["size"] = 0.3
        else:
            scores["size"] = 0.1
        
        # Weighted average (wc/tx weighted heavily as it's the smoking gun)
        weights = {
            "freshness": 0.15,
            "concentration": 0.15,
            "conviction": 0.15,
            "wc_tx": 0.35,  # Heavily weighted - this is the key signal
            "size": 0.20
        }
        
        radar_score = sum(scores[k] * weights[k] for k in scores)
        
        return {
            "score": radar_score,
            "components": scores,
            "weights": weights
        }
    
    def analyze_trade(self, trade: Trade) -> Optional[Alert]:
        """Analyze a single trade for suspicious patterns"""
        
        # *** EARLY FILTER 1: Skip small notionals ***
        if trade.usdc_size < self.thresholds["min_notional_usd"]:
            return None
        
        # *** EARLY FILTER 2: Skip high favourites (>85% probability) ***
        # Betting on near-certainties isn't insider trading, just rational behavior
        if trade.price >= self.thresholds["high_favorite_threshold"]:
            return None
        
        # Get wallet profile
        profile = self.get_wallet_profile(trade.wallet)
        
        if not profile:
            # Can't analyze without profile - might want to flag anyway
            return None
        
        # Classify the market
        market_info = self.classify_market(trade.market_title)
        
        # *** EARLY FILTER 3: Skip SPORTS and CRYPTO markets entirely ***
        if market_info["category"] in ["SPORTS", "CRYPTO"]:
            return None
        
        # Calculate radar score (the new smoking gun metric)
        radar = self.calculate_radar_score(trade, profile)
        radar_score = radar["score"]
        
        # Calculate longshot multiplier
        longshot_mult = self.calculate_longshot_multiplier(trade.price)
        
        # Combined multiplier
        combined_multiplier = market_info["priority_multiplier"] * longshot_mult
        
        # Calculate trade age (how long ago was this trade?)
        trade_time = datetime.fromtimestamp(trade.timestamp)
        trade_age_hours = (datetime.now() - trade_time).total_seconds() / 3600
        
        # Calculate wallet age
        wallet_age_hours = (datetime.now() - profile.first_seen).total_seconds() / 3600
        
        # *** PERFECT SETUP CHECK (highest priority) ***
        # All criteria from Polysights must be met:
        # - Wallet age under 1 day
        # - Less than 3 total markets
        # - Size over $10k
        # - Radar score above 50%
        # - wc/tx under 20% (time from wallet creation to first trade as % of wallet age)
        # - Less than 5 hours since the trade
        
        # Calculate wc/tx as percentage of wallet age
        wallet_age_minutes = wallet_age_hours * 60
        wc_tx_pct = None
        if profile.wc_tx_minutes is not None and wallet_age_minutes > 0:
            wc_tx_pct = (profile.wc_tx_minutes / wallet_age_minutes) * 100
        
        is_perfect_wallet_age = wallet_age_hours < self.thresholds["perfect_wallet_age_hours"]
        is_perfect_markets = profile.unique_markets < self.thresholds["perfect_max_markets"]
        is_perfect_size = trade.usdc_size >= self.thresholds["perfect_min_size_usd"]
        is_perfect_radar = radar_score >= self.thresholds["perfect_min_radar"]
        is_perfect_wc_tx = (wc_tx_pct is not None and 
                           wc_tx_pct < self.thresholds["perfect_max_wc_tx_pct"])
        is_perfect_trade_age = trade_age_hours < self.thresholds["perfect_max_trade_age_hours"]
        
        if (is_perfect_wallet_age and is_perfect_markets and is_perfect_size and 
            is_perfect_radar and is_perfect_wc_tx and is_perfect_trade_age):
            # 🚨 PERFECT SETUP - All criteria met!
            # This is the highest confidence insider signal
            severity = min(1.0, radar_score * 1.5 * combined_multiplier)  # Boosted severity
            severity = max(severity, 0.8)  # Floor at 80% for perfect setups
            
            wc_tx_str = f"{profile.wc_tx_minutes:.0f}min ({wc_tx_pct:.1f}%)"
            
            return Alert(
                alert_type="PERFECT_SETUP",
                severity=severity,
                wallet=trade.wallet,
                trade=trade,
                wallet_profile=profile,
                reason=f"[{market_info['category']}] 🚨 PERFECT SETUP: wallet {wallet_age_hours:.1f}h old, {profile.unique_markets} markets, ${trade.usdc_size:,.0f}, wc/tx={wc_tx_str}, radar={radar_score:.0%}, trade {trade_age_hours:.1f}h ago",
                timestamp=datetime.now()
            )
        
        # *** BURNER WALLET CHECK (second priority) ***
        is_fresh_wallet = wallet_age_hours <= self.thresholds["burner_wallet_age_hours"]
        is_low_market_count = profile.unique_markets < self.thresholds["burner_min_markets"]
        has_fast_wc_tx = (profile.wc_tx_minutes is not None and 
                         profile.wc_tx_minutes <= self.thresholds["burner_wc_tx_minutes"])
        has_critical_wc_tx = (profile.wc_tx_minutes is not None and 
                             profile.wc_tx_minutes <= self.thresholds["burner_wc_tx_critical"])
        
        # Burner wallet: fresh + few markets + fast wc/tx + high radar score
        if is_fresh_wallet and is_low_market_count and has_fast_wc_tx:
            if radar_score >= self.thresholds["radar_score_threshold"]:
                # This is the smoking gun pattern
                base_severity = radar_score
                if has_critical_wc_tx:
                    base_severity = min(1.0, base_severity * 1.5)  # Boost for <15min wc/tx
                
                severity = min(1.0, base_severity * combined_multiplier)
                
                wc_tx_str = f"{profile.wc_tx_minutes:.0f}min" if profile.wc_tx_minutes else "unknown"
                
                return Alert(
                    alert_type="BURNER_WALLET",
                    severity=severity,
                    wallet=trade.wallet,
                    trade=trade,
                    wallet_profile=profile,
                    reason=f"[{market_info['category']}] 🔥 BURNER WALLET: {wallet_age_hours:.1f}h old, {profile.unique_markets} markets, wc/tx={wc_tx_str}, radar={radar_score:.0%}, ${trade.usdc_size:.0f} @ {trade.price*100:.1f}¢",
                    timestamp=datetime.now()
                )
        
        # Check 1: Low activity wallet + large bet
        is_low_activity = (
            profile.total_trades <= self.thresholds["low_activity_max_trades"] or
            profile.unique_markets <= self.thresholds["low_activity_max_markets"]
        )
        is_large_bet = trade.usdc_size >= self.thresholds["large_bet_usd"]
        
        if is_low_activity and is_large_bet:
            base_severity = min(1.0, trade.usdc_size / self.thresholds["whale_bet_usd"])
            # Incorporate radar score
            base_severity = (base_severity + radar_score) / 2
            severity = min(1.0, base_severity * combined_multiplier)
            
            # Skip if severity too low after multipliers (likely sports bet on favorite)
            if severity < 0.25:
                return None
            
            return Alert(
                alert_type="LOW_ACTIVITY_LARGE_BET",
                severity=severity,
                wallet=trade.wallet,
                trade=trade,
                wallet_profile=profile,
                reason=f"[{market_info['category']}] Low activity wallet ({profile.total_trades} trades, {profile.unique_markets} markets) placed ${trade.usdc_size:.0f} bet @ {trade.price*100:.1f}¢ | radar={radar_score:.0%}",
                timestamp=datetime.now()
            )
        
        # Check 2: Fresh wallet + any significant bet
        is_fresh = wallet_age_hours <= self.thresholds["fresh_wallet_days"] * 24
        
        if is_fresh and trade.usdc_size >= self.thresholds["large_bet_usd"] / 2:
            wallet_age_days = wallet_age_hours / 24
            base_severity = min(1.0, (trade.usdc_size / self.thresholds["large_bet_usd"]) * 
                          (1 - wallet_age_days / self.thresholds["fresh_wallet_days"]))
            # Incorporate radar score
            base_severity = (base_severity + radar_score) / 2
            severity = min(1.0, base_severity * combined_multiplier)
            
            # Skip if severity too low after multipliers
            if severity < 0.25:
                return None
            
            return Alert(
                alert_type="FRESH_WALLET_BET",
                severity=severity,
                wallet=trade.wallet,
                trade=trade,
                wallet_profile=profile,
                reason=f"[{market_info['category']}] Fresh wallet ({wallet_age_days:.1f} days old) placed ${trade.usdc_size:.0f} bet @ {trade.price*100:.1f}¢ | radar={radar_score:.0%}",
                timestamp=datetime.now()
            )
        
        # Check 3: Unusual size relative to wallet history
        if profile.avg_trade_size > 0:
            size_multiple = trade.usdc_size / profile.avg_trade_size
            if size_multiple >= 5 and trade.usdc_size >= self.thresholds["large_bet_usd"]:
                base_severity = min(1.0, size_multiple / 10)
                # Incorporate radar score
                base_severity = (base_severity + radar_score) / 2
                severity = min(1.0, base_severity * combined_multiplier)
                
                # Skip if severity too low after multipliers
                if severity < 0.25:
                    return None
                
                return Alert(
                    alert_type="UNUSUAL_SIZE",
                    severity=severity,
                    wallet=trade.wallet,
                    trade=trade,
                    wallet_profile=profile,
                    reason=f"[{market_info['category']}] Trade {size_multiple:.1f}x larger than wallet average (${trade.usdc_size:.0f} vs ${profile.avg_trade_size:.0f} avg) @ {trade.price*100:.1f}¢ | radar={radar_score:.0%}",
                    timestamp=datetime.now()
                )
        
        # Check 4: High radar score alone (even if doesn't fit other patterns)
        if radar_score >= 0.7 and trade.usdc_size >= self.thresholds["whale_bet_usd"]:
            severity = min(1.0, radar_score * combined_multiplier)
            
            if severity >= 0.4:
                return Alert(
                    alert_type="HIGH_RADAR_SCORE",
                    severity=severity,
                    wallet=trade.wallet,
                    trade=trade,
                    wallet_profile=profile,
                    reason=f"[{market_info['category']}] High anomaly score: radar={radar_score:.0%}, ${trade.usdc_size:.0f} @ {trade.price*100:.1f}¢ | wc/tx={profile.wc_tx_minutes:.0f}min" if profile.wc_tx_minutes else f"[{market_info['category']}] High anomaly score: radar={radar_score:.0%}, ${trade.usdc_size:.0f} @ {trade.price*100:.1f}¢",
                    timestamp=datetime.now()
                )
        
        return None
    
    def save_alert(self, alert: Alert):
        """Save an alert to the database"""
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO alerts 
                (alert_type, severity, wallet, market_id, market_title, 
                 trade_size, trade_price, reason, tx_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (alert.alert_type, alert.severity, alert.wallet,
                  alert.trade.market_id, alert.trade.market_title,
                  alert.trade.usdc_size, alert.trade.price, alert.reason,
                  alert.trade.tx_hash))
            conn.commit()
    
    def get_recent_alerts(self, hours: int = 24, min_severity: float = 0.3) -> List[Dict]:
        """Get recent alerts above severity threshold"""
        with self._get_conn() as conn:
            rows = conn.execute("""
                SELECT * FROM alerts
                WHERE timestamp > datetime('now', ?)
                AND severity >= ?
                AND dismissed = 0
                ORDER BY severity DESC, timestamp DESC
            """, (f'-{hours} hours', min_severity)).fetchall()
            return [dict(row) for row in rows]
    
    def scan_and_alert(self, limit: int = 100, send_discord: bool = True) -> List[Alert]:
        """Main loop: fetch trades, analyze, generate alerts"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Fetching recent trades...")
        trades = self.fetch_recent_trades(limit=limit)
        
        if not trades:
            print("No trades fetched")
            return []
        
        new_count = self.save_trades(trades)
        print(f"Fetched {len(trades)} trades ({new_count} new)")
        
        alerts = []
        skipped_duplicates = 0
        for trade in trades:
            # *** DEDUPLICATION: Skip if we've already alerted on this transaction ***
            if trade.tx_hash in self._alerted_tx_hashes:
                skipped_duplicates += 1
                continue
            
            alert = self.analyze_trade(trade)
            if alert:
                # Check minimum severity threshold before saving/sending
                if alert.severity < self.thresholds["min_alert_severity"]:
                    continue  # Skip low-severity alerts entirely
                
                # Mark this tx_hash as alerted
                self._alerted_tx_hashes.add(trade.tx_hash)
                
                self.save_alert(alert)
                alerts.append(alert)
                
                # Send to Discord
                if send_discord and self.discord_webhook:
                    if self.send_discord_alert(alert):
                        print(f"📤 Sent alert to Discord: {alert.alert_type} (severity: {alert.severity:.0%})")
        
        if skipped_duplicates > 0:
            print(f"Skipped {skipped_duplicates} already-alerted transactions")
        
        return alerts
    
    def format_alert(self, alert: Alert) -> str:
        """Format alert for display (like the Discord bot)"""
        # Classify market for emoji
        market_info = self.classify_market(alert.trade.market_title)
        
        if market_info["category"] == "HIGH_VALUE":
            emoji = "🔥"
        elif market_info["category"] == "SPORTS":
            emoji = "⚽"
        else:
            emoji = "🌱" if alert.alert_type in ["LOW_ACTIVITY_LARGE_BET", "FRESH_WALLET_BET"] else "🐋"
        
        # Longshot indicator
        if alert.trade.price <= 0.10:
            price_tag = "🎯 LONGSHOT"
        elif alert.trade.price <= 0.20:
            price_tag = "📉 Low odds"
        elif alert.trade.price >= 0.80:
            price_tag = "📈 Heavy favorite"
        else:
            price_tag = ""
        
        lines = [
            f"{emoji} **{alert.alert_type.replace('_', ' ')}** [{market_info['category']}]",
            f"",
            f"**{alert.trade.market_title}**",
            f"Outcome: {alert.trade.outcome} {price_tag}",
            f"",
            f"Trader: {alert.trade.pseudonym or alert.wallet[:10] + '...' + alert.wallet[-6:]}",
            f"Side: {alert.trade.side}",
            f"Trade: {alert.trade.size:,.0f} shares @ {alert.trade.price*100:.1f}¢",
            f"",
            f"Notional: ${alert.trade.usdc_size:,.0f}",
            f"Unique markets (lifetime): {alert.wallet_profile.unique_markets}",
            f"Win Rate: n/a",
            f"",
            f"Severity: {alert.severity:.0%}",
            f"Reason: {alert.reason}"
        ]
        return "\n".join(lines)
    
    def format_discord_embed(self, alert: Alert) -> Dict:
        """Format alert as a Discord embed"""
        market_info = self.classify_market(alert.trade.market_title)
        
        # Calculate radar score for display
        radar = self.calculate_radar_score(alert.trade, alert.wallet_profile)
        
        # Color based on severity and type
        if alert.alert_type == "PERFECT_SETUP":
            color = 0x9400D3  # Purple for perfect setup
        elif alert.severity >= 0.8:
            color = 0xFF0000  # Red
        elif alert.severity >= 0.5:
            color = 0xFFA500  # Orange
        else:
            color = 0xFFFF00  # Yellow
        
        # Special color for burner wallets
        if alert.alert_type == "BURNER_WALLET":
            color = 0xFF0000  # Always red for burners
        
        # Category emoji
        if alert.alert_type == "PERFECT_SETUP":
            category_emoji = "🚨"
        elif alert.alert_type == "BURNER_WALLET":
            category_emoji = "🔥"
        elif market_info["category"] == "HIGH_VALUE":
            category_emoji = "🎯"
        elif market_info["category"] == "SPORTS":
            category_emoji = "⚽"
        elif market_info["category"] == "CRYPTO":
            category_emoji = "🪙"
        else:
            category_emoji = "🌱"
        
        # Longshot tag
        if alert.trade.price <= 0.10:
            price_tag = "🎯 LONGSHOT"
        elif alert.trade.price <= 0.20:
            price_tag = "📉 Low odds"
        elif alert.trade.price >= 0.80:
            price_tag = "📈 Heavy favorite"
        else:
            price_tag = ""
        
        # wc/tx display
        wc_tx_display = f"{alert.wallet_profile.wc_tx_minutes:.0f}min" if alert.wallet_profile.wc_tx_minutes else "n/a"
        
        # Wallet age display
        wallet_age_hours = (datetime.now() - alert.wallet_profile.first_seen).total_seconds() / 3600
        if wallet_age_hours < 24:
            age_display = f"{wallet_age_hours:.1f}h"
        else:
            age_display = f"{wallet_age_hours/24:.1f}d"
        
        # Build embed
        embed = {
            "title": f"{category_emoji} {alert.alert_type.replace('_', ' ')}",
            "description": f"**{alert.trade.market_title}**\nOutcome: {alert.trade.outcome} {price_tag}",
            "color": color,
            "fields": [
                {
                    "name": "Trader",
                    "value": alert.trade.pseudonym or f"{alert.wallet[:10]}...{alert.wallet[-6:]}",
                    "inline": True
                },
                {
                    "name": "Side",
                    "value": alert.trade.side,
                    "inline": True
                },
                {
                    "name": "Trade",
                    "value": f"{alert.trade.size:,.0f} shares @ {alert.trade.price*100:.1f}¢",
                    "inline": True
                },
                {
                    "name": "Notional",
                    "value": f"${alert.trade.usdc_size:,.0f}",
                    "inline": True
                },
                {
                    "name": "Radar Score",
                    "value": f"{radar['score']:.0%}",
                    "inline": True
                },
                {
                    "name": "wc/tx",
                    "value": wc_tx_display,
                    "inline": True
                },
                {
                    "name": "Wallet Age",
                    "value": age_display,
                    "inline": True
                },
                {
                    "name": "Markets",
                    "value": str(alert.wallet_profile.unique_markets),
                    "inline": True
                },
                {
                    "name": "Category",
                    "value": market_info["category"],
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Severity: {alert.severity:.0%} • {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }
        
        # Fetch market info (image + URL) in one call
        market_api_info = self.fetch_market_info(alert.trade.market_id)
        
        # Add market image as thumbnail if available
        if market_api_info.get("image"):
            embed["thumbnail"] = {"url": market_api_info["image"]}
        
        # Add market URL to embed
        market_url = self.get_market_url(alert.trade.market_id)
        if market_url:
            embed["url"] = market_url
        
        return embed
    
    def send_discord_alert(self, alert: Alert) -> bool:
        """Send alert to Discord webhook"""
        if not self.discord_webhook:
            return False
        
        embed = self.format_discord_embed(alert)
        
        payload = {
            "username": "Polymarket Watch",
            "embeds": [embed]
        }
        
        try:
            resp = requests.post(
                self.discord_webhook,
                json=payload,
                timeout=10
            )
            resp.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"Discord webhook error: {e}")
            return False


def main():
    """Run the insider detector"""
    webhook = os.getenv("DISCORD_WEBHOOK_URL")
    polygonscan_key = os.getenv("POLYGONSCAN_API_KEY")
    detector = InsiderDetector(discord_webhook=webhook, polygonscan_api_key=polygonscan_key)
    
    print("=" * 60)
    print("POLYMARKET INSIDER DETECTOR")
    print("=" * 60)
    print(f"Database: {detector.db_path}")
    print(f"Discord: {'✅ Connected' if detector.discord_webhook else '❌ Not configured'}")
    print(f"Polygonscan: {'✅ API Key Set' if detector.polygonscan_api_key else '⚠️  No API key (wc/tx will be estimated)'}")
    print(f"Thresholds: {json.dumps(detector.thresholds, indent=2)}")
    print("=" * 60)
    
    # Single scan mode
    alerts = detector.scan_and_alert(limit=100)
    
    if alerts:
        print(f"\n🚨 {len(alerts)} ALERTS DETECTED:\n")
        for alert in alerts:
            print("-" * 50)
            print(detector.format_alert(alert))
            print()
    else:
        print("\n✅ No suspicious activity detected in this batch")
    
    # Show recent alerts from DB
    recent = detector.get_recent_alerts(hours=24)
    if recent:
        print(f"\n📋 {len(recent)} alerts in last 24 hours")


def monitor_loop(interval: int = 30):
    """Continuous monitoring mode"""
    webhook = os.getenv("DISCORD_WEBHOOK_URL")
    polygonscan_key = os.getenv("POLYGONSCAN_API_KEY")
    detector = InsiderDetector(discord_webhook=webhook, polygonscan_api_key=polygonscan_key)
    
    print("=" * 60)
    print("POLYMARKET INSIDER DETECTOR - MONITOR MODE")
    print(f"Checking every {interval} seconds")
    print(f"Discord: {'✅ Connected' if detector.discord_webhook else '❌ Not configured'}")
    print(f"Polygonscan: {'✅ API Key Set' if detector.polygonscan_api_key else '⚠️  No API key (wc/tx will be estimated)'}")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    try:
        while True:
            alerts = detector.scan_and_alert(limit=50)
            
            for alert in alerts:
                print("\n" + "🚨" * 20)
                print(detector.format_alert(alert))
                print("🚨" * 20 + "\n")
            
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        recent = detector.get_recent_alerts(hours=1)
        print(f"Alerts in last hour: {len(recent)}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "monitor":
        interval = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        monitor_loop(interval)
    else:
        main()