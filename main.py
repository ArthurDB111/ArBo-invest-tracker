from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import os
import re
from datetime import datetime, timedelta
from typing import Optional
import httpx
from collections import defaultdict
import time

app = FastAPI(title="ArBo Portfolio Tracker — Price API")

# ── In-memory rate limiter ───────────────────────────────────────────
_rate_store: dict = defaultdict(list)

def rate_limit(request: Request, max_calls: int = 60, window: int = 60):
    """Max max_calls verzoeken per window seconden per IP."""
    ip = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    if not ip:
        ip = request.client.host if request.client else "unknown"
    now = time.time()
    if len(_rate_store) > 10000:
        cutoff = now - window
        dead = [k for k, v in _rate_store.items() if not v or max(v) < cutoff]
        for k in dead:
            del _rate_store[k]
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < window]
    if len(_rate_store[ip]) >= max_calls:
        raise HTTPException(status_code=429, detail="Te veel verzoeken — even wachten")
    _rate_store[ip].append(now)

# ── Ticker validatie ────────────────────────────────────────────────
TICKER_RE = re.compile(r'^[A-Z0-9.\-]{1,20}$')

def validate_ticker(ticker: str) -> str:
    t = ticker.upper().strip()
    if not TICKER_RE.match(t):
        raise HTTPException(status_code=400, detail=f"Ongeldige ticker: {ticker}")
    return t

# ── CORS ─────────────────────────────────────────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Security headers ─────────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ── Config ────────────────────────────────────────────────────────────
FMP_KEY = os.getenv("FMP_API_KEY", "")

_YF_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json",
}


# ══════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

@app.get("/")
def root():
    return {"status": "ok", "service": "ArBo Price API"}


@app.get("/price/{ticker}")
async def get_price(ticker: str, request: Request):
    rate_limit(request)
    ticker = validate_ticker(ticker)
    result = await _fetch_price_fmp(ticker)
    if not result:
        result = _fetch_price_yahoo(ticker)
    if not result:
        raise HTTPException(status_code=404, detail=f"Koers niet gevonden voor {ticker}")
    return result


@app.post("/prices")
async def get_prices(body: dict, request: Request):
    rate_limit(request, max_calls=30, window=60)
    raw_tickers = body.get("tickers", [])
    if not raw_tickers or not isinstance(raw_tickers, list):
        return {}
    tickers = [
        t.upper().strip() for t in raw_tickers[:50]
        if isinstance(t, str) and TICKER_RE.match(t.upper().strip())
    ]
    results: dict = {}

    # FMP batch (sneller dan losse calls)
    if FMP_KEY and tickers:
        results.update(await _fetch_prices_fmp_batch(tickers))

    # Yahoo Finance fallback voor ontbrekende tickers
    for ticker in [t for t in tickers if t not in results]:
        data = _fetch_price_yahoo(ticker)
        if data:
            results[ticker] = data

    return results


@app.get("/history/{ticker}")
async def get_history(
    ticker: str,
    period: str = "1y",
    interval: str = "1d",
    request: Request = None,
):
    if request:
        rate_limit(request, max_calls=30, window=60)
    ticker = validate_ticker(ticker)
    allowed_periods = {"1d","5d","1mo","3mo","6mo","1y","2y","5y","10y","ytd","max"}
    if period not in allowed_periods:
        period = "1y"
    result = await _fetch_history_fmp(ticker, period, interval)
    if not result:
        result = _fetch_history_yahoo(ticker, period, interval)
    if not result:
        raise HTTPException(status_code=404, detail=f"Historische data niet gevonden voor {ticker}")
    return result


@app.get("/search")
async def search_ticker(q: str, request: Request = None):
    if request:
        rate_limit(request, max_calls=20, window=60)
    q = re.sub(r'[^a-zA-Z0-9 .&-]', '', q).strip()[:50]
    if not q:
        return []
    if not FMP_KEY:
        raise HTTPException(status_code=503, detail="FMP API key niet ingesteld")

    results = []
    urls_to_try = [
        f"https://financialmodelingprep.com/stable/search-name?query={q}&limit=20&apikey={FMP_KEY}",
        f"https://financialmodelingprep.com/stable/search-symbol?query={q}&limit=20&apikey={FMP_KEY}",
        f"https://financialmodelingprep.com/api/v3/search?query={q}&limit=20&apikey={FMP_KEY}",
    ]

    async with httpx.AsyncClient(timeout=15) as client:
        for url in urls_to_try:
            try:
                r = await client.get(url)
                if not r.is_success:
                    continue
                data = r.json()
                if isinstance(data, list) and data:
                    results = data
                    break
                if isinstance(data, dict):
                    for key in ("data", "results", "stocks", "list"):
                        if key in data and isinstance(data[key], list) and data[key]:
                            results = data[key]
                            break
                if results:
                    break
            except Exception:
                continue

    if not results:
        return []

    allowed_exchanges = {
        "NASDAQ","NYSE","AMEX","EURONEXT","ENX","XETRA",
        "LSE","AMS","BRU","PAR","CBOE",
    }
    filtered = []
    seen: set = set()
    for item in results:
        sym  = item.get("symbol","") or item.get("ticker","")
        name = item.get("name","") or item.get("companyName","")
        exch = (item.get("exchangeShortName","") or item.get("exchange","")
                or item.get("stockExchange",""))
        if not sym or sym in seen:
            continue
        seen.add(sym)
        if exch.upper() not in allowed_exchanges:
            if any(c.isdigit() for c in sym) or len(sym) > 7:
                continue
        filtered.append({
            "symbol": sym, "name": name,
            "exchange": exch, "exchangeShort": exch,
            "currency": item.get("currency",""),
        })

    return filtered[:15]


# ══════════════════════════════════════════════════════════════════════
# INTERNE HULPFUNCTIES
# ══════════════════════════════════════════════════════════════════════

def _make_price_dict(sym: str, q: dict, source: str) -> Optional[dict]:
    price = q.get("price") or q.get("regularMarketPrice") or q.get("previousClose")
    if not price or float(price) == 0:
        return None
    prev = q.get("previousClose") or price
    chg  = q.get("change") or q.get("regularMarketChange") or 0
    chgP = q.get("changesPercentage") or q.get("regularMarketChangePercent") or 0
    return {
        "ticker":        sym,
        "price":         round(float(price), 4),
        "previousClose": round(float(prev), 4),
        "change":        round(float(chg), 4),
        "changePercent": round(float(chgP), 2),
        "currency":      q.get("currency", "EUR"),
        "source":        source,
        "timestamp":     datetime.utcnow().isoformat(),
        "marketOpen":    q.get("isActivelyTrading", False),
    }


async def _fetch_price_fmp(ticker: str) -> Optional[dict]:
    if not FMP_KEY:
        return None
    candidates = [ticker.upper()]
    t = ticker.upper()
    if "." not in t and "-" not in t:
        candidates += [t + ".AS", t + ".BR"]
    async with httpx.AsyncClient(timeout=10) as client:
        for sym in candidates:
            try:
                r = await client.get(
                    f"https://financialmodelingprep.com/api/v3/quote/{sym}?apikey={FMP_KEY}"
                )
                if not r.is_success:
                    continue
                data = r.json()
                if not isinstance(data, list) or not data:
                    continue
                result = _make_price_dict(sym, data[0], "FMP")
                if result:
                    return result
            except Exception:
                continue
    return None


async def _fetch_prices_fmp_batch(tickers: list) -> dict:
    if not FMP_KEY or not tickers:
        return {}
    results: dict = {}
    try:
        syms = ",".join(tickers[:50])
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://financialmodelingprep.com/api/v3/quote/{syms}?apikey={FMP_KEY}"
            )
        if not r.is_success:
            return {}
        data = r.json()
        if not isinstance(data, list):
            return {}
        for q in data:
            sym = q.get("symbol", "")
            if not sym:
                continue
            result = _make_price_dict(sym, q, "FMP")
            if result:
                results[sym] = result
    except Exception:
        pass
    return results


def _fetch_price_yahoo(ticker: str) -> Optional[dict]:
    t = ticker.upper().strip()
    candidates = [t]
    if "." not in t and "-" not in t and "=" not in t and len(t) <= 6:
        candidates += [t + ".AS", t + ".BR", t + ".DE", t + ".PA", t + ".L"]
    for sym in candidates:
        try:
            resp = httpx.get(
                f"https://query1.finance.yahoo.com/v8/finance/chart/{sym}?interval=1d&range=5d",
                headers=_YF_HEADERS, timeout=15, follow_redirects=True,
            )
            if resp.status_code != 200:
                continue
            chart = resp.json().get("chart", {})
            if chart.get("error") or not chart.get("result"):
                continue
            meta   = chart["result"][0].get("meta", {})
            closes = chart["result"][0].get("indicators", {}).get("quote", [{}])[0].get("close", [])
            price  = meta.get("regularMarketPrice") or meta.get("chartPreviousClose")
            prev   = meta.get("chartPreviousClose") or meta.get("previousClose") or price
            if not price and closes:
                valid = [c for c in closes if c is not None]
                if valid:
                    price = valid[-1]
                    prev  = valid[-2] if len(valid) > 1 else price
            if not price or float(price) == 0:
                continue
            price = round(float(price), 4)
            prev  = round(float(prev or price), 4)
            chg   = round(price - prev, 4)
            chgP  = round((chg / prev * 100) if prev else 0, 2)
            return {
                "ticker":        sym,
                "price":         price,
                "previousClose": prev,
                "change":        chg,
                "changePercent": chgP,
                "currency":      meta.get("currency", "EUR"),
                "source":        "Yahoo Finance",
                "timestamp":     datetime.utcnow().isoformat(),
                "marketOpen":    meta.get("marketState", "") in ("REGULAR", "PRE", "POST"),
            }
        except Exception as e:
            print(f"Yahoo fout voor {sym}: {e}")
    return None


async def _fetch_history_fmp(ticker: str, period: str, interval: str) -> Optional[dict]:
    if not FMP_KEY:
        return None
    candidates = [ticker.upper()]
    t = ticker.upper()
    if "." not in t:
        candidates += [t + ".AS", t + ".BR"]
    period_days = {
        "1mo": 30, "3mo": 90, "6mo": 182, "1y": 365,
        "2y": 730, "5y": 1825, "max": 99999,
    }
    days   = period_days.get(period, 365)
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    async with httpx.AsyncClient(timeout=15) as client:
        for sym in candidates:
            try:
                r = await client.get(
                    f"https://financialmodelingprep.com/api/v3/historical-price-full/{sym}?apikey={FMP_KEY}"
                )
                if not r.is_success:
                    continue
                hist = r.json().get("historical", [])
                if not hist:
                    continue
                filtered = [h for h in hist if h.get("date", "") >= cutoff] or hist
                data = [
                    {
                        "date":  h["date"],
                        "close": round(float(h.get("close", 0)), 4),
                        "open":  round(float(h.get("open",  0)), 4),
                        "high":  round(float(h.get("high",  0)), 4),
                        "low":   round(float(h.get("low",   0)), 4),
                    }
                    for h in sorted(filtered, key=lambda x: x["date"])
                ]
                return {"ticker": sym, "period": period, "interval": interval,
                        "data": data, "source": "FMP"}
            except Exception:
                continue
    return None


def _fetch_history_yahoo(ticker: str, period: str, interval: str) -> Optional[dict]:
    t = ticker.upper().strip()
    candidates = [t]
    if "." not in t and "-" not in t:
        candidates += [t + ".AS", t + ".BR"]
    range_map = {
        "1d":"1d","5d":"5d","1mo":"1mo","3mo":"3mo","6mo":"6mo",
        "1y":"1y","2y":"2y","5y":"5y","10y":"10y","ytd":"ytd","max":"max",
    }
    yf_range = range_map.get(period, "1y")
    for sym in candidates:
        try:
            resp = httpx.get(
                f"https://query1.finance.yahoo.com/v8/finance/chart/{sym}?interval={interval}&range={yf_range}",
                headers=_YF_HEADERS, timeout=15, follow_redirects=True,
            )
            if resp.status_code != 200:
                continue
            chart = resp.json().get("chart", {})
            if not chart.get("result"):
                continue
            r          = chart["result"][0]
            timestamps = r.get("timestamp", [])
            closes     = r.get("indicators", {}).get("quote", [{}])[0].get("close", [])
            if not timestamps or not closes:
                continue
            rows = [
                {
                    "date":  datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d"),
                    "close": round(float(c), 4),
                    "open":  round(float(c), 4),
                    "high":  round(float(c), 4),
                    "low":   round(float(c), 4),
                }
                for ts, c in zip(timestamps, closes) if c is not None
            ]
            if not rows:
                continue
            return {"ticker": sym, "period": period, "interval": interval,
                    "data": rows, "source": "Yahoo Finance"}
        except Exception as e:
            print(f"History fout voor {sym}: {e}")
    return None
