from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import yfinance as yf
import jwt
import bcrypt
import os
import json
from datetime import datetime, timedelta
from typing import Optional
import httpx

app = FastAPI(title="Portfolio Tracker API")

# ── CORS — sta je GitHub Pages domein toe ───────────────────────────
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Config via omgevingsvariabelen ──────────────────────────────────
JWT_SECRET   = os.getenv("JWT_SECRET", "verander-dit-naar-een-geheime-sleutel")
JWT_EXPIRES  = int(os.getenv("JWT_EXPIRES_HOURS", "720"))  # 30 dagen

# Gebruikers — opgeslagen als JSON in omgevingsvariabele
USERS_JSON   = os.getenv("USERS_JSON", "[]")

# Financial Modeling Prep API key
FMP_KEY      = os.getenv("FMP_API_KEY", "")

security = HTTPBearer(auto_error=False)


# ── Gebruikersbeheer ────────────────────────────────────────────────
def get_users() -> list:
    try:
        return json.loads(USERS_JSON)
    except Exception:
        return []


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(username: str, role: str = "user") -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Niet ingelogd")
    try:
        payload = jwt.decode(
            credentials.credentials, JWT_SECRET, algorithms=["HS256"]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Sessie verlopen")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Ongeldig token")


# ══════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ══════════════════════════════════════════════════════════════════════

@app.get("/")
def root():
    return {"status": "Portfolio Tracker API actief"}


# ── Login ────────────────────────────────────────────────────────────
@app.post("/auth/login")
def login(body: dict):
    username = body.get("username", "").strip()
    password = body.get("password", "")

    users = get_users()
    user = next((u for u in users if u["username"] == username), None)

    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Gebruikersnaam of wachtwoord onjuist")

    token = create_token(username, user.get("role", "user"))
    return {
        "token": token,
        "username": username,
        "role": user.get("role", "user"),
        "expires_hours": JWT_EXPIRES,
    }


# ── Controleer login status ──────────────────────────────────────────
@app.get("/auth/me")
def me(user=Depends(verify_token)):
    return {"username": user["sub"], "role": user["role"]}


# ── Live koers (enkelvoudig) ─────────────────────────────────────────
@app.get("/price/{ticker}")
async def get_price(ticker: str, user=Depends(verify_token)):
    """
    Haal koers op voor één ticker.
    Probeert FMP eerst, dan yfinance als fallback.
    """
    # Probeer FMP eerst
    result = await _fetch_price_fmp(ticker)
    if not result:
        # Fallback naar yfinance
        result = _fetch_price(ticker)
    if not result:
        raise HTTPException(status_code=404, detail=f"Koers niet gevonden voor {ticker}")
    return result


# ── Meerdere koersen tegelijk ─────────────────────────────────────────
@app.post("/prices")
async def get_prices(body: dict, user=Depends(verify_token)):
    """
    Haal koersen op voor meerdere tickers tegelijk via FMP batch endpoint.
    Body: {"tickers": ["AAPL", "IWDA.AS", "BTC-EUR"]}
    """
    import httpx

    tickers = body.get("tickers", [])
    if not tickers:
        return {}

    results = {}

    # Splits crypto (geen FMP nodig) en aandelen
    crypto_tickers  = [t for t in tickers if "-EUR" in t.upper() or "-USD" in t.upper()]
    stock_tickers   = [t for t in tickers if t not in crypto_tickers]

    # FMP batch call voor aandelen (max 30 tegelijk)
    if stock_tickers and FMP_KEY:
        # Bouw kandidatenlijst: probeer direct en met .AS suffix
        fmp_map = {}  # fmp_sym -> original_ticker
        fmp_syms = []
        for t in stock_tickers:
            tu = t.upper()
            if "." in tu:
                fmp_map[tu] = t
                fmp_syms.append(tu)
            else:
                fmp_map[tu] = t
                fmp_map[tu + ".AS"] = t
                fmp_syms += [tu, tu + ".AS"]

        try:
            sym_str = ",".join(fmp_syms[:60])
            url = f"https://financialmodelingprep.com/api/v3/quote/{sym_str}?apikey={FMP_KEY}"
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url)
            if r.is_success:
                for q in r.json():
                    sym = q.get("symbol", "")
                    price = q.get("price") or q.get("previousClose")
                    if not price or float(price) == 0:
                        continue
                    orig = fmp_map.get(sym, sym)
                    prev = q.get("previousClose") or price
                    results[orig] = {
                        "ticker": sym,
                        "price": round(float(price), 4),
                        "previousClose": round(float(prev), 4),
                        "change": round(float(q.get("change") or 0), 4),
                        "changePercent": round(float(q.get("changesPercentage") or 0), 2),
                        "currency": q.get("currency", "EUR"),
                        "source": "FMP",
                        "timestamp": datetime.utcnow().isoformat(),
                        "marketOpen": q.get("isActivelyTrading", False),
                    }
        except Exception:
            pass

    # Fallback naar yfinance voor tickers die FMP niet vond
    missing = [t for t in stock_tickers if t not in results]
    for ticker in missing:
        data = _fetch_price(ticker)
        if data:
            results[ticker] = data

    # Crypto via apart endpoint (wordt al via CoinGecko gedaan in de app)
    # Toch ook via FMP proberen als fallback
    for ticker in crypto_tickers:
        if ticker not in results:
            data = await _fetch_price_fmp(ticker)
            if data:
                results[ticker] = data

    return results


# ── Historische koersen (voor grafiek + benchmark) ───────────────────
@app.get("/history/{ticker}")
async def get_history(
    ticker: str,
    period: str = "1y",
    interval: str = "1d",
    user=Depends(verify_token),
):
    """
    Historische dagkoersen voor grafiek of benchmark.
    Probeert FMP eerst, dan yfinance als fallback.
    """
    import httpx

    # Probeer FMP historische data
    if FMP_KEY:
        candidates = [ticker.upper()]
        t = ticker.upper()
        if "." not in t:
            candidates += [t + ".AS", t + ".BR"]

        for sym in candidates:
            try:
                url = f"https://financialmodelingprep.com/api/v3/historical-price-full/{sym}?apikey={FMP_KEY}"
                async with httpx.AsyncClient(timeout=15) as client:
                    r = await client.get(url)
                if not r.is_success:
                    continue
                data = r.json()
                hist = data.get("historical", [])
                if not hist:
                    continue
                # Filter op period
                from datetime import timedelta
                period_days = {
                    "1mo": 30, "3mo": 90, "6mo": 182, "1y": 365,
                    "2y": 730, "5y": 1825, "max": 99999
                }
                days = period_days.get(period, 365)
                cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
                filtered = [h for h in hist if h.get("date", "") >= cutoff]
                if not filtered:
                    filtered = hist  # geef alles als filter leeg is

                result_data = [{
                    "date": h["date"],
                    "close": round(float(h.get("close", 0)), 4),
                    "open":  round(float(h.get("open",  0)), 4),
                    "high":  round(float(h.get("high",  0)), 4),
                    "low":   round(float(h.get("low",   0)), 4),
                } for h in sorted(filtered, key=lambda x: x["date"])]

                return {
                    "ticker": sym,
                    "period": period,
                    "interval": interval,
                    "data": result_data,
                    "source": "FMP",
                }
            except Exception:
                continue

    # Fallback naar yfinance
    result = _fetch_history(ticker, period, interval)
    if not result:
        raise HTTPException(
            status_code=404, detail=f"Historische data niet gevonden voor {ticker}"
        )
    return result


# ── Ticker zoeken ────────────────────────────────────────────────────
@app.get("/search")
async def search_ticker(q: str, user=Depends(verify_token)):
    """
    Zoek naar tickers via naam of symbool via FMP.
    """
    import httpx

    if not q or len(q) < 1:
        return []

    if not FMP_KEY:
        raise HTTPException(status_code=503, detail="FMP API key niet ingesteld")

    results = []

    # Probeer beide FMP endpoints
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
                # Normaliseer response - kan array zijn of object met array
                if isinstance(data, list) and len(data) > 0:
                    results = data
                    break
                elif isinstance(data, dict):
                    for key in ["data", "results", "stocks", "list"]:
                        if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                            results = data[key]
                            break
                    if results:
                        break
            except Exception:
                continue

    if not results:
        return []

    # Filter en formatteer
    allowed = {"NASDAQ","NYSE","AMEX","EURONEXT","ENX","XETRA","LSE","AMS","BRU","PAR","CBOE","EURONEXT"}
    filtered = []
    seen = set()

    for item in results:
        sym = item.get("symbol","") or item.get("ticker","")
        name = item.get("name","") or item.get("companyName","")
        exch = item.get("exchangeShortName","") or item.get("exchange","") or item.get("stockExchange","")

        if not sym or sym in seen:
            continue
        seen.add(sym)

        # Accepteer als beurs bekend is of als symbool kort en zonder cijfers
        if exch.upper() not in allowed:
            if any(c.isdigit() for c in sym) or len(sym) > 7:
                continue

        filtered.append({
            "symbol": sym,
            "name": name,
            "exchange": exch,
            "exchangeShort": exch,
            "currency": item.get("currency",""),
        })

    return filtered[:15]


# ── Admin: gebruiker aanmaken ────────────────────────────────────────
@app.post("/admin/hash-password")
def hash_password(body: dict, user=Depends(verify_token)):
    """
    Hulpendpoint om een wachtwoord te hashen voor in USERS_JSON.
    Alleen toegankelijk voor admins.
    """
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Geen toegang")
    password = body.get("password", "")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Wachtwoord te kort (min 6 tekens)")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return {"hash": hashed}


# ══════════════════════════════════════════════════════════════════════
# INTERNE HULPFUNCTIES
# ══════════════════════════════════════════════════════════════════════

async def _fetch_price_fmp(ticker: str) -> Optional[dict]:
    """
    Haal koers op via Financial Modeling Prep API.
    Werkt voor Euronext (.AS, .BR), NYSE, NASDAQ, ETFs.
    Geeft altijd de laatste bekende prijs terug.
    """
    if not FMP_KEY:
        return None

    import httpx

    # Probeer ticker direct, dan met Euronext suffixes
    candidates = [ticker.upper()]
    t = ticker.upper()
    if "." not in t and "-" not in t:
        candidates += [t + ".AS", t + ".BR"]

    for sym in candidates:
        try:
            # FMP quote endpoint — geeft altijd laatste bekende prijs
            url = f"https://financialmodelingprep.com/api/v3/quote/{sym}?apikey={FMP_KEY}"
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url)
            if not r.is_success:
                continue
            data = r.json()
            if not data or not isinstance(data, list) or len(data) == 0:
                continue
            q = data[0]
            price = q.get("price") or q.get("previousClose")
            if not price or float(price) == 0:
                continue
            prev  = q.get("previousClose") or price
            chg   = q.get("change") or 0
            chgP  = q.get("changesPercentage") or 0
            return {
                "ticker": sym,
                "price": round(float(price), 4),
                "previousClose": round(float(prev), 4),
                "change": round(float(chg), 4),
                "changePercent": round(float(chgP), 2),
                "currency": q.get("currency", "EUR"),
                "source": "FMP",
                "timestamp": datetime.utcnow().isoformat(),
                "marketOpen": q.get("isActivelyTrading", False),
            }
        except Exception:
            continue
    return None


def _fetch_price(ticker: str) -> Optional[dict]:
    """
    Probeer koers op te halen via yfinance als fallback.
    Geeft altijd de laatste bekende slotkoers terug.
    """
    candidates = [ticker]

    t = ticker.upper()
    # Voeg Euronext suffixes toe als er nog geen suffix is
    if "." not in t and "-" not in t:
        candidates += [t + ".AS", t + ".BR", t + ".L", t + ".PA"]

    for sym in candidates:
        try:
            tk = yf.Ticker(sym)

            # Strategie 1: fast_info (werkt als markt open is)
            price = None
            prev  = None
            try:
                info  = tk.fast_info
                price = getattr(info, "last_price", None)
                prev  = getattr(info, "previous_close", None)
                curr  = getattr(info, "currency", "EUR")
                if price and float(price) > 0:
                    price = round(float(price), 4)
                    prev  = round(float(prev), 4) if prev else price
                    chg   = round(price - prev, 4)
                    chgP  = round((chg / prev * 100) if prev else 0, 2)
                    return {
                        "ticker": sym,
                        "price": price,
                        "previousClose": prev,
                        "change": chg,
                        "changePercent": chgP,
                        "currency": curr,
                        "source": "yfinance (live)",
                        "timestamp": datetime.utcnow().isoformat(),
                        "marketOpen": True,
                    }
            except Exception:
                pass

            # Strategie 2: history 5 dagen dagkoersen (werkt altijd, ook buiten beurstijden)
            hist = tk.history(period="5d", interval="1d", auto_adjust=True)
            if not hist.empty:
                price = round(float(hist["Close"].iloc[-1]), 4)
                prev  = round(float(hist["Close"].iloc[-2]), 4) if len(hist) > 1 else price
                chg   = round(price - prev, 4)
                chgP  = round((chg / prev * 100) if prev else 0, 2)
                try:
                    curr = tk.fast_info.currency
                except Exception:
                    curr = "EUR"
                return {
                    "ticker": sym,
                    "price": price,
                    "previousClose": prev,
                    "change": chg,
                    "changePercent": chgP,
                    "currency": curr,
                    "source": "yfinance (slotkoers)",
                    "timestamp": datetime.utcnow().isoformat(),
                    "marketOpen": False,
                }

            # Strategie 3: history 1 maand als fallback
            hist2 = tk.history(period="1mo", interval="1d", auto_adjust=True)
            if not hist2.empty:
                price = round(float(hist2["Close"].iloc[-1]), 4)
                prev  = round(float(hist2["Close"].iloc[-2]), 4) if len(hist2) > 1 else price
                chg   = round(price - prev, 4)
                chgP  = round((chg / prev * 100) if prev else 0, 2)
                return {
                    "ticker": sym,
                    "price": price,
                    "previousClose": prev,
                    "change": chg,
                    "changePercent": chgP,
                    "currency": "EUR",
                    "source": "yfinance (historisch)",
                    "timestamp": datetime.utcnow().isoformat(),
                    "marketOpen": False,
                }

        except Exception:
            continue

    return None


def _fetch_history(ticker: str, period: str, interval: str) -> Optional[dict]:
    """
    Historische OHLC data via yfinance.
    Probeert automatisch Euronext suffixes.
    """
    candidates = [ticker]
    t = ticker.upper()
    if "." not in t and "-" not in t:
        candidates += [t + ".AS", t + ".BR", t + ".L"]

    for sym in candidates:
        try:
            tk = yf.Ticker(sym)
            hist = tk.history(period=period, interval=interval, auto_adjust=True)

            if hist.empty:
                continue

            # Converteer naar JSON-vriendelijk formaat
            data = []
            for date, row in hist.iterrows():
                data.append({
                    "date": date.strftime("%Y-%m-%d"),
                    "close": round(float(row["Close"]), 4),
                    "open":  round(float(row["Open"]), 4),
                    "high":  round(float(row["High"]), 4),
                    "low":   round(float(row["Low"]), 4),
                })

            return {
                "ticker": sym,
                "period": period,
                "interval": interval,
                "data": data,
                "source": "yfinance",
            }
        except Exception:
            continue

    return None
