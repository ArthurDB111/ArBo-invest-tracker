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
def get_prices(body: dict, user=Depends(verify_token)):
    """
    Haal koersen op voor meerdere tickers tegelijk.
    Body: {"tickers": ["AAPL", "IWDA.AS", "BTC-EUR"]}
    """
    tickers = body.get("tickers", [])
    if not tickers:
        return {}

    results = {}

    # Crypto wordt al via CoinGecko gedaan in de browser
    # Hier alleen aandelen/ETFs verwerken
    stock_tickers = [t for t in tickers if "-EUR" not in t.upper() and "-USD" not in t.upper()]

    # FMP batch call voor alle aandelen tegelijk
    if stock_tickers and FMP_KEY:
        import httpx
        try:
            # Bouw volledige lijst met originele + .AS varianten
            fmp_map = {}
            fmp_syms = []
            for t in stock_tickers:
                tu = t.upper()
                fmp_map[tu] = t
                fmp_syms.append(tu)
                if '.' not in tu:
                    fmp_map[tu+'.AS'] = t
                    fmp_syms.append(tu+'.AS')

            sym_str = ','.join(fmp_syms[:60])
            url = f"https://financialmodelingprep.com/stable/quote?symbol={sym_str}&apikey={FMP_KEY}"
            resp = httpx.get(url, timeout=20, follow_redirects=True)

            if resp.status_code == 200 and resp.text.strip():
                data = resp.json()
                if isinstance(data, list):
                    for q in data:
                        sym  = q.get('symbol', '')
                        orig = fmp_map.get(sym, sym)
                        price = q.get('price') or q.get('previousClose')
                        if not price or float(price) == 0:
                            continue
                        prev = float(q.get('previousClose') or price)
                        results[orig] = {
                            'ticker':        sym,
                            'price':         round(float(price), 4),
                            'previousClose': round(prev, 4),
                            'change':        round(float(q.get('change') or 0), 4),
                            'changePercent': round(float(q.get('changesPercentage') or 0), 2),
                            'currency':      q.get('currency', 'EUR'),
                            'source':        'FMP',
                            'timestamp':     datetime.utcnow().isoformat(),
                            'marketOpen':    bool(q.get('isActivelyTrading', False)),
                        }
        except Exception as e:
            print(f"FMP batch fout: {e}")

    # Fallback: yfinance voor tickers die FMP niet vond
    missing = [t for t in stock_tickers if t not in results]
    for ticker in missing:
        data = _fetch_price(ticker)
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
    Haal koers op via FMP stable API.
    Probeert automatisch suffixes voor Euronext.
    Geeft altijd laatste bekende prijs terug.
    """
    import httpx

    t = ticker.upper().strip()

    # Bouw kandidatenlijst
    candidates = [t]
    if '.' not in t and '-' not in t and '=' not in t and len(t) <= 6:
        candidates += [t+'.AS', t+'.BR', t+'.DE', t+'.PA', t+'.L']

    # Probeer FMP stable/quote met alle kandidaten tegelijk
    if FMP_KEY:
        try:
            sym_str = ','.join(candidates[:6])
            url = f"https://financialmodelingprep.com/stable/quote?symbol={sym_str}&apikey={FMP_KEY}"
            resp = httpx.get(url, timeout=15, follow_redirects=True)
            if resp.status_code == 200 and resp.text.strip():
                data = resp.json()
                if isinstance(data, list) and len(data) > 0:
                    for q in data:
                        price = q.get('price') or q.get('previousClose')
                        if price and float(price) > 0:
                            prev = float(q.get('previousClose') or price)
                            chg  = float(q.get('change') or 0)
                            chgP = float(q.get('changesPercentage') or 0)
                            return {
                                'ticker':        q.get('symbol', t),
                                'price':         round(float(price), 4),
                                'previousClose': round(prev, 4),
                                'change':        round(chg, 4),
                                'changePercent': round(chgP, 2),
                                'currency':      q.get('currency', 'EUR'),
                                'source':        'FMP',
                                'timestamp':     datetime.utcnow().isoformat(),
                                'marketOpen':    bool(q.get('isActivelyTrading', False)),
                            }
        except Exception as e:
            print(f"FMP fout voor {t}: {e}")

    # Fallback: yfinance zonder suffix manipulatie
    try:
        import yfinance as yf
        # Probeer alleen de exacte ticker en .AS variant
        for sym in [t, t+'.AS'] if '.' not in t else [t]:
            try:
                tk = yf.Ticker(sym)
                hist = tk.history(period='5d', interval='1d', auto_adjust=True)
                if hist is not None and not hist.empty:
                    price = round(float(hist['Close'].iloc[-1]), 4)
                    prev  = round(float(hist['Close'].iloc[-2]), 4) if len(hist) > 1 else price
                    return {
                        'ticker':        sym,
                        'price':         price,
                        'previousClose': prev,
                        'change':        round(price - prev, 4),
                        'changePercent': round((price-prev)/prev*100 if prev else 0, 2),
                        'currency':      'EUR',
                        'source':        'yfinance',
                        'timestamp':     datetime.utcnow().isoformat(),
                        'marketOpen':    False,
                    }
            except Exception:
                continue
    except Exception as e:
        print(f"yfinance fout voor {t}: {e}")

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
