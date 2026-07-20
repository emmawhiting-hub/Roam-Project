/* ============================================================
   Roam — live pricing server (SerpApi: Google Flights + Hotels)
   Proxies real prices so the prototype isn't using sample numbers.
   Keeps your SerpApi key on the server (never the browser).
   Falls back to sample prices when no key is set.
   Requires Node 18+ (built-in fetch).
   ============================================================ */
const express = require('express');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(express.json({ limit: '1mb' }));
const PORT = process.env.PORT || 3000;
const KEY = process.env.SERPAPI_KEY;
const SERP = 'https://serpapi.com/search.json';
const HTML_FILE = 'Roam App Prototype.html';

/* ============================================================
   ACCOUNTS — Supabase Auth (real auth provider: hashed/salted passwords,
   rate-limited login attempts, email confirmation, leaked-password checks —
   none of that is hand-rolled here). Itineraries live in a `trips` table
   with Row Level Security, so Postgres itself enforces that a user can only
   ever read or write their own row — not just the app code.

   Every request only ever uses the PUBLISHABLE key, scoped to that one
   user's own access token. The secret/service-role key is never used here,
   so this server can never bypass RLS even if compromised.
   ============================================================ */
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY;
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.warn('SUPABASE_URL / SUPABASE_PUBLISHABLE_KEY not set — accounts will not work until they are.');
}
const supabaseAnon = SUPABASE_URL && SUPABASE_KEY ? createClient(SUPABASE_URL, SUPABASE_KEY) : null;
// A client scoped to one user's own access token — every query it runs is subject to that user's RLS policies.
function supabaseFor(accessToken) {
  return createClient(SUPABASE_URL, SUPABASE_KEY, { global: { headers: { Authorization: `Bearer ${accessToken}` } } });
}

function parseCookies(req) {
  const out = {}; const h = req.headers.cookie || '';
  h.split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}
function setSessionCookie(res, session) {
  const payload = encodeURIComponent(JSON.stringify({ at: session.access_token, rt: session.refresh_token }));
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  // No Max-Age/Expires -> a browser-session cookie: it clears when the browser fully
  // closes, so reopening the app later starts logged out instead of silently
  // resuming someone's previous account.
  res.setHeader('Set-Cookie', `sb_session=${payload}; HttpOnly; Path=/; SameSite=Lax${secure}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'sb_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
}
function toPublicUser(user, trips) {
  return { name: (user.user_metadata && user.user_metadata.name) || user.email, email: user.email, trips: trips || [] };
}

// Resolves the logged-in user from the session cookie, transparently refreshing
// an expired access token with the refresh token (and re-issuing the cookie) so
// people don't get silently logged out mid-session.
async function authUser(req, res) {
  if (!supabaseAnon) return null;
  const raw = parseCookies(req).sb_session;
  if (!raw) return null;
  let session;
  try { session = JSON.parse(decodeURIComponent(raw)); } catch { return null; }
  if (!session || !session.at) return null;

  let client = supabaseFor(session.at);
  let { data, error } = await client.auth.getUser();
  if (error) {
    if (!session.rt) { clearSessionCookie(res); return null; }
    const refreshed = await supabaseAnon.auth.refreshSession({ refresh_token: session.rt });
    if (refreshed.error || !refreshed.data.session) { clearSessionCookie(res); return null; }
    setSessionCookie(res, refreshed.data.session);
    client = supabaseFor(refreshed.data.session.access_token);
    data = { user: refreshed.data.user };
  }
  return { user: data.user, client };
}

async function loadTrips(client, userId) {
  const { data, error } = await client.from('trips').select('trips').eq('user_id', userId).maybeSingle();
  if (error) { console.error('loadTrips error:', error.message); return []; }
  return (data && data.trips) || [];
}

// Wraps an async route handler so any thrown/rejected error becomes a clean
// JSON 500 instead of hanging the request or crashing the process — the
// client sees "could not reach the server" if this is missing and something
// downstream (e.g. a Supabase call) throws after the response hasn't been sent yet.
function wrapAsync(fn) {
  return (req, res, next) => { Promise.resolve(fn(req, res, next)).catch(next); };
}

// Catch-all error handler — never leak internals to the client, log details server-side.
function errorHandler(err, req, res, next) {
  console.error('Unhandled route error:', err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Something went wrong on our end. Please try again.' });
}

// Safety net: if something throws outside of Express's request/response cycle
// (e.g. an unawaited promise rejection), log it instead of letting the process die silently.
process.on('unhandledRejection', (err) => console.error('Unhandled rejection:', err));
process.on('uncaughtException', (err) => console.error('Uncaught exception:', err));

app.post('/api/signup', wrapAsync(async (req, res) => {
  if (!supabaseAnon) return res.status(500).json({ error: 'Accounts are not configured on this server.' });
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required.' });
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Please enter a valid email.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const { data, error } = await supabaseAnon.auth.signUp({ email, password, options: { data: { name } } });
  if (error) return res.status(400).json({ error: error.message });
  if (!data.session) {
    // Email confirmation is required before a session is issued (default Supabase behavior).
    return res.status(200).json({ needsConfirmation: true, error: 'Check your email to confirm your account, then log in.' });
  }
  setSessionCookie(res, data.session);
  res.json({ user: toPublicUser(data.user, []) });
}));

app.post('/api/login', wrapAsync(async (req, res) => {
  if (!supabaseAnon) return res.status(500).json({ error: 'Accounts are not configured on this server.' });
  const email = String(req.body.email || '').toLowerCase().trim();
  const password = String(req.body.password || '');
  const { data, error } = await supabaseAnon.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: 'Incorrect email or password.' });
  setSessionCookie(res, data.session);
  const trips = await loadTrips(supabaseFor(data.session.access_token), data.user.id);
  res.json({ user: toPublicUser(data.user, trips) });
}));

app.post('/api/logout', wrapAsync(async (req, res) => {
  const raw = parseCookies(req).sb_session;
  if (raw && supabaseAnon) {
    try { const s = JSON.parse(decodeURIComponent(raw)); await supabaseFor(s.at).auth.signOut(); } catch (e) { console.error('logout signOut error:', e.message); }
  }
  clearSessionCookie(res);
  res.json({ ok: true });
}));

app.get('/api/me', wrapAsync(async (req, res) => {
  const auth = await authUser(req, res);
  if (!auth) return res.json({ user: null });
  const trips = await loadTrips(auth.client, auth.user.id);
  res.json({ user: toPublicUser(auth.user, trips) });
}));

// load / save this user's itineraries — RLS on the trips table means this
// query can only ever touch the row belonging to the signed-in user.
app.get('/api/trips', wrapAsync(async (req, res) => {
  const auth = await authUser(req, res);
  if (!auth) return res.status(401).json({ error: 'Not logged in.' });
  res.json({ trips: await loadTrips(auth.client, auth.user.id) });
}));
app.put('/api/trips', wrapAsync(async (req, res) => {
  const auth = await authUser(req, res);
  if (!auth) return res.status(401).json({ error: 'Not logged in.' });
  const trips = Array.isArray(req.body.trips) ? req.body.trips : [];
  const { error } = await auth.client.from('trips')
    .upsert({ user_id: auth.user.id, trips, updated_at: new Date().toISOString() });
  if (error) return res.status(500).json({ error: 'Could not save trips.' });
  res.json({ ok: true, count: trips.length });
}));

/* Cache identical trip lookups so a shared/public link doesn't burn the
   SerpApi quota — repeated searches for the same route+dates are free. */
const cache = new Map();                 // key -> { time, data }
const CACHE_TTL = 1000 * 60 * 60 * 3;    // 3 hours (fresh-ish without burning quota)
let serpCallsSinceBoot = 0;

/* Resolve a typed city/country to a primary airport (for flight search).
   Catalogue trips already pass an IATA code, so this only handles free text. */
const AIRPORTS = {
  // catalogue
  lisbon:'LIS', portugal:'LIS', porto:'OPO', 'mexico city':'MEX', mexico:'MEX',
  oaxaca:'OAX', bangkok:'BKK', thailand:'BKK', 'chiang mai':'CNX', 'medellin':'MDE',
  'medellín':'MDE', colombia:'BOG', cartagena:'CTG', athens:'ATH', greece:'ATH', santorini:'JTR',
  // common extras
  spain:'MAD', madrid:'MAD', barcelona:'BCN', france:'CDG', paris:'CDG',
  italy:'FCO', rome:'FCO', milan:'MXP', venice:'VCE', florence:'FLR',
  japan:'HND', tokyo:'HND', osaka:'KIX', uk:'LHR', 'united kingdom':'LHR',
  england:'LHR', london:'LHR', germany:'FRA', berlin:'BER', munich:'MUC',
  netherlands:'AMS', amsterdam:'AMS', ireland:'DUB', dublin:'DUB',
  iceland:'KEF', reykjavik:'KEF', croatia:'DBV', dubrovnik:'DBV',
  turkey:'IST', istanbul:'IST', egypt:'CAI', cairo:'CAI', morocco:'RAK',
  marrakech:'RAK', usa:'JFK', 'united states':'JFK', 'new york':'JFK',
  'los angeles':'LAX', miami:'MIA', chicago:'ORD', boston:'BOS',
  brazil:'GRU', 'sao paulo':'GRU', 'rio de janeiro':'GIG', argentina:'EZE',
  'buenos aires':'EZE', peru:'LIM', lima:'LIM', cusco:'CUZ', chile:'SCL',
  india:'DEL', 'new delhi':'DEL', mumbai:'BOM', indonesia:'DPS', bali:'DPS',
  vietnam:'SGN', 'ho chi minh':'SGN', hanoi:'HAN', philippines:'MNL',
  australia:'SYD', sydney:'SYD', 'costa rica':'SJO', 'south africa':'JNB',
  'cape town':'CPT'
};
function resolveAirport(s) {
  if (!s) return null;
  if (/^[A-Za-z]{3}$/.test(s)) return s.toUpperCase();
  const m = s.toLowerCase().trim().match(/\(([a-z]{3})\)/);  // "New York (JFK)"
  if (m) return m[1].toUpperCase();
  return AIRPORTS[s.toLowerCase().trim()] || null;
}

/* If a country is typed, anchor flights AND hotels to one representative city
   so they're in the same area (e.g. "Spain" -> Madrid). */
const COUNTRY_CITY = {
  portugal:'Lisbon', spain:'Madrid', france:'Paris', italy:'Rome', greece:'Athens',
  thailand:'Bangkok', mexico:'Mexico City', colombia:'Cartagena', japan:'Tokyo',
  germany:'Berlin', netherlands:'Amsterdam', ireland:'Dublin', uk:'London',
  'united kingdom':'London', england:'London', iceland:'Reykjavik', croatia:'Dubrovnik',
  turkey:'Istanbul', egypt:'Cairo', morocco:'Marrakech', usa:'New York',
  'united states':'New York', brazil:'Rio de Janeiro', argentina:'Buenos Aires',
  peru:'Lima', chile:'Santiago', india:'New Delhi', indonesia:'Bali',
  vietnam:'Ho Chi Minh City', philippines:'Manila', australia:'Sydney',
  'costa rica':'San José', 'south africa':'Cape Town'
};
function resolveDest(dest, iata) {
  const code = resolveAirport(iata) || resolveAirport(dest);
  const key = (dest || '').toLowerCase().trim();
  const city = COUNTRY_CITY[key] || dest;   // hotels search this exact city
  return { code, city };
}
const fmtMin = m => { m = +m||0; const h=Math.floor(m/60), x=m%60; return (h?h+'h ':'') + (x?x+'m':''); };

async function serp(params) {
  const qs = new URLSearchParams({ ...params, api_key: KEY }).toString();
  const r = await fetch(`${SERP}?${qs}`);
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j;
}

/* ---------- flights (Google Flights, ROUND TRIP) ----------
   type=1 -> round trip; the price returned is the TOTAL round-trip fare.
   deep_search=true -> returns the same fares you see on the Google Flights page
   (without it, Google returns faster *cached* results that often read lower). */
async function flights(origin, dest, depart, ret) {
  const j = await serp({
    engine: 'google_flights', departure_id: origin, arrival_id: dest,
    outbound_date: depart, return_date: ret, currency: 'USD', hl: 'en', gl: 'us',
    type: '1', deep_search: 'true'
  });
  const all = [...(j.best_flights || []), ...(j.other_flights || [])];
  const seen = new Set();
  return all.map(f => {
    const legs = f.flights || [];
    const stops = Math.max(0, legs.length - 1);
    const airline = legs[0] ? legs[0].airline : 'Airline';
    const multi = new Set(legs.map(l => l.airline)).size > 1;
    const klass = legs[0] && legs[0].travel_class ? legs[0].travel_class : 'Economy';
    return {
      t: airline + (multi ? ' +' : '') + ' — ' + (stops ? stops + ' stop' : 'direct'),
      s: fmtMin(f.total_duration) + ' · ' + klass + ' · round-trip',
      p: Math.round(f.price)
    };
  }).filter(f => f.p > 0 && (seen.has(f.t + f.p) ? false : seen.add(f.t + f.p)))
    .sort((a, b) => a.p - b.p).slice(0, 6);
}

/* ---------- hotels (Google Hotels) — well-rated, spread across price tiers ---------- */
async function hotels(city, ci, co) {
  const j = await serp({
    engine: 'google_hotels', q: city, check_in_date: ci, check_out_date: co,
    adults: '1', currency: 'USD', hl: 'en', gl: 'us', sort_by: '8' // 8 = highest rating
  });
  const nights = Math.max(1, Math.round((new Date(co) - new Date(ci)) / 86400000));
  const num = v => v == null ? NaN : (typeof v === 'number' ? v : parseFloat(String(v).replace(/[^0-9.]/g, '')));
  const arr = (j.properties || []).map(p => {
    // Prefer the ALL-IN total (taxes & fees) so it matches what you actually pay,
    // then express it as a per-night number; fall back to the nightly rate.
    const totalAll = p.total_rate && num(p.total_rate.extracted_lowest != null ? p.total_rate.extracted_lowest : p.total_rate.lowest);
    const nightly = p.rate_per_night && num(p.rate_per_night.extracted_lowest != null ? p.rate_per_night.extracted_lowest : p.rate_per_night.lowest);
    const per = !isNaN(totalAll) ? Math.round(totalAll / nights) : (!isNaN(nightly) ? Math.round(nightly) : 0);
    const rating = p.overall_rating || 0;
    const cls = p.hotel_class ? p.hotel_class : 'hotel';
    return {
      t: p.name,
      s: (rating ? rating + '★ · ' : '') + cls + ' · incl. taxes',
      p: per,
      rating
    };
  }).filter(h => h.t && h.p > 0);
  // keep only well-rated hotels when ratings are available
  const rated = arr.filter(h => h.rating >= 4.0);
  const base = rated.length >= 3 ? rated : arr;
  return base.sort((a, b) => a.p - b.p).slice(0, 10);
}

/* ---------- combined endpoint ----------
   Activities aren't priced reliably by Google, so they stay as sample
   estimates (with the corrected Viator search links) on the front end. */
app.get('/api/trip', wrapAsync(async (req, res) => {
  const { origin, dest, iata, depart, return: ret } = req.query;
  if (!KEY) return res.json({ live: false, error: 'no_key' });
  if (!origin || !dest || !depart || !ret) return res.json({ live: false, error: 'missing_params' });

  // serve a cached result if we've looked up this exact trip recently
  const cacheKey = [origin, dest, iata, depart, ret].join('|').toLowerCase();
  const hit = cache.get(cacheKey);
  if (hit && Date.now() - hit.time < CACHE_TTL) return res.json({ ...hit.data, cached: true });

  const originCode = resolveAirport(origin);
  const { code: destCode, city: hotelCity } = resolveDest(dest, iata);
  const out = { live: true, resolved: { origin: originCode, dest: destCode, city: hotelCity } };

  await Promise.allSettled([
    (originCode && destCode)
      ? flights(originCode, destCode, depart, ret).then(x => out.flights = x)
          .catch(e => out.flightsError = String(e.message || e))
      : Promise.resolve(out.flightsError = 'could not resolve airport'),
    hotels(hotelCity, depart, ret).then(x => out.hotels = x)
      .catch(e => out.hotelsError = String(e.message || e))
  ]);

  // only cache useful results (don't cache transient failures)
  if ((out.flights && out.flights.length) || (out.hotels && out.hotels.length)) {
    cache.set(cacheKey, { time: Date.now(), data: out });
    serpCallsSinceBoot++;
  }
  res.json(out);
}));

/* ---------- flexible dates: cheapest fare for nearby departure dates ---------- */
const isoD = d => `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
app.get('/api/flexdates', wrapAsync(async (req, res) => {
  const { origin, dest, iata, depart, nights } = req.query;
  if (!KEY) return res.json({ live: false, error: 'no_key' });
  if (!origin || !dest || !depart || !nights) return res.json({ error: 'missing_params' });
  const cacheKey = 'flex|' + [origin, dest, iata, depart, nights].join('|').toLowerCase();
  const hit = cache.get(cacheKey);
  if (hit && Date.now() - hit.time < CACHE_TTL) return res.json({ ...hit.data, cached: true });

  const originCode = resolveAirport(origin);
  const { code: destCode } = resolveDest(dest, iata);
  if (!originCode || !destCode) return res.json({ error: 'unresolved_location' });
  const n = parseInt(nights) || 4;
  const [y, m, d] = depart.split('-').map(Number);
  const base = new Date(y, m - 1, d, 12);
  const offsets = [-3, -1, 0, 1, 3];
  const out = [];
  await Promise.all(offsets.map(async off => {
    const dd = new Date(base); dd.setDate(dd.getDate() + off);
    const rr = new Date(dd); rr.setDate(rr.getDate() + n);
    try {
      const list = await flights(originCode, destCode, isoD(dd), isoD(rr));
      if (list.length) out.push({ offset: off, date: isoD(dd), price: list[0].p });
    } catch (e) { /* skip this date */ }
  }));
  out.sort((a, b) => a.offset - b.offset);
  const result = { live: true, options: out };
  if (out.length) { cache.set(cacheKey, { time: Date.now(), data: result }); serpCallsSinceBoot += out.length; }
  res.json(result);
}));

/* health check */
app.get('/api/status', (req, res) => res.json({
  ok: true, key: !!KEY, provider: 'serpapi',
  cachedTrips: cache.size, lookupsSinceBoot: serpCallsSinceBoot
}));

/* serve the app HTML + the airport dataset only — never the whole folder, so .env stays private */
app.get('/airports.js', (req, res) => res.sendFile(path.join(__dirname, 'airports.js')));
app.get(['/', '/' + encodeURIComponent(HTML_FILE), '/index.html'], (req, res) =>
  res.sendFile(path.join(__dirname, HTML_FILE)));

// must be registered after all routes — catches anything wrapAsync passed to next()
app.use(errorHandler);

// On Vercel this file is imported as a serverless function (module.exports = app)
// rather than run directly, so app.listen() must only fire for local/`npm start` use —
// otherwise every request would try to bind a port inside the serverless sandbox.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log('Roam running →  http://localhost:' + PORT);
    console.log(KEY
      ? 'Live pricing ON (SerpApi — Google Flights & Hotels)'
      : 'Live pricing OFF — add SERPAPI_KEY to .env to enable (showing estimates).');
  });
}
module.exports = app;
