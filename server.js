require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const DEXCOM_BASE = process.env.USE_SANDBOX === 'true'
  ? 'https://sandbox-api.dexcom.com'
  : 'https://api.dexcom.com';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.SESSION_SECRET || 'change-me'));
app.use(express.static(path.join(__dirname, 'public')));

const COOKIE_OPTS = { httpOnly: true, secure: true, sameSite: 'lax', path: '/' };

function setTokenCookies(res, data) {
  res.cookie('dex_access',  data.access_token,  { ...COOKIE_OPTS, maxAge: data.expires_in * 1000 });
  res.cookie('dex_refresh', data.refresh_token, { ...COOKIE_OPTS, maxAge: 30 * 24 * 60 * 60 * 1000 });
  res.cookie('dex_expiry',  String(Date.now() + data.expires_in * 1000), { ...COOKIE_OPTS, maxAge: 30 * 24 * 60 * 60 * 1000 });
}

function clearTokenCookies(res) {
  res.clearCookie('dex_access');
  res.clearCookie('dex_refresh');
  res.clearCookie('dex_expiry');
}

async function getValidToken(req, res) {
  const { dex_access, dex_refresh, dex_expiry } = req.cookies;
  if (!dex_access && !dex_refresh) throw new Error('Not authenticated');
  if (!dex_access || Date.now() > Number(dex_expiry) - 300000) {
    const r = await axios.post(`${DEXCOM_BASE}/v2/oauth2/token`,
      new URLSearchParams({
        client_id:     process.env.DEXCOM_CLIENT_ID,
        client_secret: process.env.DEXCOM_CLIENT_SECRET,
        refresh_token: dex_refresh,
        grant_type:    'refresh_token',
        redirect_uri:  process.env.REDIRECT_URI
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    setTokenCookies(res, r.data);
    return r.data.access_token;
  }
  return dex_access;
}

app.get('/api/status', (req, res) => {
  const connected = !!(req.cookies.dex_access || req.cookies.dex_refresh);
  res.json({ connected, sandbox: process.env.USE_SANDBOX === 'true' });
});

app.get('/auth/dexcom', (req, res) => {
  const state = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);
  res.cookie('oauth_state', state, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 5 * 60 * 1000 });
  const params = new URLSearchParams({
    client_id:     process.env.DEXCOM_CLIENT_ID,
    redirect_uri:  process.env.REDIRECT_URI,
    response_type: 'code',
    scope:         'offline_access',
    state
  });
  res.redirect(`${DEXCOM_BASE}/v2/oauth2/login?${params.toString()}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  const storedState = req.cookies.oauth_state;
  if (error) return res.redirect('/?dexcom_error=' + encodeURIComponent(error));
  if (!storedState || state !== storedState) return res.redirect('/?dexcom_error=state_mismatch');
  res.clearCookie('oauth_state');
  try {
    const r = await axios.post(`${DEXCOM_BASE}/v2/oauth2/token`,
      new URLSearchParams({
        client_id:     process.env.DEXCOM_CLIENT_ID,
        client_secret: process.env.DEXCOM_CLIENT_SECRET,
        code,
        grant_type:    'authorization_code',
        redirect_uri:  process.env.REDIRECT_URI
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    setTokenCookies(res, r.data);
    res.redirect('/?dexcom_connected=true');
  } catch (e) {
    console.error('Token exchange failed:', e.response?.data || e.message);
    res.redirect('/?dexcom_error=token_exchange_failed');
  }
});

app.get('/api/glucose', async (req, res) => {
  try {
    const token = await getValidToken(req, res);
    const end   = new Date().toISOString().slice(0, 19);
    const start = new Date(Date.now() - 86400000).toISOString().slice(0, 19);
    const r = await axios.get(`${DEXCOM_BASE}/v3/users/self/egvs`, {
      headers: { Authorization: `Bearer ${token}` },
      params:  { startDate: start, endDate: end }
    });
    const records = r.data.records || r.data.egvs || [];
    if (!records.length) return res.json({ connected: true, value: null });
    const latest = records[records.length - 1];
    res.json({ connected: true, value: latest.value, trend: latest.trend, displayTime: latest.displayTime, sandbox: process.env.USE_SANDBOX === 'true' });
  } catch (e) {
    if (e.message === 'Not authenticated') return res.status(401).json({ connected: false });
    res.status(500).json({ connected: false, error: e.message });
  }
});

app.post('/auth/disconnect', (req, res) => {
  clearTokenCookies(res);
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
