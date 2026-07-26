require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

const DEXCOM_BASE = process.env.USE_SANDBOX === 'true'
  ? 'https://sandbox-api.dexcom.com'
  : 'https://api.dexcom.com';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false, saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 86400000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

async function refreshToken(sess) {
  const r = await axios.post(`${DEXCOM_BASE}/v2/oauth2/token`, new URLSearchParams({
    client_id: process.env.DEXCOM_CLIENT_ID,
    client_secret: process.env.DEXCOM_CLIENT_SECRET,
    refresh_token: sess.refreshToken,
    grant_type: 'refresh_token',
    redirect_uri: process.env.REDIRECT_URI
  }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  sess.accessToken = r.data.access_token;
  sess.refreshToken = r.data.refresh_token;
  sess.tokenExpiry = Date.now() + r.data.expires_in * 1000;
  return r.data.access_token;
}
async function getToken(sess) {
  if (!sess.accessToken) throw new Error('Not authenticated');
  if (Date.now() > sess.tokenExpiry - 300000) return refreshToken(sess);
  return sess.accessToken;
}

app.get('/api/status', (req, res) => res.json({ connected: !!req.session.accessToken, sandbox: process.env.USE_SANDBOX === 'true' }));

app.get('/auth/dexcom', (req, res) => {
  const state = Math.random().toString(36).substring(2);
  req.session.oauthState = state;
  const params = new URLSearchParams({ client_id: process.env.DEXCOM_CLIENT_ID, redirect_uri: process.env.REDIRECT_URI, response_type: 'code', scope: 'offline_access', state });
  res.redirect(`${DEXCOM_BASE}/v2/oauth2/login?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;
  if (error) return res.redirect('/?dexcom_error=' + error);
  if (state !== req.session.oauthState) return res.redirect('/?dexcom_error=state_mismatch');
  try {
    const r = await axios.post(`${DEXCOM_BASE}/v2/oauth2/token`, new URLSearchParams({
      client_id: process.env.DEXCOM_CLIENT_ID,
      client_secret: process.env.DEXCOM_CLIENT_SECRET,
      code, grant_type: 'authorization_code',
      redirect_uri: process.env.REDIRECT_URI
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    req.session.accessToken = r.data.access_token;
    req.session.refreshToken = r.data.refresh_token;
    req.session.tokenExpiry = Date.now() + r.data.expires_in * 1000;
    res.redirect('/?dexcom_connected=true');
  } catch(e) { res.redirect('/?dexcom_error=token_failed'); }
});

app.get('/api/glucose', async (req, res) => {
  try {
    const token = await getToken(req.session);
    const end = new Date().toISOString().slice(0,19);
    const start = new Date(Date.now() - 86400000).toISOString().slice(0,19);
    const r = await axios.get(`${DEXCOM_BASE}/v3/users/self/egvs`, {
      headers: { Authorization: `Bearer ${token}` },
      params: { startDate: start, endDate: end }
    });
    const records = r.data.records || r.data.egvs || [];
    if (!records.length) return res.json({ connected: true, value: null });
    const latest = records[records.length - 1];
    res.json({ connected: true, value: latest.value, trend: latest.trend, displayTime: latest.displayTime, sandbox: process.env.USE_SANDBOX === 'true' });
  } catch(e) {
    if (e.message === 'Not authenticated') return res.status(401).json({ connected: false });
    res.status(500).json({ connected: false, error: e.message });
  }
});

app.post('/auth/disconnect', (req, res) => {
  req.session.accessToken = req.session.refreshToken = req.session.tokenExpiry = null;
  res.json({ success: true });
});

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
