# NullexGuard — OSINT Intelligence Platform

Breach intelligence and email OSINT powered by the Dehashed API.

---

## Setup

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
```
Open `.env` and fill in:
```
DEHASHED_EMAIL=your_dehashed_account_email@example.com
DEHASHED_APIKEY=your_api_key_here
```
Get your API key at: https://dehashed.com/profile

### 3. Run the server
```bash
npm start
```

Open your browser at: **http://localhost:3001**

---

## Project Structure

```
nullexguard-backend/
├── server.js          # Express backend — Dehashed API proxy
├── public/
│   └── index.html     # Full frontend (served by Express)
├── .env               # Your credentials (never commit this)
├── .env.example       # Template
└── package.json
```

---

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/lookup?email=xxx` | Query Dehashed for breach data |
| `GET /api/health` | Check server + credentials |
| `GET /*` | Serves the frontend |

---

## How it works

1. User enters an email on the frontend
2. Frontend calls `/api/lookup?email=...`
3. Backend queries `https://api.dehashed.com/search` with your credentials
4. Results are grouped by breach source, identity signals extracted
5. Passwords masked to first + last character only
6. Frontend renders the results in the NullexGuard UI

---

## Security notes

- API key stays server-side — never exposed to the browser
- Passwords are masked before being sent to the frontend
- Add auth middleware before deploying publicly
- Add rate limiting before deploying publicly (`npm install express-rate-limit`)

---

## Next steps

- [ ] Add persistent user accounts with a real database (SQLite/Postgres)
- [ ] Add rate limiting per user
- [ ] Wire up Holehe for platform registration checks
- [ ] Add Gravatar + Google account lookups
- [ ] Add monitoring/alerts when new breaches match a watched email
