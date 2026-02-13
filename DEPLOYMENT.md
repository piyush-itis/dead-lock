# Deployment Guide

Deadlock runs as a single Node.js server that serves both the API and frontend. One deploy, no separate services unless you choose a split setup.

**Database:** PostgreSQL only ([Neon](https://neon.tech) free tier recommended). SQLite is not supported.

---

## Deploy to Vercel (recommended)

### Prerequisites

- [Neon](https://neon.tech) account (free tier)
- GitHub repo with your code
- [Vercel](https://vercel.com) account

### Step 1: Create the database

1. Go to [Neon](https://neon.tech) and create a new project.
2. Copy the **connection string** — use the **pooler** URL (ends with `-pooler`) for serverless.
3. Add `?sslmode=require` if not present.

### Step 2: Deploy

1. Go to [vercel.com](https://vercel.com) and sign in with GitHub.
2. Click **Add New** → **Project** and import your Deadlock repo.
3. **Framework Preset:** Other (or leave default).
4. **Build Command:** `npm run build` (default)
5. **Output Directory:** `client/dist` (Vercel may auto-detect from vercel.json)
6. **Root Directory:** leave empty

### Step 3: Environment variables

In Project Settings → Environment Variables, add:

| Variable | Value |
|----------|-------|
| `DATABASE_URL` | Your Neon pooler connection string |
| `NODE_ENV` | `production` |
| `ALLOWED_ORIGINS` | Your Vercel URL, e.g. `https://your-app.vercel.app` (optional for same-origin) |

### Step 4: Deploy

Click **Deploy**. Vercel will:
- Build the frontend → `client/dist`
- Deploy the API as serverless functions (from `api/`)
- Serve the app at your `.vercel.app` URL

### Step 5: Test

Open your Vercel URL, create an account, and add a password.

---

## Deploy to Railway

### Prerequisites

- [Neon](https://neon.tech) or [Supabase](https://supabase.com) account (free tier works)
- GitHub repo with your code
- An account on [Railway](https://railway.app)

---

## Step 1: Create the database

1. Go to [Neon](https://neon.tech) and create a new project.
2. Copy the connection string (e.g. `postgresql://user:pass@ep-xxx.region.aws.neon.tech/neondb?sslmode=require`).
3. Keep it for Step 3.

---

## Step 2: Build locally (optional check)

```bash
npm install
npm run build
```

This creates `client/dist/` with the frontend. The server will serve these files in production.

---

## Step 3: Deploy to Railway

### 3.1 Connect the repo

1. Go to [railway.app](https://railway.app) and sign in (e.g. with GitHub).
2. Click **New Project** → **Deploy from GitHub repo**.
3. Choose your Deadlock repo and branch.

### 3.2 Configure the service

1. In the project, open your service → **Variables**.
2. Add:

| Variable | Value |
|----------|-------|
| `NODE_ENV` | `production` |
| `DATABASE_URL` | `postgresql://...` (your Neon connection string) |
| `ALLOWED_ORIGINS` | Optional for same-origin. If using a custom domain or split deploy, add it (e.g. `https://your-app.railway.app`) |

### 3.3 Set build & start commands

1. In **Settings** → **Build**:
   - **Build Command:** `npm install && npm run build`
   - **Output Directory:** leave empty (we use the repo root)
   - **Root Directory:** leave empty

2. **Start Command:** `npm start` (or `node server/index.js`)

3. Ensure **Watch Paths** includes the project so deploys trigger on pushes.

### 3.4 Deploy

1. Click **Deploy** or push to the connected branch.
2. Railway builds, runs the server, and assigns a URL (e.g. `https://your-app.up.railway.app`).
3. If you set a custom domain, use that in `ALLOWED_ORIGINS`.

### 3.5 Test

- Open `https://your-app.up.railway.app` in a browser.
- Register and add a password to confirm everything works.

---

## Alternative: Deploy to Render

### 1. New Web Service

1. Go to [render.com](https://render.com) and sign in.
2. **New** → **Web Service**.
3. Connect your GitHub repo.

### 2. Configure

| Field | Value |
|-------|-------|
| **Build Command** | `npm install && npm run build` |
| **Start Command** | `npm start` |
| **Instance Type** | Free (or paid for better performance) |

### 3. Environment variables

Add:

- `NODE_ENV` = `production`
- `DATABASE_URL` = your Neon connection string
- `ALLOWED_ORIGINS` = `https://your-app.onrender.com` (your Render URL)

### 4. Deploy

Click **Create Web Service**. Render builds and deploys; your app is available at the generated URL.

---

## Split deployment (optional)

If you want the frontend on Vercel and the API elsewhere:

### Backend (Railway / Render)

1. Deploy the same app to Railway or Render.
2. Use the backend URL (e.g. `https://deadlock-api.railway.app`) as the base.

### Frontend (Vercel)

1. Add an environment variable for the API URL, e.g. `VITE_API_URL=https://deadlock-api.railway.app`.
2. In the client, use `const API = import.meta.env.VITE_API_URL || '/api'`.
3. Configure CORS: `ALLOWED_ORIGINS=https://your-frontend.vercel.app` on the backend.
4. Deploy the frontend to Vercel pointing at `VITE_API_URL`.

You’ll need to make the client use `VITE_API_URL` when set. This is an extra step beyond the default single-server deploy.

---

## Environment variables summary

| Variable | Required | Description |
|----------|----------|-------------|
| `NODE_ENV` | Yes (prod) | Set to `production` |
| `DATABASE_URL` | Yes | PostgreSQL connection string (e.g. Neon) |
| `ALLOWED_ORIGINS` | If split | Comma-separated origins (e.g. `https://app.example.com`) |
| `PORT` | No | Default `3000`; host sets it automatically |

---

## Troubleshooting

**Blank page or 404**
- Check that `npm run build` runs during deploy and produces `client/dist/`.
- Inspect server logs for path or static-serving errors.

**“Invalid request” / 403**
- Ensure the frontend sends `X-Requested-With: XMLHttpRequest` (it’s in `API_HEADERS`).
- Verify `ALLOWED_ORIGINS` includes your frontend URL if you use a separate origin.

**Database errors**
- Confirm `DATABASE_URL` is set and correct.
- For Neon, use `?sslmode=require` in the connection string.
- Check that the DB allows connections from your host’s IP (Neon usually allows all).

**CORS errors**
- Add your frontend URL to `ALLOWED_ORIGINS`.
- For same-origin deploy (API + frontend together), CORS is usually not an issue.
