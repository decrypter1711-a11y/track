# Employee Tracker — sugar.relax

A hardened Flask + MongoDB app for employee attendance, daily work updates,
**live activity / idle / away-from-app tracking**, an **audible** 2-hour
progress reminder (no blocking popups), an admin console with **automatic IP
blocking**, **per-user PDF reports** (single day / month / N-days), live
monitor, and login history.

---

## Deploy to Vercel (no terminal needed)

**1. Push this folder to GitHub**
- Go to [github.com/new](https://github.com/new), create a new repository (Public or Private, your choice), and **do not** initialize it with a README.
- On the empty repo page, use **"uploading an existing file"** and drag-and-drop every file/folder from this project into it (or drag the whole folder — GitHub's web uploader supports folders in most browsers).
- Commit the files to the `main` branch.

**2. Import the repo into Vercel**
- Go to [vercel.com/new](https://vercel.com/new), sign in, and click **Import** next to the GitHub repo you just created.
- Vercel will detect `vercel.json` and use the Python builder automatically — you don't need to change any build/output settings.

**3. Add environment variables (Vercel dashboard, not your terminal)**
Before clicking Deploy (or right after, then redeploy), open **Project → Settings → Environment Variables** and add:

| Key | Value |
|---|---|
| `MONGO_URI` | `mongodb+srv://vaibhavjain:CNgsMCp8teQ2eucy@cluster0.pkquxad.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0` |
| `SECRET_KEY` | `a582f7b6b7d723487b7168a79fe61712ee8d1c12b4a2ac8ae08f310b2f218d90de94effdde56037a0038c8fe9826430aa88dff3b3356c924ff38aae5656b0260` |
| `ADMIN_USERNAME` | pick your own admin login name |
| `ADMIN_PASSWORD` | pick your own strong admin password |
| `COOKIE_SECURE` | `1` |

`SECRET_KEY` above is a ready-to-use random value generated for you — you can use it as-is or generate your own. Setting it is **required** on Vercel: without it, sessions can silently log people out because serverless instances don't share a local file to store a generated key.

**4. Allow Vercel to reach your MongoDB Atlas cluster**
In MongoDB Atlas → **Network Access**, add the IP `0.0.0.0/0` ("Allow access from anywhere"). Vercel's serverless functions don't have a fixed IP address, so the cluster must accept connections from any IP (Atlas still authenticates with your username/password).

**5. Deploy**
Click **Deploy**. Vercel gives you a live `*.vercel.app` URL when it finishes.

### Known limits of running this app on Vercel
This app was originally built to run continuously (e.g. on Render/Railway/a VPS via the included `Procfile`). Two features behave differently on Vercel's serverless model, where each request can run in a fresh, short-lived instance with a read-only filesystem:
- **File attachments on "Add Update"** are saved to a temporary folder that is **not persistent** — an attachment may disappear and fail to reopen later. Everything else (login, attendance, dashboards, admin panel, PDF exports) works normally since it's all stored in MongoDB.
- **Automatic "mark offline after inactivity"** runs on a background timer in the code; on Vercel that timer only runs while an instance happens to be warm, so it's less reliable than on a normal server. Live status shown while a user is actively using the app is not affected.

If you later want file attachments and the offline-timer to work reliably, the same code (via the included `Procfile`) deploys as-is to Render or Railway, which run the app as one continuous process instead of on-demand functions — happy to set that up too if you'd rather go that route.

---

## Quick start (Windows)

```cmd
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open <http://localhost:5000>.

- **Admin** → <http://localhost:5000/admin>
- **Default admin credentials:** username `******` with the password set via the `ADMIN_PASSWORD` environment variable (a built-in default is used if the variable is absent — you will see a warning in the console; change it before deploying).
  Override via `ADMIN_USERNAME` / `ADMIN_PASSWORD` env vars.

MongoDB must be running locally on `mongodb://localhost:27017/`
(install MongoDB Community Server and let it install as a service),
or set `MONGO_URI` to your connection string.

---

## What's in the box

### Employee side
- Register with **unique username** + separate **display name** (real name
  can be duplicated across people) + unique email.
- PBKDF2-hashed passwords (never stored in plain text).
- Check-in / check-out, attendance history, post work updates.
- **No popup nag.** Instead a coloured countdown badge plus **audible beeps**
  at 10 min, 5 min and 1 min before the 2-hour deadline, and a beep every
  minute once overdue. Optional desktop notifications if the browser allows.
- The browser tracks mouse, keyboard, scroll, touch, **and whether the
  tracker tab is hidden or unfocused** ("Away from app").

### Admin side
- **Live Monitor** (`/admin/live-monitor`) — auto-refreshes every 30 s:
  - Online list (green dot)
  - **Inactive list, marked in red, with minutes inactive**
  - Offline list
- **Employees** — table view; inactive rows are red-tinted, "Idle Today"
  and "Away from app" columns surface the bad-news numbers.
- **Login History** (`/admin/login-history`) — last 500 login / logout
  events with timestamp, IP and User-Agent.
- **Manage employee** — add a work update on behalf of someone who didn't,
  edit or delete any update, fix activity for a date (including a
  "mark all idle as active" helper).
- **PDF reports** per employee — choose:
  - a **single day**, or
  - a **whole month**, or
  - the **last N days** (1–365)

  PDFs are properly aligned, sugar.relax-branded, with the logo, employee info
  block, and a clean table of dated updates with admin-edit tags.
- CSV exports (per-employee, or zip with one CSV each + a combined file).
- **Auto IP blocking** for scanner UAs, probe paths, missing UAs and
  request floods; admin can unblock from the panel.

---

## ⚠️ Honest limit: tracking apps outside the browser

The user asked for tracking of **Netflix / YouTube / games** etc. A web page
**cannot** see what runs in other browser tabs or other applications — this
is a fundamental browser-security rule that protects every website on the
internet from spying on every other one. There is no workaround inside a
web app.

What this app **does** detect:
- **Away from app** — every second the tracker tab is hidden or the window
  is unfocused is counted, with a count of how many times they switched
  away. This is the strongest "they're not on the tracker right now" signal
  a web page can produce.

For actual per-app or per-URL tracking you need one of:
1. A **browser extension** (employee installs it; can read the URL of the
   active tab if they grant the `tabs` permission).
2. A **desktop agent** (a small program running on the employee's machine
   that reports the foreground window / process to the server).

Both are larger projects of their own and would integrate with this app
via a new `/agent-report` endpoint. Happy to scaffold either if you want
to go that route.

---

## Configuration

| Variable             | Purpose                                    | Default                       |
|----------------------|--------------------------------------------|-------------------------------|
| `SECRET_KEY`         | Flask session signing key. **Set this.**   | random (resets each restart)  |
| `ADMIN_USERNAME`     | Admin login name                           | `******`                  |
| `ADMIN_PASSWORD`     | Admin login password. **Set this.**        | *(insecure default — change)* |
| `MONGO_URI`          | MongoDB connection string                  | `mongodb://localhost:27017/`  |
| `COOKIE_SECURE`      | Set to `1` when serving over HTTPS         | `0`                           |
| `TRUSTED_PROXIES`    | Comma-separated IPs of trusted reverse proxies. Only these are allowed to set `X-Forwarded-For`. | *(none)* |

> **Security:** A startup warning is printed to stderr if `ADMIN_PASSWORD` is not set via the environment variable.  Set it before deploying.

---

## Collections

- `employees` — username (unique), display_name, email (unique), password (hash), last_active
- `attendance` — employee_id, date, check_in, check_out, status
- `daily_updates` — employee_id, work_update, date, admin_added/edited_by_admin flags
- `activity` — employee_id, date, active_seconds, idle_seconds, **away_seconds**, idle_events, away_events
- `blocked_ips` — ip (unique), reason, user_agent, path, blocked_at
- `login_events` — employee_id, event ("login"/"logout"), timestamp, ip, user_agent
