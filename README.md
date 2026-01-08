# CoreRecon - Setup & Usage Guide

A professional passive reconnaissance platform built with FastAPI and React.

---

## Table of Contents

- [What You'll Need](#what-youll-need)
- [Getting Started](#getting-started)
- [Running Locally](#running-locally)
- [Using GitHub Codespaces](#using-github-codespaces)
- [How to Use CoreRecon](#how-to-use-corerecon)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)

---

## What You'll Need

Before starting, make sure you have these installed:

- **Python 3.8 or newer** - [Download here](https://www.python.org/downloads/)
- **Node.js 16 or newer** - [Download here](https://nodejs.org/)
- **Git** - [Download here](https://git-scm.com/downloads)
- **VS Code** (recommended) - [Download here](https://code.visualstudio.com/)

You can verify everything is installed by running these commands:

```bash
python --version
node --version
git --version
```

---

## Getting Started

Here's the quickest way to get CoreRecon running:

```bash
# Clone the repository
git clone https://github.com/SamFrieman/core-recon-passive-reconnaissance.git
cd core-recon-passive-reconnaissance

# Install Python dependencies
pip install -r requirements.txt

# Install Node dependencies
npm install

# Start the backend (in one terminal)
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Start the frontend (in another terminal)
cd frontend
npm run dev
```

If running into vite issues do a fresh npm install in frontend:
```bash
# Go to Frontend
cd frontend

# Clear any corrupted cache
npm cache clean --force

# Remove node_modules and package-lock.json
rm -rf node_modules package-lock.json

# Install dependencies fresh
npm install

# Now try running the dev server
npm run dev
```
### *Note that rm -rf node_modules package-lock.json is not neccesary and may result with an error. If error occurs move on*

Then open your browser to `http://localhost:5173`

---

## Running Locally

This is the recommended approach if you're developing on your own machine.

### Step 1: Clone the Repository

Open your terminal and run:

```bash
git clone https://github.com/SamFrieman/core-recon-passive-reconnaissance.git
cd core-recon-passive-reconnaissance
```

### Step 2: Open in VS Code

```bash
code .
```

Or open VS Code manually and use File > Open Folder to select the project directory.

### Step 3: Set Up the Backend

I recommend using a virtual environment to keep dependencies isolated:

**Windows:**
```bash
python -m venv venv
.\venv\Scripts\activate
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

Then install the Python dependencies:

```bash
pip install -r requirements.txt
```

If you run into issues, try upgrading pip first:
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Set Up the Frontend

Install the Node.js dependencies:

```bash
npm install
```

### Step 5: Start the Application

You'll need two terminal windows in VS Code. Open a new terminal with Terminal > New Terminal.

**Terminal 1 - Backend:**
```bash
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

You should see output like:
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Application startup complete.
```

**Terminal 2 - Frontend:**

Open a second terminal and run:
```bash
npm run dev
```

You should see:
```
  VITE v5.x.x  ready in xxx ms

  Local:   http://localhost:5173/
```

### Step 6: Open the Application

Navigate to `http://localhost:5173` in your web browser. You should see the CoreRecon interface.

---

## Using GitHub Codespaces

If you prefer working in the cloud, GitHub Codespaces is a great option.

### Setting Up

1. Go to [the repository](https://github.com/SamFrieman/core-recon-passive-reconnaissance)
2. Click the green **Code** button
3. Select the **Codespaces** tab
4. Click **Create codespace on main**

### Installing Dependencies

Once your Codespace loads, run:

```bash
pip install -r requirements.txt
npm install
```

### Running the Application

Same as the local setup - you need two terminals:

**Terminal 1:**
```bash
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2:**
```bash
npm run dev
```

Codespaces will automatically forward the ports. Look for the notification in the bottom-right corner, or check the PORTS tab to find your application URL.

---

## How to Use CoreRecon

### Basic Workflow

The tool is pretty straightforward to use:

1. **Enter a target** - Type a domain, URL, or IP address into the search bar
   - Examples: `example.com`, `www.example.com`, `https://example.com`, `8.8.8.8`

2. **Start the scan** - Click "Begin Scan" and wait for the reconnaissance to complete
   - This usually takes 10-30 seconds depending on the target

3. **Review the results** - Expand each card to see detailed findings:
   - Infrastructure Intelligence (IP, location, ASN)
   - DNS Records (A, AAAA, MX, NS, TXT, SOA, CNAME)
   - Subdomain Discovery (from certificate transparency logs)
   - Security Headers (HSTS, CSP, X-Frame-Options, etc.)
   - SSL/TLS Certificate details
   - WHOIS information
   - Technology Stack (web frameworks, libraries)
   - Web Archive history

4. **Generate a report** - Click "Download Report" to get a professional PDF with all findings

### Testing It Out

Here are some good domains to test with:

```
google.com
github.com
cloudflare.com
mozilla.org
```

### Using the API Directly

You can also interact with the backend API directly:

**Scan a domain:**
```bash
curl http://localhost:8000/api/v1/recon/example.com
```

**Get scan history:**
```bash
curl http://localhost:8000/api/v1/history
```

**Download a report:**
```bash
curl http://localhost:8000/api/v1/report/example.com --output report.pdf
```

**Check API status:**
```bash
curl http://localhost:8000/
```

---

## Troubleshooting

### Port Already in Use

If you see an error like "Address already in use: Port 8000", something is already using that port.

**Windows:**
```bash
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

**macOS/Linux:**
```bash
lsof -ti:8000 | xargs kill -9
```

Or just use a different port:
```bash
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8001
```

### Module Not Found

If you get `ModuleNotFoundError: No module named 'fastapi'`, your dependencies aren't installed properly.

Make sure you're in the project directory and run:
```bash
pip install -r requirements.txt
```

If you're using a virtual environment, make sure it's activated:
```bash
source venv/bin/activate  # macOS/Linux
.\venv\Scripts\activate   # Windows
```

### npm Installation Fails

If npm gives you errors during installation:

```bash
# Clear the cache
npm cache clean --force

# Remove old files
rm -rf node_modules package-lock.json  # macOS/Linux
rmdir /s node_modules & del package-lock.json  # Windows

# Try again
npm install
```

### CORS Errors

If you see CORS-related errors in your browser console, make sure:
- Both the backend and frontend are running
- You're accessing the site from `http://localhost:5173` (not `127.0.0.1`)

### Database Locked

If you get "database is locked" errors:

```bash
# Remove the database (you'll lose scan history)
rm recon_history.db  # macOS/Linux
del recon_history.db  # Windows

# Restart the backend - it will create a fresh database
```

### Python Command Not Recognized

On some systems, you need to use `python3` instead of `python`:

```bash
python3 -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

---

## Project Structure

Here's how the project is organized:

```
core-recon-passive-reconnaissance/
├── backend/
│   ├── main.py              # FastAPI backend server
│   └── __init__.py
├── src/
│   ├── App.jsx              # Main React component
│   ├── main.jsx             # React entry point
│   └── index.css            # Global styles
├── public/                  # Static assets
├── package.json             # Node.js dependencies
├── requirements.txt         # Python dependencies
├── vite.config.js           # Vite configuration
├── tailwind.config.js       # Tailwind CSS config
└── index.html               # HTML entry point
```

Generated files (not in git):
- `node_modules/` - Node dependencies
- `venv/` - Python virtual environment
- `recon_history.db` - SQLite database for scan history

---

## Important Security Notes

A few things to keep in mind:

- **Only scan domains you own or have permission to test.** Unauthorized scanning can violate laws and terms of service.

- **This tool uses passive reconnaissance only.** It doesn't perform active probing or exploitation.

- **Use responsibly.** CoreRecon is designed for authorized security testing and research purposes.

---

## Getting Help

If you run into issues:

1. Check this guide thoroughly
2. Look through existing [GitHub Issues](https://github.com/SamFrieman/core-recon-passive-reconnaissance/issues)
3. Open a new issue with details about your problem

When reporting issues, please include:
- Your operating system and version
- Python version (`python --version`)
- Node.js version (`node --version`)
- The full error message
- Steps to reproduce the problem

---

## Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [React Documentation](https://react.dev/)
- [Vite Documentation](https://vitejs.dev/)
- [Tailwind CSS](https://tailwindcss.com/)

---

Built for the security community. Feel free to contribute or report issues on GitHub.
