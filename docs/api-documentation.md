# 🛡️ Passive Recon Tool: API Documentation

Welcome to the "Brain" of the operation. This API is designed to gather intelligence on a target domain without ever sending a packet directly to their servers. We use a **stealth-first** approach, relying on public records like DNS, WHOIS, and Certificate Transparency logs to build a digital footprint.

---

## 🏗️ The Architecture (How it works)

To keep the UI snappy, we don't make the user wait for long-running tasks. We use a **Distributed Task Queue** model:

1. **The Request**: The user submits a domain via the React frontend.
2. **The Hand-off**: FastAPI validates the domain and hands the heavy lifting to **Celery**.
3. **The Broker**: **Redis** manages the message queue, making sure no tasks are lost.
4. **The Worker**: A background process runs our modules (DNS, OSINT, etc.) and saves the results once finished.



---

## 📡 The Endpoints

### 1. The "Quick Look" (Synchronous)
If you just need the basics fast (DNS, WHOIS, and IP info), use this. It runs in real-time and returns data immediately.

* **URL**: `GET /api/v1/recon/{domain}`
* **Best for**: Instant feedback on a target's primary infrastructure.
* **Response**: A full JSON object containing primary intel.

### 2. The "Deep Dive" (Asynchronous)
This is the heavy hitter. This endpoint triggers the full suite of modules, including the slower Wayback Machine and Subdomain scrapers.

* **URL**: `POST /api/v1/recon/start/{domain}`
* **Response**: You'll get a `task_id`. Think of this like a "claim ticket" at a dry cleaner—you use it to check back later.
* **Success Body**:
    ```json
    {
      "task_id": "8c5e-unique-uuid",
      "status": "Processing"
    }
    ```

### 3. Checking the Status
Once you have a `task_id`, you'll poll this endpoint to see if the workers have finished their job.

* **URL**: `GET /api/v1/recon/status/{task_id}`
* **Logic**: If `task_status` is `SUCCESS`, the full intelligence report will be attached to the `task_result` field.

---

## 🛠️ Module Breakdown (The "Intel")

We've broken the recon down into specific modules to keep the code clean and modular:

| Module | What it finds | Why we use it |
| :--- | :--- | :--- |
| **Domain Intel** | Registrar & DNS | To see who owns the domain and where their mail is hosted. |
| **Subdomains** | CT Logs (crt.sh) | To find hidden "dev" or "staging" sites without brute-forcing. |
| **Infrastructure** | GeoIP & ASN | To see if they are behind Cloudflare or hosting on AWS/GCP. |
| **OSINT** | Wayback Machine | To find old URLs that might still be active but forgotten. |
| **Certs** | SSL Details | To check for expiry dates and certificate authority trust. |



---

## ⚠️ Common Gotchas

* **Invalid Domains**: If you send something like `not_a_domain!!`, our `validator.py` utility will catch it and return a `400 Bad Request`.
* **Timeouts**: Some external APIs (like `crt.sh`) can be moody. If a module fails, the API will still return results for the other modules rather than crashing.
* **CORS**: We've enabled CORS so that your React frontend can talk to this API even though they run on different ports (8000 vs 3000).

---

*Authored by Samfrieman - Passive Recon Project*