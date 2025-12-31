import os
from celery import Celery
from backend.modules.domain_intel import get_domain_info
from backend.modules.subdomain_discovery import get_subdomains
from backend.modules.infrastructure import get_infrastructure_info
from backend.modules.osint import get_osint_data

# Initialize Celery
# 'redis://localhost:6379/0' tells Celery where the message broker is
celery_app = Celery(
    "recon_worker",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
)

@celery_app.task(name="run_full_recon_task")
def run_full_recon_task(domain):
    """
    This is the background process that runs all modules.
    """
    results = {
        "target": domain,
        "intel": get_domain_info(domain),
        "infrastructure": get_infrastructure_info(domain),
        "subdomains": get_subdomains(domain),
        "osint": get_osint_data(domain)
    }
    return results