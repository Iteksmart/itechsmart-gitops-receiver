"""
iTechSmart GitOps Webhook Receiver
Accepts GitHub push/registry webhooks with HMAC-SHA256 auth.
Pulls latest image and restarts the target compose service.
Seals a ProofLink receipt (category gitops_deploy) for every deploy.

Flow: git push → GitHub Action → POST /hook → HMAC verify →
      docker compose pull && up -d → append.py receipt seal
"""
import hashlib, hmac, json, logging, os, subprocess, time
from fastapi import FastAPI, Request, HTTPException, Header
from typing import Optional

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("gitops.receiver")

WEBHOOK_SECRET   = os.environ.get("GITOPS_WEBHOOK_SECRET", "")
APPEND_PY        = os.environ.get("APPEND_PY", "/opt/itechsmart/audit_ledger/append.py")
COMPOSE_DIR      = os.environ.get("COMPOSE_DIR", "/opt/itechsmart/iTechSmart-Suite")

# Map service → compose file (host-side paths). Extend when adding Wave 2+ services.
COMPOSE_MAP: dict[str, str] = json.loads(
    os.environ.get("GITOPS_COMPOSE_MAP", "{}")
)

app = FastAPI(title="iTechSmart GitOps Receiver", docs_url=None, redoc_url=None)


def _verify_hmac(body: bytes, sig_header: str) -> bool:
    if not WEBHOOK_SECRET:
        return False
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig_header or "")


def _seal_receipt(service: str, image: str, outcome: str, details: dict) -> Optional[str]:
    args = [
        "python3", APPEND_PY,
        "--category", "gitops_deploy",
        "--actor", "gitops-receiver",
        "--subject", service,
        "--action", f"docker compose pull+up for {service} (image: {image})",
        "--outcome", outcome,
        "--details", json.dumps(details)[:4000],
        "--no-ots",
    ]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            out = json.loads(r.stdout.strip().splitlines()[-1])
            return out.get("id")
    except Exception as e:
        log.error(f"seal failed: {e}")
    return None


def _deploy(service: str, compose_file: str) -> tuple[bool, str]:
    """Pull latest image + restart only the named service."""
    pull = subprocess.run(
        ["docker", "compose", "-f", compose_file, "pull", service],
        capture_output=True, text=True, timeout=120
    )
    if pull.returncode != 0:
        return False, f"pull failed: {pull.stderr[:200]}"
    up = subprocess.run(
        ["docker", "compose", "-f", compose_file, "up", "-d", "--no-deps", service],
        capture_output=True, text=True, timeout=120
    )
    if up.returncode != 0:
        return False, f"up failed: {up.stderr[:200]}"
    return True, up.stdout.strip()[:400]


@app.get("/health")
def health():
    return {"ok": True, "service": "gitops-receiver", "registered_services": list(COMPOSE_MAP.keys())}


@app.post("/hook")
async def hook(
    request: Request,
    x_hub_signature_256: str = Header(default=""),
):
    body = await request.body()
    if not _verify_hmac(body, x_hub_signature_256):
        raise HTTPException(status_code=403, detail="invalid signature")
    try:
        payload = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="bad json")

    service = payload.get("service", "")
    image   = payload.get("image", "")
    if not service:
        raise HTTPException(status_code=400, detail="missing service")
    if service not in COMPOSE_MAP:
        raise HTTPException(status_code=404, detail=f"service '{service}' not in compose map")

    compose_file = COMPOSE_MAP[service]
    log.info(f"deploying {service} from {compose_file}")
    ok, msg = _deploy(service, compose_file)
    outcome = "success" if ok else "failed"
    receipt_id = _seal_receipt(service, image, outcome, {
        "compose_file": compose_file, "deploy_msg": msg, "triggered_by": "webhook"
    })
    return {
        "ok": ok, "service": service, "outcome": outcome,
        "receipt_id": receipt_id, "msg": msg[:200]
    }
