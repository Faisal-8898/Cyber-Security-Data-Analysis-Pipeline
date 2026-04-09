"""pipeline/core.py — task decorator, structured logger, git hash."""
import logging
import subprocess
import sys
from datetime import datetime
from functools import wraps
from pathlib import Path
import os

LOG_DIR = Path(os.getenv("PIPELINE_LOG_DIR", "/tmp/iot-pipeline/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "pipeline.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("pipeline")


def get_pipeline_version() -> str:
    """Returns the current git short hash, or 'unversioned'."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or "unversioned"
    except Exception:
        return "unversioned"


def task(name: str):
    """Decorator: wraps a pipeline step with start/done/fail logging."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            logger.info(f"START task={name}")
            start = datetime.now()
            try:
                result = fn(*args, **kwargs)
                elapsed = (datetime.now() - start).total_seconds()
                logger.info(f"DONE  task={name} elapsed={elapsed:.1f}s")
                return result
            except Exception as e:
                elapsed = (datetime.now() - start).total_seconds()
                logger.error(
                    f"FAIL  task={name} elapsed={elapsed:.1f}s error={e}",
                    exc_info=True,
                )
                return None
        return wrapper
    return decorator
