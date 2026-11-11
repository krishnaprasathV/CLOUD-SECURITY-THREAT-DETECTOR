"""
Config module for Cloud Security Threat Detector.
Handles environment variables, threshold defaults, and application constants.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load .env if present
load_dotenv(BASE_DIR / ".env")


class Config:
    """Application configuration."""

    # Flask Settings
    SECRET_KEY = os.getenv("SECRET_KEY", "wipro-cppe-cloud-sec-detector-2026-secret")
    DEBUG = os.getenv("FLASK_DEBUG", "0") in ("1", "true", "True")
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))

    # File uploads & storage
    DATABASE_PATH = str(BASE_DIR / os.getenv("DATABASE_PATH", "threat_detector.db"))
    UPLOAD_FOLDER = str(BASE_DIR / os.getenv("UPLOAD_FOLDER", "data/uploads"))
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH_MB", "16")) * 1024 * 1024
    ALLOWED_EXTENSIONS = {".csv"}

    # Detection Engine Thresholds (Configurable defaults)
    DEFAULT_FAILED_ATTEMPT_THRESHOLD = int(os.getenv("DETECTION_FAILED_ATTEMPT_THRESHOLD", "4"))
    DEFAULT_TIME_WINDOW_MINUTES = int(os.getenv("DETECTION_TIME_WINDOW_MINUTES", "15"))
    DEFAULT_SPRAY_USER_COUNT = int(os.getenv("DETECTION_SPRAY_USER_COUNT", "3"))
    DEFAULT_VELOCITY_THRESHOLD = int(os.getenv("DETECTION_VELOCITY_THRESHOLD", "10"))
    DEFAULT_VELOCITY_WINDOW_MINUTES = int(os.getenv("DETECTION_VELOCITY_WINDOW_MINUTES", "5"))

    # Generative AI & Explainability
    ENABLE_LOCAL_EXPLAINER = os.getenv("ENABLE_LOCAL_EXPLAINER", "true").lower() == "true"
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "local_rule_based")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

    # AWS Academy / Learner Lab settings
    AWS_OFFLINE_MODE = os.getenv("AWS_OFFLINE_MODE", "true").lower() == "true"
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    AWS_S3_BUCKET = os.getenv("AWS_S3_BUCKET", "wipro-security-threat-logs-demo")
    AWS_CLOUDWATCH_NAMESPACE = os.getenv(
        "AWS_CLOUDWATCH_NAMESPACE", "Wipro/CloudSecurityThreatDetector"
    )

    @classmethod
    def ensure_directories(cls):
        """Ensure required data and upload directories exist."""
        os.makedirs(cls.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Path(cls.DATABASE_PATH).parent, exist_ok=True)
