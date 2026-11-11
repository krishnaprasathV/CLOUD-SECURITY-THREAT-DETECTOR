"""
AWS Cloud Integration Module for Cloud Security Threat Detector.
Maps to Wipro CPPE Module 4 (Cloud Security & AWS Architecture).

Supports:
- Amazon S3 (log object storage)
- Amazon CloudWatch (custom security metric publishing)
- AWS Lambda telemetry simulation
- Graceful offline fallback for restricted AWS Academy Learner Lab accounts.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from config import Config
from database import log_audit

logger = logging.getLogger(__name__)

# Try importing boto3
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class AWSIntegrationService:
    """Manages AWS service interactions with offline simulation mode."""

    def __init__(self):
        self.offline_mode = Config.AWS_OFFLINE_MODE
        self.region = Config.AWS_REGION
        self.s3_bucket = Config.AWS_S3_BUCKET
        self.namespace = Config.AWS_CLOUDWATCH_NAMESPACE

        self.s3_client = None
        self.cw_client = None
        self.credentials_valid = False

        if not self.offline_mode and BOTO3_AVAILABLE:
            self._init_aws_clients()

    def _init_aws_clients(self):
        """Initializes boto3 clients using standard AWS credential provider chain."""
        try:
            session = boto3.Session(region_name=self.region)
            # Verify credentials with STS
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            self.credentials_valid = True
            logger.info("AWS Credentials verified successfully for ARN: %s", identity.get("Arn"))

            self.s3_client = session.client("s3")
            self.cw_client = session.client("cloudwatch")
        except Exception as e:
            logger.warning("AWS client initialization skipped: %s. Defaulting to Offline Mode.", e)
            self.offline_mode = True
            self.credentials_valid = False

    def upload_log_to_s3(self, file_content: str, object_name: str) -> Dict[str, Any]:
        """
        Uploads a raw CSV log file to Amazon S3.
        In offline mode, simulates successful S3 object storage.
        """
        if self.offline_mode or not self.credentials_valid or not self.s3_client:
            # Simulated offline S3 ingestion
            simulated_s3_uri = f"s3://{self.s3_bucket}/raw-logs/{object_name}"
            log_audit(
                actor="System/ETL",
                action="AWS_S3_SIMULATED_UPLOAD",
                details=f"Simulated S3 upload to {simulated_s3_uri} ({len(file_content)} bytes)",
            )
            return {
                "success": True,
                "mode": "Simulated (Learner Lab / Offline)",
                "s3_uri": simulated_s3_uri,
                "bucket": self.s3_bucket,
                "key": f"raw-logs/{object_name}",
                "bytes": len(file_content),
            }

        try:
            self.s3_client.put_object(
                Bucket=self.s3_bucket,
                Key=f"raw-logs/{object_name}",
                Body=file_content.encode("utf-8"),
                ContentType="text/csv",
                ServerSideEncryption="AES256",
            )
            s3_uri = f"s3://{self.s3_bucket}/raw-logs/{object_name}"
            log_audit(actor="System/ETL", action="AWS_S3_UPLOAD", details=f"Uploaded to {s3_uri}")
            return {
                "success": True,
                "mode": "Live AWS Cloud",
                "s3_uri": s3_uri,
                "bucket": self.s3_bucket,
                "key": f"raw-logs/{object_name}",
            }
        except Exception as e:
            logger.error("Failed to upload to S3: %s", e)
            return {
                "success": False,
                "error": str(e),
                "mode": "Live AWS Cloud",
            }

    def publish_threat_metric(self, metric_name: str, value: float, unit: str = "Count") -> Dict[str, Any]:
        """
        Publishes custom telemetry metric to Amazon CloudWatch.
        In offline mode, logs metric to application audit stream.
        """
        if self.offline_mode or not self.credentials_valid or not self.cw_client:
            log_audit(
                actor="DetectionEngine",
                action="CLOUDWATCH_SIMULATED_METRIC",
                details=f"Metric: {metric_name} = {value} ({unit}) in namespace {self.namespace}",
            )
            return {
                "success": True,
                "mode": "Simulated (Learner Lab / Offline)",
                "metric_name": metric_name,
                "value": value,
                "namespace": self.namespace,
            }

        try:
            self.cw_client.put_metric_data(
                Namespace=self.namespace,
                MetricData=[
                    {
                        "MetricName": metric_name,
                        "Value": value,
                        "Unit": unit,
                        "Timestamp": datetime.now(timezone.utc),
                    }
                ],
            )
            return {
                "success": True,
                "mode": "Live AWS CloudWatch",
                "metric_name": metric_name,
                "value": value,
            }
        except Exception as e:
            logger.error("Failed to publish CloudWatch metric: %s", e)
            return {"success": False, "error": str(e)}

    def get_cloud_status(self) -> Dict[str, Any]:
        """Returns the operational status of AWS connectivity."""
        return {
            "boto3_installed": BOTO3_AVAILABLE,
            "offline_mode_active": self.offline_mode,
            "credentials_valid": self.credentials_valid,
            "region": self.region,
            "s3_target_bucket": self.s3_bucket,
            "cloudwatch_namespace": self.namespace,
            "message": (
                "Operating in Offline Simulation Mode (Safe for AWS Academy Learner Lab)"
                if self.offline_mode or not self.credentials_valid
                else "Connected to Live AWS Cloud Services"
            ),
        }
