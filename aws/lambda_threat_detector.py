"""
AWS Lambda Serverless Threat Detector Handler.
Event-driven serverless architecture for Amazon S3 log ingestion.

Triggered automatically whenever a new log CSV object is uploaded to the S3 bucket.
Parses records, evaluates security correlation rules, and publishes alarms to CloudWatch.
"""

import csv
import io
import json
import logging
import os
import urllib.parse
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client("s3")
cw_client = boto3.client("cloudwatch")

NAMESPACE = os.environ.get("CLOUDWATCH_NAMESPACE", "Wipro/CloudSecurityThreatDetector")
FAILED_THRESHOLD = int(os.environ.get("FAILED_ATTEMPT_THRESHOLD", "4"))


def lambda_handler(event, context):
    """
    AWS Lambda entrypoint triggered by Amazon S3 ObjectCreated events.
    """
    logger.info("Received S3 Event: %s", json.dumps(event))

    records_processed = 0
    threats_flagged = 0

    for record in event.get("Records", []):
        bucket = record["s3"]["bucket"]["name"]
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"], encoding="utf-8")

        logger.info("Processing S3 object: s3://%s/%s", bucket, key)

        try:
            # 1. Fetch CSV object from S3
            response = s3_client.get_object(Bucket=bucket, Key=key)
            lines = response["Body"].read().decode("utf-8").splitlines()
            reader = csv.DictReader(lines)

            events = list(reader)
            records_processed += len(events)

            # 2. Correlate Failed Logins (Brute Force Detection)
            user_failures = {}
            for row in events:
                user = row.get("username", "UNKNOWN")
                status = row.get("status", "").upper()
                if status in ("FAILED", "FAILURE"):
                    user_failures[user] = user_failures.get(user, 0) + 1

            for user, count in user_failures.items():
                if count >= FAILED_THRESHOLD:
                    threats_flagged += 1
                    logger.warning("[ALERT] High failure count for user %s: %d attempts", user, count)

            # 3. Publish Telemetry Metrics to Amazon CloudWatch
            cw_client.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=[
                    {"MetricName": "ServerlessLogsIngested", "Value": len(events), "Unit": "Count"},
                    {"MetricName": "ServerlessThreatsDetected", "Value": threats_flagged, "Unit": "Count"},
                ],
            )

        except Exception as e:
            logger.error("Error processing object %s from bucket %s: %s", key, bucket, str(e))
            raise e

    return {
        "statusCode": 200,
        "body": json.dumps({
            "message": "Log processing complete",
            "records_processed": records_processed,
            "threats_flagged": threats_flagged,
        }),
    }
