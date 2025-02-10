import json
import time
import boto3
import logging

logger = logging.getLogger(__name__)


class AWSSessionManager:
    def __init__(self, creds_json, role_arn, role_session_name, duration_seconds=3600):
        self.session = None
        self.refresh_time = 0

        if not creds_json:
            logger.warning("Disabling Session Manager")
            return

        self.creds_json = json.loads(creds_json)
        self.role_arn = role_arn
        self.role_session_name = role_session_name
        self.duration_seconds = duration_seconds

    def use_session_manager(self) -> bool:
        return hasattr(self, "creds_json") and self.creds_json is not None

    def get_session(self):
        current_time = time.time()
        # Refresh credentials if they're expired or about to expire (30 mins buffer)
        if current_time >= self.refresh_time - 1800:
            self._refresh_credentials()
        if not self.session:
            raise Exception("Unable to refresh credentials")
        return self.session

    def _refresh_credentials(self):
        try:
            # Create STS client using SAML credentials
            sts = boto3.client(
                "sts",
                aws_access_key_id=self.creds_json["AccessKeyId"],
                aws_secret_access_key=self.creds_json["SecretAccessKey"],
                aws_session_token=self.creds_json["SessionToken"],
            )

            # Assume role
            response = sts.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName=self.role_session_name,
                DurationSeconds=self.duration_seconds,
            )

            # Create new session with assumed role credentials
            self.session = boto3.Session(
                aws_access_key_id=response["Credentials"]["AccessKeyId"],
                aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
                aws_session_token=response["Credentials"]["SessionToken"],
            )

            # Set refresh time
            self.refresh_time = time.time() + self.duration_seconds

        except Exception as e:
            logger.error(f"Error refreshing credentials: {e}")
            raise
