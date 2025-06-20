#!/usr/bin/env python3
import re
import sys
import json
import requests
import argparse
from urllib.parse import urljoin
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    PURPLE = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class JSSecurityScanner:
    def __init__(self, verbose=False, threads=5):
        self.verbose = verbose
        self.threads = threads
        self.findings = defaultdict(list)
        self.common_js_paths = [
            'app.js', 'main.js', 'script.js', 'bundle.js',
            'vendor.js', 'runtime.js', 'chunk.js', 'assets/js/',
            'static/js/', 'js/', 'dist/js/', 'build/js/'
        ]
        
        # Common library patterns to ignore
        self.common_libs = [
            'jquery', 'angular', 'bootstrap', 'isotope', 
            'react', 'vue', 'lodash', 'underscore',
            'modernizr', 'moment', 'chart', 'bibtex',
            'fontawesome', 'popper', 'axios'
        ]

        # Comprehensive secret detection patterns
        self.secret_patterns = {
            # General credentials
            'general_creds': re.compile(
                r'(access_id|access_key|access_secret|access_token|access_token_secret|'
                r'account_key|account_number|account_sid|adb_private_key|address|admin_email|'
                r'admin_key|admin_pass|admin_password|admin_private_key|admin_secret|admin_token|'
                r'algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|'
                r'amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|'
                r'api\.googlemaps AIza|api_auth|api_auth_key|api_auth_token|api_endpoint|api_key|'
                r'api_key_secret|api_key_sid|api_secret|api_token|api_username|apikey|apiKey|'
                r'apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|app_secret_key|'
                r'appkey|appkeysecret|application_key|appsecret|appspot|auth|auth_cookie|auth_hash|'
                r'auth_key|auth_login|auth_passphrase|auth_password|auth_secret|auth_token|'
                r'auth0_client_id|auth0_client_secret|authConfig|authorization|authorization_header|'
                r'authorization_token|authorizationToken|aws_access|aws_access_key|'
                r'aws_access_key_id|aws_auth|aws_bucket|aws_iam_user|aws_instance_id|aws_key|'
                r'aws_region|aws_region_name|aws_resource_arn|aws_s_bucket|aws_secret|'
                r'aws_secret_access_key|aws_secret_key|aws_secret_token|aws_token|aws_user_key|'
                r'AWSSecretKey|azure_access_token|azure_account_key|azure_account_name|'
                r'azure_blob_key|azure_client_id|azure_client_secret|azure_devops_key|'
                r'azure_function_key|azure_key|azure_secret_key|azure_sql_server|'
                r'azure_storage_key|azure_subscription_id|azure_tenant_id|azure_webhook|'
                r'backup_password|backup_secret|bank_account|bank_code|bank_name|base64secret|'
                r'basic_auth|bearer|b2_app_key|bintray_apikey|bintray_gpg_password|bintray_key|'
                r'bintraykey|bitbucket_secret|bitly_client_id|bitly_client_secret|'
                r'bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|'
                r'bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|'
                r'built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|card_cvv|'
                r'card_expiry|card\[number\]|card\[cvc\]|card\[exp_month\]|cardholder_name|'
                r'cc_number|cert_password|certificate_password|checkout_session|cipher_key|'
                r'cipher_secret|cattle_access_key|cattle_secret_key|clojars_password|client_id|'
                r'client_key|client_secret|client_zpk_secret_key|cloud_api_key|'
                r'cloud_watch_aws_access_key|cloudant_password|cloudflare_account_id|'
                r'cloudflare_api_key|cloudflare_auth_key|cloudflare_zone_id|cloudinary_api_key|'
                r'cloudinary_api_secret|cloudinary_cloud_name|cloudinary_name|cloudinary_secret|'
                r'codecov_token|config|config\.js|config_key|config\.secret|connectionString|'
                r'conn\.login|connection_string|consumer_key|consumer_secret|cookie_key|'
                r'cookie_secret|credentials|creditCardNumber|credit_card_number|crypto_key|'
                r'csrf_token|cypress_record_key|custom_api_key|customer_id|database_key|'
                r'database_name|database_password|database_schema_test|database_secret|'
                r'database_uri|database_url|datadog_api_key|datadog_app_key|db_admin_password|'
                r'db_auth|db_auth_token|db_conn_string|db_connection_string|db_encryption_key|'
                r'db_host|db_pass|db_password|db_secret_key|db_secret_token|db_server|db_url|'
                r'db_user|db_user_key|db_username|dbpasswd|dbpassword|dbuser|debug=true|'
                r'debug_mode|deploy_password|digitalocean_api_key|digitalocean_key|'
                r'digitalocean_secret|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|'
                r'digitalocean_token|discord_token|django_secret_key|dob|docker_hub_password|'
                r'docker_key|docker_pass|docker_passwd|docker_password|docker_token|'
                r'dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|'
                r'dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|'
                r'elasticsearch_host|elasticsearch_key|elasticsearch_password|elasticsearch_port|'
                r'elasticsearch_username|email_host|email_key|email_password|email_secret|'
                r'email_user|encrypted_data|encryption_key|encryption_password|encryption_salt|'
                r'encryption_secret|env\.PASSWORD|env\.SECRET|eyJ|facebook_access_token|'
                r'facebook_app_id|facebook_client_id|facebook_secret|face_id|fb_client_id|'
                r'fb_secret|fcm_sender_id|fcm_server_key|firebaseConfig|firebase_api_key|'
                r'firebase_auth_domain|firebase_client_key|firebase_db_secret|firebase_db_url|'
                r'firebase_key|firebase_messaging_key|firebase_private_key|firebase_project_id|'
                r'firebase_secret|firebaseio\.com|first_name|flask_secret|ftp_host|ftp_key|'
                r'ftp_password|ftp_secret|ftp_url|ftp_user|ftp_username|gcp_key|gcp_keyfile|'
                r'gcp_project|gcp_project_id|gender|github_access_token|github_api_key|'
                r'github_client_id|github_client_secret|github_secret_key|github_token|'
                r'gitlab_api_key|gitlab_secret_key|gitlab_token|google_api_key|'
                r'google_auth_token|google_client_id|google_client_secret|google_oauth_token|'
                r'google_project_id|google_project_secret|gpay_client_secret|gpay_merchant_id|'
                r'gpay_merchant_key|gpg_key|gpg_passphrase|hash_secret|heroku_api_key|'
                r'heroku_auth|heroku_secret|host_url|http_auth|ibm_auth|ibmcloud_api_key|'
                r'id_card|identity_number|instagram_client_id|instagram_client_secret|'
                r'instagram_secret|instagram_token|internal_api|internal_url|invoice_id|'
                r'json_web_token|jwt|jwt_access_token|jwt_secret|jwt_token|kibana_password|'
                r'kibana_username|key_pass|kubeconfig|kubernetes_secret|last_name|ldap_password|'
                r'license_code|license_key|linode_api_key|linode_token|linkedin_api_key|'
                r'linkedin_client_id|linkedin_client_secret|linkedin_secret|mailchimp_api_key|'
                r'mailchimp_secret|mailerlite_api_key|mailgun_api_key|mailgun_public_key|'
                r'mailgun_secret|mailgun_secret_key|mandrill_api_key|mapbox_api_key|'
                r'mapbox_token|master_key|master_password|microsoft_app_id|'
                r'microsoft_app_password|microsoft_client_id|microsoft_client_secret|'
                r'mongodb\+srv://|mongodb://|mongodb_host|mongodb_key|mongodb_pass|'
                r'mongodb_password|mongodb_port|mongodb_uri|mongodb_user|mongo_uri|mysql_host|'
                r'mysql_password|mysql_url|mysql_user|netlify_auth_token|node_env|'
                r'notification_key|npm_token|oauth_client_id|oauth_client_secret|oauth_key|'
                r'oauth_token|oauth_token_secret|oauth2_client_id|oauth2_client_secret|'
                r'onesignal_api_key|onesignal_app_id|otp_secret|pass=|passphrase|'
                r'passport_number|passwd=|password|paypal_client_id|paypal_client_secret|'
                r'paypal_password|paypal_secret|paypal_secret_token|payment_intent|pg_database|'
                r'pg_host|pg_key|pg_password|pg_port|pg_user|pgp_key|pgp_passphrase|phone_number|'
                r'pin_code|pk_live_|PKCS8|plan_key|postgres_password|postgres_secret|postgres_user|'
                r'postgresql://|postgres:|postmark_api_key|private_hash|private_key|private_token|'
                r'production_server|project_id|proxy_auth|proxy_key|proxy_password|proxy_secret|'
                r'proxy_url|proxy_user|pusher_app_id|pusher_key|pusher_secret|push_key|push_secret|'
                r'push_token|recaptcha_key|recaptcha_secret|recaptcha_site_key|recovery_key|'
                r'recovery_token|redis_host|redis_password|redis_port|redis_uri|redis_url|'
                r'refresh_token|refresh_token_secret|reset_password_token|rsa_key|ruby_secret|'
                r's3_access_id|s3_access_key|s3_bucket|s3_bucket_name|s3_key|s3_secret|'
                r's3_secret_key|secret|secret_id|secret_key|secret_password|secret_phrase|'
                r'secret_token|secure_token|security_password_salt|security_token|'
                r'sendgrid_api_key|sendgrid_secret|sendgrid_secret_key|sentry_auth_token|'
                r'sentry_dsn|sentry_key|server_encryption_key|server_password|server_secret_key|'
                r'server_token|service_account|service_key|service_password|service_secret|'
                r'session_id|session_key|session_secret|session_token|sftp_host|sftp_password|'
                r'sftp_user|shopify_api_key|shopify_api_secret|shopify_token|signature|sin|'
                r'site:github\.com|slack_bot_token|slack_token|slack_webhook|slack_webhook_url|'
                r'sms_api_key|sms_auth_key|sms_secret|sms_secret_key|smtp_access_key|smtp_auth|'
                r'smtp_host|smtp_key|smtp_pass|smtp_password|smtp_secret|smtp_secret_key|'
                r'smtp_server|smtp_user|smtp_username|sns_access_key|sns_secret_key|'
                r'sns_topic_arn|sort_code|sqs_access_key|sqs_queue_url|sqs_secret_key|ssh_host|'
                r'ssh_key|ssh_password|ssh_private_key|ssh_user|ssh-rsa|ssl_cert|ssl_key|'
                r'ssl_passphrase|ssn|sso_key|sso_password|sso_secret|sso_token|staging_server|'
                r'storage_account|storage_bucket|storage_key|storage_secret|stripe_api_key|'
                r'stripe_client_id|stripe_client_secret|stripe_publishable_key|stripe_secret|'
                r'stripe_secret_key|stripe_webhook_secret|superuser_password|tax_id|'
                r'telegram_bot_token|telegram_token|thumbprint|ticket_id|ticket_number|token|'
                r'totp_secret|travis_api_token|travis_yml|twilio_account_key|twilio_account_sid|'
                r'twilio_account_token|twilio_auth_token|twitter_api_key|twitter_secret|'
                r'type":"service_account"|user_hash|user_password|user_private_key|user_secret|'
                r'user_token|vault_key|webhook_password|webhook_secret|webhook_url|'
                r'wechat_api_key|wechat_secret|x509|youtube_api_key|zip_code)\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{10,100})["\']?',
                re.I
            ),

            # Payment and financial patterns
            'payment_creds': re.compile(
                r'(card_cvv|card_expiry|card\[number\]|card\[cvc\]|card\[exp_month\]|'
                r'cardholder_name|cc_number|checkout_session|payment_intent|'
                r'stripe_api_key|stripe_secret_key|paypal_client_secret)\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{10,100})["\']?',
                re.I
            ),

            # Database connection strings
            'db_conn_strings': re.compile(
                r'(mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@|'
                r'postgres(?:ql)?:\/\/[^:]+:[^@]+@|'
                r'mysql:\/\/[^:]+:[^@]+@|'
                r'redis:\/\/[^:]+:[^@]+@|'
                r'sqlserver:\/\/[^:]+:[^@]+@)'
                r'oracle:\/\/[^:\s]+:[^@\s]+@|'  
                r'snowflake:\/\/[^:\s]+:[^@\s]+@|' 
                r'sqlite:\/\/\/[^\'"\s]+|'   
                r'couchdb:\/\/[^:\s]+:[^@\s]+@|' 
                r'cassandra:\/\/[^:\s]+:[^@\s]+@|'  
                r'neo4j:\/\/[^:\s]+:[^@\s]+@',
                re.I
            ),

            # Cloud service credentials
            'cloud_creds': re.compile(
                r'(aws_access_key_id|aws_secret_access_key|azure_account_key|'
                r'aws_access_key_id|aws_secret_access_key|aws_session_token|'
                r'amazon_aws_access_key_id|amazon_aws_secret_access_key|'
                r'azure_account_key|azure_storage_account|azure_client_secret|'
                r'gcp_key|gcp_secret|google_(?:api_key|project_secret|client_secret)|'
                r'digitalocean_api_key|do_api_key|'
                r'heroku_api_key|heroku_oauth_token|'
                r'cloudflare_api_key|cloudflare_token|cf_api_key|'
                r'alibaba_access_key_id|alibaba_access_key_secret|'
                r'firebase_api_key'
                r'auth0_client_secret|'
                r'salesforce_access_token|'
                r'ibm_cloud_api_key|'
                r'openstack_auth_token|'
                r'linode_api_key|'
                r'gcp_key|google_project_secret|digitalocean_api_key|'
                r'heroku_api_key|cloudflare_api_key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{20,100})["\']?',
                re.I
            ),

            # Social media and communication tokens
            'social_tokens': re.compile(
                r'(facebook_access_token|twitter_api_key|twitter_secret|'
                r'twitter_api_key|twitter_secret|twitter_access_token|twitter_access_token_secret|'
                r'discord_token|discord_client_secret|'
                r'slack_bot_token|slack_user_token|slack_webhook_url|'
                r'telegram_bot_token|telegram_api_key|'
                r'linkedin_client_secret|linkedin_access_token|'
                r'github_access_token|github_token|'
                r'instagram_access_token|'
                r'whatsapp_token|'
                r'twilio_account_sid|twilio_auth_token|'
                r'signal_api_key'
                r'discord_token|slack_bot_token|telegram_bot_token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{20,100})["\']?',
                re.I
            ),

            # Email service credentials
            'email_creds': re.compile(
                r'(smtp_pass|smtp_password|sendgrid_api_key|mailgun_api_key|'
                r'smtp_pass|smtp_password|smtp_secret|smtp_token|'
                r'smtp_api_key|smtp_auth_token|'
                r'sendgrid_api_key|sendgrid_key|'
                r'mailgun_api_key|mailgun_private_key|'
                r'postmark_api_key|postmark_server_token|'
                r'mandrill_api_key|'
                r'sparkpost_api_key|'
                r'zoho_mail_token|'
                r'yahoo_app_password'
                r'gmail_client_secret|gmail_refresh_token|gmail_access_token|'
                r'aws_ses_smtp_password|aws_ses_access_key|'
                r'postmark_api_key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{20,100})["\']?',
                re.I
            ),

            # API keys with specific patterns
            'specific_api_keys': re.compile(
                r'(AIza[0-9A-Za-z\-_]{35}|'  # Google API key
                r'sk_live_[0-9a-z]{24}|'     # Stripe secret key
                r'xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}|'  # Slack token
                r'gh[pousr]_[A-Za-z0-9_]{36}|'  # GitHub token
                r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)'  # JWT
           ),


            # Private keys
            'private_keys': re.compile(
                r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[\s\S]*?-----END \1 PRIVATE KEY-----'
                r'-----BEGIN (?:'
                r'RSA|'                          # RSA private key
                r'DSA|'                          # DSA private key
                r'EC|ECPRIVATEKEY|'             # EC (Elliptic Curve)
                r'OPENSSH|'                     # OpenSSH private key
                r'PRIVATE KEY|'                 # Generic label (used in PKCS#8 format)
                r'ENCRYPTED PRIVATE KEY|'       # Encrypted PKCS#8
                r'SSH2 ENCRYPTED PRIVATE KEY|'  # SSH2 encrypted format
                r'PGP PRIVATE KEY BLOCK'        # PGP private key
                r')-----[\s\S]*?-----END \1-----',
            ),

            # Sensitive personal information
            'personal_info': re.compile(
                r'(ssn|social_security_number|tax_id|dob|date_of_birth|'
                r'ssn|social_security_number|social_sec_number|sin|nin|tin|tax_id|'
                r'dob|date_of_birth|birth_date|'
                r'driver_license|driver_licence|dl_number|'
                r'passport_number|passport_no|'
                r'aadhaar|aadhaar_number|pan|pan_number|'
                r'national_id|identity_number|id_number|id_no|govt_id|'
                r'phone_number|address|zip_code|passport_number|'
                r'address|street_address|home_address|residential_address|'
                r'address|street_address|home_address|residential_address|'
                r'zip_code|postal_code|postcode'
                r'phone_number|mobile_number|contact_number|'
                r'driver_license|identity_number)\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{5,50})["\']?',
                re.I
            )
        }

        # Comprehensive API key patterns
        self.api_key_patterns = {
            "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
            "Firebase URL": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
            "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
            "AWS Secret Access Key": re.compile(r"(?i)aws(.{0,20})?(secret|private)?(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
            "Stripe Secret Key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
            "Stripe Public Key": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
            "SendGrid API Key": re.compile(r"SG\.[A-Za-z0-9_\-\.]{22,}"),
            "Twilio API Key": re.compile(r"SK[0-9a-fA-F]{32}"),
            "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
            "GitHub PAT": re.compile(r"ghp_[A-Za-z0-9]{36,}"),
            "GitLab PAT": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
            "Facebook Access Token": re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),
            "Heroku API Key": re.compile(r"heroku[a-z0-9]{32}"),
            "Mailgun API Key": re.compile(r"key-[0-9a-f]{32}"),
            "Shopify Access Token": re.compile(r"shpat_[a-fA-F0-9]{32}"),
            "DigitalOcean Token": re.compile(r"dop_v1_[a-f0-9]{64}"),
            "Algolia API Key": re.compile(r"(ALGOLIA|algolia)[a-zA-Z0-9_\-]{10,}"),
            "MongoDB URI": re.compile(r"mongodb\+srv://[^:]+:[^@]+@[^\"'\s]+"),
            "Auth0 Client Secret": re.compile(r"(?i)client_secret['\"]?\s*[:=]\s*['\"][\w-]{10,}['\"]"),
            "PayPal Access Token": re.compile(r"access_token\$production\$[A-Za-z0-9]+"),
            "Azure Connection String": re.compile(r"Endpoint=sb://[a-z0-9\-]+\.servicebus\.windows\.net/;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+"),
            "Netlify Token": re.compile(r"netlify[a-zA-Z0-9\-_]{20,}"),
            "OpenAI API Key": re.compile(r"sk-[A-Za-z0-9]{48}"),
            "Bitly Access Token": re.compile(r"[a-zA-Z0-9_]{30,}=="),
            "Cloudinary URL": re.compile(r"cloudinary://[0-9a-zA-Z]+:[0-9a-zA-Z]+@[0-9a-zA-Z]+"),
            "Mapbox Token": re.compile(r"pk\.[a-z0-9\.\-]{60,}"),
            "Sentry DSN": re.compile(r"https://[0-9a-f]+@[a-z0-9\-.]+/[0-9]+"),
            "Postman API Key": re.compile(r"PMAK-[a-f0-9]{24}-[a-f0-9]{34}"),
            "Asana Personal Token": re.compile(r"0/[0-9a-f]{32}"),
            "Trello Key": re.compile(r"[a-f0-9]{32}"),
            "Pusher App Key": re.compile(r"(?i)pusher_?(app)?_?(key)?['\"]?\s*[:=]\s*['\"][a-z0-9]{20,}['\"]"),
            "Ably API Key": re.compile(r"[a-zA-Z0-9]{30}\.[a-zA-Z0-9]{30}"),
            "Segment Write Key": re.compile(r"[0-9a-f]{32}"),
            "Intercom App ID": re.compile(r"app_id=['\"]?[a-z0-9]{8}['\"]?"),
            "Crisp Website ID": re.compile(r"crisp-client/website-[a-f0-9]{20,}"),
            "Amplitude API Key": re.compile(r"amplitudeApiKey['\"]?\s*[:=]\s*['\"][a-z0-9]{32}['\"]"),
            "Datadog API Key": re.compile(r"dd_api_key\s*[:=]\s*['\"][a-z0-9]{32}['\"]"),
            "Bugsnag API Key": re.compile(r"bugsnagApiKey['\"]?\s*[:=]\s*['\"][a-f0-9]{32}['\"]"),
            "OneSignal App ID": re.compile(r"onesignal_app_id['\"]?\s*[:=]\s*['\"][a-z0-9\-]{36}['\"]"),
            "Zoho Access Token": re.compile(r"1000\.[a-z0-9]{20,}\.[a-z0-9]{20,}"),
            "Discord Bot Token": re.compile(r"([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})"),
            "Telegram Bot Token": re.compile(r"[0-9]{9}:[A-Za-z0-9_-]{35}"),
            "Linear API Key": re.compile(r"lin_api_[a-z0-9]{40}"),
            "Notion Token": re.compile(r"secret_[a-zA-Z0-9]{43}"),
            "ClickUp API Key": re.compile(r"pk_[a-z0-9]{30,}"),
            "Plaid Client ID": re.compile(r"(?i)plaid.+client.+(id|key)['\"]?\s*[:=]\s*['\"][a-z0-9]{20,}['\"]"),
            "Square Access Token": re.compile(r"sq0atp-[0-9A-Za-z\-_]{22}"),
            "Okta API Token": re.compile(r"00[a-zA-Z0-9]{38}"),
            "HubSpot API Key": re.compile(r"[a-f0-9]{32}-us[0-9]{1,2}"),
            "Typeform API Key": re.compile(r"tfp_[a-z0-9]{32}"),
            "Dropbox API Key": re.compile(r"sl\.[A-Za-z0-9\-_]{60,}"),
            "Apple Client Secret": re.compile(r"eyJhbGciOi.*eyJpc3MiOi.*"),
            "Bitbucket App Password": re.compile(r"[a-z0-9]{20}"),
            "Vercel Token": re.compile(r"vercelToken['\"]?\s*[:=]\s*['\"][a-zA-Z0-9\-_]{24,}['\"]"),
            "Fastly API Key": re.compile(r"fastly[a-zA-Z0-9]{32,}"),
            "Imgix Token": re.compile(r"ixlib=rb-1.2.1&q=[0-9]+&s=[a-f0-9]{32}"),
            "IPinfo Token": re.compile(r"token=[a-z0-9]{32}"),
            "Freshdesk API Key": re.compile(r"[a-z0-9]{32}:X"),
            "Supabase API Key": re.compile(r"supabaseKey['\"]?\s*[:=]\s*['\"][a-zA-Z0-9\-_]{40,}['\"]"),
            "Hasura Admin Secret": re.compile(r"x-hasura-admin-secret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9\-_]{32,}['\"]"),
            "Recurly API Key": re.compile(r"recurly_api_key['\"]?\s*[:=]\s*['\"][a-f0-9]{40}['\"]"),
            "Chargebee API Key": re.compile(r"chargebee_api_key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_]{20,}['\"]"),
            "Klaviyo API Key": re.compile(r"pk_[a-zA-Z0-9]{20,}"),
            "Mailchimp API Key": re.compile(r"[a-f0-9]{32}-us[0-9]{1,2}"),
            "Google Analytics Secret": re.compile(r"G-[A-Z0-9]{10}"),
            "Mixpanel Token": re.compile(r"mixpanel\.init\(['\"]([a-f0-9]{32})['\"]\)"),
            "Heap App ID": re.compile(r"heap.load\(['\"]([0-9]{9})['\"]\)"),
            "Contentful Access Token": re.compile(r"CFPAT-[a-zA-Z0-9\-_]{40,}"),
            "Sanity Token": re.compile(r"sk[0-9a-z]{32,}"),
            "Strapi Token": re.compile(r"strapiToken['\"]?\s*[:=]\s*['\"][a-z0-9\-_]{40,}['\"]"),
            "Rollbar Access Token": re.compile(r"post_server_item: ['\"][a-z0-9]{32}['\"]"),
            "LogRocket App ID": re.compile(r"appId: ['\"][a-z0-9]{10}/[a-z0-9]{5}['\"]"),
            "LaunchDarkly SDK Key": re.compile(r"ldClient\(['\"][a-z0-9]{20,}['\"]\)"),
            "Appwrite Key": re.compile(r"APPWRITE_API_KEY=[a-zA-Z0-9_]{30,}"),
            "Magic.link Secret": re.compile(r"magicPublishableKey['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_]{30,}['\"]"),
            "Clerk.dev API Key": re.compile(r"clerk_publishable_key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9]{30,}['\"]"),
            "Keycloak Client Secret": re.compile(r"keycloakClientSecret['\"]?\s*[:=]\s*['\"][a-zA-Z0-9\-_]{32,}['\"]"),
            "Vault Token": re.compile(r"s\.([a-z0-9]{20,})"),
            "Cloudflare API Token": re.compile(r"cf_api_key['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_]{37}['\"]"),
            "Firebase Cloud Messaging Key": re.compile(r"AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}"),
            "Microsoft Graph Token": re.compile(r"Bearer ey[A-Za-z0-9\-\_]+?\.[A-Za-z0-9\-\_]+?\.[A-Za-z0-9\-\_]+"),
            "LINE Messaging API": re.compile(r"LINE_ACCESS_TOKEN=['\"][A-Za-z0-9+/]{30,}['\"]"),
            "Telegram Bot API Token": re.compile(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}"),
            "Tencent Cloud Secret": re.compile(r"TENCENTCLOUD_SECRET_ID=['\"][A-Z0-9]{20}['\"]"),
            "Baidu API Key": re.compile(r"BAIDU_API_KEY=['\"][A-Za-z0-9]{32}['\"]"),
            "SAP Client Secret": re.compile(r"sapClientSecret['\"]?\s*[:=]\s*['\"][A-Za-z0-9]{32,}['\"]"),
            "Oracle Cloud API Key": re.compile(r"ocid1\.tenancy\.oc1..*"),
        }

        # Enhanced endpoint patterns organized by category
        self.endpoint_patterns = [
            # Authentication & Session Management
            r'/api/login', r'/auth/signin', r'/users/authenticate',
            r'/api/logout', r'/auth/signout', r'/token/revoke',
            r'/auth/refresh', r'/token/refresh', r'/api/jwt/refresh',
            r'/auth/reset', r'/forgot-password', r'/password/reset',
            r'/api/otp', r'/mfa', r'/auth/2fa', r'/verify-code',
            r'/sso/callback', r'/oauth/callback', r'/openid/authorize',
            
            # Access Control & Privilege Escalation
            r'/users/me', r'/users/list', r'/admin/users',
            r'/api/admin/settings', r'/admin/config', r'/privileged',
            r'/api/roles', r'/api/permissions', r'/isAdmin',
            r'/user/upgrade-role', r'/grant-access', r'/assign-role',
            r'/users/me|/users/list|/users/search|/users/all|'
            r'/admin/users|/admin/roles|/admin/logs|/admin/config|/admin/settings|'
            r'/api/admin/settings|/api/admin/config|/api/admin/.*?|'
            r'/api/roles|/api/permissions|/api/privileges|'
            r'/privileged|/superuser|/elevated-access|'
            r'/isAdmin|/is-admin|/check-admin|'
            r'/user/upgrade-role|/user/promote|/user/assign-role|'
            r'/grant-access|/assign-role|/set-role|/change-role|'
            r'/access-control|/access/override|/access/manage|'
            r'/debug/config|/debug/auth|/internal/roles|/internal/admin'
                  
            # Development & Debugging
            r'/__debug__', r'/debug/info', r'/debug/db',
            r'/test-endpoint', r'/test-api', r'/beta-api',
            r'/swagger', r'/api-docs', r'/openapi.json',
            r'/internal-api/', r'/api/private/', r'/api/experimental/',
            r'/healthcheck', r'/status', r'/sysinfo',
            
            # Data & Object Access
            r'/user/[^{}/]+', r'/profile/[^{}/]+', r'/records/[^{}/]+',
            r'/data/export', r'/report/download', r'/logs',
            r'/backup', r'/database/export', r'/dump',
            
            # File Handling
            r'/upload', r'/file/upload', r'/image/upload',
            r'/file/delete', r'/files/list', r'/attachments',
            r'/import', r'/csv/upload', r'/media/upload',
            
            # Download/Export/SSRF
            r'/export/pdf', r'/generate-report', r'/download/file',
            r'/proxy\?url=', r'/fetch\?link=', r'/image/fetch',
            r'/url/download', r'/preview\?url=', r'/api/fetch\?uri=',
            
            # Real-time Communication
            r'/ws', r'/socket.io/', r'/live/', r'/events/stream',
            r'/notifications', r'/activity-feed', r'/messages',
            
            # Feature Flags
            r'/flags', r'/feature-status', r'/experiments',
            r'/enable-beta', r'/api/feature-toggles',
            r'/api/hidden-feature', r'/dev-only-endpoint',
            
            # Configuration Exposure
            r'/config', r'/env', r'/settings', r'/init',
            r'/firebase-config.js', r'/runtime-config.json',
            r'/app-config.json', r'/api/public-config',
            
            # Token Leakage
            r'/get-token', r'/public-key', r'/client-secrets',
            r'/reset-api-key', r'/generate-token', r'/access-token',
            
            # Legacy APIs
            r'/v1/', r'/old/', r'/deprecated', r'/legacy-api/',
            r'/v0/api', r'/beta-api', r'/experimental-endpoint',
            r'/mobile-api', r'/flash-api', r'/ie-support',
            r'/v0(?:/|$)|/v1(?:/|$)|/v1\.0(?:/|$)|/v1_0(?:/|$)|'      # Older versions
            r'/api/v0|/api/v1(?:/|$)|/rest/v1(?:/|$)|'               # RESTful versioned endpoints
            r'/old/|/old-api/|/legacy/|/legacy-api/|'                # Legacy labels
            r'/deprecated|/deprecated-api|/obsolete|/sunset-api|'    # Deprecated markers
            r'/beta/|/beta-api|/experimental/|/experimental-api/|'   # Experimental & beta features
            r'/internal-api|/private-api|/shadow-api|/hidden-api|'   # Unofficial/internal APIs
            r'/test-api|/mock-api|/dummy-api|/sandbox-api|'          # Used for test environments
            r'/dev-api|/staging-api|/qa-api|/alpha-api|'             # Lower environments
            r'/mobile-api|/android-api|/ios-api|/tablet-api|'        # Device-specific legacy APIs
            r'/flash-api|/silverlight-api|/activex/|/ie-support|'    # Legacy browser/tech support
            r'/windows98/|/blackberry/|/symbian/|/nokia/'            # Dead platforms (still show up!)
            r'/old_dashboard|/admin_legacy|/console/v1/|'            # Admin panels and legacy UIs
            r'/api1/|/legacyService/|/deprecatedEndpoint/|'          # Vendor-specific naming patterns
            r'/webservices/v1/|/soap-api/|/rpc/v1/|/xml-api/|'       # SOAP/XML/RPC style endpoints
            r'/v1/backup/|/v1/archive/|/archive-api/|'               # Archived/stale APIs
            r'/preprod/|/oldadmin/|/oldpanel/|/v1auth/|/api-old/'
             
            # Authentication Bypass
            r'/auth-bypass', r'/admin-bypass', r'/bypass-login',
            r'/emulate-user', r'/sudo-login', r'/impersonate',
            r'/test-login\?user=admin', r'/\?admin=true',
            
            # Interesting File Types
            r'\.json', r'\.map', r'\.php', r'\.action', r'\.do',
            r'\.zip', r'\.bak', r'\.old', r'\.swp', r'\.log'
        ]

        # Hidden functionality patterns
        self.hidden_functionality_patterns = {
            # Authentication/Privilege functions
            'auth_functions': re.compile(
                r'(\.|function\s+)(isAdmin|isSuperuser|makeAdmin|elevatePrivileges|'
                r'bypassAuth|sudoLogin|impersonateUser|emulateUser|forceLogin|'
                r'validateAdminToken)\s*\(', 
                re.I
            ),
            
            # Debug/Test mode indicators
            'debug_functions': re.compile(
                r'(\.|function\s+|var\s+|const\s+|let\s+|window\.)(enableDebugMode|'
                r'runTests|loadTestUser|initDevTools|showDebugPanel|showLogs)\s*[\(=]|'
                r'(debugMode\s*=\s*true|window\.(debug|__DEV__)\s*=\s*true)',
                re.I
            ),
            
            # Internal/hidden tools
            'internal_tools': re.compile(
                r'(\.|function\s+)(loadAdminTools|showInternalPanel|adminOverride|'
                r'accessControlPanel|openBackdoor|launchInternalTool|showDiagnostics)\s*\(',
                re.I
            ),
            
            # Dangerous actions
            'dangerous_actions': re.compile(
                r'(\.|function\s+)(deleteUser|resetDatabase|wipeLogs|clearUsers|'
                r'executeCommand|evalPayload|grantAccess)\s*\(',
                re.I
            ),
            
            # Feature flags/beta UI
            'feature_flags': re.compile(
                r'(\.|window\.)(featureFlags\.enableBeta|enableExperimentalUI|'
                r'toggleHiddenFeatures|loadBetaFeatures|isInternalUser|'
                r'isFeatureEnabled|betaUI\s*=\s*true)',
                re.I
            ),
            
            # API/endpoint indicators
            'api_indicators': re.compile(
                r'(\.|function\s+)(getSecretEndpoints|internalAPI|fetchPrivateData|'
                r'getAllTokens|adminAPI|downloadBackup|uploadShell)\s*\(',
                re.I
            ),
            
            # Token/credential access
            'token_access': re.compile(
                r'(\.|function\s+)(generateAdminToken|getJwtToken|getCredentials|'
                r'resetApiKey|retrieveSecrets)\s*\(',
                re.I
            ),
            
            # Other suspicious functions
            'suspicious_functions': re.compile(
                r'(\.|function\s+)(hiddenLogin|stealthMode|godMode|legacyLogin|'
                r'simulateSession|accessHiddenUI|invisibleLogout)\s*\(',
                re.I
            ),
            
            # Global variables
            'global_vars': re.compile(
                r'window\.(secretTools|superAdmin|internalConfig|adminAccess|'
                r'__EXPERIMENTAL__|debugToken)\s*=',
                re.I
            )
        }

        # Enhanced hardcoded credential patterns
        self.credential_patterns = {
            # Username/password variables
            'username_password': re.compile(
                r'(?:var|let|const|\.)\s*('
                r'username|password|user|pass|adminUser|adminPass|'
                r'loginUser|loginPassword|ftp_user|ftp_pass|db_user|db_pass'
                r')\s*=\s*["\'][^"\']+["\']',
                re.I
            ),
            
            # Email + password patterns
            'email_credentials': re.compile(
                r'(?:var|let|const|\.)\s*('
                r'email|user_email|user_email_address|email_login|'
                r'emailPassword|mailUser|mailPass'
                r')\s*=\s*["\'][^"\']+["\']',
                re.I
            ),
            
            # Tokens & secrets
            'tokens_secrets': re.compile(
                r'(?:var|let|const|\.)\s*('
                r'access_token|refresh_token|auth_token|jwt_token|'
                r'session_token|secret_token|api_token|client_secret|'
                r'consumer_secret|private_key|api_secret'
                r')\s*=\s*["\'][^"\']+["\']',
                re.I
            ),
            
            # Test/dev credentials
            'test_credentials': re.compile(
                r'(?:var|let|const|\.)\s*('
                r'testUser|testPassword|demoUser|demoPass|dev_user|'
                r'dev_pass|staging_user|staging_password|debug_user|debug_password'
                r')\s*=\s*["\'][^"\']+["\']',
                re.I
            ),
            
            # Service-specific keys
            'service_keys': re.compile(
                r'(?:var|let|const|\.)\s*('
                r'smtp_username|smtp_password|mailgun_user|mailgun_pass|'
                r'twilio_account_sid|twilio_auth_token|firebase_secret|'
                r'stripe_secret_key|github_token|aws_secret_key|db_connection_string'
                r')\s*=\s*["\'][^"\']+["\']',
                re.I
            ),
            
            # Other suspicious credential keys
            'suspicious_credentials': re.compile(
                r'(?:var|let|const|\.)\s*('
                r'root_user|root_password|admin_login|admin_credentials|'
                r'credentials|default_password|initial_password|'
                r'superuser_password|backup_user|system_password'
                r')\s*=\s*["\'][^"\']+["\']',
                re.I
            ),
            
            # Client-side storage patterns
            'client_storage': re.compile(
                r'(localStorage\.setItem\(|sessionStorage\[|document\.cookie\s*=\s*)'
                r'["\']('
                r'authToken|jwt|token|session|secret|credentials|'
                r'access_token|refresh_token|api_key'
                r')["\'][^)]*["\'][^"\']+["\']',
                re.I
            )
        }

        # Compile endpoint patterns into regex
        endpoint_patterns_str = '|'.join([p.replace('/', r'\/') for p in self.endpoint_patterns])
        self.endpoint_regex = re.compile(
            r'["\'](' + endpoint_patterns_str + r')[^"\']*["\']',
            re.I
        )

        # Severity mappings
        self.endpoint_severity = {
            'auth': 'high',
            'access_control': 'critical',
            'debug': 'medium',
            'data_access': 'high',
            'file_handling': 'medium',
            'ssrf': 'high',
            'realtime': 'medium',
            'feature_flags': 'low',
            'config': 'critical',
            'token': 'critical',
            'legacy': 'low',
            'bypass': 'critical',
            'file_types': 'low'
        }

        self.hidden_func_severity = {
            'auth_functions': 'critical',
            'debug_functions': 'high',
            'internal_tools': 'critical',
            'dangerous_actions': 'critical',
            'feature_flags': 'medium',
            'api_indicators': 'high',
            'token_access': 'critical',
            'suspicious_functions': 'high',
            'global_vars': 'medium'
        }

        self.credential_severity = {
            'username_password': 'high',
            'email_credentials': 'high',
            'tokens_secrets': 'critical',
            'test_credentials': 'medium',
            'service_keys': 'critical',
            'suspicious_credentials': 'high',
            'client_storage': 'high'
        }

        # Combine all patterns
        self.patterns = {
            **self.secret_patterns,
            **self.api_key_patterns,
            'endpoints': self.endpoint_regex,
            'ws_urls': re.compile(r'new WebSocket\(["\']([^"\']+)["\']'),
            'sensitive_funcs': re.compile(
                r'(?:\.|function\s+)(login|authenticate|auth|checkout|payment|token|password|verifyPassword|changePassword|updateCredentials|processPayment)'
                r'(?:\s*\(|\s*=|\s*:)',
                re.I
            ),
            **self.hidden_functionality_patterns,
            **self.credential_patterns
        }

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def log(self, message, level="info"):
        if self.verbose or level != "info":
            color = {
                "info": Colors.BLUE,
                "warning": Colors.YELLOW,
                "error": Colors.RED,
                "success": Colors.GREEN
            }.get(level, Colors.BLUE)
            prefix = {
                "info": "[*]",
                "warning": "[!]",
                "error": "[X]",
                "success": "[+]"
            }.get(level, "[*]")
            print(f"{color}{prefix}{Colors.END} {message}")

    def normalize_url(self, url):
        """Ensure URL has proper scheme and format"""
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        return url.rstrip('/')

    def find_js_files(self, base_url):
        """Discover JavaScript files from common paths"""
        found_files = []
        for path in self.common_js_paths:
            url = urljoin(base_url, path)
            try:
                response = self.session.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    # Skip common library files
                    if not any(lib in url.lower() for lib in self.common_libs):
                        found_files.append(url)
                        self.log(f"Found JS file: {url}", "success")
                    elif self.verbose:
                        self.log(f"Skipping common library: {url}", "info")
            except requests.RequestException as e:
                if self.verbose:
                    self.log(f"Error checking {url}: {str(e)}", "warning")
        return found_files

    def analyze_js_content(self, content, source_url=""):
        """Analyze JavaScript content for security issues"""
        if not content:
            return

        # Skip analysis for common library files
        if any(lib in source_url.lower() for lib in self.common_libs):
            if self.verbose:
                self.log(f"Skipping analysis of common library: {source_url}", "info")
            return

        self._check_secrets(content, source_url)
        self._check_endpoints(content, source_url)
        self._check_sensitive_functions(content, source_url)
        self._check_hidden_functionality(content, source_url)
        self._check_hardcoded_credentials(content, source_url)

    def _check_secrets(self, content, source_url):
        """Enhanced secret checking with all patterns"""
        for pattern_name, pattern in self.secret_patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                if not match.groups():
                    continue
                    
                # Skip comments and common false positives
                context = content[max(0, match.start()-50):match.end()+50]
                if '//' in context or '/*' in context:
                    continue
                    
                # Determine severity based on pattern type
                severity = "high"
                if pattern_name in ['private_keys', 'specific_api_keys']:
                    severity = "critical"
                elif pattern_name in ['personal_info', 'payment_creds']:
                    severity = "high"
                else:
                    severity = "medium"
                
                # Get the matched value
                if len(match.groups()) > 1:
                    key = match.group(1)
                    value = match.group(2)
                else:
                    key = pattern_name.replace('_', ' ').title()
                    value = match.group(0)
                
                self.findings['hardcoded_secrets'].append({
                    "type": f"{key}",
                    "value": value[:100] + ("..." if len(value) > 100 else ""),
                    "source": source_url,
                    "severity": severity,
                    "found": match.group(0),
                    "context": context.strip()
                })

        # Check API key patterns
        for pattern_name, pattern in self.api_key_patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                context = content[max(0, match.start()-50):match.end()+50]
                if '//' in context or '/*' in context:
                    continue
                
                self.findings['api_keys'].append({
                    "type": pattern_name,
                    "value": match.group(0)[:100] + ("..." if len(match.group(0)) > 100 else ""),
                    "source": source_url,
                    "severity": "critical",
                    "found": match.group(0),
                    "context": context.strip()
                })

    def _check_endpoints(self, content, source_url):
        """Enhanced endpoint detection with comprehensive patterns"""
        endpoints = self.patterns['endpoints'].finditer(content)
        for match in endpoints:
            endpoint = match.group(0).strip('"\'')
            
            # Determine endpoint category and severity
            severity = "medium"
            endpoint_type = "Generic Endpoint"
            
            if any(p in endpoint for p in ['/auth', '/login', '/token']):
                endpoint_type = "Authentication Endpoint"
                severity = self.endpoint_severity['auth']
            elif any(p in endpoint for p in ['/admin', '/privileged', '/roles']):
                endpoint_type = "Access Control Endpoint"
                severity = self.endpoint_severity['access_control']
            elif any(p in endpoint for p in ['/debug', '/test-api', '/swagger']):
                endpoint_type = "Debug Endpoint"
                severity = self.endpoint_severity['debug']
            elif any(p in endpoint for p in ['/user/', '/profile/', '/data/']):
                endpoint_type = "Data Access Endpoint"
                severity = self.endpoint_severity['data_access']
            elif any(p in endpoint for p in ['/upload', '/file/']):
                endpoint_type = "File Handling Endpoint"
                severity = self.endpoint_severity['file_handling']
            elif any(p in endpoint for p in ['?url=', '?link=', '/fetch']):
                endpoint_type = "Potential SSRF Endpoint"
                severity = self.endpoint_severity['ssrf']
            elif any(p in endpoint for p in ['/ws', '/socket.io', '/notifications']):
                endpoint_type = "Realtime Endpoint"
                severity = self.endpoint_severity['realtime']
            elif any(p in endpoint for p in ['/config', '/env', '-config.js']):
                endpoint_type = "Configuration Endpoint"
                severity = self.endpoint_severity['config']
            elif any(p in endpoint for p in ['/token', '/api-key', '/client-secrets']):
                endpoint_type = "Token Endpoint"
                severity = self.endpoint_severity['token']
            elif any(p in endpoint for p in ['/bypass', '/sudo-login', '?admin=true']):
                endpoint_type = "Auth Bypass Endpoint"
                severity = self.endpoint_severity['bypass']
            
            # Get context for verification
            context = content[max(0, match.start()-50):match.end()+50]
            
            self.findings['endpoints'].append({
                "type": endpoint_type,
                "value": endpoint,
                "source": source_url,
                "severity": severity,
                "found": match.group(0),
                "context": context.strip()
            })

        # WebSocket URLs
        ws_matches = self.patterns['ws_urls'].finditer(content)
        for match in ws_matches:
            ws_url = match.group(1)
            context = content[max(0, match.start()-50):match.end()+50]
            
            self.findings['endpoints'].append({
                "type": "WebSocket URL",
                "value": ws_url,
                "source": source_url,
                "severity": "medium",
                "found": match.group(0),
                "context": context.strip()
            })

    def _check_sensitive_functions(self, content, source_url):
        """Check for sensitive function names with common library filtering"""
        sensitive_funcs = self.patterns['sensitive_funcs'].finditer(content)
        for match in sensitive_funcs:
            func = match.group(1)  # Get just the function name
            context = content[max(0, match.start()-50):match.end()+50]
            
            # Skip if this is part of a common library pattern
            if any(
                f' {func} ' in f' {context.lower()} '  # Check with spaces around
                for f in ['function', 'var', 'const', 'let', 'return']
            ):
                continue
                
            self.findings['sensitive_functions'].append({
                "type": "Sensitive Function",
                "value": func,
                "source": source_url,
                "severity": "low",
                "found": match.group(0),
                "context": context.strip()
            })

    def _check_hidden_functionality(self, content, source_url):
        """Check for hidden functionality and dangerous patterns"""
        for pattern_name, pattern in self.hidden_functionality_patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                # Skip comments
                context = content[max(0, match.start()-50):match.end()+50]
                if '//' in context or '/*' in context:
                    continue
                    
                # Get the matched functionality
                if '=' in match.group(0):
                    found = match.group(0).split('=')[0].strip()
                    value = match.group(0).split('=')[1].strip()
                else:
                    found = match.group(0)
                    value = None
                    
                self.findings['hidden_functionality'].append({
                    "type": pattern_name.replace('_', ' ').title(),
                    "value": found,
                    "source": source_url,
                    "severity": self.hidden_func_severity.get(pattern_name, 'medium'),
                    "found": match.group(0),
                    "context": context.strip(),
                    "assigned_value": value
                })

    def _check_hardcoded_credentials(self, content, source_url):
        """Check for hardcoded credentials in JavaScript"""
        for pattern_name, pattern in self.credential_patterns.items():
            matches = pattern.finditer(content)
            for match in matches:
                # Skip comments
                context = content[max(0, match.start()-50):match.end()+50]
                if '//' in context or '/*' in context:
                    continue
                    
                # Extract the credential information
                if pattern_name == 'client_storage':
                    # For storage patterns, capture the storage mechanism
                    storage_type = 'localStorage' if 'localStorage' in match.group(0) else \
                                 'sessionStorage' if 'sessionStorage' in match.group(0) else \
                                 'cookie'
                    credential_key = match.group(2)
                    credential_value = match.group(0).split('=')[-1].strip('"\'; ')
                else:
                    # For variable assignments
                    parts = match.group(0).split('=')
                    credential_key = parts[0].strip()
                    credential_value = parts[1].strip(' "\';')
                    storage_type = 'variable'
                    
                self.findings['hardcoded_credentials'].append({
                    "type": pattern_name.replace('_', ' ').title(),
                    "key": credential_key,
                    "value": credential_value[:100] + ("..." if len(credential_value) > 100 else ""),
                    "storage": storage_type,
                    "source": source_url,
                    "severity": self.credential_severity.get(pattern_name, 'medium'),
                    "found": match.group(0),
                    "context": context.strip()
                })

    def scan_url(self, url):
        """Scan a single URL"""
        self.base_url = self.normalize_url(url)
        
        if url.lower().endswith('.js'):
            self.log(f"\n[+] Scanning JS file: {self.base_url}")
            self.process_js_file(self.base_url)
            return
            
        self.log(f"\n[+] Scanning: {self.base_url}")
        js_files = self.find_js_files(self.base_url)
        if not js_files:
            self.log("[!] No JS files found automatically")
            return

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for js_url in js_files:
                futures.append(executor.submit(self.process_js_file, js_url))
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.log(f"[X] Error processing file: {str(e)}")

    def process_js_file(self, js_url):
        """Process a single JS file with common library checks"""
        # Skip common library files
        if any(lib in js_url.lower() for lib in self.common_libs):
            if self.verbose:
                self.log(f"[*] Skipping common library: {js_url}")
            return
            
        self.log(f"[*] Analyzing: {js_url}")
        try:
            response = self.session.get(js_url, timeout=15)
            if response.status_code == 200:
                self.analyze_js_content(response.text, js_url)
            else:
                self.log(f"[!] Failed to fetch {js_url}: HTTP {response.status_code}")
        except requests.exceptions.Timeout:
            self.log(f"[!] Timeout while fetching {js_url}")
        except requests.RequestException as e:
            self.log(f"[X] Error fetching {js_url}: {str(e)}")

    def scan_list(self, file_path):
        """Scan a list of URLs from a file"""
        try:
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            if not urls:
                self.log("[!] No URLs found in input file")
                return
            
            for url in urls:
                if url.lower().endswith('.js'):
                    self.process_js_file(self.normalize_url(url))
                else:
                    self.scan_url(url)
        except FileNotFoundError:
            self.log(f"[X] File not found: {file_path}")
        except Exception as e:
            self.log(f"[X] Error reading file: {str(e)}")

    def generate_report(self, output_format="text", min_severity="low"):
        """Generate color-coded findings report with severity filtering"""
        if not self.findings:
            return f"{Colors.BLUE}[*] No security findings detected.{Colors.END}"

        severity_levels = {
            'critical': {'level': 4, 'color': Colors.RED + Colors.BOLD},
            'high': {'level': 3, 'color': Colors.RED},
            'medium': {'level': 2, 'color': Colors.YELLOW},
            'low': {'level': 1, 'color': Colors.BLUE}
        }
        min_level = severity_levels.get(min_severity.lower(), severity_levels['low'])['level']

        if output_format == "json":
            filtered = {
                cat: [item for item in items 
                     if severity_levels[item['severity'].lower()]['level'] >= min_level]
                for cat, items in self.findings.items()
            }
            return json.dumps(filtered, indent=2)
        
        report = []
        seen_findings = set()
        
        for category, items in self.findings.items():
            if not items:
                continue
                
            # Filter by severity
            filtered_items = [
                item for item in items 
                if severity_levels[item['severity'].lower()]['level'] >= min_level
            ]
            if not filtered_items:
                continue
                
            report.append(
                f"\n{Colors.PURPLE}=== {category.upper().replace('_', ' ')} ==={Colors.END}"
            )
            
            # Sort by severity (critical first)
            filtered_items.sort(
                key=lambda x: -severity_levels[x['severity'].lower()]['level']
            )
            
            for item in filtered_items:
                finding_key = (item['type'], item['value'], item['source'], item.get('found', ''))
                if finding_key not in seen_findings:
                    seen_findings.add(finding_key)
                    severity = item['severity'].upper()
                    color = severity_levels[item['severity'].lower()]['color']
                    
                    # Build the report line with colors
                    report_line = [
                        f"{color}[{severity}]{Colors.END} {Colors.BOLD}{item['type']}{Colors.END}",
                        f"{Colors.GREEN}- Location:{Colors.END} {item['source']}",
                        f"{Colors.GREEN}- Value:{Colors.END} {item['value']}"
                    ]
                    
                    if 'found' in item:
                        report_line.append(
                            f"{Colors.GREEN}- Found:{Colors.END} {Colors.YELLOW}{item['found']}{Colors.END}"
                        )
                    if 'context' in item:
                        report_line.append(
                            f"{Colors.GREEN}- Context:{Colors.END}\n{Colors.BLUE}{item['context']}{Colors.END}"
                        )
                    if 'storage' in item:
                        report_line.append(
                            f"{Colors.GREEN}- Storage:{Colors.END} {item['storage']}"
                        )
                    if 'assigned_value' in item:
                        report_line.append(
                            f"{Colors.GREEN}- Assigned Value:{Colors.END} {item['assigned_value']}"
                        )
                    
                    report.append("\n".join(report_line))
        
        return "\n".join(report) if report else \
               f"{Colors.BLUE}[*] No findings meet the minimum severity threshold.{Colors.END}"

def main():
    parser = argparse.ArgumentParser(description="JavaScript Security Scanner")
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-l", "--list", help="File containing list of URLs to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("-o", "--output", choices=["text", "json"], default="text", help="Output format")
    parser.add_argument("--min-severity", choices=["critical", "high", "medium", "low"], default="low", 
                       help="Minimum severity level to report")
    
    args = parser.parse_args()

    if not args.url and not args.list:
        parser.print_help()
        sys.exit(1)

    scanner = JSSecurityScanner(args.verbose, args.threads)

    # Add color support check
    if sys.stdout.isatty() and args.output == "text":
        print(  # Print color legend
            f"\n{Colors.BOLD}Color Legend:{Colors.END}\n"
            f"{Colors.RED + Colors.BOLD}Critical{Colors.END}\n"
            f"{Colors.RED}High{Colors.END}\n"
            f"{Colors.YELLOW}Medium{Colors.END}\n"
            f"{Colors.BLUE}Low{Colors.END}\n"
        )

    if args.url:
        scanner.scan_url(args.url)
    elif args.list:
        scanner.scan_list(args.list)

    print(scanner.generate_report(args.output, args.min_severity))

if __name__ == "__main__":
    main()
