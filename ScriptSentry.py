#!/usr/bin/env python3
import re
import sys
import json
import requests
import argparse
from urllib.parse import urljoin
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
init(autoreset=True)

print(Fore.CYAN + r"""
 _____           _       _   _____            _              
/  ___|         (_)     | | /  ___|          | |             
\ `--.  ___ _ __ _ _ __ | |_\ `--.  ___ _ __ | |_ _ __ _   _ 
 `--. \/ __| '__| | '_ \| __|`--. \/ _ \ '_ \| __| '__| | | |
/\__/ / (__| |  | | |_) | |_/\__/ /  __/ | | | |_| |  | |_| |
\____/ \___|_|  |_| .__/ \__\____/ \___|_| |_|\__|_|   \__, |
                  | |                                   __/ |
                  |_|                                  |___/ 
""" + Fore.YELLOW + "──────────────────────────────────────────────[By XploitPoy-777]──────" + Style.RESET_ALL)

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

        # Comprehensive secret detection patterns with all requested keywords
        self.secret_patterns = {
            # General credentials (expanded with all requested keywords)
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
                r'sqlserver:\/\/[^:]+:[^@]+@)',
                re.I
            ),

            # Cloud service credentials
            'cloud_creds': re.compile(
                r'(aws_access_key_id|aws_secret_access_key|azure_account_key|'
                r'gcp_key|google_project_secret|digitalocean_api_key|'
                r'heroku_api_key|cloudflare_api_key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{20,100})["\']?',
                re.I
            ),

            # Social media and communication tokens
            'social_tokens': re.compile(
                r'(facebook_access_token|twitter_api_key|twitter_secret|'
                r'discord_token|slack_bot_token|telegram_bot_token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{20,100})["\']?',
                re.I
            ),

            # Email service credentials
            'email_creds': re.compile(
                r'(smtp_pass|smtp_password|sendgrid_api_key|mailgun_api_key|'
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
            ),

            # Sensitive personal information
            'personal_info': re.compile(
                r'(ssn|social_security_number|tax_id|dob|date_of_birth|'
                r'phone_number|address|zip_code|passport_number|'
                r'driver_license|identity_number)\s*[:=]\s*["\']?([a-zA-Z0-9_\-=]{5,50})["\']?',
                re.I
            )
        }

        # Comprehensive endpoint patterns
        self.endpoint_patterns = [
            # API & Backend Endpoints
            r'/api/', r'/api/v[1-4]/', r'/apis/', r'/rest/', r'/restapi/',
            r'/jsonapi/', r'/graphql', r'/gql/', r'/grpc/', r'/soap/',
            r'/rpc/', r'/endpoint/', r'/service/', r'/backend/',
            r'/microservice/', r'/internal-api/', r'/private-api/',
            r'/external-api/', r'/partner-api/',
            
            # Authentication & Authorization
            r'/auth/', r'/authentication/', r'/authorize/', r'/oauth/',
            r'/oauth2/', r'/openid/', r'/saml/', r'/oidc/', r'/jwt/',
            r'/token/', r'/refresh-token/', r'/access-token/', r'/session/',
            r'/login/', r'/logout/', r'/signin/', r'/signout/', r'/register/',
            r'/signup/', r'/forgot-password/', r'/reset-password/', r'/verify/',
            r'/2fa/', r'/mfa/', r'/otp/', r'/validate/',
            
            # Admin & Privileged Access
            r'/admin/', r'/administrator/', r'/cpanel/', r'/wp-admin/',
            r'/wp-login/', r'/dashboard/', r'/manager/', r'/console/',
            r'/controlpanel/', r'/system/', r'/root/', r'/superuser/',
            r'/superadmin/', r'/staff/', r'/support/', r'/operator/',
            r'/configurator/',
            
            # User & Account Management
            r'/user/', r'/users/', r'/account/', r'/accounts/', r'/profile/',
            r'/profiles/', r'/member/', r'/members/', r'/customer/',
            r'/customers/', r'/client/', r'/clients/', r'/guest/', r'/guests/',
            
            # File & Data Operations
            r'/file/', r'/files/', r'/upload/', r'/download/', r'/export/',
            r'/import/', r'/data/', r'/database/', r'/db/', r'/sql/',
            r'/mongodb/', r'/redis/', r'/backup/', r'/restore/', r'/dump/',
            r'/load/', r'/storage/', r'/blob/', r'/document/', r'/documents/',
            r'/attachment/', r'/attachments/',
            
            # System & Debugging
            r'/system/', r'/sys/', r'/info/', r'/status/', r'/health/',
            r'/healthcheck/', r'/ready/', r'/live/', r'/version/', r'/metrics/',
            r'/stats/', r'/statistics/', r'/log/', r'/logs/', r'/logger/',
            r'/trace/', r'/debug/', r'/debugger/', r'/dev/', r'/development/',
            r'/test/', r'/testing/', r'/qa/', r'/staging/', r'/experimental/',
            r'/experiment/',
            
            # Payment & Financial
            r'/payment/', r'/payments/', r'/checkout/', r'/invoice/',
            r'/invoices/', r'/billing/', r'/subscription/', r'/subscriptions/',
            r'/refund/', r'/refunds/', r'/transaction/', r'/transactions/',
            r'/stripe/', r'/paypal/', r'/braintree/', r'/square/', r'/webhook/',
            r'/webhooks/', r'/callback/', r'/callbacks/',
            
            # Communication & Real-Time
            r'/ws/', r'/wss/', r'/socket/', r'/sockets/', r'/socket\.io/',
            r'/signalr/', r'/websocket/', r'/events/', r'/event/', r'/sse/',
            r'/poll/', r'/longpoll/', r'/notify/', r'/notification/',
            r'/notifications/', r'/alert/', r'/alerts/', r'/message/',
            r'/messages/', r'/chat/', r'/chats/',
            
            # Cloud & Infrastructure
            r'/aws/', r'/s3/', r'/ec2/', r'/lambda/', r'/azure/', r'/gcp/',
            r'/firebase/', r'/cloud/', r'/cloudfunctions/', r'/k8s/',
            r'/kubernetes/', r'/docker/', r'/vm/', r'/virtualmachine/',
            r'/container/', r'/containers/', r'/orchestrator/',
            
            # Hidden & Suspicious
            r'/secret/', r'/secrets/', r'/private/', r'/hidden/', r'/legacy/',
            r'/old/', r'/temp/', r'/tmp/', r'/archive/', r'/backdoor/',
            r'/shell/', r'/exec/', r'/cmd/', r'/command/', r'/console/',
            r'/terminal/', r'/inject/', r'/exploit/', r'/attack/',
            
            # Third-Party Services
            r'/firebase/', r'/twilio/', r'/sendgrid/', r'/mailchimp/',
            r'/aws/', r'/google/', r'/facebook/', r'/twitter/', r'/linkedin/',
            r'/github/', r'/gitlab/', r'/bitbucket/', r'/slack/', r'/discord/',
            r'/zoom/',
            
            # Miscellaneous High-Value
            r'/config/', r'/configuration/', r'/settings/', r'/env/',
            r'/environment/', r'/flags/', r'/feature/', r'/features/',
            r'/swagger/', r'/openapi/', r'/redoc/', r'/api-docs/',
            r'/documentation/', r'/docs/', r'/wiki/', r'/help/', r'/support/',
            r'/contact/', r'/feedback/', r'/report/'
        ]

        # Compile endpoint patterns into regex
        endpoint_patterns_str = '|'.join([p.replace('/', r'\/') for p in self.endpoint_patterns])
        self.endpoint_regex = re.compile(
            r'["\'](' + endpoint_patterns_str + r')[^"\']*["\']',
            re.I
        )

        # Combined patterns dictionary
        self.patterns = {
            **self.secret_patterns,
            'endpoints': self.endpoint_regex,
            'ws_urls': re.compile(r'new WebSocket\(["\']([^"\']+)["\']'),
            'sensitive_funcs': re.compile(
                r'(?:\.|function\s+)(login|authenticate|auth|checkout|payment|token|password|verifyPassword|changePassword|updateCredentials|processPayment)'
                r'(?:\s*\(|\s*=|\s*:)',
                re.I
            )
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

    def _check_endpoints(self, content, source_url):
        """Enhanced endpoint detection with comprehensive patterns"""
        endpoints = self.patterns['endpoints'].finditer(content)
        for match in endpoints:
            endpoint = match.group(0).strip('"\'')
            if not endpoint.startswith(('http://', 'https://')):
                endpoint = urljoin(self.base_url, endpoint)
            
            # Classify endpoint by type
            endpoint_type = "API Endpoint"
            if any(p in endpoint for p in ['/auth', '/login', '/oauth']):
                endpoint_type = "Auth Endpoint"
            elif any(p in endpoint for p in ['/admin', '/cpanel', '/wp-admin']):
                endpoint_type = "Admin Endpoint"
            elif any(p in endpoint for p in ['/ws', '/socket', '/websocket']):
                endpoint_type = "WebSocket Endpoint"
            elif any(p in endpoint for p in ['/payment', '/stripe', '/paypal']):
                endpoint_type = "Payment Endpoint"
            elif any(p in endpoint for p in ['/config', '/env', '/settings']):
                endpoint_type = "Configuration Endpoint"
            
            severity = "medium"
            if "admin" in endpoint.lower() or "internal" in endpoint.lower():
                severity = "high"
            if "auth" in endpoint.lower() or "token" in endpoint.lower():
                severity = "high"
            if "config" in endpoint.lower() or "secret" in endpoint.lower():
                severity = "high"
            
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
