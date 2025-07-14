// Sample JavaScript file with test secrets for ScriptSentry

// 1. Hardcoded API Keys (Should be detected)
const stripeApiKey = "sk_live_51Hx9x2Kv3XrY6w9J8XyZ1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U";
const awsAccessKey = "AKIAIOSFODNN7EXAMPLE";
const awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const firebaseConfig = {
  apiKey: "AIzaSyD-9tB8s1X2v3Y4Z5X6Y7Z8A9B0C1D2E3F4G5H6",
  authDomain: "test-project.firebaseapp.com",
  databaseURL: "https://test-project.firebaseio.com",
};

// 2. Database Connection Strings (Should be flagged)
const mongoDBUrl = "mongodb://admin:password123@localhost:27017/mydb";
const postgresUrl = "postgres://user:pass123@localhost:5432/testdb";

// 3. OAuth & JWT Tokens (Should trigger alerts)
const oauthToken = "ya29.A0ARrdaM-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

// 4. Sensitive Endpoints (Should be detected)
const internalApiUrl = "https://api.internal.example.com/v1/users";
const adminPanelUrl = "https://admin.example.com/login";

// 5. Debug/Test Mode (Should be flagged)
const debugMode = true;
const testCredentials = {
  username: "testadmin",
  password: "TempPass123!"
};

// 6. AWS S3 Bucket (Should trigger detection)
const s3Bucket = "s3://my-private-bucket/secret-files/";

// 7. Slack Webhook (Should be detected)
const slackWebhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";

// 8. Payment Info (Should be flagged)
const creditCardNumber = "4111 1111 1111 1111";
const cvv = "123";

// 9. Private Key (Should be detected)
const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx6yJwX7U6U7K6Y5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5XmY5
-----END RSA PRIVATE KEY-----
`;

// 10. Social Media Tokens (Should be flagged)
const facebookToken = "EAACEdEose0cBA1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const twitterToken = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";

// 11. Debug Functions (Should be flagged)
function enableAdminMode() {
  console.log("Admin mode enabled!");
}

function resetDatabase() {
  console.log("Database reset!");
}
