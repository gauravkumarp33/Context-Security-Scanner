# Security Scanner Rules Catalog

This document is automatically generated from the rule definitions in `rules/*.yaml`.
Run `python scripts/gen_rules_doc.py` to regenerate.

## Summary of Rules

| Rule ID | Title | Base Severity | Engine | Source Catalog |
|---|---|---|---|---|
| `code-sql-injection` | SQL Injection via String Concatenation or Formatting | `HIGH` | `regex` | `insecure-code.yaml` |
| `code-eval-exec` | Dynamic Code Execution (eval/exec) | `HIGH` | `regex` | `insecure-code.yaml` |
| `code-subprocess-shell` | Subprocess Execution with shell=True | `HIGH` | `regex` | `insecure-code.yaml` |
| `code-hardcoded-secret-key` | Hardcoded Application Secret Key | `HIGH` | `regex` | `insecure-code.yaml` |
| `code-debug-mode` | Debug Mode Enabled in Source Code | `MEDIUM` | `regex` | `insecure-code.yaml` |
| `code-tls-verify-disabled` | TLS Certificate Verification Disabled | `HIGH` | `regex` | `insecure-code.yaml` |
| `code-weak-password-hash` | Weak Hash Algorithm (MD5/SHA1) | `MEDIUM` | `regex` | `insecure-code.yaml` |
| `code-cors-wildcard` | Wildcard CORS Policy | `MEDIUM` | `regex` | `insecure-code.yaml` |
| `firebase-open-access` | Firebase Open Access | `HIGH` | `regex` | `insecure-config.yaml` |
| `firebase-auth-without-authorization` | Firebase Authentication Without Authorization | `MEDIUM` | `regex` | `insecure-config.yaml` |
| `config-docker-db-port-exposed` | Database Port Exposed on All Host Interfaces | `HIGH` | `regex` | `insecure-config.yaml` |
| `config-db-password-env` | Hardcoded Database Password in Environment Configuration | `HIGH` | `regex` | `insecure-config.yaml` |
| `config-docker-container-root` | Container Running as Root User | `MEDIUM` | `regex` | `insecure-config.yaml` |
| `config-github-actions-pull-request-target` | Dangerous GitHub Actions pull_request_target Trigger | `HIGH` | `regex` | `insecure-config.yaml` |
| `config-github-actions-unpinned` | Unpinned Third-Party GitHub Action | `MEDIUM` | `regex` | `insecure-config.yaml` |
| `secret-aws-access-key` | AWS Access Key | `CRITICAL` | `regex` | `secrets.yaml` |
| `secret-github-token` | GitHub Personal Access Token | `HIGH` | `regex` | `secrets.yaml` |
| `secret-stripe-key` | Stripe API Key | `HIGH` | `regex` | `secrets.yaml` |
| `secret-private-key` | Private Cryptographic Key | `CRITICAL` | `regex` | `secrets.yaml` |
| `secret-db-connection-string` | Database Connection String with Password | `CRITICAL` | `regex` | `secrets.yaml` |
| `secret-generic-password` | Hardcoded Password or API Key Assignment | `MEDIUM` | `regex` | `secrets.yaml` |

---

## Rule Details

### `code-sql-injection` - SQL Injection via String Concatenation or Formatting

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `*.py, *.js, *.ts`
- **Raise in Production:** `true`
- **What it detects:** SQL queries constructed via dynamic string formatting, f-strings, or string concatenation.
- **Why it's risky:** Attackers can manipulate query structure to bypass authentication, exfiltrate confidential data, or destroy tables.
- **Remediation:** Use parameterized queries with bind variables or an ORM instead of manual string formatting. Replace with cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)).

#### Insecure Example
```text
cursor.execute(f"SELECT * FROM users WHERE username = '{user_input}'")
```

#### Remediated Example
```text
cursor.execute("SELECT * FROM users WHERE username = %s", (user_input,))
```

---

### `code-eval-exec` - Dynamic Code Execution (eval/exec)

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `*.py, *.js, *.ts`
- **Raise in Production:** `true`
- **What it detects:** Invocations of eval() or exec() passing dynamic input expressions.
- **Why it's risky:** Executing unvalidated user input as code grants adversaries full remote code execution.
- **Remediation:** Replace eval() and exec() with safe structured parsers like json.loads() or ast.literal_eval().

#### Insecure Example
```text
user_obj = eval(user_payload)
```

#### Remediated Example
```text
import json
user_obj = json.loads(user_payload)
```

---

### `code-subprocess-shell` - Subprocess Execution with shell=True

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `*.py`
- **Raise in Production:** `true`
- **What it detects:** Subprocess calls where shell=True is explicitly configured.
- **Why it's risky:** Command arguments containing shell metacharacters can spawn arbitrary host commands.
- **Remediation:** Pass shell=False and provide the command and arguments as a list of strings. Replace with subprocess.run(['ls', target_dir], shell=False).

#### Insecure Example
```text
subprocess.run(f"cat {user_file}", shell=True)
```

#### Remediated Example
```text
subprocess.run(["cat", user_file], shell=False)
```

---

### `code-hardcoded-secret-key` - Hardcoded Application Secret Key

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `*.py, *.js, *.ts`
- **Raise in Production:** `true`
- **What it detects:** Hardcoded assignments to SECRET_KEY in source files.
- **Why it's risky:** Knowing the secret key allows adversaries to forge authentication cookies and sign malicious tokens.
- **Remediation:** Load SECRET_KEY from environment variables using os.environ.get('SECRET_KEY').

#### Insecure Example
```text
SECRET_KEY = "django-insecure-hardcoded-secret-key-12345"
```

#### Remediated Example
```text
import os
SECRET_KEY = os.environ.get("SECRET_KEY")
```

---

### `code-debug-mode` - Debug Mode Enabled in Source Code

- **Base Severity:** `MEDIUM`
- **Engine:** `regex`
- **Target Globs:** `*.py, *.js, *.ts, *.env, *.ini`
- **Raise in Production:** `true`
- **What it detects:** Explicit DEBUG = True declarations in application code or configuration.
- **Why it's risky:** Enabled debug modes expose detailed error traces and interactive consoles that attackers exploit.
- **Remediation:** Set DEBUG = False or load the flag from an environment variable like os.getenv('DEBUG', 'False') == 'True'.

#### Insecure Example
```text
DEBUG = True
```

#### Remediated Example
```text
import os
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1")
```

---

### `code-tls-verify-disabled` - TLS Certificate Verification Disabled

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `*.py`
- **Raise in Production:** `true`
- **What it detects:** HTTP client requests with TLS certificate verification explicitly turned off.
- **Why it's risky:** Adversaries positioned on the local network can intercept, inspect, and modify API traffic.
- **Remediation:** Enable certificate verification by setting verify=True or specify a trusted custom CA bundle path.

#### Insecure Example
```text
response = requests.get("https://api.internal/v1", verify=False)
```

#### Remediated Example
```text
response = requests.get("https://api.internal/v1", verify=True)
```

---

### `code-weak-password-hash` - Weak Hash Algorithm (MD5/SHA1)

- **Base Severity:** `MEDIUM`
- **Engine:** `regex`
- **Target Globs:** `*.py, *.js, *.ts`
- **Raise in Production:** `false`
- **What it detects:** Invocations of MD5 or SHA1 cryptographic hashing routines.
- **Why it's risky:** MD5 and SHA1 suffer from proven collision vulnerabilities and can be cracked rapidly on commodity hardware.
- **Remediation:** Replace MD5 or SHA1 with modern password hashing algorithms such as Argon2id or bcrypt.

#### Insecure Example
```text
import hashlib
pwd_hash = hashlib.md5(password.encode()).hexdigest()
```

#### Remediated Example
```text
import bcrypt
pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

---

### `code-cors-wildcard` - Wildcard CORS Policy

- **Base Severity:** `MEDIUM`
- **Engine:** `regex`
- **Target Globs:** `*.py, *.js, *.ts`
- **Raise in Production:** `true`
- **What it detects:** CORS configurations granting unrestricted wildcard ('*') origin access.
- **Why it's risky:** Permissive CORS policies allow malicious third-party origins to read authenticated private responses.
- **Remediation:** Replace '*' with an explicit whitelist of trusted domain origins in the CORS configuration.

#### Insecure Example
```text
response.headers["Access-Control-Allow-Origin"] = "*"
```

#### Remediated Example
```text
response.headers["Access-Control-Allow-Origin"] = "https://app.example.com"
```

---

### `firebase-open-access` - Firebase Open Access

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `*.rules`
- **Raise in Production:** `false`
- **What it detects:** Firestore security rules with allow read, write: if true;.
- **Why it's risky:** Anyone on the Internet can read, modify, and delete all application data stored in Firestore.
- **Remediation:** Replace 'if true;' with user authentication checks such as 'allow read, write: if request.auth != null;'. Restrict access based on document ownership.

#### Insecure Example
```text
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
```

#### Remediated Example
```text
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

---

### `firebase-auth-without-authorization` - Firebase Authentication Without Authorization

- **Base Severity:** `MEDIUM`
- **Engine:** `regex`
- **Target Globs:** `*.rules`
- **Raise in Production:** `true`
- **What it detects:** Firestore security rules checking only request.auth != null without ownership checks.
- **Why it's risky:** Any authenticated user can read or overwrite data belonging to other users or tenants.
- **Remediation:** Replace with request.auth.uid == resource.data.ownerId. Enforce role-based or ownership-based security constraints.

#### Insecure Example
```text
match /documents/{docId} {
  allow read, write: if request.auth != null;
}
```

#### Remediated Example
```text
match /documents/{docId} {
  allow read, write: if request.auth != null && request.auth.uid == resource.data.ownerId;
}
```

---

### `config-docker-db-port-exposed` - Database Port Exposed on All Host Interfaces

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `docker-compose*.yml, docker-compose*.yaml, compose*.yml, compose*.yaml`
- **Raise in Production:** `true`
- **What it detects:** Docker compose port mappings binding database ports to all interfaces (0.0.0.0).
- **Why it's risky:** Exposed database ports invite brute-force credential stuffing and direct network exploits.
- **Remediation:** Bind the port to localhost using '127.0.0.1:5432:5432' or rely exclusively on internal Docker networks.

#### Insecure Example
```text
services:
  db:
    image: postgres:15
    ports:
      - "5432:5432"
```

#### Remediated Example
```text
services:
  db:
    image: postgres:15
    ports:
      - "127.0.0.1:5432:5432"
```

---

### `config-db-password-env` - Hardcoded Database Password in Environment Configuration

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `docker-compose*.yml, docker-compose*.yaml, *.env, .env*`
- **Raise in Production:** `true`
- **What it detects:** Hardcoded database password assignments in compose or env files.
- **Why it's risky:** Passwords committed to repository files remain visible in revision history.
- **Remediation:** Reference secrets via external environment variables like '${POSTGRES_PASSWORD}' or use Docker secrets.

#### Insecure Example
```text
services:
  db:
    environment:
      POSTGRES_PASSWORD: "mysecretpassword123"
```

#### Remediated Example
```text
services:
  db:
    environment:
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
```

---

### `config-docker-container-root` - Container Running as Root User

- **Base Severity:** `MEDIUM`
- **Engine:** `regex`
- **Target Globs:** `Dockerfile*, docker-compose*.yml, docker-compose*.yaml`
- **Raise in Production:** `true`
- **What it detects:** USER root or user: root/0 declarations in Dockerfiles or compose files.
- **Why it's risky:** Root processes inside containers pose serious security risks if container isolation is bypassed.
- **Remediation:** Create a non-privileged user and switch to it using 'USER <username>' in the container configuration.

#### Insecure Example
```text
FROM alpine:latest
USER root
CMD ["sh"]
```

#### Remediated Example
```text
FROM alpine:latest
RUN adduser -D appuser
USER appuser
CMD ["sh"]
```

---

### `config-github-actions-pull-request-target` - Dangerous GitHub Actions pull_request_target Trigger

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `.github/workflows/*.yml, .github/workflows/*.yaml`
- **Raise in Production:** `true`
- **What it detects:** GitHub Actions workflows triggering on pull_request_target.
- **Why it's risky:** Malicious pull request authors can exfiltrate repository secrets by triggering workflows with write access.
- **Remediation:** Replace pull_request_target with pull_request, or do not check out and execute code from untrusted forks.

#### Insecure Example
```text
name: CI
on:
  pull_request_target:
```

#### Remediated Example
```text
name: CI
on:
  pull_request:
```

---

### `config-github-actions-unpinned` - Unpinned Third-Party GitHub Action

- **Base Severity:** `MEDIUM`
- **Engine:** `regex`
- **Target Globs:** `.github/workflows/*.yml, .github/workflows/*.yaml`
- **Raise in Production:** `true`
- **What it detects:** GitHub Actions uses: references pointing to mutable tags (v3) or branches (main).
- **Why it's risky:** Compromised tags can silently execute malicious scripts in build and deployment pipelines.
- **Remediation:** Pin actions to an immutable 40-character commit SHA like actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab.

#### Insecure Example
```text
- uses: actions/checkout@v3
```

#### Remediated Example
```text
- uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab # v3.5.2
```

---

### `secret-aws-access-key` - AWS Access Key

- **Base Severity:** `CRITICAL`
- **Engine:** `regex`
- **Target Globs:** `*`
- **Raise in Production:** `true`
- **What it detects:** Hardcoded AWS Access Key ID tokens in source files or configuration.
- **Why it's risky:** Attackers with repository access can hijack cloud resources, delete data, and incur extensive infrastructure costs.
- **Remediation:** Store AWS credentials in environment variables such as AWS_ACCESS_KEY_ID or use IAM roles.

#### Insecure Example
```text
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
```

#### Remediated Example
```text
import os
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
```

---

### `secret-github-token` - GitHub Personal Access Token

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `*`
- **Raise in Production:** `true`
- **What it detects:** Hardcoded GitHub personal access tokens and OAuth tokens.
- **Why it's risky:** Leaked tokens allow attackers to tamper with repository source code, release tags, and CI/CD automation.
- **Remediation:** Revoke the exposed token and inject it dynamically using GitHub Secrets or the GITHUB_TOKEN environment variable.

#### Insecure Example
```text
GITHUB_TOKEN = "ghp_EXAMPLE_TOKEN_PLACEHOLDER_STRING_12345"
```

#### Remediated Example
```text
import os
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
```

---

### `secret-stripe-key` - Stripe API Key

- **Base Severity:** `HIGH`
- **Engine:** `regex`
- **Target Globs:** `*`
- **Raise in Production:** `true`
- **What it detects:** Hardcoded Stripe live or test secret API keys.
- **Why it's risky:** Exposed keys can lead to fraudulent transactions, customer record exposure, and financial liability.
- **Remediation:** Revoke the exposed key in the Stripe Dashboard and load keys via the STRIPE_API_KEY environment variable.

#### Insecure Example
```text
stripe.api_key = "sk_live_EXAMPLE_STRIPE_KEY_PLACEHOLDER_12345"
```

#### Remediated Example
```text
import os
stripe.api_key = os.environ.get("STRIPE_API_KEY")
```

---

### `secret-private-key` - Private Cryptographic Key

- **Base Severity:** `CRITICAL`
- **Engine:** `regex`
- **Target Globs:** `*`
- **Raise in Production:** `true`
- **What it detects:** Plaintext RSA, EC, DSA, and OpenSSH private key PEM headers.
- **Why it's risky:** Exposed private keys compromise encrypted channels, digital signatures, and server authentication.
- **Remediation:** Remove the private key from source control and load it securely from an external key vault.

#### Insecure Example
```text
-----BEGIN RSA PRIVATE KEY-----
MIIE...<RUNTIME_SAFE_KEY_PLACEHOLDER>...
-----END RSA PRIVATE KEY-----
```

#### Remediated Example
```text
from key_vault import load_secret
private_key_pem = load_secret("APP_PRIVATE_KEY")
```

---

### `secret-db-connection-string` - Database Connection String with Password

- **Base Severity:** `CRITICAL`
- **Engine:** `regex`
- **Target Globs:** `*`
- **Raise in Production:** `true`
- **What it detects:** Database connection URLs containing embedded passwords.
- **Why it's risky:** Hardcoded connection strings expose database instances directly to credential theft and unauthorized data dumping.
- **Remediation:** Extract database credentials to environment variables and build connection URLs dynamically at runtime.

#### Insecure Example
```text
DB_URL = "postgresql://dbuser:secretpass@db.internal:5432/proddb"
```

#### Remediated Example
```text
import os
DB_URL = f"postgresql://{os.environ['DB_USER']}:{os.environ['DB_PASS']}@{os.environ['DB_HOST']}:5432/proddb"
```

---

### `secret-generic-password` - Hardcoded Password or API Key Assignment

- **Base Severity:** `MEDIUM`
- **Engine:** `regex`
- **Target Globs:** `*`
- **Raise in Production:** `false`
- **What it detects:** Generic password, passwd, or API key variable assignments.
- **Why it's risky:** Plaintext secrets in source code persist in commit history and are easily leaked to third parties.
- **Remediation:** Inject secrets dynamically from environment variables or a secret vault instead of hardcoding values.

#### Insecure Example
```text
password = "supersecretpassword123"
```

#### Remediated Example
```text
import os
password = os.environ.get("SERVICE_PASSWORD")
```

---
