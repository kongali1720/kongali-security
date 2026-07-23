# Kongali Security Report

**Target:** `https://kongali1720.com`

**Overall Risk:** `CRITICAL`

**Overall Score:** `0/100`

## Summary

- Total Findings: 6
- Critical: 0
- High: 4
- Medium: 2
- Low: 0

## Findings

### 1. Missing security header: Content-Security-Policy

**Severity:** `HIGH`

**Category:** HTTP Security Headers

**OWASP:** A05:2021 - Security Misconfiguration

**CWE:** CWE-693 - Protection Mechanism Failure

The HTTP response does not include the Content-Security-Policy security header.

**Impact**

Missing Content-Security-Policy may increase the risk of client-side injection and content execution attacks.

**Evidence**

```json
{
  "header": "Content-Security-Policy",
  "status": "missing"
}
```

**Remediation**

Implement a restrictive Content-Security-Policy appropriate for the application.

### 2. Missing security header: Strict-Transport-Security

**Severity:** `HIGH`

**Category:** HTTP Security Headers

**OWASP:** A05:2021 - Security Misconfiguration

**CWE:** CWE-319 - Cleartext Transmission of Sensitive Information

The HTTP response does not include the Strict-Transport-Security security header.

**Impact**

Without HSTS, users may be exposed to protocol downgrade or insecure HTTP connections.

**Evidence**

```json
{
  "header": "Strict-Transport-Security",
  "status": "missing"
}
```

**Remediation**

Enable HTTP Strict Transport Security with an appropriate max-age and HTTPS deployment.

### 3. Missing security header: X-Content-Type-Options

**Severity:** `HIGH`

**Category:** HTTP Security Headers

**OWASP:** A05:2021 - Security Misconfiguration

**CWE:** CWE-693 - Protection Mechanism Failure

The HTTP response does not include the X-Content-Type-Options security header.

**Impact**

Missing X-Content-Type-Options may allow browsers to MIME-sniff responses unexpectedly.

**Evidence**

```json
{
  "header": "X-Content-Type-Options",
  "status": "missing"
}
```

**Remediation**

Set the X-Content-Type-Options header to nosniff.

### 4. Missing security header: X-Frame-Options

**Severity:** `HIGH`

**Category:** HTTP Security Headers

**OWASP:** A05:2021 - Security Misconfiguration

**CWE:** CWE-693 - Protection Mechanism Failure

The HTTP response does not include the X-Frame-Options security header.

**Impact**

Missing clickjacking protection may allow malicious sites to frame the application.

**Evidence**

```json
{
  "header": "X-Frame-Options",
  "status": "missing"
}
```

**Remediation**

Set X-Frame-Options to DENY or SAMEORIGIN, or use an appropriate CSP frame-ancestors policy.

### 5. Missing security header: Referrer-Policy

**Severity:** `MEDIUM`

**Category:** HTTP Security Headers

**OWASP:** A05:2021 - Security Misconfiguration

**CWE:** CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor

The HTTP response does not include the Referrer-Policy security header.

**Impact**

An overly permissive referrer policy may expose sensitive URL information to external origins.

**Evidence**

```json
{
  "header": "Referrer-Policy",
  "status": "missing"
}
```

**Remediation**

Configure a restrictive Referrer-Policy such as strict-origin-when-cross-origin.

### 6. Missing security header: Permissions-Policy

**Severity:** `MEDIUM`

**Category:** HTTP Security Headers

**OWASP:** A05:2021 - Security Misconfiguration

**CWE:** CWE-693 - Protection Mechanism Failure

The HTTP response does not include the Permissions-Policy security header.

**Impact**

Missing Permissions-Policy may allow unnecessary browser capabilities to remain available.

**Evidence**

```json
{
  "header": "Permissions-Policy",
  "status": "missing"
}
```

**Remediation**

Configure Permissions-Policy to explicitly restrict unnecessary browser capabilities.

## Technical Scan Data

```json
{
  "target": "https://kongali1720.com",
  "url": {
    "value": "https://kongali1720.com",
    "type": "url",
    "valid": true,
    "scheme": "https",
    "hostname": "kongali1720.com",
    "port": null,
    "path": "",
    "query": "",
    "fragment": "",
    "metadata": {
      "username_present": false,
      "password_present": false,
      "netloc": "kongali1720.com"
    }
  },
  "dns": {
    "domain": "kongali1720.com",
    "valid": true,
    "resolved": false,
    "ipv4": [],
    "ipv6": [],
    "metadata": {
      "error": "[Errno -2] Name or service not known"
    }
  },
  "whois": {
    "domain": "kongali1720.com",
    "valid": true,
    "queried": true,
    "registrar": null,
    "creation_date": null,
    "expiration_date": null,
    "updated_date": null,
    "name_servers": [],
    "statuses": [],
    "metadata": {
      "return_code": 0,
      "output_length": 3075
    }
  },
  "headers": {
    "url": "https://kongali1720.com",
    "reachable": false,
    "status_code": null,
    "headers": {},
    "present": [],
    "missing": [
      "Content-Security-Policy",
      "Strict-Transport-Security",
      "X-Content-Type-Options",
      "X-Frame-Options",
      "Referrer-Policy",
      "Permissions-Policy"
    ],
    "security_score": 0,
    "risk_level": "HIGH",
    "metadata": {
      "error": "<urlopen error [Errno -2] Name or service not known>"
    },
    "findings": []
  }
}
```

---

Generated by Kongali Security.