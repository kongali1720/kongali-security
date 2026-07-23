# Kongali Security Report

**Target:** `https://blanchedalmond-gorilla-295483.hostingersite.com`

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
  "target": "https://blanchedalmond-gorilla-295483.hostingersite.com",
  "url": {
    "value": "https://blanchedalmond-gorilla-295483.hostingersite.com",
    "type": "url",
    "valid": true,
    "scheme": "https",
    "hostname": "blanchedalmond-gorilla-295483.hostingersite.com",
    "port": null,
    "path": "",
    "query": "",
    "fragment": "",
    "metadata": {
      "username_present": false,
      "password_present": false,
      "netloc": "blanchedalmond-gorilla-295483.hostingersite.com"
    }
  },
  "dns": {
    "domain": "blanchedalmond-gorilla-295483.hostingersite.com",
    "valid": true,
    "resolved": true,
    "ipv4": [
      "185.124.137.71",
      "91.108.119.118"
    ],
    "ipv6": [
      "2a02:4780:1c:3677:fcd1:9585:f0a8:2f51",
      "2a02:4780:3a:e7f5:1ac7:af17:550b:e192"
    ],
    "metadata": {
      "record_count": 4
    }
  },
  "whois": {
    "domain": "blanchedalmond-gorilla-295483.hostingersite.com",
    "valid": true,
    "queried": true,
    "registrar": null,
    "creation_date": null,
    "expiration_date": null,
    "updated_date": null,
    "name_servers": [],
    "statuses": [],
    "metadata": {
      "return_code": 1,
      "output_length": 2273
    }
  },
  "headers": {
    "url": "https://blanchedalmond-gorilla-295483.hostingersite.com",
    "reachable": true,
    "status_code": 200,
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
      "total_security_headers": 6,
      "headers_present": 0,
      "headers_missing": 6
    },
    "findings": [
      {
        "id": "KONGALI-HEADERS-0001",
        "title": "Missing security header: Content-Security-Policy",
        "severity": "HIGH",
        "category": "HTTP Security Headers",
        "description": "The HTTP response does not include the Content-Security-Policy security header.",
        "owasp": {
          "id": "A05:2021",
          "name": "Security Misconfiguration"
        },
        "cwe": {
          "id": "CWE-693",
          "name": "Protection Mechanism Failure"
        },
        "cvss": {
          "version": "3.1",
          "score": 8.1,
          "severity": "HIGH",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        },
        "impact": "Missing Content-Security-Policy may increase the risk of client-side injection and content execution attacks.",
        "remediation": "Implement a restrictive Content-Security-Policy appropriate for the application.",
        "evidence": {
          "url": "https://blanchedalmond-gorilla-295483.hostingersite.com",
          "status_code": 200,
          "header": "Content-Security-Policy",
          "status": "missing"
        },
        "references": [
          "https://owasp.org/www-project-secure-headers/"
        ],
        "metadata": {
          "module": "headers_analyzer",
          "module_version": "0.1.0"
        }
      },
      {
        "id": "KONGALI-HEADERS-0002",
        "title": "Missing security header: Strict-Transport-Security",
        "severity": "HIGH",
        "category": "HTTP Security Headers",
        "description": "The HTTP response does not include the Strict-Transport-Security security header.",
        "owasp": {
          "id": "A05:2021",
          "name": "Security Misconfiguration"
        },
        "cwe": {
          "id": "CWE-319",
          "name": "Cleartext Transmission of Sensitive Information"
        },
        "cvss": {
          "version": "3.1",
          "score": 8.1,
          "severity": "HIGH",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        },
        "impact": "Without HSTS, users may be exposed to protocol downgrade or insecure HTTP connections.",
        "remediation": "Enable HTTP Strict Transport Security with an appropriate max-age and HTTPS deployment.",
        "evidence": {
          "url": "https://blanchedalmond-gorilla-295483.hostingersite.com",
          "status_code": 200,
          "header": "Strict-Transport-Security",
          "status": "missing"
        },
        "references": [
          "https://owasp.org/www-project-secure-headers/"
        ],
        "metadata": {
          "module": "headers_analyzer",
          "module_version": "0.1.0"
        }
      },
      {
        "id": "KONGALI-HEADERS-0003",
        "title": "Missing security header: X-Content-Type-Options",
        "severity": "HIGH",
        "category": "HTTP Security Headers",
        "description": "The HTTP response does not include the X-Content-Type-Options security header.",
        "owasp": {
          "id": "A05:2021",
          "name": "Security Misconfiguration"
        },
        "cwe": {
          "id": "CWE-693",
          "name": "Protection Mechanism Failure"
        },
        "cvss": {
          "version": "3.1",
          "score": 8.1,
          "severity": "HIGH",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        },
        "impact": "Missing X-Content-Type-Options may allow browsers to MIME-sniff responses unexpectedly.",
        "remediation": "Set X-Content-Type-Options to nosniff.",
        "evidence": {
          "url": "https://blanchedalmond-gorilla-295483.hostingersite.com",
          "status_code": 200,
          "header": "X-Content-Type-Options",
          "status": "missing"
        },
        "references": [
          "https://owasp.org/www-project-secure-headers/"
        ],
        "metadata": {
          "module": "headers_analyzer",
          "module_version": "0.1.0"
        }
      },
      {
        "id": "KONGALI-HEADERS-0004",
        "title": "Missing security header: X-Frame-Options",
        "severity": "HIGH",
        "category": "HTTP Security Headers",
        "description": "The HTTP response does not include the X-Frame-Options security header.",
        "owasp": {
          "id": "A05:2021",
          "name": "Security Misconfiguration"
        },
        "cwe": {
          "id": "CWE-693",
          "name": "Protection Mechanism Failure"
        },
        "cvss": {
          "version": "3.1",
          "score": 8.1,
          "severity": "HIGH",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
        },
        "impact": "Missing clickjacking protection may allow malicious sites to frame the application.",
        "remediation": "Set X-Frame-Options to DENY or SAMEORIGIN, or use an appropriate CSP frame-ancestors policy.",
        "evidence": {
          "url": "https://blanchedalmond-gorilla-295483.hostingersite.com",
          "status_code": 200,
          "header": "X-Frame-Options",
          "status": "missing"
        },
        "references": [
          "https://owasp.org/www-project-secure-headers/"
        ],
        "metadata": {
          "module": "headers_analyzer",
          "module_version": "0.1.0"
        }
      },
      {
        "id": "KONGALI-HEADERS-0005",
        "title": "Missing security header: Referrer-Policy",
        "severity": "MEDIUM",
        "category": "HTTP Security Headers",
        "description": "The HTTP response does not include the Referrer-Policy security header.",
        "owasp": {
          "id": "A05:2021",
          "name": "Security Misconfiguration"
        },
        "cwe": {
          "id": "CWE-200",
          "name": "Exposure of Sensitive Information to an Unauthorized Actor"
        },
        "cvss": {
          "version": "3.1",
          "score": 6.4,
          "severity": "MEDIUM",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        },
        "impact": "An overly permissive referrer policy may expose sensitive URL information to external origins.",
        "remediation": "Configure a restrictive Referrer-Policy such as strict-origin-when-cross-origin.",
        "evidence": {
          "url": "https://blanchedalmond-gorilla-295483.hostingersite.com",
          "status_code": 200,
          "header": "Referrer-Policy",
          "status": "missing"
        },
        "references": [
          "https://owasp.org/www-project-secure-headers/"
        ],
        "metadata": {
          "module": "headers_analyzer",
          "module_version": "0.1.0"
        }
      },
      {
        "id": "KONGALI-HEADERS-0006",
        "title": "Missing security header: Permissions-Policy",
        "severity": "MEDIUM",
        "category": "HTTP Security Headers",
        "description": "The HTTP response does not include the Permissions-Policy security header.",
        "owasp": {
          "id": "A05:2021",
          "name": "Security Misconfiguration"
        },
        "cwe": {
          "id": "CWE-693",
          "name": "Protection Mechanism Failure"
        },
        "cvss": {
          "version": "3.1",
          "score": 6.4,
          "severity": "MEDIUM",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        },
        "impact": "Missing Permissions-Policy may allow unnecessary browser capabilities to remain available.",
        "remediation": "Configure Permissions-Policy to explicitly restrict unnecessary browser capabilities.",
        "evidence": {
          "url": "https://blanchedalmond-gorilla-295483.hostingersite.com",
          "status_code": 200,
          "header": "Permissions-Policy",
          "status": "missing"
        },
        "references": [
          "https://owasp.org/www-project-secure-headers/"
        ],
        "metadata": {
          "module": "headers_analyzer",
          "module_version": "0.1.0"
        }
      }
    ]
  }
}
```

---

Generated by Kongali Security.