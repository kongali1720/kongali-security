"""Security compliance mapping."""

from __future__ import annotations


COMPLIANCE_MAP = {

    "Content-Security-Policy":
        [
            "OWASP ASVS",
            "OWASP Top 10 A05",
        ],

    "Strict-Transport-Security":
        [
            "OWASP ASVS",
            "CWE-319",
        ],

    "X-Frame-Options":
        [
            "OWASP Top 10 A05",
            "CWE-1021",
        ],

    "Permissions-Policy":
        [
            "OWASP ASVS",
        ],
}


def map_compliance(
    findings: list[dict],
) -> list[dict]:

    results = []


    for finding in findings:

        title = finding.get(
            "title",
            "",
        )


        standards = []


        for keyword, items in COMPLIANCE_MAP.items():

            if keyword in title:

                standards.extend(
                    items
                )


        results.append(
            {
                "finding": title,
                "standards": standards,
            }
        )


    return results
