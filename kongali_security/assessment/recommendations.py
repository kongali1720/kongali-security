"""Security remediation recommendations."""


def generate_recommendations(
    findings: list[dict],
) -> list[str]:

    recommendations = []


    for finding in findings:

        remediation = finding.get(
            "remediation"
        )


        if remediation:

            recommendations.append(
                remediation
            )

        else:

            title = finding.get(
                "title",
                "Security issue",
            )

            recommendations.append(
                f"Review and remediate: {title}"
            )


    return list(
        dict.fromkeys(
            recommendations
        )
    )
