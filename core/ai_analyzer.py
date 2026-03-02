"""
AI Analyzer Module
Mock implementation for tablet development.
Designed to be replaced with real LLM backend later.
"""


class MockAIAnalyzer:

    def analyze_port(self, port_data):
        """
        Generate AI-style explanation for a single port.
        """

        severity = port_data["severity"]
        service = port_data["service"]
        version = port_data["version"]

        explanation = (
            f"The service '{service}' (version: {version}) "
            f"is classified as {severity}. "
        )

        if severity in ["CRITICAL", "HIGH"]:
            explanation += (
                "This service should be reviewed immediately for "
                "misconfigurations or known vulnerabilities."
            )
        elif severity == "MEDIUM":
            explanation += (
                "It may pose security risks if exposed publicly. "
                "Consider restricting access."
            )
        elif severity == "LOW":
            explanation += (
                "This service is generally lower risk but still "
                "should be monitored."
            )
        else:
            explanation += (
                "No specific risk rule matched. Manual review recommended."
            )

        return explanation

    def analyze_overall(self, findings, summary):
        """
        Generate AI-style overall scan summary.
        """

        critical = summary.get("CRITICAL", 0)
        high = summary.get("HIGH", 0)

        if critical > 0:
            overall = (
                f"The scan identified {critical} critical services. "
                "Immediate remediation is recommended."
            )
        elif high > 0:
            overall = (
                f"The scan identified {high} high-risk services. "
                "Security hardening is advised."
            )
        else:
            overall = (
                "No critical services detected. Continue monitoring "
                "and apply standard security best practices."
            )

        return overall
