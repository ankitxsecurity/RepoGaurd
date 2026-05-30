import re
from findings import add_finding
def scan_secrets(content, filepath):

    if re.search(r"password\s*=", content, re.IGNORECASE):

        add_finding(
        "HIGH",
        "SECRET",
        "Hardcoded password detected",
        filepath
    )

    if re.search(r"api[_-]?key\s*=", content, re.IGNORECASE):

        add_finding(
            "HIGH",
            "SECRET",
            "Hardcoded API key found",
            filepath
        ) 

    if re.search(r"api[-_]?token*=",content,re.IGNORECASE):
        add_finding(
            "HIGH",
            "SECRET",
            "Hardcoded API Token found",
            filepath
        )
    if re.search(r"JWT[-_]?token*=",content,re.IGNORECASE):
        add_finding(
            "HIGH",
            "SECRET",
            "Hardcoded JWT Token found",
            filepath
        )


    if re.search(r"AWS[-_]?token*=",content,re.IGNORECASE):
        add_finding(
            "HIGH",
            "SECRET",
            "Hardcoded AWS Token found",
            filepath
        )
    