import subprocess


def run_scan(target):
    """
    Runs nmap with XML output.
    Returns XML scan result as string.
    """

    try:
        command = ["nmap", "-sV", "-oX", "-", target]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return None, result.stderr

        return result.stdout, None

    except Exception as e:
        return None, str(e)
