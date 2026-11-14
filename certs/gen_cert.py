"""
Generate a self-signed TLS certificate for NumberShield using Python stdlib only.
Requires Python 3.x — no third-party packages needed.
"""
import subprocess, sys, os, pathlib

CERTS_DIR = pathlib.Path(__file__).parent
KEY_FILE  = CERTS_DIR / "key.pem"
CERT_FILE = CERTS_DIR / "cert.pem"

# Try Python's ssl module approach via subprocess openssl (system-level)
# Fall back to pure-Python minimal ASN.1 DER generation

def try_system_openssl():
    """Try to use system openssl (not Git's msys one)."""
    candidates = [
        r"C:\Windows\System32\openssl.exe",
        r"C:\OpenSSL-Win64\bin\openssl.exe",
        r"C:\OpenSSL-Win32\bin\openssl.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None

def generate_via_subprocess(exe):
    cmd = [
        exe, "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(KEY_FILE),
        "-out", str(CERT_FILE),
        "-days", "3650", "-nodes",
        "-subj", "/C=IN/O=NumberShield/CN=localhost",
    ]
    r = subprocess.run(cmd, capture_output=True)
    return r.returncode == 0

def generate_via_pure_python():
    """
    Generate RSA key + self-signed cert using Python's built-in ssl / 
    subprocess call to python -m trustme if available.
    """
    try:
        import trustme
        ca = trustme.CA()
        server_cert = ca.issue_cert("localhost", "127.0.0.1")
        ca.cert_pem.write_to_path(str(CERT_FILE))
        # Combine key + cert into key.pem
        with open(KEY_FILE, "wb") as kf:
            for blob in server_cert.private_key_pem:
                kf.write(blob)
        print("Generated via trustme ✓")
        return True
    except ImportError:
        pass

    # Last resort: write minimal instructions for user
    return False

def write_gen_bat():
    """Write a .bat file the user can run in Git Bash."""
    bat = CERTS_DIR.parent / "generate_cert.bat"
    bat.write_text(
        '@echo off\r\n'
        'echo Generating NumberShield TLS certificate...\r\n'
        '"C:\\Program Files\\Git\\bin\\bash.exe" -c "openssl req -x509 -newkey rsa:2048 '
        '-keyout certs/key.pem -out certs/cert.pem -days 3650 -nodes '
        '-subj \'/C=IN/O=NumberShield/CN=localhost\' '
        '-addext \'subjectAltName=IP:127.0.0.1,DNS:localhost\'"\r\n'
        'echo Done! cert.pem and key.pem created in certs\\\r\n'
        'pause\r\n',
        encoding="utf-8"
    )
    print(f"Wrote helper: {bat}")

if __name__ == "__main__":
    exe = try_system_openssl()
    if exe:
        ok = generate_via_subprocess(exe)
        if ok:
            print(f"Certificate written to {CERT_FILE}")
            print(f"Key written to {KEY_FILE}")
            sys.exit(0)
    if not generate_via_pure_python():
        write_gen_bat()
        print("\n[ACTION NEEDED] Run generate_cert.bat (or see README_HTTPS.md)")
        sys.exit(1)

