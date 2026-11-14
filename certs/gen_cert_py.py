"""
Pure-Python self-signed certificate generator for NumberShield.
Uses only Python stdlib: ssl, tempfile, subprocess (calling python itself via ssl.create_default_context tricks).
Actually uses the OpenSSL bindings embedded inside Python's ssl module via ctypes approach.

Simpler approach: use subprocess to call python -c with the ssl._ssl create_connection path,
OR just use the pyopenssl if installed.

Cleanest stdlib-only approach on Windows: use the built-in Windows CNG/SChannel via certutil.
"""
import subprocess, sys, pathlib, os, textwrap

CERTS_DIR = pathlib.Path(r"c:\Users\Varun Kumar\OneDrive\Desktop\numbershield\certs")
KEY_FILE  = CERTS_DIR / "key.pem"
CERT_FILE = CERTS_DIR / "cert.pem"

def try_certreq():
    """Use Windows built-in certreq.exe to generate a self-signed cert."""
    inf_path = CERTS_DIR / "numbershield.inf"
    cer_path = CERTS_DIR / "cert.cer"

    inf_content = textwrap.dedent("""\
        [Version]
        Signature="$Windows NT$"

        [NewRequest]
        Subject = "CN=localhost, O=NumberShield, C=IN"
        KeySpec = 1
        KeyLength = 2048
        Exportable = TRUE
        MachineKeySet = FALSE
        SMIME = False
        PrivateKeyArchive = FALSE
        UserProtected = FALSE
        UseExistingKeySet = FALSE
        ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
        ProviderType = 12
        RequestType = Cert
        KeyUsage = 0xa0
        ValidityPeriod = Years
        ValidityPeriodUnits = 10

        [Extensions]
        2.5.29.17 = "{text}ip=127.0.0.1&dns=localhost"
    """)
    inf_path.write_text(inf_content, encoding="utf-8")

    r = subprocess.run(
        ["certreq", "-new", "-user", str(inf_path), str(cer_path)],
        capture_output=True, text=True
    )
    print("certreq stdout:", r.stdout[:300])
    print("certreq stderr:", r.stderr[:300])
    return r.returncode == 0 and cer_path.exists()

def try_new_selfsignedcert():
    """Use PowerShell New-SelfSignedCertificate + Export-PfxCertificate."""
    pfx_path = CERTS_DIR / "numbershield.pfx"
    ps_script = textwrap.dedent(f"""
        $cert = New-SelfSignedCertificate `
            -DnsName "localhost" `
            -CertStoreLocation "Cert:\\CurrentUser\\My" `
            -FriendlyName "NumberShield Dev TLS" `
            -NotAfter (Get-Date).AddYears(10) `
            -KeyAlgorithm RSA `
            -KeyLength 2048 `
            -KeyUsage DigitalSignature,KeyEncipherment `
            -TextExtension @("2.5.29.17={{text}}dns=localhost&IPAddress=127.0.0.1")
        $thumb = $cert.Thumbprint
        $pwd = ConvertTo-SecureString -String "numbershield" -Force -AsPlainText
        Export-PfxCertificate -Cert "Cert:\\CurrentUser\\My\\$thumb" -FilePath "{pfx_path}" -Password $pwd
        Write-Output $thumb
    """)
    r = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_script],
        capture_output=True, text=True
    )
    print("PS stdout:", r.stdout[:300])
    print("PS stderr:", r.stderr[:300])
    if r.returncode != 0 or not pfx_path.exists():
        return False

    # Convert PFX → PEM key + cert using python ssl via openssl in git bash
    gitbash = r"C:\Program Files\Git\bin\bash.exe"
    if not os.path.exists(gitbash):
        print("Git bash not found, cannot convert PFX to PEM")
        return False

    cmds = [
        f'openssl pkcs12 -in certs/numbershield.pfx -nocerts -nodes -passin pass:numbershield -out certs/key.pem',
        f'openssl pkcs12 -in certs/numbershield.pfx -clcerts -nokeys -passin pass:numbershield -out certs/cert.pem',
    ]
    for cmd in cmds:
        r2 = subprocess.run(
            [gitbash, "-c", cmd],
            capture_output=True, text=True,
            cwd=r"c:\Users\Varun Kumar\OneDrive\Desktop\numbershield"
        )
        print(f"bash cmd: {cmd}")
        print("stdout:", r2.stdout[:200])
        print("stderr:", r2.stderr[:200])
        if r2.returncode != 0:
            return False
    return KEY_FILE.exists() and CERT_FILE.exists()

if __name__ == "__main__":
    print("=== NumberShield HTTPS Certificate Generator ===")
    if try_new_selfsignedcert():
        print(f"\n✅ cert.pem → {CERT_FILE}")
        print(f"✅ key.pem  → {KEY_FILE}")
        sys.exit(0)
    print("\n❌ All methods failed.")
    sys.exit(1)

