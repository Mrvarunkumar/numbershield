# Trust the NumberShield self-signed certificate (removes browser warning permanently)
$certPath = "c:\Users\Varun Kumar\OneDrive\Desktop\numbershield\certs\cert.pem"
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","CurrentUser")
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
Write-Host "Certificate trusted successfully! Restart Chrome and visit https://127.0.0.1:8443" -ForegroundColor Green

