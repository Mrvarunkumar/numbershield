$cert = New-SelfSignedCertificate `
    -Subject "CN=localhost, O=NumberShield, C=IN" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -FriendlyName "NumberShield Dev TLS" `
    -NotAfter (Get-Date).AddYears(10) `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -KeyUsage DigitalSignature,KeyEncipherment

$thumb = $cert.Thumbprint
Write-Host "Thumbprint: $thumb"

$pfxPath = "c:\Users\Varun Kumar\OneDrive\Desktop\numbershield\certs\numbershield.pfx"
$pwd = ConvertTo-SecureString -String "numbershield123" -Force -AsPlainText
Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$thumb" -FilePath $pfxPath -Password $pwd
Write-Host "PFX exported to: $pfxPath"

