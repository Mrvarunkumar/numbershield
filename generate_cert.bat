@echo off
echo Generating NumberShield TLS certificate...
"C:\Program Files\Git\bin\bash.exe" -c "openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 3650 -nodes -subj '/C=IN/O=NumberShield/CN=localhost' -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost'"
echo Done! cert.pem and key.pem created in certs\
pause
