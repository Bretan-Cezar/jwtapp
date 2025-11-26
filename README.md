# Basic JWT back-end application
Simple JWT authorization back-end application using RS256 in Java/Spring.

## Certificate and keys creation procedure:

```
mkdir ./certs
cd ./certs

# Interactive
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.crt -sha256 -days 365

openssl x509 -pubkey -noout -in cert.crt > pub.pem

openssl pkcs8 -in key.pem > key_unenc.pem

cd ..
cp -a ./certs/. ./src/main/resources
```

## Certificate local hosting procedure:

```
cd ./certs
python3 -m http.server
```

This will open a http server on port 8000 that serves the files in the current directory. 
A GET request at ```http://localhost:8000/cert.crt``` will retrieve a file named ```cert.crt``` from the directory.

## Application start procedure:

```bash
# In an environment with gradle installed (e.g. Intellij IDEA, Docker Container)
gradle bootRun
```

This will open the back-end app on port 8080 (port can be changed in application.yaml configuration).
Has two endpoints:

- ```GET``` ```http://localhost:8080/auth/``` for obtaining a valid JWT token
- ```POST``` ```http://localhost:8080/auth/``` accessible only with a JWT token preceded by 
  "Bearer " in the Authorization HTTP header. Returns a response indicating whether
  a JWT token is valid. If not, the reason is also included.

Utilities for requests:

- Postman (Windows, MacOS, Ubuntu, Fedora)
- ATAC (Arch Linux)
- curl (any CLI)

