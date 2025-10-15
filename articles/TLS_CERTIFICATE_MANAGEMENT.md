# 🔐 TLS/SSL Certificate Management
## OpenSSL and Java KeyStore Guide for Enterprise Authentication

[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0+-721412?style=flat-square&logo=openssl&logoColor=white)](https://www.openssl.org/)
[![Java](https://img.shields.io/badge/Java-KeyStore-007396?style=flat-square&logo=java&logoColor=white)](#)
[![TLS](https://img.shields.io/badge/TLS-1.2%2F1.3-326CE5?style=flat-square&logo=letsencrypt&logoColor=white)](#)

> **Comprehensive certificate management for secure enterprise communications**
>
> Master OpenSSL and Java KeyStore operations for MarkLogic and enterprise applications

---

## 📋 Table of Contents

- [Introduction](#-introduction)
- [OpenSSL Fundamentals](#-openssl-fundamentals)
- [Private Key Management](#-private-key-management)
- [Certificate Operations](#-certificate-operations)
- [Certificate Signing Requests](#-certificate-signing-requests)
- [Self-Signed Certificates](#-self-signed-certificates)
- [Certificate Chain Management](#-certificate-chain-management)
- [Java KeyStore Operations](#-java-keystore-operations)
- [Conversion Between Formats](#-conversion-between-formats)
- [Certificate Validation](#-certificate-validation)
- [Troubleshooting Common Issues](#-troubleshooting-common-issues)
- [MarkLogic Integration](#-marklogic-integration)

---

## 🎯 Introduction

SSL/TLS certificates are fundamental to secure enterprise communications. This guide provides practical examples for managing certificates using OpenSSL and Java KeyStore, the primary tools used with MarkLogic Server.

### 🔧 Why Certificate Management Matters

Certificate management is critical for:
- **Secure Communication** - Encrypting data in transit
- **Authentication** - Verifying server and client identities
- **Compliance** - Meeting security and regulatory requirements
- **Trust Establishment** - Building secure communication channels
- **MarkLogic Security** - Enabling HTTPS, LDAPS, and client certificate authentication

### 🎯 Common Use Cases

| Scenario | Tool | Purpose |
|----------|------|---------|
| **Web Server SSL** | OpenSSL | Generate server certificates for HTTPS |
| **Client Authentication** | OpenSSL + Java KeyStore | Create client certificates for mutual TLS |
| **LDAPS Connection** | OpenSSL | Generate certificates for secure LDAP |
| **MarkLogic App Server** | Java KeyStore | Configure application server certificates |
| **Certificate Validation** | OpenSSL | Verify certificate chains and validity |
| **Format Conversion** | OpenSSL | Convert between PEM, DER, PKCS#12 formats |

---

## 🔧 OpenSSL Fundamentals

### 📦 **Installation and Verification**

#### Linux/macOS Installation
```bash
# CentOS/RHEL
sudo yum install openssl

# Amazon Linux
sudo yum install openssl

# macOS (Homebrew)
brew install openssl

# Verify installation
openssl version -a
```

#### Basic OpenSSL Information
```bash
# Check OpenSSL version
openssl version

# List available algorithms
openssl list -digest-algorithms
openssl list -cipher-algorithms

# Check supported TLS versions
openssl s_client -help 2>&1 | grep -E "(tls1|ssl)"
```

### 🎯 **File Format Overview**

| Format | Extension | Description | Usage |
|--------|-----------|-------------|-------|
| **PEM** | .pem, .crt, .cer, .key | Base64 encoded, human readable | Most common, text format |
| **DER** | .der, .cer | Binary encoded | Compact binary format |
| **PKCS#12** | .p12, .pfx | Password-protected container | Includes private key + certificate |
| **JKS** | .jks | Java KeyStore format | Java applications |

---

## 🔑 Private Key Management

### 🔐 **RSA Private Keys**

#### Generate RSA Private Keys
```bash
# Generate 2048-bit RSA private key
openssl genrsa -out private.key 2048

# Generate 4096-bit RSA private key (more secure)
openssl genrsa -out private-4096.key 4096

# Generate encrypted private key (password protected)
openssl genrsa -aes256 -out private-encrypted.key 2048

# Generate key with specific passphrase
openssl genrsa -aes256 -passout pass:MySecurePassword -out private-pass.key 2048
```

#### View RSA Private Key Information
```bash
# Display private key details
openssl rsa -in private.key -text -noout

# Check if private key is encrypted
openssl rsa -in private.key -check -noout

# Extract public key from private key
openssl rsa -in private.key -pubout -out public.key

# Remove passphrase from encrypted key
openssl rsa -in private-encrypted.key -out private-unencrypted.key
```

### 🔐 **EC (Elliptic Curve) Private Keys**

#### Generate EC Private Keys
```bash
# List available EC curves
openssl ecparam -list_curves

# Generate P-256 EC private key
openssl ecparam -genkey -name prime256v1 -out ec-private.key

# Generate P-384 EC private key (more secure)
openssl ecparam -genkey -name secp384r1 -out ec-private-384.key

# Generate encrypted EC private key
openssl ecparam -genkey -name prime256v1 | openssl ec -aes256 -out ec-encrypted.key
```

#### View EC Private Key Information
```bash
# Display EC private key details
openssl ec -in ec-private.key -text -noout

# Extract EC public key
openssl ec -in ec-private.key -pubout -out ec-public.key
```

### 🔒 **Key Security Best Practices**

#### Secure Key Generation
```bash
# Generate key with secure random source
openssl genrsa -rand /dev/urandom -out secure.key 2048

# Set proper file permissions (owner read-only)
chmod 600 private.key

# Verify key integrity
openssl rsa -in private.key -check -noout
```

#### Key Storage Recommendations
```bash
# Create secure directory for keys
sudo mkdir -p /etc/ssl/private
sudo chmod 700 /etc/ssl/private
sudo chown root:root /etc/ssl/private

# Store private keys securely
sudo cp private.key /etc/ssl/private/
sudo chmod 600 /etc/ssl/private/private.key
```

---

## 📜 Certificate Operations

### 🏷️ **Viewing Certificate Information**

#### Basic Certificate Inspection
```bash
# View certificate details (PEM format)
openssl x509 -in certificate.crt -text -noout

# View certificate subject and issuer
openssl x509 -in certificate.crt -subject -issuer -noout

# Check certificate validity dates
openssl x509 -in certificate.crt -dates -noout

# Display certificate fingerprint
openssl x509 -in certificate.crt -fingerprint -noout

# Show certificate serial number
openssl x509 -in certificate.crt -serial -noout
```

#### Certificate Chain Analysis
```bash
# View certificate chain from file
openssl crl2pkcs7 -nocrl -certfile certificate-chain.pem | openssl pkcs7 -print_certs -text -noout

# Verify certificate against CA bundle
openssl verify -CAfile ca-bundle.crt certificate.crt

# Show certificate purpose/usage
openssl x509 -in certificate.crt -purpose -noout
```

### 🌐 **Remote Certificate Inspection**

#### HTTPS Server Certificates
```bash
# Check HTTPS certificate for website
openssl s_client -connect www.example.com:443 -servername www.example.com

# Get certificate chain from HTTPS server
openssl s_client -connect www.example.com:443 -showcerts

# Check specific TLS version support
openssl s_client -connect www.example.com:443 -tls1_2
openssl s_client -connect www.example.com:443 -tls1_3

# Check certificate expiration for HTTPS server
echo | openssl s_client -connect www.example.com:443 2>/dev/null | openssl x509 -dates -noout
```

#### LDAPS Server Certificates
```bash
# Check LDAPS certificate
openssl s_client -connect ldap.example.com:636

# Verify LDAPS certificate chain
openssl s_client -connect ldap.example.com:636 -verify_return_error

# Save LDAPS server certificate
echo | openssl s_client -connect ldap.example.com:636 2>/dev/null | openssl x509 > ldap-server.crt
```

---

## 📝 Certificate Signing Requests

### 🎯 **Creating CSRs**

#### Basic CSR Generation
```bash
# Generate CSR with new private key
openssl req -new -newkey rsa:2048 -keyout private.key -out request.csr

# Generate CSR using existing private key
openssl req -new -key private.key -out request.csr

# Generate CSR with subject information in command line
openssl req -new -key private.key -out request.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/OU=IT Department/CN=www.example.com"
```

#### CSR with Subject Alternative Names (SAN)
```bash
# Create config file for SAN certificate
cat > san.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Example Corp
OU = IT Department
CN = www.example.com

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = www.example.com
DNS.2 = example.com
DNS.3 = api.example.com
IP.1 = 192.168.1.100
EOF

# Generate CSR with SAN
openssl req -new -key private.key -out san-request.csr -config san.conf
```

#### EC CSR Generation
```bash
# Generate EC CSR
openssl req -new -key ec-private.key -out ec-request.csr

# Generate EC CSR with specific curve
openssl ecparam -genkey -name prime256v1 | openssl req -new -key /dev/stdin -out ec-request.csr
```

### 🔍 **Viewing and Validating CSRs**

#### CSR Inspection
```bash
# View CSR details
openssl req -in request.csr -text -noout

# Verify CSR signature
openssl req -in request.csr -verify -noout

# Extract public key from CSR
openssl req -in request.csr -pubkey -noout

# Check CSR subject information
openssl req -in request.csr -subject -noout
```

#### CSR Validation
```bash
# Verify CSR matches private key
openssl req -in request.csr -noout -pubkey | openssl md5
openssl rsa -in private.key -pubout | openssl md5

# Check CSR for SAN extensions
openssl req -in san-request.csr -text -noout | grep -A 1 "Subject Alternative Name"
```

---

## 🏆 Self-Signed Certificates

### 🎯 **Basic Self-Signed Certificates**

#### Simple Self-Signed Certificate
```bash
# Generate self-signed certificate (all-in-one)
openssl req -x509 -newkey rsa:2048 -keyout selfsigned.key -out selfigned.crt -days 365

# Generate self-signed certificate without passphrase
openssl req -x509 -newkey rsa:2048 -keyout selfigned.key -out selfigned.crt -days 365 -nodes

# Generate using existing private key
openssl req -x509 -key private.key -out selfigned.crt -days 365
```

#### Self-Signed with Subject Information
```bash
# Self-signed certificate with subject in command line
openssl req -x509 -newkey rsa:2048 -keyout selfigned.key -out selfigned.crt -days 365 -nodes \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/OU=IT Department/CN=localhost"
```

### 🌐 **Advanced Self-Signed Certificates**

#### Self-Signed with SAN
```bash
# Create configuration for self-signed SAN certificate
cat > selfigned-san.conf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = California
L = San Francisco
O = Example Corp
OU = IT Department
CN = localhost

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.example.local
DNS.3 = test.example.com
IP.1 = 127.0.0.1
IP.2 = 192.168.1.100
EOF

# Generate self-signed certificate with SAN
openssl req -x509 -newkey rsa:2048 -keyout selfigned-san.key -out selfigned-san.crt \
    -days 365 -nodes -config selfigned-san.conf
```

#### Long-Term Self-Signed Certificates
```bash
# Generate long-term self-signed certificate (10 years)
openssl req -x509 -newkey rsa:4096 -keyout longterm.key -out longterm.crt -days 3650 -nodes

# Self-signed with strong encryption
openssl req -x509 -newkey rsa:4096 -sha256 -keyout strong.key -out strong.crt -days 3650 -nodes
```

### 🔐 **CA-Style Self-Signed Certificates**

#### Create Root CA Certificate
```bash
# Generate root CA private key
openssl genrsa -aes256 -out rootCA.key 4096

# Create root CA certificate
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 -out rootCA.crt \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/OU=Root CA/CN=Example Root CA"

# Create CA configuration
cat > ca.conf << EOF
[ca]
default_ca = CA_default

[CA_default]
dir = ./ca
certs = \$dir/certs
crl_dir = \$dir/crl
database = \$dir/index.txt
new_certs_dir = \$dir/newcerts
certificate = \$dir/rootCA.crt
serial = \$dir/serial
crlnumber = \$dir/crlnumber
crl = \$dir/crl.pem
private_key = \$dir/rootCA.key
RANDFILE = \$dir/.rand
default_days = 365
default_crl_days = 30
default_md = sha256
preserve = no
policy = policy_strict

[policy_strict]
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
EOF
```

---

## 🔗 Certificate Chain Management

### 🏗️ **Building Certificate Chains**

#### Understanding Certificate Chains
- **End Entity Certificate** - Server/client certificate
- **Intermediate Certificates** - Issued by CA, signs end entity
- **Root Certificate** - Self-signed, trusted anchor

#### Creating Certificate Chains
```bash
# Combine certificates into chain (order matters: end entity first)
cat server.crt intermediate.crt rootCA.crt > certificate-chain.pem

# Create chain with proper ordering
cat > certificate-chain.pem << EOF
-----BEGIN CERTIFICATE-----
[End Entity Certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Intermediate Certificate]
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
[Root Certificate]
-----END CERTIFICATE-----
EOF
```

### 🔍 **Validating Certificate Chains**

#### Chain Verification
```bash
# Verify certificate chain
openssl verify -CAfile rootCA.crt -untrusted intermediate.crt server.crt

# Verify chain from combined file
openssl verify -CAfile certificate-chain.pem server.crt

# Show certificate chain validation path
openssl verify -CAfile rootCA.crt -untrusted intermediate.crt -show_chain server.crt
```

#### Chain Analysis
```bash
# Extract individual certificates from chain
openssl crl2pkcs7 -nocrl -certfile certificate-chain.pem | openssl pkcs7 -print_certs -out separated-certs.pem

# Count certificates in chain
grep -c "BEGIN CERTIFICATE" certificate-chain.pem

# Show chain hierarchy
openssl crl2pkcs7 -nocrl -certfile certificate-chain.pem | openssl pkcs7 -print_certs -text -noout | grep -E "(Subject:|Issuer:)"
```

---

## ☕ Java KeyStore Operations

### 📦 **KeyStore Fundamentals**

#### KeyStore Types
| Type | Description | Usage |
|------|-------------|-------|
| **JKS** | Java KeyStore (legacy) | Traditional Java applications |
| **PKCS12** | Industry standard | Recommended for new applications |
| **JCEKS** | Java Cryptography Extension | Enhanced security features |

#### Basic KeyStore Operations
```bash
# Create new keystore
keytool -genkeypair -alias mykey -keyalg RSA -keysize 2048 -keystore keystore.jks

# List keystore contents
keytool -list -keystore keystore.jks

# List with detailed information
keytool -list -v -keystore keystore.jks

# Check specific alias
keytool -list -alias mykey -keystore keystore.jks
```

### 🔐 **Private Key and Certificate Management**

#### Generate Key Pair in KeyStore
```bash
# Generate RSA key pair
keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -keystore server.jks \
    -dname "CN=www.example.com,OU=IT,O=Example Corp,L=San Francisco,ST=California,C=US" \
    -validity 365

# Generate EC key pair
keytool -genkeypair -alias server-ec -keyalg EC -keysize 256 -keystore server.jks \
    -dname "CN=www.example.com,OU=IT,O=Example Corp,L=San Francisco,ST=California,C=US"

# Generate with SAN extension
keytool -genkeypair -alias server-san -keyalg RSA -keysize 2048 -keystore server.jks \
    -dname "CN=www.example.com,OU=IT,O=Example Corp,L=San Francisco,ST=California,C=US" \
    -ext SAN=dns:www.example.com,dns:example.com,ip:192.168.1.100
```

#### Import Certificates into KeyStore
```bash
# Import certificate authority
keytool -import -alias rootca -file rootCA.crt -keystore truststore.jks

# Import certificate chain
keytool -import -alias server -file certificate-chain.pem -keystore server.jks

# Import trusted certificate
keytool -import -alias ldapserver -file ldap-server.crt -keystore truststore.jks -trustcacerts
```

#### Export from KeyStore
```bash
# Export certificate
keytool -export -alias server -file server.crt -keystore server.jks

# Export certificate chain
keytool -export -alias server -file server-chain.crt -keystore server.jks -rfc

# Export private key (requires conversion)
# Note: keytool cannot directly export private keys
# Use PKCS12 format for private key export
```

### 🔄 **KeyStore Conversion and Migration**

#### Convert JKS to PKCS12
```bash
# Convert JKS to PKCS12 (recommended format)
keytool -importkeystore -srckeystore keystore.jks -destkeystore keystore.p12 \
    -srcstoretype JKS -deststoretype PKCS12

# Convert with specific alias
keytool -importkeystore -srckeystore keystore.jks -destkeystore keystore.p12 \
    -srcstoretype JKS -deststoretype PKCS12 -srcalias mykey -destalias mykey
```

#### Merge KeyStores
```bash
# Merge multiple keystores
keytool -importkeystore -srckeystore source1.jks -destkeystore merged.jks
keytool -importkeystore -srckeystore source2.jks -destkeystore merged.jks

# Copy specific aliases between keystores
keytool -importkeystore -srckeystore source.jks -destkeystore target.jks \
    -srcalias specific-alias -destalias new-alias
```

### 🔧 **KeyStore Management**

#### Password Management
```bash
# Change keystore password
keytool -storepasswd -keystore keystore.jks

# Change key password
keytool -keypasswd -alias mykey -keystore keystore.jks

# Change alias name
keytool -changealias -alias oldname -destalias newname -keystore keystore.jks
```

#### Certificate Management
```bash
# Delete certificate/key
keytool -delete -alias unwanted -keystore keystore.jks

# Replace certificate
keytool -delete -alias server -keystore keystore.jks
keytool -import -alias server -file new-server.crt -keystore keystore.jks

# Update certificate chain
keytool -import -alias server -file updated-chain.pem -keystore keystore.jks
```

---

## 🔄 Conversion Between Formats

### 📝 **PEM ↔ DER Conversion**

#### PEM to DER
```bash
# Convert certificate PEM to DER
openssl x509 -in certificate.pem -outform DER -out certificate.der

# Convert private key PEM to DER
openssl rsa -in private.key -outform DER -out private.der

# Convert CSR PEM to DER
openssl req -in request.csr -outform DER -out request.der
```

#### DER to PEM
```bash
# Convert certificate DER to PEM
openssl x509 -in certificate.der -inform DER -outform PEM -out certificate.pem

# Convert private key DER to PEM
openssl rsa -in private.der -inform DER -outform PEM -out private.pem

# Convert CSR DER to PEM
openssl req -in request.der -inform DER -outform PEM -out request.pem
```

### 📦 **PKCS#12 Operations**

#### Create PKCS#12
```bash
# Create PKCS#12 from certificate and private key
openssl pkcs12 -export -out certificate.p12 -inkey private.key -in certificate.crt

# Create PKCS#12 with certificate chain
openssl pkcs12 -export -out certificate.p12 -inkey private.key \
    -in certificate.crt -certfile certificate-chain.pem

# Create PKCS#12 with friendly name
openssl pkcs12 -export -out certificate.p12 -inkey private.key -in certificate.crt \
    -name "My Server Certificate"
```

#### Extract from PKCS#12
```bash
# Extract private key from PKCS#12
openssl pkcs12 -in certificate.p12 -nocerts -out private.key

# Extract certificate from PKCS#12
openssl pkcs12 -in certificate.p12 -nokeys -out certificate.crt

# Extract CA certificates from PKCS#12
openssl pkcs12 -in certificate.p12 -cacerts -nokeys -out ca-certificates.crt

# Extract everything from PKCS#12
openssl pkcs12 -in certificate.p12 -out combined.pem
```

### ☕ **OpenSSL ↔ Java KeyStore**

#### Import OpenSSL to Java KeyStore
```bash
# Convert OpenSSL format to PKCS#12 first
openssl pkcs12 -export -out temp.p12 -inkey private.key -in certificate.crt

# Import PKCS#12 to Java KeyStore
keytool -importkeystore -srckeystore temp.p12 -srcstoretype PKCS12 \
    -destkeystore keystore.jks -deststoretype JKS

# Clean up temporary file
rm temp.p12
```

#### Export Java KeyStore to OpenSSL
```bash
# Convert JKS to PKCS#12
keytool -importkeystore -srckeystore keystore.jks -destkeystore temp.p12 \
    -srcstoretype JKS -deststoretype PKCS12

# Extract private key
openssl pkcs12 -in temp.p12 -nocerts -out private.key

# Extract certificate
openssl pkcs12 -in temp.p12 -nokeys -out certificate.crt

# Clean up
rm temp.p12
```

---

## ✅ Certificate Validation

### 🔍 **Basic Validation**

#### Certificate Integrity
```bash
# Verify certificate signature
openssl x509 -in certificate.crt -noout -text | grep "Signature Algorithm"

# Check certificate validity period
openssl x509 -in certificate.crt -noout -dates

# Verify certificate has not expired
openssl x509 -in certificate.crt -noout -checkend 86400  # 24 hours

# Check certificate fingerprint
openssl x509 -in certificate.crt -noout -fingerprint -sha256
```

#### Private Key Validation
```bash
# Verify private key integrity
openssl rsa -in private.key -check -noout

# Check if private key matches certificate
openssl x509 -in certificate.crt -noout -modulus | openssl md5
openssl rsa -in private.key -noout -modulus | openssl md5

# Verify private key matches CSR
openssl req -in request.csr -noout -modulus | openssl md5
openssl rsa -in private.key -noout -modulus | openssl md5
```

### 🌐 **Online Certificate Validation**

#### OCSP Validation
```bash
# Check certificate revocation status via OCSP
openssl ocsp -issuer issuer.crt -cert certificate.crt -url http://ocsp.example.com

# Verify OCSP response
openssl ocsp -issuer issuer.crt -cert certificate.crt -url http://ocsp.example.com -resp_text
```

#### CRL Validation
```bash
# Download and check Certificate Revocation List
wget http://crl.example.com/example.crl
openssl crl -in example.crl -text -noout

# Verify certificate against CRL
openssl verify -CRLfile example.crl -crl_check certificate.crt
```

### 🔐 **SSL/TLS Connection Validation**

#### Server Certificate Testing
```bash
# Test SSL certificate on server
openssl s_client -connect www.example.com:443 -verify_return_error

# Check certificate chain validation
openssl s_client -connect www.example.com:443 -showcerts -verify 5

# Test specific protocol version support
openssl s_client -connect www.example.com:443 -tls1_2 -verify_return_error

# Check cipher suite support
openssl s_client -connect www.example.com:443 -cipher 'ECDHE+AESGCM'
```

#### Client Certificate Testing
```bash
# Test client certificate authentication
openssl s_client -connect server.example.com:443 -cert client.crt -key client.key

# Test client certificate with CA bundle
openssl s_client -connect server.example.com:443 -cert client.crt -key client.key -CAfile ca-bundle.crt
```

---

## 🚨 Troubleshooting Common Issues

### ❌ **Certificate Errors**

#### "Certificate has expired"
```bash
# Check certificate expiration
openssl x509 -in certificate.crt -noout -dates

# Check how long until expiration
openssl x509 -in certificate.crt -noout -checkend 2592000  # 30 days

# Solution: Renew certificate before expiration
openssl req -new -key private.key -out renewal.csr
```

#### "Certificate verification failed"
```bash
# Check certificate chain
openssl verify -CAfile ca-bundle.crt certificate.crt

# Common issues:
# 1. Missing intermediate certificates
cat server.crt intermediate.crt > complete-chain.crt

# 2. Wrong certificate order in chain
# Correct order: server cert, intermediate cert, root cert

# 3. Self-signed certificate not in trust store
keytool -import -alias myca -file rootCA.crt -keystore truststore.jks
```

#### "Hostname verification failed"
```bash
# Check certificate subject and SAN
openssl x509 -in certificate.crt -noout -text | grep -A 1 "Subject Alternative Name"

# Solution: Generate certificate with correct hostnames
openssl req -new -key private.key -out corrected.csr -config san.conf
```

### 🔧 **KeyStore Issues**

#### "KeyStore was tampered with, or password was incorrect"
```bash
# Try different password
keytool -list -keystore keystore.jks -storepass differentpassword

# Check keystore integrity
keytool -list -keystore keystore.jks -storetype JKS

# Recover from backup if corrupted
cp keystore.jks.backup keystore.jks
```

#### "Alias does not exist"
```bash
# List all aliases
keytool -list -keystore keystore.jks

# Check specific alias with different case
keytool -list -alias MYKEY -keystore keystore.jks
keytool -list -alias mykey -keystore keystore.jks

# Import missing certificate
keytool -import -alias missing -file certificate.crt -keystore keystore.jks
```

### 🌐 **SSL Connection Issues**

#### "SSL handshake failed"
```bash
# Test SSL connection with verbose output
openssl s_client -connect server.example.com:443 -debug

# Check supported cipher suites
nmap --script ssl-enum-ciphers -p 443 server.example.com

# Test specific TLS version
openssl s_client -connect server.example.com:443 -tls1_2
openssl s_client -connect server.example.com:443 -tls1_3
```

#### "Certificate chain incomplete"
```bash
# Get complete certificate chain from server
openssl s_client -connect server.example.com:443 -showcerts > server-chain.pem

# Extract individual certificates
awk '/BEGIN/{p++}{if(p){print > "cert" p ".pem"}}' server-chain.pem

# Verify chain order
openssl verify -CAfile rootCA.crt -untrusted intermediate.crt server.crt
```

---

## 🎯 MarkLogic Integration

### 🏗️ **MarkLogic Certificate Configuration**

#### App Server SSL Configuration
```bash
# Generate server certificate for MarkLogic App Server
openssl genrsa -out marklogic-server.key 2048

# Create CSR for MarkLogic server
openssl req -new -key marklogic-server.key -out marklogic-server.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=marklogic.example.com"

# Generate self-signed certificate for development
openssl x509 -req -in marklogic-server.csr -signkey marklogic-server.key \
    -out marklogic-server.crt -days 365
```

#### Client Certificate for Authentication
```bash
# Generate client certificate for MarkLogic authentication
openssl genrsa -out marklogic-client.key 2048

# Create client certificate CSR
openssl req -new -key marklogic-client.key -out marklogic-client.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=client.example.com"

# Sign client certificate (using CA or self-signed)
openssl x509 -req -in marklogic-client.csr -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out marklogic-client.crt -days 365
```

### 📦 **MarkLogic KeyStore Setup**

#### Create TrustStore for MarkLogic
```bash
# Create truststore for CA certificates
keytool -genkeypair -alias dummy -keystore marklogic-truststore.jks -keyalg RSA
keytool -delete -alias dummy -keystore marklogic-truststore.jks

# Import CA certificate
keytool -import -alias rootca -file rootCA.crt -keystore marklogic-truststore.jks -trustcacerts

# Import LDAP server certificate
keytool -import -alias ldapserver -file ldap-server.crt -keystore marklogic-truststore.jks -trustcacerts
```

#### Configure MarkLogic Keystore
```bash
# Create keystore for MarkLogic server certificates
keytool -importkeystore -srckeystore temp.p12 -srcstoretype PKCS12 \
    -destkeystore marklogic-keystore.jks -deststoretype JKS

# Verify keystore contents
keytool -list -v -keystore marklogic-keystore.jks
```

### 🔐 **LDAPS Integration**

#### LDAP Server Certificate Validation
```bash
# Test LDAPS connection
openssl s_client -connect ldap.example.com:636 -verify_return_error

# Extract LDAP server certificate
echo | openssl s_client -connect ldap.example.com:636 2>/dev/null | \
    openssl x509 > ldap-server.crt

# Import LDAP certificate to MarkLogic truststore
keytool -import -alias ldapserver -file ldap-server.crt \
    -keystore marklogic-truststore.jks -trustcacerts
```

#### Client Certificate for LDAP Authentication
```bash
# Create client certificate for LDAP client authentication
openssl genrsa -out ldap-client.key 2048

# Generate client certificate
openssl req -new -key ldap-client.key -out ldap-client.csr \
    -subj "/C=US/ST=California/L=San Francisco/O=Example Corp/CN=marklogic-client"

# Convert to PKCS#12 for MarkLogic
openssl pkcs12 -export -out ldap-client.p12 -inkey ldap-client.key -in ldap-client.crt

# Import to MarkLogic keystore
keytool -importkeystore -srckeystore ldap-client.p12 -srcstoretype PKCS12 \
    -destkeystore marklogic-keystore.jks -deststoretype JKS
```

### 📋 **MarkLogic Configuration Scripts**

#### Automated Certificate Setup
```bash
#!/bin/bash
# MarkLogic certificate setup script

DOMAIN="marklogic.example.com"
ORG="Example Corp"
KEYSTORE_PASS="changeit"

# Create directories
mkdir -p certs keystores

# Generate CA certificate
openssl genrsa -out certs/rootCA.key 4096
openssl req -x509 -new -nodes -key certs/rootCA.key -sha256 -days 3650 \
    -out certs/rootCA.crt -subj "/C=US/ST=CA/L=SF/O=$ORG/CN=Root CA"

# Generate server certificate
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr \
    -subj "/C=US/ST=CA/L=SF/O=$ORG/CN=$DOMAIN"
openssl x509 -req -in certs/server.csr -CA certs/rootCA.crt -CAkey certs/rootCA.key \
    -CAcreateserial -out certs/server.crt -days 365

# Create PKCS#12 and import to keystore
openssl pkcs12 -export -out certs/server.p12 -inkey certs/server.key \
    -in certs/server.crt -passout pass:$KEYSTORE_PASS

keytool -importkeystore -srckeystore certs/server.p12 -srcstoretype PKCS12 \
    -destkeystore keystores/marklogic-keystore.jks -deststoretype JKS \
    -srcstorepass $KEYSTORE_PASS -deststorepass $KEYSTORE_PASS

# Create truststore
keytool -import -alias rootca -file certs/rootCA.crt \
    -keystore keystores/marklogic-truststore.jks -storepass $KEYSTORE_PASS -noprompt

echo "Certificates generated successfully!"
echo "Keystore: keystores/marklogic-keystore.jks"
echo "Truststore: keystores/marklogic-truststore.jks"
```

---

## 📋 Summary

This comprehensive guide covers essential SSL/TLS certificate management operations using OpenSSL and Java KeyStore tools.

### 🎯 **Key Takeaways**

#### **OpenSSL Mastery**
- Generate secure private keys (RSA and EC)
- Create and manage certificate signing requests
- Generate self-signed certificates with SAN extensions
- Perform certificate validation and troubleshooting

#### **Java KeyStore Operations**
- Manage keystores and truststores
- Import/export certificates and keys
- Convert between different formats
- Integrate with enterprise applications

#### **Format Conversions**
- Master PEM ↔ DER conversions
- Work with PKCS#12 containers
- Integrate OpenSSL and Java KeyStore workflows

#### **MarkLogic Integration**
- Configure SSL for App Servers
- Set up LDAPS authentication
- Manage certificate chains for external authentication
- Automate certificate deployment

### 🔧 **Best Practices**
- Use strong key sizes (RSA 2048+, EC P-256+)
- Implement proper certificate chain validation
- Maintain secure key storage and permissions
- Regular certificate expiration monitoring
- Test SSL/TLS configurations thoroughly

Mastering these certificate management techniques will ensure secure, reliable TLS/SSL implementations across your enterprise authentication infrastructure.