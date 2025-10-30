# 🔐 SAML 2.0 Authentication Troubleshooting
## MarkLogic Identity Provider Integration and Diagnostics

[![SAML](https://img.shields.io/badge/SAML-2.0-0066CC?style=flat-square&logo=saml&logoColor=white)](#)
[![MarkLogic](https://img.shields.io/badge/MarkLogic-10%2B-FF6B35?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAiIGhlaWdodD0iMjAiIHZpZXdCb3g9IjAgMCAyMCAyMCIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHJlY3Qgd2lkdGg9IjIwIiBoZWlnaHQ9IjIwIiBmaWxsPSIjRkY2QjM1Ii8+CjwvU3ZnPgo=&logoColor=white)](https://docs.marklogic.com/)
[![Enterprise](https://img.shields.io/badge/Enterprise-SSO-2E8B57?style=flat-square&logo=shield&logoColor=white)](#)

> **Comprehensive SAML 2.0 troubleshooting for MarkLogic enterprise authentication**
>
> Master identity provider integration, certificate management, and SSO diagnostics

---

## 📋 Table of Contents

- [Introduction](#-introduction)
- [SAML 2.0 Fundamentals](#-saml-20-fundamentals)
- [MarkLogic SAML Configuration](#-marklogic-saml-configuration)
- [Identity Provider Setup](#-identity-provider-setup)
- [Certificate Management](#-certificate-management)
- [Troubleshooting Tools](#-troubleshooting-tools)
- [Common Issues](#-common-issues)
- [Validation and Testing](#-validation-and-testing)
- [Performance Optimization](#-performance-optimization)
- [Security Best Practices](#-security-best-practices)

---

## 🎯 Introduction

SAML (Security Assertion Markup Language) 2.0 enables secure single sign-on (SSO) between MarkLogic and identity providers like Active Directory Federation Services (ADFS), Okta, Azure AD, and others. This guide provides comprehensive troubleshooting techniques for SAML authentication issues.

### 🔧 Why SAML Matters

SAML authentication provides:
- **Single Sign-On (SSO)** - Users authenticate once across multiple systems
- **Federated Identity** - Centralized identity management
- **Strong Security** - XML-based assertions with digital signatures
- **Compliance** - Meets enterprise security requirements
- **Scalability** - Supports large user populations

### 🎯 SAML vs Other Authentication Methods

| Feature | SAML 2.0 | LDAP | OAuth 2.0 | Kerberos |
|---------|----------|------|-----------|----------|
| **SSO Support** | ✅ Native | ❌ No | ✅ Limited | ✅ Native |
| **Web-based** | ✅ Yes | ❌ No | ✅ Yes | ⚠️ Limited |
| **Federation** | ✅ Full | ❌ No | ✅ Yes | ⚠️ Domain-based |
| **Mobile Support** | ⚠️ Limited | ❌ No | ✅ Excellent | ❌ No |
| **Complexity** | 🔶 High | 🟢 Low | 🟡 Medium | 🔶 High |

---

## 📚 SAML 2.0 Fundamentals

### 🏗️ **Core Components**

#### **Identity Provider (IdP)**
The system that authenticates users and issues SAML assertions.

**Examples:**
- Microsoft ADFS
- Azure Active Directory
- Okta
- Ping Identity
- MLEAProxy (Development/Testing)

#### **Service Provider (SP)**
The application that consumes SAML assertions (MarkLogic in our case).

**MarkLogic Acts As:**
- Service Provider (SP) for user authentication
- Relies on IdP for identity verification

#### **SAML Assertions**
XML documents containing:
- **Authentication Statement** - Proof of user authentication
- **Attribute Statement** - User attributes (name, email, roles)
- **Authorization Decision** - Access permissions

### 🔄 **SAML Authentication Flow**

```mermaid
sequenceDiagram
    participant User
    participant MarkLogic as MarkLogic (SP)
    participant IdP as Identity Provider
    
    User->>MarkLogic: 1. Access protected resource
    MarkLogic->>User: 2. Redirect to IdP (AuthnRequest)
    User->>IdP: 3. Present credentials
    IdP->>User: 4. Return SAML Response
    User->>MarkLogic: 5. POST SAML Response
    MarkLogic->>MarkLogic: 6. Validate assertion
    MarkLogic->>User: 7. Grant access
```

### 📝 **Key SAML Concepts**

#### **Metadata**
XML documents describing SP and IdP capabilities:
- Entity IDs
- Certificate information
- Endpoint URLs
- Supported bindings

#### **Bindings**
Methods for transporting SAML messages:
- **HTTP-Redirect** - GET parameters (common for AuthnRequest)
- **HTTP-POST** - Form-based submission (common for Response)
- **HTTP-Artifact** - Indirect reference resolution

#### **Name ID Formats**
User identifier formats:
- `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
- `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`
- `urn:oasis:names:tc:SAML:2.0:nameid-format:transient`
- `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`

---

## 🏗️ MarkLogic SAML Configuration

### 📋 **External Security Configuration**

#### **Basic SAML Setup**
```bash
curl -X POST --anyauth -u admin:admin \
  -H "Content-Type:application/json" \
  -d '{
    "external-security-name": "SAML-Keycloak",
    "description": "SAML configuration for Keycloak IdP",
    "authentication": "saml",
    "cache-timeout": 300,
    "authorization": "internal",
    "saml-server": {
      "saml-entity-id": "https://keycloak.example.com/realms/marklogic",
      "saml-destination": "https://marklogic.example.com:8443/saml/acs",
      "saml-issuer": "https://keycloak.example.com/realms/marklogic",
      "saml-assertion-host": "marklogic.example.com",
      "saml-idp-certificate-authority": "-----BEGIN CERTIFICATE-----\n[YOUR_IDP_CERTIFICATE_HERE]\n-----END CERTIFICATE-----",
      "saml-authn-signature": true,
      "saml-attribute-names": {
        "saml-attribute-name": ["role", "email", "name"]
      },
      "saml-privilege-attribute-name": "privileges"
    }
  }' \
  "http://saml.warnesnet.com:8002/manage/v2/external-security"
```

#### **SAML External Security Options**

| Parameter | Description | Example | Notes |
|-----------|-------------|---------|-------|
| **external-security-name** | Name of the external security configuration | `"SAML-Keycloak"` | Unique identifier for the config |
| **description** | Description of the configuration | `"SAML configuration for Keycloak IdP"` | Optional descriptive text |
| **authentication** | Authentication method | `"saml"` | Required for SAML |
| **authorization** | Authorization source | `"internal"` or `"saml"` | Controls role assignment |
| **cache-timeout** | Session cache duration (seconds) | `300` | Default: 300 seconds |
| **saml-entity-id** | SAML entity ID | `"https://keycloak.example.com/realms/marklogic"` | Required if authorization is SAML |
| **saml-destination** | SAML destination | `"https://marklogic.example.com:8443/saml/acs"` | Target URL for SAML responses |
| **saml-issuer** | SAML issuer | `"https://keycloak.example.com/realms/marklogic"` | Identity provider issuer identifier |
| **saml-assertion-host** | SAML assertion host | `"marklogic.example.com"` | Host name for assertion validation |
| **saml-idp-certificate-authority** | IdP certificate authority | `"-----BEGIN CERTIFICATE-----..."` | PEM encoded X509 certificate for IdP |
| **saml-sp-certificate** | SP certificate | `"-----BEGIN CERTIFICATE-----..."` | PEM encoded X509 certificate for SP (optional) |
| **saml-sp-private-key** | SP private key | `"-----BEGIN PRIVATE KEY-----..."` | PEM encoded private key for SP (optional) |
| **saml-authn-signature** | Require authentication signature | `true` | Enable signature validation |
| **saml-attribute-names** | SAML attribute names | `{"saml-attribute-name": ["role", "email"]}` | List of SAML attribute names to map |
| **saml-privilege-attribute-name** | Privilege attribute name | `"privileges"` | SAML attribute containing user privileges |

### 🔐 **Certificate Configuration**

#### **Update IdP Certificate**
```bash
# Update the SAML external security configuration with IdP certificate
curl -X PUT --anyauth -u admin:admin \
  -H "Content-Type:application/json" \
  -d '{
    "saml-server": {
      "saml-idp-certificate-authority": "-----BEGIN CERTIFICATE-----\nMIIDyzCCArOgAwIBAgIUVfpV56K9w6BsaPh9Wd6nRzF4zB0wDQYJKoZIhvcNAQEL...\n-----END CERTIFICATE-----"
    }
  }' \
  "http://saml.warnesnet.com:8002/manage/v2/external-security/SAML-Keycloak"
```

#### **Add SP Certificate and Private Key (Optional)**
```bash
# If you need to configure SP signing/encryption
curl -X PUT --anyauth -u admin:admin \
  -H "Content-Type:application/json" \
  -d '{
    "saml-server": {
      "saml-sp-certificate": "-----BEGIN CERTIFICATE-----\n[YOUR_SP_CERTIFICATE_HERE]\n-----END CERTIFICATE-----",
      "saml-sp-private-key": "-----BEGIN PRIVATE KEY-----\n[YOUR_SP_PRIVATE_KEY_HERE]\n-----END PRIVATE KEY-----"
    }
  }' \
  "http://saml.warnesnet.com:8002/manage/v2/external-security/SAML-Keycloak"
```

### 🌐 **App Server Configuration**

#### **Configure SAML Authentication**
```bash
curl -X PUT --anyauth -u admin:admin \
  -H "Content-Type:application/json" \
  -d '{
    "authentication": "external-security",
    "external-security": "SAML-Keycloak"
  }' \
  "http://saml.warnesnet.com:8002/manage/v2/servers/my-app-server/properties"
```

#### **Verify App Server Configuration**
```bash
# Check the current app server configuration
curl -X GET --anyauth -u admin:admin \
  -H "Accept:application/json" \
  "http://saml.warnesnet.com:8002/manage/v2/servers/my-app-server/properties"
```

> **Note**: SAML-specific properties like entity IDs, destinations, and certificates are configured in the external security configuration, not directly on the app server. The app server only needs to reference the external security configuration name.

---

## 🏢 Identity Provider Setup

### 🔧 **Generic IdP Configuration**

#### **Required IdP Settings**
| Setting | Value | Description |
|---------|-------|-------------|
| **Entity ID** | `http://idp.example.com/saml/metadata` | Unique IdP identifier |
| **SSO URL** | `http://idp.example.com/saml/sso` | Single sign-on endpoint |
| **Signing Certificate** | X.509 Certificate | For assertion signing |
| **Name ID Format** | Email or Persistent | User identifier format |
| **Attributes** | role, email, name | User attributes to include |

#### **Service Provider Registration**
Configure MarkLogic as SP in your IdP:

```xml
<!-- SP Metadata Template -->
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                     entityID="http://marklogic.example.com/saml/sp">
  <md:SPSSODescriptor AuthnRequestsSigned="false" 
                      WantAssertionsSigned="true" 
                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    
    <md:AssertionConsumerService 
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
        Location="http://marklogic.example.com:8080/saml/acs" 
        index="1" 
        isDefault="true"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
```

### 🏢 **Microsoft ADFS Configuration**

#### **Add Relying Party Trust**
```powershell
# PowerShell commands for ADFS configuration
Add-AdfsRelyingPartyTrust `
    -Name "MarkLogic Server" `
    -Identifier "http://marklogic.example.com/saml/sp" `
    -SamlEndpoint @(
        New-AdfsSamlEndpoint `
            -Binding "POST" `
            -Protocol "SAMLAssertionConsumer" `
            -Uri "http://marklogic.example.com:8080/saml/acs"
    )

# Configure claim rules
$rules = @'
@RuleName = "Send Email as Name ID"
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
=> issue(Type = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier", 
         Issuer = c.Issuer, 
         OriginalIssuer = c.OriginalIssuer, 
         Value = c.Value, 
         ValueType = c.ValueType, 
         Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/format"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

@RuleName = "Send Group Membership as Role"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-..."]
=> issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", Value = "marklogic-admin");
'@

Set-AdfsRelyingPartyTrust -TargetName "MarkLogic Server" -IssuanceTransformRules $rules
```

#### **ADFS Claim Rules Template**
```xml
<!-- Email as Name ID -->
<Rule>
  <ClaimType>http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier</ClaimType>
  <Source>http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress</Source>
  <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
</Rule>

<!-- Group Membership to Roles -->
<Rule>
  <ClaimType>http://schemas.microsoft.com/ws/2008/06/identity/claims/role</ClaimType>
  <Source>http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid</Source>
  <Condition>Value=="S-1-5-21-domain-group-id"</Condition>
  <OutputValue>marklogic-user</OutputValue>
</Rule>
```

### ☁️ **Azure Active Directory Configuration**

#### **Enterprise Application Setup**
1. **Create Enterprise Application**
   - Azure Portal → Enterprise Applications → New Application
   - Create your own application → Non-gallery application

2. **Configure Single Sign-On**
   ```
   Basic SAML Configuration:
   - Identifier (Entity ID): http://marklogic.example.com/saml/sp
   - Reply URL: http://marklogic.example.com:8080/saml/acs
   - Sign on URL: http://marklogic.example.com:8080/
   ```

3. **User Attributes & Claims**
   ```
   Name ID Format: Email address
   Source Attribute: user.mail
   
   Additional Claims:
   - role: user.assignedroles
   - email: user.mail
   - name: user.displayname
   ```

### 🔧 **MLEAProxy IdP (Development)**

For development and testing, MLEAProxy provides a simple SAML IdP:

#### **MLEAProxy SAML Configuration**
```properties
# Enable SAML debug logging
saml.debug=true

# SAML response validity (5 minutes)
saml.response.validity=300

# Default roles for users
saml.default.roles=user

# IdP Entity Configuration
saml.idp.entity.id=http://localhost:8080/saml/idp
saml.idp.sso.url=http://localhost:8080/saml/auth
```

#### **MLEAProxy Endpoints**
- **SSO Endpoint**: `http://localhost:8080/saml/auth`
- **Metadata**: `http://localhost:8080/saml/idp-metadata`
- **Direct Assertion**: `http://localhost:8080/saml/wrapassertion`

---

## 🔐 Certificate Management

### 📜 **SAML Certificate Requirements**

#### **Certificate Types**
| Certificate | Purpose | Location | Required |
|-------------|---------|----------|----------|
| **IdP Signing** | Validates SAML assertions | IdP | ✅ Yes |
| **IdP Encryption** | Encrypts SAML assertions | IdP | ⚠️ Optional |
| **SP Signing** | Signs SAML requests | MarkLogic | ⚠️ Optional |
| **SP Encryption** | Decrypts SAML assertions | MarkLogic | ⚠️ Optional |

> 🔧 **Certificate Operations**: For comprehensive certificate management, see our [TLS Certificate Management Guide](../TLS_CERTIFICATE_MANAGEMENT.md).

### 🔍 **Extracting IdP Certificates**

#### **From Metadata URL**
```bash
# Download and extract certificate from IdP metadata
curl -s https://idp.example.com/saml/metadata | \
    xmllint --xpath "//ds:X509Certificate/text()" - | \
    sed 's/^/-----BEGIN CERTIFICATE-----\n/' | \
    sed 's/$/\n-----END CERTIFICATE-----/' > idp-cert.pem

# Verify certificate
openssl x509 -in idp-cert.pem -text -noout
```

#### **From ADFS Metadata**
```bash
# Extract ADFS signing certificate
curl -s https://adfs.example.com/federationmetadata/2007-06/federationmetadata.xml | \
    xmllint --format - | \
    grep -A 1 'use="signing"' | \
    grep X509Certificate | \
    sed 's/.*<ds:X509Certificate>//' | \
    sed 's/<\/ds:X509Certificate>.*//' | \
    base64 -d | \
    openssl x509 -inform DER -outform PEM
```

#### **Manual Certificate Extraction**
```bash
# If you have the certificate file directly
# Convert from various formats to PEM
openssl x509 -in certificate.crt -outform PEM -out idp-signing.pem
openssl x509 -in certificate.der -inform DER -outform PEM -out idp-signing.pem

# Verify certificate details
openssl x509 -in idp-signing.pem -text -noout | grep -E "(Subject:|Issuer:|Not Before:|Not After:)"
```

### 🔑 **MarkLogic Certificate Import**

#### **Import via QConsole**
```xquery
(: Import IdP signing certificate into MarkLogic :)
import module namespace pki = "http://marklogic.com/xdmp/pki" 
  at "/MarkLogic/pki.xqy";

let $cert-pem := 'PASTE_CERTIFICATE_PEM_HERE'
let $template := pki:certificate-template(
  "saml-idp-signing-cert",
  "SAML IdP Signing Certificate",
  $cert-pem
)
return pki:insert-trusted-certificates($template)
```

#### **Verify Certificate Import**
```xquery
(: List all trusted certificates :)
import module namespace pki = "http://marklogic.com/xdmp/pki" 
  at "/MarkLogic/pki.xqy";

for $cert in pki:trusted-certificates()
let $template := pki:trusted-certificate-template($cert)
where contains(pki:template-get-description($template), "SAML")
return (
  "ID: " || pki:template-get-id($template),
  "Description: " || pki:template-get-description($template),
  "Subject: " || pki:template-get-subject($template),
  "---"
)
```

### 🔄 **Certificate Rotation**

#### **Automated Certificate Update**
```xquery
(: Update IdP certificate during rotation :)
import module namespace pki = "http://marklogic.com/xdmp/pki" 
  at "/MarkLogic/pki.xqy";

(: Remove old certificate :)
let $old-cert-id := "saml-idp-signing-cert"
let $_ := pki:delete-trusted-certificate($old-cert-id)

(: Insert new certificate :)
let $new-cert-pem := 'NEW_CERTIFICATE_PEM_HERE'
let $template := pki:certificate-template(
  $old-cert-id,
  "SAML IdP Signing Certificate (Updated)",
  $new-cert-pem
)
return pki:insert-trusted-certificates($template)
```

---

## 🔧 Troubleshooting Tools

### 🛠️ **Essential SAML Tools**

| Tool | Platform | Purpose | Skill Level |
|------|----------|---------|-------------|
| **SAML Tracer** | Browser Extension | HTTP/SAML message inspection | Beginner |
| **Wireshark** | Cross-platform | Network packet analysis ([Guide](../NETWORK_TROUBLESHOOTING.md)) | Advanced |
| **QConsole** | MarkLogic | XQuery debugging and testing | Intermediate |
| **openssl** | Command-line | Certificate verification and analysis | Intermediate |
| **xmllint** | Command-line | XML validation and formatting | Intermediate |
| **SAML Developer Tools** | Browser DevTools | HTTP request/response analysis | Beginner |

### 🔍 **SAML Tracer (Browser Extension)**

#### **Installation and Setup**
1. **Chrome**: Install SAML-tracer extension from Chrome Web Store
2. **Firefox**: Install SAML-tracer add-on from Mozilla Add-ons
3. **Enable**: Activate tracing before authentication attempt

#### **Key Features**
- **HTTP Request/Response Capture** - Complete SAML message flow
- **XML Formatting** - Pretty-printed SAML assertions
- **Message Validation** - Basic SAML structure checking
- **Timeline View** - Sequence of authentication steps

#### **Using SAML Tracer**
```
1. Open SAML Tracer in browser
2. Navigate to MarkLogic application
3. Initiate SAML authentication
4. Review captured messages:
   - AuthnRequest (SP → IdP)
   - SAML Response (IdP → SP)
   - HTTP redirects and form posts
```

### 🖥️ **Command-Line Analysis**

#### **Decode SAML Messages**
```bash
# Decode base64-encoded SAML request/response
echo "BASE64_SAML_MESSAGE" | base64 -d | xmllint --format -

# Extract and decode from URL
# For SAML Redirect binding
python3 -c "
import urllib.parse
import base64
import zlib

# Extract SAMLRequest parameter from URL
saml_request = 'ENCODED_SAML_REQUEST'
decoded = base64.b64decode(saml_request)
inflated = zlib.decompress(decoded, -15)
print(inflated.decode('utf-8'))
"
```

#### **Certificate Validation**
```bash
# Verify SAML assertion signature
# Extract certificate from assertion
xmllint --xpath "//ds:X509Certificate/text()" assertion.xml | \
    base64 -d | \
    openssl x509 -inform DER -text -noout

# Check certificate validity
openssl x509 -in idp-cert.pem -checkend 86400 -noout
echo $? # 0 = valid, 1 = expired within 24 hours
```

### 📊 **MarkLogic Debugging**

#### **Enable SAML Logging**
```xquery
(: Enable detailed SAML logging :)
import module namespace admin = "http://marklogic.com/xdmp/admin" 
  at "/MarkLogic/admin.xqy";

let $config := admin:get-configuration()
let $appserver-id := admin:appserver-get-id($config, 
  admin:group-get-id($config, "Default"), "my-app-server")

(: Enable debug logging :)
let $config := admin:appserver-set-debug-allow($config, $appserver-id, fn:true())
let $config := admin:appserver-set-profile-allow($config, $appserver-id, fn:true())

return admin:save-configuration($config)
```

#### **SAML Debugging Queries**
```xquery
(: Check SAML external security configuration :)
import module namespace sec = "http://marklogic.com/xdmp/security" 
  at "/MarkLogic/security.xqy";

for $ext-sec in sec:get-external-securities()
where sec:external-security-get-authentication($ext-sec) = "saml"
return (
  "Name: " || sec:external-security-get-external-security-name($ext-sec),
  "Authentication: " || sec:external-security-get-authentication($ext-sec),
  "Authorization: " || sec:external-security-get-authorization($ext-sec),
  "Cache Timeout: " || sec:external-security-get-cache-timeout($ext-sec),
  "---"
)
```

#### **Test SAML Assertion Processing**
```xquery
(: Test SAML assertion validation :)
declare namespace saml = "urn:oasis:names:tc:SAML:2.0:assertion";

let $assertion := '
<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <!-- Your SAML assertion XML here -->
</saml:Assertion>'

(: Parse assertion for debugging :)
let $parsed := xdmp:unquote($assertion)
return (
  "Subject: " || $parsed//saml:Subject/saml:NameID/text(),
  "Attributes: " || fn:string-join($parsed//saml:Attribute/@Name, ", "),
  "Valid Until: " || $parsed//saml:Conditions/@NotOnOrAfter
)
```

---

## ❌ Common Issues

### 🚨 **Authentication Failures**

#### **"SAML assertion validation failed"**

**Symptoms:**
- User redirected to IdP successfully
- IdP authentication succeeds
- MarkLogic rejects SAML assertion

**Root Causes:**
1. **Invalid signature** - Certificate mismatch
2. **Expired assertion** - Clock skew or old assertion
3. **Wrong audience** - Entity ID mismatch
4. **Missing attributes** - Required claims not present

**Troubleshooting Steps:**
```bash
# 1. Verify IdP certificate
openssl x509 -in idp-cert.pem -text -noout | grep -E "(Subject:|Not After:)"

# 2. Check assertion signature
# Use SAML Tracer to capture assertion, then:
xmllint --xpath "//ds:Signature" assertion.xml

# 3. Validate assertion timing
xmllint --xpath "//saml:Conditions/@*" assertion.xml
```

**Solution:**
```xquery
(: Update IdP certificate in MarkLogic :)
import module namespace pki = "http://marklogic.com/xdmp/pki" 
  at "/MarkLogic/pki.xqy";

(: Remove old certificate and add new one :)
pki:delete-trusted-certificate("old-saml-idp-cert"),
pki:insert-trusted-certificates(
  pki:certificate-template(
    "saml-idp-cert-updated",
    "Updated SAML IdP Certificate",
    $new-cert-pem
  )
)
```

#### **"No matching external security configuration"**

**Symptoms:**
- SAML authentication not triggered
- Users see standard login form

**Root Causes:**
1. **App Server misconfiguration** - External security not enabled
2. **Wrong external security name** - Configuration name mismatch
3. **Authentication method mismatch** - Not set to "external-security"

**Solution:**
```xquery
(: Configure App Server for SAML :)
import module namespace admin = "http://marklogic.com/xdmp/admin" 
  at "/MarkLogic/admin.xqy";

let $config := admin:get-configuration()
let $appserver-id := admin:appserver-get-id($config, 
  admin:group-get-id($config, "Default"), "my-app-server")

let $config := admin:appserver-set-authentication($config, 
  $appserver-id, "external-security")
let $config := admin:appserver-set-external-security($config, 
  $appserver-id, "saml-config")

return admin:save-configuration($config)
```

### 🔐 **Certificate Issues**

#### **"Certificate verification failed"**

**Symptoms:**
- SAML assertion rejected
- Certificate-related errors in logs

**Diagnosis:**
```bash
# Check certificate chain
openssl verify -CAfile ca-bundle.pem idp-cert.pem

# Check certificate dates
openssl x509 -in idp-cert.pem -dates -noout

# Compare certificate fingerprints
openssl x509 -in idp-cert.pem -fingerprint -sha256 -noout
openssl x509 -in expected-cert.pem -fingerprint -sha256 -noout
```

**Solution:**
1. **Update certificate** in MarkLogic trusted store
2. **Verify certificate chain** is complete
3. **Check clock synchronization** between systems

#### **"No signing certificate found"**

**Symptoms:**
- IdP metadata missing certificate information
- Signature validation fails

**Solution:**
```bash
# Extract certificate from metadata
curl -s https://idp.example.com/metadata | \
    xmllint --xpath "//ds:X509Certificate[1]/text()" - | \
    sed 's/^/-----BEGIN CERTIFICATE-----\n/' | \
    sed 's/$/\n-----END CERTIFICATE-----/' > extracted-cert.pem

# Import to MarkLogic
# Use QConsole with certificate import code above
```

### ⏰ **Timing Issues**

#### **"SAML assertion expired"**

**Symptoms:**
- Authentication works sporadically
- Time-related error messages

**Root Causes:**
1. **Clock skew** between IdP and MarkLogic
2. **Short assertion validity** period
3. **Network delays** in message transmission

**Diagnosis:**
```bash
# Check system time synchronization
ntpq -p
timedatectl status

# Compare times
curl -I https://idp.example.com/ | grep Date
date
```

**Solution:**
1. **Synchronize clocks** using NTP
2. **Increase assertion validity** period at IdP
3. **Configure clock tolerance** in MarkLogic (if supported)

### 🔗 **URL and Binding Issues**

#### **"Invalid destination URL"**

**Symptoms:**
- SAML response rejected
- URL mismatch errors

**Root Causes:**
1. **ACS URL mismatch** - Response sent to wrong endpoint
2. **Entity ID mismatch** - SP identifier incorrect
3. **Protocol mismatch** - HTTP vs HTTPS

**Solution:**
```xquery
(: Update App Server SAML URLs :)
let $config := admin:get-configuration()
let $appserver-id := admin:appserver-get-id($config, 
  admin:group-get-id($config, "Default"), "my-app-server")

let $config := admin:appserver-set-saml-sp-entity-id($config, 
  $appserver-id, "https://marklogic.example.com/saml/sp")
let $config := admin:appserver-set-saml-acs-url($config, 
  $appserver-id, "https://marklogic.example.com:8443/saml/acs")

return admin:save-configuration($config)
```

---

## ✅ Validation and Testing

### 🧪 **SAML Flow Testing**

#### **End-to-End Authentication Test**
```bash
#!/bin/bash
# SAML authentication flow test script

MARKLOGIC_URL="https://marklogic.example.com:8443"
IDP_URL="https://idp.example.com"

echo "Testing SAML Authentication Flow..."

# 1. Access protected resource
echo "1. Accessing protected resource..."
RESPONSE=$(curl -s -i -c cookies.txt "$MARKLOGIC_URL/protected-resource")

# 2. Check for SAML redirect
if echo "$RESPONSE" | grep -q "Location.*$IDP_URL"; then
    echo "✅ SAML redirect detected"
    REDIRECT_URL=$(echo "$RESPONSE" | grep "Location:" | sed 's/Location: //' | tr -d '\r')
    echo "   Redirect URL: $REDIRECT_URL"
else
    echo "❌ No SAML redirect found"
    exit 1
fi

# 3. Follow redirect and check for login form
echo "2. Following redirect to IdP..."
IDP_RESPONSE=$(curl -s -i -b cookies.txt -c cookies.txt "$REDIRECT_URL")

if echo "$IDP_RESPONSE" | grep -q "login\|password\|username"; then
    echo "✅ IdP login form detected"
else
    echo "❌ No login form found at IdP"
    exit 1
fi

echo "✅ SAML flow initiation successful"
```

#### **Metadata Validation**
```bash
# Validate SP metadata
xmllint --schema saml-metadata.xsd sp-metadata.xml --noout

# Validate IdP metadata
curl -s https://idp.example.com/metadata | xmllint --format - > idp-metadata.xml
xmllint --schema saml-metadata.xsd idp-metadata.xml --noout

# Check metadata elements
xmllint --xpath "//md:SingleSignOnService/@Location" idp-metadata.xml
xmllint --xpath "//md:AssertionConsumerService/@Location" sp-metadata.xml
```

### 📊 **Performance Testing**

#### **SAML Authentication Performance**
```xquery
(: Measure SAML authentication performance :)
let $start-time := fn:current-dateTime()

(: Simulate SAML authentication processing :)
let $external-security := sec:get-external-security("saml-config")
let $processing-time := fn:current-dateTime() - $start-time

return (
  "SAML Config Load Time: " || $processing-time,
  "Cache Timeout: " || sec:external-security-get-cache-timeout($external-security),
  "Authentication Method: " || sec:external-security-get-authentication($external-security)
)
```

#### **Load Testing SAML Endpoints**
```bash
# Use Apache Bench for basic load testing
ab -n 100 -c 10 -C "session-cookie=value" https://marklogic.example.com:8443/saml-protected-app/

# More comprehensive testing with curl
for i in {1..50}; do
    time curl -s -o /dev/null -w "%{http_code} %{time_total}s\n" \
        https://marklogic.example.com:8443/saml-protected-app/
done | awk '{total+=$2; count++} END {print "Average time:", total/count "s"}'
```

### 🔍 **Security Validation**

#### **SAML Assertion Security Check**
```xquery
(: Validate SAML assertion security attributes :)
declare namespace saml = "urn:oasis:names:tc:SAML:2.0:assertion";

let $assertion := 'YOUR_SAML_ASSERTION_XML'
let $parsed := xdmp:unquote($assertion)
return (
  "Signature Present: " || fn:exists($parsed//ds:Signature),
  "Encrypted: " || fn:exists($parsed//saml:EncryptedAssertion),
  "Valid Period: " || ($parsed//saml:Conditions/@NotOnOrAfter - fn:current-dateTime()),
  "Audience: " || $parsed//saml:AudienceRestriction/saml:Audience/text(),
  "Subject Format: " || $parsed//saml:Subject/saml:NameID/@Format
)
```

#### **Certificate Security Audit**
```bash
# Check certificate strength
openssl x509 -in idp-cert.pem -text -noout | grep -E "(Public-Key|Signature Algorithm)"

# Verify certificate not in CRL
openssl crl -in certificate-revocation-list.crl -text -noout | grep -A 1 -B 1 "Serial Number"

# Check certificate expiration
openssl x509 -in idp-cert.pem -checkend $((30*24*3600)) -noout || echo "Certificate expires within 30 days"
```

---

## ⚡ Performance Optimization

### 🚀 **Cache Configuration**

#### **Optimal Cache Settings**
```xquery
(: Configure SAML cache for performance :)
import module namespace sec = "http://marklogic.com/xdmp/security" 
  at "/MarkLogic/security.xqy";

(: Update cache timeout for balance of security and performance :)
sec:external-security-set-cache-timeout("saml-config", 900) (: 15 minutes :)
```

#### **Cache Tuning Guidelines**
| Environment | Cache Timeout | Rationale |
|-------------|---------------|-----------|
| **Development** | 60 seconds | Frequent changes, quick testing |
| **Testing** | 300 seconds | Balance testing and performance |
| **Production** | 900 seconds | Optimize performance, reasonable security |
| **High Security** | 300 seconds | Shorter sessions, frequent validation |

### 📈 **Connection Optimization**

#### **HTTP Client Configuration**
```xquery
(: Optimize HTTP connections for SAML :)
import module namespace admin = "http://marklogic.com/xdmp/admin" 
  at "/MarkLogic/admin.xqy";

let $config := admin:get-configuration()
let $appserver-id := admin:appserver-get-id($config, 
  admin:group-get-id($config, "Default"), "my-app-server")

(: Configure connection pooling :)
let $config := admin:appserver-set-concurrent-request-limit($config, 
  $appserver-id, 32)
let $config := admin:appserver-set-request-timeout($config, 
  $appserver-id, 30)

return admin:save-configuration($config)
```

### 📊 **Monitoring and Metrics**

#### **SAML Performance Monitoring**
```xquery
(: Monitor SAML authentication metrics :)
let $log-entries := xdmp:filesystem-directory("/var/opt/MarkLogic/Logs/")//directory:entry
  [fn:contains(directory:filename, "ErrorLog")]

for $log in $log-entries[fn:position() = 1 to 5]
let $content := xdmp:filesystem-file(directory:pathname)
where fn:contains($content, "SAML")
return fn:tokenize($content, "\n")[fn:contains(., "SAML")][1 to 10]
```

---

## 🔒 Security Best Practices

### 🛡️ **SAML Security Hardening**

#### **Essential Security Settings**
```xquery
(: Implement SAML security best practices :)
let $config := admin:get-configuration()
let $appserver-id := admin:appserver-get-id($config, 
  admin:group-get-id($config, "Default"), "my-app-server")

(: Require signed assertions :)
let $config := admin:appserver-set-saml-want-assertions-signed($config, 
  $appserver-id, fn:true())

(: Configure secure bindings only :)
let $config := admin:appserver-set-ssl-require-client-certificate($config, 
  $appserver-id, "optional")

return admin:save-configuration($config)
```

#### **Security Checklist**
- ✅ **Assertions signed** by trusted IdP certificate
- ✅ **HTTPS only** for all SAML endpoints
- ✅ **Certificate validation** enabled and current
- ✅ **Short assertion lifetime** (≤ 5 minutes)
- ✅ **Audience restriction** to specific SP Entity ID
- ✅ **Subject confirmation** with appropriate method
- ✅ **Replay attack protection** through assertion ID tracking

### 🔐 **Certificate Security**

#### **Certificate Management Best Practices**
1. **Regular Rotation** - Update certificates before expiration
2. **Strong Algorithms** - Use RSA 2048+ or ECC P-256+
3. **Secure Storage** - Protect private keys with proper permissions
4. **Certificate Pinning** - Validate specific certificates, not just CA
5. **Monitoring** - Alert on certificate expiration

#### **Automated Certificate Monitoring**
```bash
#!/bin/bash
# Certificate expiration monitoring script

CERT_FILE="/path/to/idp-cert.pem"
DAYS_WARNING=30

# Check certificate expiration
if openssl x509 -in "$CERT_FILE" -checkend $((DAYS_WARNING*24*3600)) -noout; then
    echo "Certificate valid for more than $DAYS_WARNING days"
else
    echo "WARNING: Certificate expires within $DAYS_WARNING days"
    openssl x509 -in "$CERT_FILE" -dates -noout
    # Send alert to monitoring system
fi
```

### 🔍 **Audit and Compliance**

#### **SAML Audit Logging**
```xquery
(: Enable comprehensive SAML audit logging :)
import module namespace sec = "http://marklogic.com/xdmp/security" 
  at "/MarkLogic/security.xqy";

(: Configure audit events :)
sec:create-audit-configuration(
  "saml-audit",
  "SAML Authentication Audit",
  fn:true(),
  ("authentication-success", "authentication-failure", "authorization-failure")
)
```

#### **Compliance Reporting**
```xquery
(: Generate SAML compliance report :)
let $external-securities := sec:get-external-securities()
  [sec:external-security-get-authentication(.) = "saml"]

for $ext-sec in $external-securities
return (
  "Configuration: " || sec:external-security-get-external-security-name($ext-sec),
  "Cache Timeout: " || sec:external-security-get-cache-timeout($ext-sec) || " seconds",
  "Authorization: " || sec:external-security-get-authorization($ext-sec),
  "Last Modified: " || xdmp:timestamp-to-wallclock(
    sec:external-security-get-last-modified($ext-sec)),
  "---"
)
```

---

## 📋 Summary

This comprehensive SAML 2.0 troubleshooting guide provides everything needed to successfully implement and maintain SAML authentication with MarkLogic.

### 🎯 **Key Takeaways**

#### **SAML Implementation**
- Configure MarkLogic as Service Provider (SP)
- Set up Identity Provider with proper metadata
- Import and manage IdP signing certificates
- Test end-to-end authentication flow

#### **Troubleshooting Approach**
- Use SAML Tracer for message inspection
- Validate certificates and signatures
- Check timing and URL configurations
- Monitor performance and security

#### **Security Excellence**
- Require signed SAML assertions
- Use HTTPS for all endpoints
- Implement certificate rotation
- Enable comprehensive audit logging

#### **Performance Optimization**
- Configure appropriate cache timeouts
- Optimize HTTP connection settings
- Monitor authentication metrics
- Plan for scalability

### 🔧 **Essential Tools Mastery**
- **SAML Tracer** for message flow analysis
- **OpenSSL** for certificate management ([Complete Guide](../TLS_CERTIFICATE_MANAGEMENT.md))
- **Wireshark** for network troubleshooting ([Usage Guide](../NETWORK_TROUBLESHOOTING.md))
- **QConsole** for MarkLogic configuration and testing

### 📊 **Production Readiness**
- Comprehensive error handling and logging
- Automated certificate monitoring
- Performance testing and optimization
- Security hardening and compliance

Mastering SAML 2.0 authentication enables secure, scalable single sign-on solutions that meet enterprise requirements while providing excellent user experience.