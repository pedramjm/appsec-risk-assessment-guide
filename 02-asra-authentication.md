### General

[Authentication testing guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README)


### 2.1 Password security

[OWASP Top Ten 2017: Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication)

[CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

General example:

| Requirement | details |
| ------ | -- |
| Length | 12 |
| Complexity | i.e. at least 1 upper, 1 lower, 1 special case |
| Re-use | do not allow the same password as the last *5* passwords |
| Age | passwords must be changed after *180* days |

Password Storage
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)


##

### 2.2 Credential recovery

[OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)


##

### 2.3 MFA/2FA and OTPs

[OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
[Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)

### 2.4 Captcha

### 2.5 Federated ID
- SAML
[SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- OAuth
[OAuth Security](https://oauth.net/security/)
- OpenID

### 2.6 Service Authentication (Back-end)
- Application authentication
- MicroService authentication
- DB Authentication
