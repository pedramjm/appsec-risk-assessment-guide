2.1.1	Verify that user set passwords are at least 12 characters in length. 
2.1.10	Verify that there are no periodic credential rotation or password history requirements.
2.1.11	Verify that "paste" functionality, browser password helpers, and external password managers are permitted.
2.1.12	Verify that the user can choose to either temporarily view the entire masked password, or temporarily view the last typed character of the password on platforms that do not have this as native functionality.
2.1.2	Verify that passwords 64 characters or longer are permitted. 
2.1.3	Verify that passwords can contain spaces and truncation is not performed. Consecutive multiple spaces MAY optionally be coalesced. 
2.1.4	Verify that Unicode characters are permitted in passwords. A single Unicode code point is considered a character, so 12 emoji or 64 kanji characters should be valid and permitted.
2.1.5	Verify users can change their password.
2.1.6	Verify that password change functionality requires the user's current and new password.
2.1.7	Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords either locally  or using an external API. If using an API a zero knowledge proof or other mechanism should be used to ensure that the plain text password is not sent or used in verifying the breach status of the password. If the password is breached, the application must require the user to set a new non-breached password. 
2.1.8	Verify that a password strength meter is provided to help users set a stronger password.
2.1.9	Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper or lower case or numbers or special characters. 
2.10.1	Verify that integration secrets do not rely on unchanging passwords, such as API keys or shared privileged accounts.
2.10.2	Verify that if passwords are required, the credentials are not a default account.
2.10.3	Verify that passwords are stored with sufficient protection to prevent offline recovery attacks, including local system access.
2.10.4	Verify passwords, integrations with databases and third-party systems, seeds and internal secrets, and API keys are managed securely and not included in the source code or stored within source code repositories. Such storage SHOULD resist offline attacks. The use of a secure software key store (L1, hardware trusted platform module (TPM, or a hardware security module (L3 is recommended for password storage.
2.2.1	Verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks. Such controls include blocking the most common breached passwords, soft lockouts, rate limiting, CAPTCHA, ever increasing delays between attempts, IP address restrictions, or risk-based restrictions such as location, first login on a device, recent attempts to unlock the account, or similar. Verify that no more than 100 failed attempts per hour is possible on a single account.
2.2.2	Verify that the use of weak authenticators (such as SMS and email is limited to secondary verification and transaction approval and not as a replacement for more secure authentication methods. Verify that stronger methods are offered before weak methods, users are aware of the risks, or that proper measures are in place to limit the risks of account compromise.
2.2.3	Verify that secure notifications are sent to users after updates to authentication details, such as credential resets, email or address changes, logging in from unknown or risky locations. The use of push notifications - rather than SMS or email - is preferred, but in the absence of push notifications, SMS or email is acceptable as long as no sensitive information is disclosed in the notification.
2.2.4	Verify impersonation resistance against phishing, such as the use of multi-factor authentication, cryptographic devices with intent (such as connected keys with a push to authenticate, or at higher AAL levels, client-side certificates.
2.2.5	Verify that where a credential service provider (CSP and the application verifying authentication are separated, mutually authenticated TLS is in place between the two endpoints.
2.2.6	Verify replay resistance through the mandated use of OTP devices, cryptographic authenticators, or lookup codes.
2.2.7	Verify intent to authenticate by requiring the entry of an OTP token or user-initiated action such as a button press on a FIDO hardware key.
2.3.1	Verify system generated initial passwords or activation codes SHOULD be securely randomly generated, SHOULD be at least 6 characters long, and MAY contain letters and numbers, and expire after a short period of time. These initial secrets must not be permitted to become the long term password.
2.3.2	Verify that enrollment and use of subscriber-provided authentication devices are supported, such as a U2F or FIDO tokens.
2.3.3	Verify that renewal instructions are sent with sufficient time to renew time bound authenticators.
2.4.1	Verify that passwords are stored in a form that is resistant to offline attacks. Passwords SHALL be salted and hashed using an approved one-way key derivation or password hashing function. Key derivation and password hashing functions take a password, a salt, and a cost factor as inputs when generating a password hash. 
2.4.2	Verify that the salt is at least 32 bits in length and be chosen arbitrarily to minimize salt value collisions among stored hashes. For each credential, a unique salt value and the resulting hash SHALL be stored. 
2.4.3	Verify that if PBKDF2 is used, the iteration count SHOULD be as large as verification server performance will allow, typically at least 100,000 iterations. 
2.4.4	Verify that if bcrypt is used, the work factor SHOULD be as large as verification server performance will allow, typically at least 13. 
2.4.5	Verify that an additional iteration of a key derivation function is performed, using a salt value that is secret and known only to the verifier. Generate the salt value using an approved random bit generator [SP 800-90Ar1] and provide at least the minimum security strength specified in the latest revision of SP 800-131A. The secret salt value SHALL be stored separately from the hashed passwords (e.g., in a specialized device like a hardware security module.
2.5.1	Verify that a system generated initial activation or recovery secret is not sent in clear text to the user. 
2.5.2	Verify password hints or knowledge-based authentication (so-called "secret questions" are not present.
2.5.3	Verify password credential recovery does not reveal the current password in any way. 
2.5.4	Verify shared or default accounts are not present (e.g. "root", "admin", or "sa".
2.5.5	Verify that if an authentication factor is changed or replaced, that the user is notified of this event.
2.5.6	Verify forgotten password, and other recovery paths use a secure recovery mechanism, such as TOTP or other soft token, mobile push, or another offline recovery mechanism. 
2.5.7	Verify that if OTP or multi-factor authentication factors are lost, that evidence of identity proofing is performed at the same level as during enrollment.
2.6.1	Verify that lookup secrets can be used only once.
2.6.2	Verify that lookup secrets have sufficient randomness (112 bits of entropy, or if less than 112 bits of entropy, salted with a unique and random 32-bit salt and hashed with an approved one-way hash.
2.6.3	Verify that lookup secrets are resistant to offline attacks, such as predictable values.
2.7.1	Verify that clear text out of band (NIST "restricted" authenticators, such as SMS or PSTN, are not offered by default, and stronger alternatives such as push notifications are offered first.
2.7.2	Verify that the out of band verifier expires out of band authentication requests, codes, or tokens after 10 minutes.
2.7.3	Verify that the out of band verifier authentication requests, codes, or tokens are only usable once, and only for the original authentication request.
2.7.4	Verify that the out of band authenticator and verifier communicates over a secure independent channel.
2.7.5	Verify that the out of band verifier retains only a hashed version of the authentication code.
2.7.6	Verify that the initial authentication code is generated by a secure random number generator, containing at least 20 bits of entropy (typically a six digital random number is sufficient.
2.8.1	Verify that time-based OTPs have a defined lifetime before expiring.
2.8.2	Verify that symmetric keys used to verify submitted OTPs are highly protected, such as by using a hardware security module or secure operating system based key storage.
2.8.3	Verify that approved cryptographic algorithms are used in the generation, seeding, and verification.
2.8.4	Verify that time-based OTP can be used only once within the validity period.
2.8.5	Verify that if a time-based multi factor OTP token is re-used during the validity period, it is logged and rejected with secure notifications being sent to the holder of the device.
2.8.6	Verify physical single factor OTP generator can be revoked in case of theft or other loss. Ensure that revocation is immediately effective across logged in sessions, regardless of location.
2.8.7	Verify that biometric authenticators are limited to use only as secondary factors in conjunction with either something you have and something you know.
2.9.1	Verify that cryptographic keys used in verification are stored securely and protected against disclosure, such as using a TPM or HSM, or an OS service that can use this secure storage.
2.9.2	Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device.
2.9.3	Verify that approved cryptographic algorithms are used in the generation, seeding, and verification.
2.10.1	Verify that integration secrets do not rely on unchanging passwords, such as API keys or shared privileged accounts.
2.10.2	Verify that if passwords are required, the credentials are not a default account.
2.10.3	Verify that passwords are stored with sufficient protection to prevent offline recovery attacks, including local system access.
2.10.4	Verify passwords, integrations with databases and third-party systems, seeds and internal secrets, and API keys are managed securely and not included in the source code or stored within source code repositories. Such storage SHOULD resist offline attacks. The use of a secure software key store (L1), hardware trusted platform module (TPM), or a hardware security module (L3) is recommended for password storage.





This includes the following:

2.1 Password security
- Login mechanisms
- Password complexity
- Password form fields
- Password update
- Password storage

2.2 Credential recovery
- forgot password / username / email

2.3 MFA/2FA and OTPs
- TOTP/HOTP
- Authentications
- SMS, Email etc.

2.4 Captcha

2.5 Federated ID
- SAML
- OAuth
- OpenID

2.6 Service Authentication (Back-end)
- Application authentication
- MicroService authentication
- DB Authentication


More information:
https://github.com/pedramjm/appsec-risk-assessment-guide/blob/master/02-asra-authentication.md



---










# V2: Authentication

[Authentication testing guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README)

[OWASP Top Ten 2017: Broken Authentication](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication)





# 2.1 Password security

[CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)


### Password complexity

General example:

| Requirement | details |
| ------ | -- |
| Length | 12 |
| Complexity | i.e. at least 1 upper, 1 lower, 1 special case |
| Re-use | do not allow the same password as the last *5* passwords |
| Age | passwords must be changed after *180* days |
* Note: this is an example, not recommended

### Password form fields

[CSRF Protection](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

### Password update

[OWASP Forgot Password Cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)


### Password Storage
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)







# 2.2 Credential recovery

[OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)






# 2.3 MFA/2FA and OTPs

[OWASP MFA Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)

[Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)






# 2.4 Captcha

[reCAPTCHA](https://developers.google.com/recaptcha)






# 2.5 Federated ID
- [SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [OAuth Security](https://oauth.net/security/)
- OpenID






# 2.6 Service Authentication (Back-end)
- Application authentication
- MicroService authentication
- DB Authentication
