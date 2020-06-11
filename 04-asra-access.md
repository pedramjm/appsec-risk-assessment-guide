[OWASP Proactive Controls: Access control](https://owasp.org/www-project-proactive-controls/v3/en/c7-enforce-access-controls)

https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control




4.1.1	Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is present and could be bypassed.
4.1.2	Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless specifically authorized.
4.1.3	Verify that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers, services, and other resources, for which they possess specific authorization. This implies protection against spoofing and elevation of privilege. 
4.1.4	Verify that the principle of deny by default exists whereby new users/roles start with minimal or no permissions and users/roles do not receive access to new features until access is explicitly assigned.  
4.1.5	Verify that access controls fail securely including when an exception occurs. 
4.2.1	Verify that sensitive data and APIs are protected against direct object attacks targeting creation, reading, updating and deletion of records, such as creating or updating someone else's record, viewing everyone's records, or deleting all records.
4.2.2	Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective anti-automation or anti-CSRF protects unauthenticated functionality.
4.3.1	Verify administrative interfaces use appropriate multi-factor authentication to prevent unauthorized use.
4.3.2	Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or disclosure of file or directory metadata, such as Thumbs.db, .DS_Store, .git or .svn folders.
4.3.3	Verify the application has additional authorization  for lower value systems, and / or segregation of duties for high value applications to enforce anti-fraud controls as per the risk of application and past fraud.



This includes the following:

4.1 General access control design
4.2 Authorization checks
4.3 Permissions
4.4 Restrictions
4.5 General design and implementation


Note: when taking access control and authorization design decisions into consideration, it is helpful to consider examples:

Can a user circumvent the access control and authorization checks we have placed by
- directly accessing a URL (rather than following links)
- tampering with cookies
- tampering with HTTP requests (using proxy software)
- enumerating (brute forcing) over sequential identifiers

