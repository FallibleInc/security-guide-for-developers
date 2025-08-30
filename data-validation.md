[Back to Contents](README.md)

# Data Validation and Sanitization: Never Trust User Input

> [!WARNING]
> **Rule #1 of Security**: Never trust user input. All external data is potentially malicious.

One of the fundamental rules of security is to never trust user input. All data coming from users, APIs, files, or external sources should be validated, sanitized, and handled securely. This chapter covers the essential practices for protecting your application from injection attacks and malicious input.

## Table of Contents
- [Input Validation Principles](#input-validation-principles)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [SQL Injection](#sql-injection)
- [Command Injection](#command-injection)
- [File Upload Security](#file-upload-security)
- [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
- [Validation Implementation Strategy](#validation-implementation-strategy)
- [Best Practices](#best-practices)

## Input Validation Principles

### The Golden Rules

| Rule | Description | Why It Matters |
|------|-------------|----------------|
| **Validate all input** | Never trust any data from external sources | Prevents injection attacks |
| **Whitelist over blacklist** | Define what's allowed rather than forbidden | Blacklists are easily bypassed |
| **Validate early** | Check input at entry points | Fail fast, reduce attack surface |
| **Sanitize for context** | Different contexts need different sanitization | HTML vs SQL vs shell contexts |
| **Fail securely** | Default to denying access when validation fails | Secure by default |

### Understanding Input Sources

**User Input Sources:**
- Form fields and text inputs
- URL parameters and query strings
- HTTP headers (including cookies)
- File uploads
- JSON/XML payloads
- WebSocket messages

**External Data Sources:**
- API responses from third parties
- Database queries returning user data
- File system reads
- Network requests
- Configuration files

### Validation vs. Sanitization

**Input Validation:**
- Check if input meets expected format and constraints
- Reject invalid input entirely
- Examples: Email format validation, number range checks

**Input Sanitization:**
- Remove or escape dangerous characters
- Transform input to make it safe
- Examples: HTML encoding, SQL escaping

> [!IMPORTANT]
> **Both validation AND sanitization are needed**. Validation ensures data quality; sanitization prevents injection attacks.

## Cross-Site Scripting (XSS)

XSS attacks inject malicious scripts into web applications that execute in other users' browsers, potentially stealing cookies, session tokens, or personal information.

### Types of XSS Attacks

**Reflected XSS:**
- Malicious script is reflected off a web server
- Victim clicks a crafted link containing the payload
- Script executes immediately in the victim's browser

**Stored XSS:**
- Malicious script is stored on the server (database, file, etc.)
- Script executes when other users view the stored content
- More dangerous as it affects multiple users

**DOM-Based XSS:**
- Vulnerability exists in client-side code
- JavaScript modifies the DOM in an unsafe way
- Attack payload never touches the server

### XSS Prevention Strategies

**Output Encoding:**
Encode data based on the context where it will be displayed:

- **HTML Context**: `&lt;script&gt;` instead of `<script>`
- **JavaScript Context**: `\"alert()\"` instead of `"alert()"`
- **URL Context**: `%3Cscript%3E` for URL parameters
- **CSS Context**: Remove or escape CSS-specific characters

**Content Security Policy (CSP):**
Use CSP headers to restrict script execution:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc123'
```

**Input Validation:**
- Validate input format and length
- Use allowlists for acceptable characters
- Reject suspicious patterns like `<script>`, `javascript:`, `on*=`

### Modern XSS Protection

**Framework-Level Protection:**
Modern frameworks provide built-in XSS protection:
- React automatically escapes JSX variables
- Angular sanitizes interpolated values
- Django auto-escapes template variables

**Browser-Level Protection:**
- XSS filters in modern browsers (though being deprecated)
- Content Security Policy support
- Same-origin policy enforcement

## SQL Injection

SQL injection occurs when user input is improperly included in SQL queries, allowing attackers to manipulate database operations.

### How SQL Injection Works

**Vulnerable Code Pattern:**
```python
# DANGEROUS - Never do this
query = f"SELECT * FROM users WHERE username = '{username}'"
```

**Attack Example:**
If username = `admin'; DROP TABLE users; --`, the query becomes:
```sql
SELECT * FROM users WHERE username = 'admin'; DROP TABLE users; --'
```

### SQL Injection Prevention

**Parameterized Queries (Best Practice):**
Use parameterized queries or prepared statements:
```python
# SAFE - Use parameterized queries
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

**Stored Procedures:**
Use stored procedures with proper parameter handling (but parameterized queries are often simpler).

**Input Validation:**
- Validate data types (ensure integers are integers)
- Check string lengths and formats
- Use allowlists for acceptable characters

**Least Privilege:**
- Database users should have minimal necessary permissions
- Don't use admin accounts for application connections
- Separate read and write operations with different accounts

### Advanced SQL Injection Protection

**ORM Usage:**
Object-Relational Mapping frameworks provide built-in protection:
- Django ORM automatically uses parameterized queries
- SQLAlchemy provides safe query construction
- Entity Framework prevents most injection attacks

**Database-Level Protection:**
- Enable SQL injection detection and blocking
- Use database firewalls
- Monitor for suspicious query patterns
- Regular security updates for database software

## Command Injection

Command injection occurs when applications execute system commands with user-controlled input, allowing attackers to execute arbitrary commands.

### Understanding Command Injection

**Vulnerable Pattern:**
```python
# DANGEROUS - Never execute user input directly
os.system(f"ping {user_input}")
```

**Attack Example:**
If user_input = `8.8.8.8; rm -rf /`, the command becomes:
```bash
ping 8.8.8.8; rm -rf /
```

### Prevention Strategies

**Avoid System Commands:**
- Use libraries instead of shell commands when possible
- For network operations, use networking libraries
- For file operations, use built-in file handling

**Input Validation:**
- Strictly validate command parameters
- Use allowlists for acceptable values
- Reject input containing shell metacharacters (`;`, `|`, `&`, etc.)

**Safe Command Execution:**
When system commands are necessary:
```python
# SAFER - Use subprocess with shell=False and argument lists
import subprocess
result = subprocess.run(['ping', '-c', '1', validated_ip], 
                       capture_output=True, shell=False)
```

**Sandboxing:**
- Run commands in restricted environments
- Use containers or chroot jails
- Implement strict resource limits

## File Upload Security

File uploads are a common attack vector, allowing malicious file execution, server compromise, or denial of service.

### File Upload Risks

**Malicious File Execution:**
- PHP, JSP, or other executable files uploaded to web directories
- Server executes uploaded files as code

**Path Traversal:**
- Filenames like `../../etc/passwd` can overwrite system files
- Directory traversal to access sensitive areas

**Denial of Service:**
- Large files consuming disk space
- ZIP bombs that expand to massive sizes

**Malware Distribution:**
- Uploading malware that affects other users
- Using your server to host malicious content

### File Upload Protection

**File Type Validation:**
- Validate file extensions against allowlists
- Check MIME types (but don't rely solely on them)
- Use file signature/magic number validation
- Scan file contents, not just names

**File Size Limits:**
- Implement reasonable file size limits
- Use progressive upload with size checking
- Monitor total storage usage per user

**Safe Storage:**
- Store uploads outside web root directory
- Use separate domain for file serving
- Rename uploaded files to prevent execution
- Implement virus scanning for uploads

**Content Scanning:**
- Scan uploaded files for malware
- Check for suspicious file structures
- Validate file headers and metadata
- Use sandboxing for file processing

### Secure File Handling

**File Processing:**
- Process files in isolated environments
- Use specialized libraries for file format validation
- Implement timeout limits for file processing
- Log all file upload activities

**Access Controls:**
- Authenticate users before allowing uploads
- Implement per-user storage quotas
- Require authorization for file downloads
- Track file access and modifications

## Server-Side Request Forgery (SSRF)

SSRF attacks trick servers into making unintended requests to internal or external systems, potentially exposing internal services or facilitating attacks.

### How SSRF Works

**Basic SSRF:**
Application fetches a URL provided by the user:
```python
# VULNERABLE - Fetching user-provided URLs
import requests
response = requests.get(user_provided_url)
```

**Attack Scenarios:**
- `http://localhost:22` - Scan internal ports
- `http://169.254.169.254/` - Access cloud metadata
- `file:///etc/passwd` - Read local files
- `http://internal-admin-panel/` - Access internal services

### SSRF Prevention

**URL Validation:**
- Use allowlists for acceptable domains
- Block private IP ranges (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16)
- Reject localhost and metadata service IPs
- Validate URL schemes (allow only HTTP/HTTPS)

**Network-Level Protection:**
- Use network segmentation
- Implement egress filtering
- Deploy application firewalls
- Monitor outbound network connections

**Application-Level Controls:**
- Use proxy servers for external requests
- Implement request timeouts
- Log all outbound requests
- Use dedicated services for URL fetching

### Advanced SSRF Protection

**DNS Resolution Control:**
- Use custom DNS resolution
- Block resolution of internal hostnames
- Monitor DNS queries for suspicious patterns

**Response Validation:**
- Validate response content types
- Check response sizes
- Monitor for unexpected response patterns

## Validation Implementation Strategy

### Layered Validation Approach

**Client-Side Validation:**
- Immediate user feedback
- Improved user experience
- Basic format checking
- **Never rely on this for security**

**Server-Side Validation:**
- Primary security control
- Comprehensive input checking
- Business logic validation
- Always validate on the server

**Database-Level Validation:**
- Final safety check
- Data integrity constraints
- Type and format enforcement

### Validation Framework Design

**Centralized Validation:**
- Create reusable validation functions
- Consistent validation across the application
- Easier to maintain and update
- Centralized security controls

**Context-Aware Validation:**
- Different validation for different contexts
- Email validation for email fields
- Phone number validation for phone fields
- Custom validation for business-specific fields

**Error Handling:**
- Generic error messages for users
- Detailed logging for developers
- No information disclosure in error messages
- Consistent error response format

### Testing Input Validation

**Security Testing:**
- Test with malicious payloads
- Boundary value testing
- Fuzz testing with random inputs
- Test error handling paths

**Functional Testing:**
- Test valid input acceptance
- Test invalid input rejection
- Test edge cases and limits
- User experience testing

## Best Practices

### Development Practices

**Secure by Default:**
- Default to rejecting input
- Require explicit validation for acceptance
- Use secure libraries and frameworks
- Regular security code reviews

**Defense in Depth:**
- Multiple validation layers
- Both validation and sanitization
- Server-side and client-side controls
- Network and application-level protection

**Regular Updates:**
- Keep validation libraries updated
- Monitor security advisories
- Update validation rules as needed
- Regular security assessments

### Operational Practices

**Monitoring and Logging:**
- Log all validation failures
- Monitor for attack patterns
- Set up alerts for suspicious activity
- Regular log review and analysis

**Incident Response:**
- Plan for validation bypass scenarios
- Rapid response procedures
- Communication protocols
- Recovery and remediation steps

### Compliance Considerations

**Regulatory Requirements:**
- GDPR data protection requirements
- PCI DSS for payment data
- HIPAA for healthcare data
- Industry-specific standards

**Audit and Documentation:**
- Document validation requirements
- Maintain validation test cases
- Regular compliance audits
- Evidence collection and retention

## Common Validation Mistakes

### Technical Mistakes

**Blacklist-Only Validation:**
Relying solely on blocking "bad" input instead of allowing only "good" input.

**Client-Side Only Validation:**
Trusting client-side validation without server-side verification.

**Inconsistent Validation:**
Different validation rules across different parts of the application.

**Information Disclosure:**
Error messages that reveal too much about the system or validation logic.

### Process Mistakes

**Incomplete Coverage:**
Missing validation for some input sources or edge cases.

**Poor Error Handling:**
Inconsistent or insecure error handling that can be exploited.

**Lack of Testing:**
Insufficient security testing of validation logic.

**Maintenance Neglect:**
Failing to update validation rules as the application evolves.

## Conclusion

Input validation and sanitization are fundamental security controls that protect against a wide range of attacks. Effective validation requires understanding various attack vectors, implementing layered defenses, and maintaining vigilant security practices.

**Key Takeaways:**
- **Never trust user input** - validate and sanitize all external data
- **Use allowlists** over blacklists for validation
- **Implement multiple layers** of validation and sanitization
- **Context matters** - sanitize data appropriately for its intended use
- **Test thoroughly** with both valid and malicious inputs
- **Keep updated** with new attack techniques and defenses

Remember: Input validation is not a one-time implementation but an ongoing security practice that requires regular review and updates as your application and the threat landscape evolve.

---

*"The price of security is eternal vigilance."* - This is especially true for input validation.

Treat every piece of external data as potentially malicious until proven otherwise through proper validation and sanitization.