[Back to Contents](README.md)

# Security Headers: Fixing Security One Header at a Time

> [!IMPORTANT]
> **HTTP security headers are your first line of defense** against many web attacks. They tell browsers how to behave when handling your site's content.

HTTP security headers are simple yet powerful tools that can prevent a wide range of attacks including XSS, clickjacking, CSRF, and information disclosure. This chapter covers the essential security headers every web application should implement and how to configure them effectively.

## Table of Contents
- [Why Security Headers Matter](#why-security-headers-matter)
- [Content Security Policy (CSP)](#content-security-policy-csp)
- [HTTP Strict Transport Security (HSTS)](#http-strict-transport-security-hsts)
- [Frame Protection Headers](#frame-protection-headers)
- [Content Type Security](#content-type-security)
- [Referrer Policy](#referrer-policy)
- [Permissions Policy](#permissions-policy)
- [Cross-Origin Headers](#cross-origin-headers)
- [Implementation Guide](#implementation-guide)

## Why Security Headers Matter

Security headers provide **defense-in-depth** by instructing browsers on how to handle your content securely. They're particularly effective because:

- **Easy to implement**: Just configure your web server or application
- **Broad protection**: Defend against multiple attack vectors simultaneously
- **Client-side enforcement**: Browsers enforce the policies automatically
- **Immediate impact**: Take effect as soon as they're deployed

> [!WARNING]
> **Headers are not magic**: They only work in browsers that support them and don't replace proper server-side security controls.

### Security Headers Checklist

| Header | Purpose | Priority | Browser Support |
|--------|---------|----------|-----------------|
| Content-Security-Policy | Prevent XSS/injection | 🔴 Critical | Modern browsers |
| Strict-Transport-Security | Enforce HTTPS | 🔴 Critical | All browsers |
| X-Frame-Options | Prevent clickjacking | 🟡 High | All browsers |
| X-Content-Type-Options | Prevent MIME sniffing | 🟡 High | All browsers |
| Referrer-Policy | Control referrer info | 🟡 High | Modern browsers |
| Permissions-Policy | Control browser features | 🟢 Medium | Modern browsers |
| X-XSS-Protection | Legacy XSS protection | 🟢 Low | Deprecated |

## Content Security Policy (CSP)

CSP is the most powerful security header, acting as a robust defense against XSS and data injection attacks.

### How CSP Works

CSP works by defining trusted sources for different types of content:
- **Scripts**: Where JavaScript can be loaded from
- **Styles**: Where CSS can be loaded from  
- **Images**: Where images can be loaded from
- **Fonts**: Where web fonts can be loaded from
- **Connections**: Where AJAX requests can be made to

### CSP Directives

**Essential Directives:**
- `default-src`: Fallback for all resource types
- `script-src`: Controls JavaScript execution
- `style-src`: Controls CSS loading
- `img-src`: Controls image loading
- `connect-src`: Controls AJAX, WebSocket, and EventSource connections
- `font-src`: Controls web font loading
- `object-src`: Controls plugins like Flash
- `frame-src`: Controls embedded frames

**Example CSP Header:**
```http
Content-Security-Policy: default-src 'self'; 
                        script-src 'self' https://trusted-cdn.com; 
                        style-src 'self' 'unsafe-inline'; 
                        img-src 'self' data: https:; 
                        connect-src 'self' https://api.example.com;
```

### CSP Implementation Strategy

**1. Start with Report-Only Mode**
Begin by monitoring violations without blocking content:
```http
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-violations
```

**2. Analyze Violation Reports**
Review reports to understand what resources your application uses:
- Third-party scripts and styles
- Inline JavaScript and CSS
- External APIs and image sources
- User-generated content requirements

**3. Gradually Tighten Policy**
Start with a permissive policy and progressively restrict it:
```http
# Phase 1: Permissive
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' https:

# Phase 2: Remove unsafe-eval
Content-Security-Policy: default-src 'self' 'unsafe-inline' https:

# Phase 3: Target inline restrictions
Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
```

### Common CSP Challenges

**Inline JavaScript and CSS:**
CSP blocks inline scripts and styles by default. Solutions:
- Move inline code to external files
- Use nonces for specific inline scripts
- Use hashes for static inline content
- Refactor to use event listeners instead of inline handlers

**Third-Party Integrations:**
Many services require relaxed CSP policies:
- Analytics tools (Google Analytics, etc.)
- Social media widgets
- Payment processors
- Chat widgets

**Dynamic Content:**
User-generated content can conflict with strict CSP policies:
- Sanitize user HTML content
- Use allowlisted domains for user images
- Implement separate CSP policies for user content areas

## HTTP Strict Transport Security (HSTS)

HSTS prevents SSL stripping attacks by forcing browsers to use HTTPS.

### How HSTS Works

When a browser receives an HSTS header:
1. It remembers that the site should only be accessed via HTTPS
2. Future requests automatically use HTTPS
3. Certificate errors become non-bypassable
4. The browser refuses to connect over HTTP

### HSTS Configuration

**Basic HSTS Header:**
```http
Strict-Transport-Security: max-age=31536000
```

**Complete HSTS Header:**
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Directive Explanations:**
- `max-age`: How long browsers should remember the HSTS policy (in seconds)
- `includeSubDomains`: Apply HSTS to all subdomains
- `preload`: Eligible for browser preload lists

### HSTS Preload List

The HSTS preload list is built into browsers and protects sites from the very first visit:

**Benefits:**
- Protection from first visit
- No trust-on-first-use vulnerability
- Permanent inclusion in browsers

**Requirements for Preload:**
- Serve valid certificate
- Redirect HTTP to HTTPS
- Serve HSTS header with preload directive
- Submit domain to hstspreload.org

**Caution with Preload:**
- Very difficult to remove from preload lists
- Affects all subdomains permanently
- Can break HTTP-only development environments

## Frame Protection Headers

Protect against clickjacking attacks by controlling how your pages can be framed.

### X-Frame-Options

**Legacy but Widely Supported:**
```http
# Deny all framing
X-Frame-Options: DENY

# Allow framing only from same origin
X-Frame-Options: SAMEORIGIN

# Allow framing from specific domain
X-Frame-Options: ALLOW-FROM https://trusted.example.com
```

### Content Security Policy frame-ancestors

**Modern CSP-based Approach:**
```http
# Equivalent to DENY
Content-Security-Policy: frame-ancestors 'none'

# Equivalent to SAMEORIGIN  
Content-Security-Policy: frame-ancestors 'self'

# Allow specific domains
Content-Security-Policy: frame-ancestors https://trusted.example.com
```

### When to Use Frame Protection

**Use DENY for:**
- Login pages
- Payment pages
- Administrative interfaces
- Pages with sensitive user data

**Use SAMEORIGIN for:**
- General application pages
- Pages that might be embedded in your own frames
- Content management interfaces

**Allow Framing for:**
- Embeddable widgets
- Public content meant for sharing
- API documentation or examples

## Content Type Security

Prevent browsers from MIME-sniffing and executing files as unexpected types.

### X-Content-Type-Options

**The Header:**
```http
X-Content-Type-Options: nosniff
```

**What It Prevents:**
- Browsers interpreting text files as JavaScript
- Image files being executed as HTML
- JSON responses being rendered as HTML
- File upload vulnerabilities

**Example Attack Scenario:**
1. User uploads an image file containing JavaScript
2. Browser incorrectly interprets it as text/html
3. JavaScript executes in the security context of your site
4. X-Content-Type-Options prevents this by enforcing declared MIME types

### Proper Content-Type Configuration

**Common MIME Types:**
```http
# JavaScript files
Content-Type: application/javascript

# CSS files  
Content-Type: text/css

# JSON responses
Content-Type: application/json

# HTML pages
Content-Type: text/html; charset=utf-8

# Images
Content-Type: image/png
Content-Type: image/jpeg
```

## Referrer Policy

Control how much referrer information is sent with requests.

### Referrer Policy Options

**Policy Values:**
- `no-referrer`: Never send referrer information
- `no-referrer-when-downgrade`: Send referrer except HTTPS to HTTP
- `origin`: Send only the origin (domain)
- `origin-when-cross-origin`: Send full URL for same-origin, origin for cross-origin
- `same-origin`: Send referrer only for same-origin requests
- `strict-origin`: Send origin for same security level
- `strict-origin-when-cross-origin`: Most restrictive while maintaining functionality
- `unsafe-url`: Always send full URL (not recommended)

### Recommended Configuration

**For Most Applications:**
```http
Referrer-Policy: strict-origin-when-cross-origin
```

**For High-Privacy Applications:**
```http
Referrer-Policy: no-referrer
```

**For Applications with External Analytics:**
```http
Referrer-Policy: origin-when-cross-origin
```

### Privacy and Security Implications

**Privacy Concerns:**
- Referrer headers can leak sensitive URLs
- User tracking across sites
- Exposure of internal URL structures

**Functional Considerations:**
- Some external services require referrer information
- Analytics tools may need referrer data for attribution
- Payment processors sometimes validate referrer headers

## Permissions Policy

Control which browser features your site can access.

### How Permissions Policy Works

Permissions Policy (formerly Feature Policy) allows you to:
- Disable potentially dangerous browser features
- Prevent third-party content from accessing sensitive APIs
- Improve performance by blocking unused features
- Enhance privacy by limiting data access

### Common Policy Directives

**Privacy-Related Features:**
```http
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Performance-Related Features:**
```http
Permissions-Policy: sync-xhr=(), picture-in-picture=()
```

**Security-Related Features:**
```http
Permissions-Policy: payment=(), usb=()
```

### Practical Examples

**E-commerce Site:**
```http
Permissions-Policy: geolocation=(self), microphone=(), camera=(), payment=(self "https://payments.stripe.com")
```

**Corporate Application:**
```http
Permissions-Policy: geolocation=(), microphone=(), camera=(), usb=(), payment=()
```

**Media Application:**
```http
Permissions-Policy: geolocation=(self), microphone=(self), camera=(self), autoplay=(self)
```

## Cross-Origin Headers

Control how your resources can be accessed from other origins.

### Cross-Origin Resource Sharing (CORS)

**Basic CORS Headers:**
```http
# Allow specific origin
Access-Control-Allow-Origin: https://trusted.example.com

# Allow any origin (use carefully)
Access-Control-Allow-Origin: *

# Allow credentials
Access-Control-Allow-Credentials: true

# Specify allowed methods
Access-Control-Allow-Methods: GET, POST, PUT, DELETE

# Specify allowed headers
Access-Control-Allow-Headers: Content-Type, Authorization
```

### Cross-Origin Embedder Policy (COEP)

**Enable Shared Array Buffer:**
```http
Cross-Origin-Embedder-Policy: require-corp
```

### Cross-Origin Opener Policy (COOP)

**Isolate Browsing Context:**
```http
Cross-Origin-Opener-Policy: same-origin
```

## Implementation Guide

### Web Server Configuration

**Apache (.htaccess):**
```apache
# Security Headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

**Nginx:**
```nginx
# Security Headers
add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

### Application-Level Implementation

**Express.js (Node.js):**
```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://trusted-cdn.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
```

**Django (Python):**
```python
# settings.py
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
CSP_DEFAULT_SRC = ("'self'",)
```

### Testing Security Headers

**Online Tools:**
- Security Headers Scanner (securityheaders.com)
- Mozilla Observatory (observatory.mozilla.org)
- CSP Evaluator (csp-evaluator.withgoogle.com)

**Browser Developer Tools:**
- Check Network tab for header presence
- Console shows CSP violations
- Security tab shows HTTPS/certificate status

**Command Line Testing:**
```bash
# Check headers with curl
curl -I https://your-site.com

# Test specific header
curl -I https://your-site.com | grep -i "content-security-policy"
```

## Common Implementation Mistakes

### CSP Mistakes

**Using 'unsafe-inline' unnecessarily:**
```http
# Bad - overly permissive
Content-Security-Policy: script-src 'self' 'unsafe-inline' 'unsafe-eval'

# Better - use nonces or move to external files
Content-Security-Policy: script-src 'self' 'nonce-abc123'
```

**Forgetting about report-uri:**
```http
# Add reporting to catch violations
Content-Security-Policy: default-src 'self'; report-uri /csp-violations
```

### HSTS Mistakes

**Too short max-age:**
```http
# Bad - too short to be effective
Strict-Transport-Security: max-age=300

# Good - one year minimum
Strict-Transport-Security: max-age=31536000
```

**Missing on subdomains:**
```http
# Include subdomains for complete protection
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

### CORS Mistakes

**Overly permissive origins:**
```http
# Dangerous - allows any origin with credentials
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true

# Better - specify trusted origins
Access-Control-Allow-Origin: https://trusted.example.com
Access-Control-Allow-Credentials: true
```

## Security Headers Checklist

### Essential Headers (Must Have)
- [ ] Content-Security-Policy (start with report-only)
- [ ] Strict-Transport-Security (with long max-age)
- [ ] X-Content-Type-Options: nosniff
- [ ] X-Frame-Options or CSP frame-ancestors

### Recommended Headers
- [ ] Referrer-Policy (strict-origin-when-cross-origin)
- [ ] Permissions-Policy (disable unused features)
- [ ] Proper CORS configuration if needed

### Advanced Headers
- [ ] Cross-Origin-Embedder-Policy (if using SharedArrayBuffer)
- [ ] Cross-Origin-Opener-Policy (for isolation)
- [ ] Expect-CT (for certificate transparency)

### Testing and Monitoring
- [ ] Test headers with online scanners
- [ ] Monitor CSP violation reports
- [ ] Regular security header audits
- [ ] Update policies as application changes

## Conclusion

Security headers are one of the most cost-effective security improvements you can make. They require minimal implementation effort but provide broad protection against many common attacks.

**Key Takeaways:**
- **Start simple**: Implement basic headers first, then gradually enhance
- **Use report-only mode**: Test CSP policies before enforcing them
- **Regular testing**: Use automated tools to verify header configuration
- **Stay updated**: Security header standards evolve, keep policies current
- **Defense in depth**: Headers complement but don't replace other security measures

Remember: Security headers are just one layer of defense. They work best when combined with secure coding practices, proper authentication, input validation, and other security controls.

---

*"An ounce of prevention is worth a pound of cure."* - Benjamin Franklin

Implement security headers today and prevent attacks before they happen.