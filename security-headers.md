[Back to Contents](README.md)

# Security Headers: Fixing Security One Header at a Time

HTTP security headers are your first line of defense against many web attacks. They tell browsers how to behave when handling your site's content, preventing everything from XSS to clickjacking. This chapter covers essential security headers and their proper implementation.

## Table of Contents
- [Why Security Headers Matter](#why-security-headers-matter)
- [Content Security Policy (CSP)](#content-security-policy-csp)
- [HTTP Strict Transport Security (HSTS)](#http-strict-transport-security-hsts)
- [Frame Protection Headers](#frame-protection-headers)
- [Content Type Security](#content-type-security)
- [Referrer Policy](#referrer-policy)
- [Permissions Policy](#permissions-policy)
- [Cross-Origin Headers](#cross-origin-headers)
- [Implementation Examples](#implementation-examples)

## Why Security Headers Matter

Security headers provide defense-in-depth by:
- **Preventing XSS attacks** through Content Security Policy
- **Enforcing HTTPS** with HSTS
- **Stopping clickjacking** with frame protection
- **Controlling feature access** with Permissions Policy
- **Protecting sensitive data** with referrer controls

> [!IMPORTANT]
> Security headers only work in browsers that support them. Always implement server-side protections as well.

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

CSP is the most powerful security header, preventing XSS and data injection attacks.

### CSP Basics

```python
class CSPBuilder:
    """Build Content Security Policy headers"""
    
    def __init__(self):
        self.directives = {}
        self.report_only = False
        self.nonce_length = 16
    
    def set_default_src(self, sources):
        """Set default source for all resource types"""
        self.directives['default-src'] = self._normalize_sources(sources)
        return self
    
    def set_script_src(self, sources):
        """Set allowed script sources"""
        self.directives['script-src'] = self._normalize_sources(sources)
        return self
    
    def set_style_src(self, sources):
        """Set allowed style sources"""
        self.directives['style-src'] = self._normalize_sources(sources)
        return self
    
    def set_img_src(self, sources):
        """Set allowed image sources"""
        self.directives['img-src'] = self._normalize_sources(sources)
        return self
    
    def set_connect_src(self, sources):
        """Set allowed AJAX/WebSocket sources"""
        self.directives['connect-src'] = self._normalize_sources(sources)
        return self
    
    def set_font_src(self, sources):
        """Set allowed font sources"""
        self.directives['font-src'] = self._normalize_sources(sources)
        return self
    
    def set_frame_src(self, sources):
        """Set allowed frame sources"""
        self.directives['frame-src'] = self._normalize_sources(sources)
        return self
    
    def set_media_src(self, sources):
        """Set allowed media sources"""
        self.directives['media-src'] = self._normalize_sources(sources)
        return self
    
    def set_object_src(self, sources):
        """Set allowed object/embed sources"""
        self.directives['object-src'] = self._normalize_sources(sources)
        return self
    
    def set_base_uri(self, sources):
        """Set allowed base URI sources"""
        self.directives['base-uri'] = self._normalize_sources(sources)
        return self
    
    def set_form_action(self, sources):
        """Set allowed form action sources"""
        self.directives['form-action'] = self._normalize_sources(sources)
        return self
    
    def set_frame_ancestors(self, sources):
        """Set allowed frame ancestors (replaces X-Frame-Options)"""
        self.directives['frame-ancestors'] = self._normalize_sources(sources)
        return self
    
    def enable_upgrade_insecure_requests(self):
        """Upgrade HTTP requests to HTTPS"""
        self.directives['upgrade-insecure-requests'] = []
        return self
    
    def enable_block_all_mixed_content(self):
        """Block all mixed content"""
        self.directives['block-all-mixed-content'] = []
        return self
    
    def set_report_uri(self, uri):
        """Set CSP violation report URI"""
        self.directives['report-uri'] = [uri]
        return self
    
    def set_report_to(self, group_name):
        """Set CSP violation report group (newer standard)"""
        self.directives['report-to'] = [group_name]
        return self
    
    def add_nonce_support(self):
        """Add nonce support for inline scripts/styles"""
        return self._generate_nonce()
    
    def set_report_only(self, report_only=True):
        """Set CSP to report-only mode"""
        self.report_only = report_only
        return self
    
    def _normalize_sources(self, sources):
        """Normalize source list"""
        if isinstance(sources, str):
            sources = [sources]
        return sources
    
    def _generate_nonce(self):
        """Generate cryptographic nonce"""
        import secrets
        return secrets.token_urlsafe(self.nonce_length)
    
    def build(self):
        """Build CSP header value"""
        policy_parts = []
        
        for directive, sources in self.directives.items():
            if sources:
                policy_parts.append(f"{directive} {' '.join(sources)}")
            else:
                policy_parts.append(directive)
        
        return '; '.join(policy_parts)
    
    def get_header_name(self):
        """Get appropriate header name"""
        return 'Content-Security-Policy-Report-Only' if self.report_only else 'Content-Security-Policy'

# CSP Examples for different application types
class CSPProfiles:
    """Pre-configured CSP profiles for common scenarios"""
    
    @staticmethod
    def strict_csp():
        """Strict CSP for maximum security"""
        return (CSPBuilder()
                .set_default_src(["'none'"])
                .set_script_src(["'self'"])
                .set_style_src(["'self'"])
                .set_img_src(["'self'", "data:"])
                .set_connect_src(["'self'"])
                .set_font_src(["'self'"])
                .set_frame_src(["'none'"])
                .set_object_src(["'none'"])
                .set_base_uri(["'self'"])
                .set_form_action(["'self'"])
                .set_frame_ancestors(["'none'"])
                .enable_upgrade_insecure_requests())
    
    @staticmethod
    def spa_csp(api_domain, cdn_domain=None):
        """CSP for Single Page Applications"""
        builder = (CSPBuilder()
                  .set_default_src(["'self'"])
                  .set_script_src(["'self'"])
                  .set_style_src(["'self'", "'unsafe-inline'"])  # Many CSS frameworks need this
                  .set_img_src(["'self'", "data:", "https:"])
                  .set_connect_src(["'self'", api_domain])
                  .set_font_src(["'self'"])
                  .set_frame_src(["'none'"])
                  .set_object_src(["'none'"])
                  .set_base_uri(["'self'"]))
        
        if cdn_domain:
            builder.set_script_src(["'self'", cdn_domain])
            builder.set_style_src(["'self'", "'unsafe-inline'", cdn_domain])
        
        return builder
    
    @staticmethod
    def development_csp():
        """Relaxed CSP for development"""
        return (CSPBuilder()
                .set_default_src(["'self'"])
                .set_script_src(["'self'", "'unsafe-inline'", "'unsafe-eval'"])
                .set_style_src(["'self'", "'unsafe-inline'"])
                .set_img_src(["'self'", "data:", "https:"])
                .set_connect_src(["'self'", "ws:", "wss:"])  # WebSocket for hot reload
                .set_report_only(True))  # Report-only in development

# Nonce-based CSP implementation
import secrets
from flask import Flask, request, g

class CSPNonceManager:
    """Manage CSP nonces for inline scripts/styles"""
    
    def __init__(self):
        self.nonce_length = 16
    
    def generate_nonce(self):
        """Generate new nonce for request"""
        return secrets.token_urlsafe(self.nonce_length)
    
    def get_nonce_csp(self, script_nonce, style_nonce):
        """Get CSP with nonces"""
        return (CSPBuilder()
                .set_default_src(["'self'"])
                .set_script_src(["'self'", f"'nonce-{script_nonce}'"])
                .set_style_src(["'self'", f"'nonce-{style_nonce}'"])
                .set_img_src(["'self'", "data:"])
                .set_connect_src(["'self'"])
                .set_frame_ancestors(["'none'"])
                .build())

# Flask integration
app = Flask(__name__)
nonce_manager = CSPNonceManager()

@app.before_request
def generate_nonces():
    """Generate nonces for each request"""
    g.script_nonce = nonce_manager.generate_nonce()
    g.style_nonce = nonce_manager.generate_nonce()

@app.after_request
def add_csp_header(response):
    """Add CSP header to response"""
    csp_value = nonce_manager.get_nonce_csp(g.script_nonce, g.style_nonce)
    response.headers['Content-Security-Policy'] = csp_value
    return response

# Template usage with nonces
template_with_nonce = '''
<!DOCTYPE html>
<html>
<head>
    <style nonce="{{ g.style_nonce }}">
        body { font-family: Arial, sans-serif; }
    </style>
</head>
<body>
    <h1>Secure Page</h1>
    <script nonce="{{ g.script_nonce }}">
        console.log('This script is allowed by CSP nonce');
    </script>
</body>
</html>
'''
```

### CSP Violation Reporting

```python
import json
from datetime import datetime
from typing import Dict, List

class CSPViolationReporter:
    """Handle CSP violation reports"""
    
    def __init__(self, storage_backend):
        self.storage = storage_backend
    
    def process_violation_report(self, report_data: Dict) -> bool:
        """Process incoming CSP violation report"""
        try:
            # Parse the violation report
            csp_report = report_data.get('csp-report', {})
            
            violation = {
                'timestamp': datetime.utcnow().isoformat(),
                'document_uri': csp_report.get('document-uri'),
                'violated_directive': csp_report.get('violated-directive'),
                'blocked_uri': csp_report.get('blocked-uri'),
                'source_file': csp_report.get('source-file'),
                'line_number': csp_report.get('line-number'),
                'column_number': csp_report.get('column-number'),
                'original_policy': csp_report.get('original-policy')
            }
            
            # Store violation
            self.storage.store_violation(violation)
            
            # Check if this is a critical violation
            if self._is_critical_violation(violation):
                self._alert_security_team(violation)
            
            return True
            
        except Exception as e:
            print(f"Error processing CSP violation: {e}")
            return False
    
    def _is_critical_violation(self, violation: Dict) -> bool:
        """Determine if violation indicates potential attack"""
        blocked_uri = violation.get('blocked_uri', '').lower()
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'javascript:',
            'data:text/html',
            'vbscript:',
            'eval(',
            'expression(',
            'xss',
            'script',
            'onload',
            'onerror'
        ]
        
        return any(pattern in blocked_uri for pattern in suspicious_patterns)
    
    def _alert_security_team(self, violation: Dict):
        """Send alert for critical violations"""
        # Implement alerting logic (email, Slack, etc.)
        print(f"SECURITY ALERT: Critical CSP violation detected: {violation}")
    
    def get_violation_summary(self, days: int = 7) -> Dict:
        """Get summary of violations in past N days"""
        violations = self.storage.get_violations_since(
            datetime.utcnow() - timedelta(days=days)
        )
        
        return {
            'total_violations': len(violations),
            'unique_blocked_uris': len(set(v['blocked_uri'] for v in violations)),
            'top_violated_directives': self._get_top_directives(violations),
            'critical_violations': len([v for v in violations if self._is_critical_violation(v)])
        }
    
    def _get_top_directives(self, violations: List[Dict]) -> List[tuple]:
        """Get most frequently violated directives"""
        from collections import Counter
        directive_counts = Counter(v['violated_directive'] for v in violations)
        return directive_counts.most_common(5)

# Flask endpoint for CSP reporting
@app.route('/csp-report', methods=['POST'])
def csp_report():
    """Endpoint to receive CSP violation reports"""
    try:
        report_data = request.get_json()
        reporter = CSPViolationReporter(violation_storage)
        reporter.process_violation_report(report_data)
        return '', 204
    except Exception:
        return '', 400
```

## HTTP Strict Transport Security (HSTS)

HSTS forces browsers to use HTTPS and prevents SSL stripping attacks.

```python
class HSTSBuilder:
    """Build HSTS headers"""
    
    def __init__(self):
        self.max_age = 31536000  # 1 year default
        self.include_subdomains = False
        self.preload = False
    
    def set_max_age(self, seconds):
        """Set HSTS max age in seconds"""
        self.max_age = seconds
        return self
    
    def include_subdomains(self, include=True):
        """Include subdomains in HSTS policy"""
        self.include_subdomains = include
        return self
    
    def enable_preload(self, preload=True):
        """Enable HSTS preloading"""
        self.preload = preload
        return self
    
    def build(self):
        """Build HSTS header value"""
        header_parts = [f"max-age={self.max_age}"]
        
        if self.include_subdomains:
            header_parts.append("includeSubDomains")
        
        if self.preload:
            header_parts.append("preload")
        
        return "; ".join(header_parts)

# HSTS configurations
class HSTSProfiles:
    """Pre-configured HSTS profiles"""
    
    @staticmethod
    def strict_hsts():
        """Maximum security HSTS"""
        return (HSTSBuilder()
                .set_max_age(63072000)  # 2 years
                .include_subdomains(True)
                .enable_preload(True))
    
    @staticmethod
    def development_hsts():
        """HSTS for development (shorter duration)"""
        return (HSTSBuilder()
                .set_max_age(300)  # 5 minutes
                .include_subdomains(False)
                .enable_preload(False))
    
    @staticmethod
    def production_hsts():
        """HSTS for production"""
        return (HSTSBuilder()
                .set_max_age(31536000)  # 1 year
                .include_subdomains(True)
                .enable_preload(False))  # Enable after testing

# HSTS implementation with gradual rollout
class HSTSManager:
    """Manage HSTS deployment"""
    
    def __init__(self):
        self.rollout_stages = [
            {'max_age': 300, 'duration_days': 1},      # 5 minutes for 1 day
            {'max_age': 3600, 'duration_days': 7},     # 1 hour for 1 week
            {'max_age': 86400, 'duration_days': 30},   # 1 day for 1 month
            {'max_age': 31536000, 'duration_days': -1} # 1 year permanently
        ]
        self.deployment_start = datetime(2025, 1, 1)  # Set your start date
    
    def get_current_hsts_header(self):
        """Get HSTS header for current deployment stage"""
        days_since_start = (datetime.utcnow() - self.deployment_start).days
        
        cumulative_days = 0
        for stage in self.rollout_stages:
            if stage['duration_days'] == -1 or cumulative_days + stage['duration_days'] > days_since_start:
                return (HSTSBuilder()
                        .set_max_age(stage['max_age'])
                        .include_subdomains(True)
                        .build())
            cumulative_days += stage['duration_days']
        
        # Default to final stage
        return (HSTSBuilder()
                .set_max_age(31536000)
                .include_subdomains(True)
                .enable_preload(True)
                .build())
```

## Frame Protection Headers

Prevent clickjacking attacks by controlling how your page can be framed.

```python
class FrameProtection:
    """Frame protection headers"""
    
    @staticmethod
    def x_frame_options_deny():
        """Deny all framing"""
        return "DENY"
    
    @staticmethod
    def x_frame_options_sameorigin():
        """Allow framing from same origin"""
        return "SAMEORIGIN"
    
    @staticmethod
    def x_frame_options_allow_from(uri):
        """Allow framing from specific URI (deprecated)"""
        return f"ALLOW-FROM {uri}"
    
    @staticmethod
    def csp_frame_ancestors_none():
        """CSP directive to prevent framing"""
        return "frame-ancestors 'none'"
    
    @staticmethod
    def csp_frame_ancestors_self():
        """CSP directive to allow same-origin framing"""
        return "frame-ancestors 'self'"
    
    @staticmethod
    def csp_frame_ancestors_allow(sources):
        """CSP directive to allow specific sources"""
        if isinstance(sources, str):
            sources = [sources]
        return f"frame-ancestors {' '.join(sources)}"

# Combined frame protection
class ClickjackingProtection:
    """Comprehensive clickjacking protection"""
    
    def __init__(self, protection_level='strict'):
        self.protection_level = protection_level
    
    def get_headers(self, allowed_sources=None):
        """Get frame protection headers"""
        headers = {}
        
        if self.protection_level == 'strict':
            headers['X-Frame-Options'] = FrameProtection.x_frame_options_deny()
            headers['Content-Security-Policy'] = FrameProtection.csp_frame_ancestors_none()
        
        elif self.protection_level == 'sameorigin':
            headers['X-Frame-Options'] = FrameProtection.x_frame_options_sameorigin()
            headers['Content-Security-Policy'] = FrameProtection.csp_frame_ancestors_self()
        
        elif self.protection_level == 'custom' and allowed_sources:
            headers['X-Frame-Options'] = FrameProtection.x_frame_options_sameorigin()
            headers['Content-Security-Policy'] = FrameProtection.csp_frame_ancestors_allow(allowed_sources)
        
        return headers

# Usage example
protection = ClickjackingProtection('strict')
frame_headers = protection.get_headers()
# Returns: {'X-Frame-Options': 'DENY', 'Content-Security-Policy': "frame-ancestors 'none'"}
```

## Content Type Security

Prevent MIME type confusion attacks.

```python
class ContentTypeSecurity:
    """Content type security headers"""
    
    @staticmethod
    def nosniff_header():
        """Prevent MIME type sniffing"""
        return "nosniff"
    
    @staticmethod
    def xss_protection_header():
        """Legacy XSS protection (deprecated but still useful)"""
        return "1; mode=block"
    
    @staticmethod
    def xss_protection_disabled():
        """Disable XSS protection (for CSP-enabled sites)"""
        return "0"

class MIMETypeValidator:
    """Validate and secure MIME types"""
    
    SAFE_MIME_TYPES = {
        'text/plain',
        'text/html',
        'text/css',
        'text/javascript',
        'application/javascript',
        'application/json',
        'application/xml',
        'image/jpeg',
        'image/png',
        'image/gif',
        'image/svg+xml',
        'image/webp',
        'application/pdf'
    }
    
    DANGEROUS_MIME_TYPES = {
        'text/html',  # Can contain scripts
        'image/svg+xml',  # Can contain scripts
        'application/xml',  # Can contain entities
        'text/xml'  # Can contain entities
    }
    
    @classmethod
    def is_safe_mime_type(cls, mime_type):
        """Check if MIME type is generally safe"""
        return mime_type in cls.SAFE_MIME_TYPES
    
    @classmethod
    def requires_sandbox(cls, mime_type):
        """Check if MIME type should be sandboxed"""
        return mime_type in cls.DANGEROUS_MIME_TYPES
    
    @classmethod
    def get_safe_content_type_header(cls, mime_type, charset='utf-8'):
        """Get safe Content-Type header"""
        if cls.is_safe_mime_type(mime_type):
            if mime_type.startswith('text/'):
                return f"{mime_type}; charset={charset}"
            return mime_type
        
        # Default to safe type
        return f"text/plain; charset={charset}"
```

## Referrer Policy

Control how much referrer information is sent with requests.

```python
class ReferrerPolicyBuilder:
    """Build Referrer-Policy headers"""
    
    POLICIES = {
        'no-referrer': 'Send no referrer information',
        'no-referrer-when-downgrade': 'Send referrer to same-security origins',
        'origin': 'Send only origin (no path)',
        'origin-when-cross-origin': 'Send full URL for same-origin, origin for cross-origin',
        'same-origin': 'Send referrer only for same-origin requests',
        'strict-origin': 'Send origin for same-security, nothing for downgrades',
        'strict-origin-when-cross-origin': 'Default browser behavior (recommended)',
        'unsafe-url': 'Always send full URL (not recommended)'
    }
    
    @staticmethod
    def get_recommended_policy():
        """Get recommended referrer policy"""
        return 'strict-origin-when-cross-origin'
    
    @staticmethod
    def get_privacy_focused_policy():
        """Get privacy-focused referrer policy"""
        return 'no-referrer'
    
    @staticmethod
    def get_analytics_friendly_policy():
        """Get policy that works well with analytics"""
        return 'origin-when-cross-origin'
    
    @classmethod
    def validate_policy(cls, policy):
        """Validate referrer policy"""
        return policy in cls.POLICIES
    
    @classmethod
    def get_policy_description(cls, policy):
        """Get description of policy"""
        return cls.POLICIES.get(policy, 'Unknown policy')

# Dynamic referrer policy based on content type
class DynamicReferrerPolicy:
    """Apply different referrer policies based on content"""
    
    def __init__(self):
        self.policies = {
            'public_content': 'strict-origin-when-cross-origin',
            'sensitive_content': 'no-referrer',
            'api_endpoints': 'origin',
            'analytics_pages': 'origin-when-cross-origin'
        }
    
    def get_policy_for_content(self, content_type):
        """Get appropriate policy for content type"""
        return self.policies.get(content_type, 'strict-origin-when-cross-origin')
    
    def get_policy_for_path(self, path):
        """Get policy based on URL path"""
        if path.startswith('/api/'):
            return self.get_policy_for_content('api_endpoints')
        elif path.startswith('/admin/') or path.startswith('/account/'):
            return self.get_policy_for_content('sensitive_content')
        elif path.startswith('/analytics/'):
            return self.get_policy_for_content('analytics_pages')
        else:
            return self.get_policy_for_content('public_content')

# Flask integration
from flask import request

referrer_policy_manager = DynamicReferrerPolicy()

@app.after_request
def add_referrer_policy(response):
    """Add appropriate referrer policy"""
    policy = referrer_policy_manager.get_policy_for_path(request.path)
    response.headers['Referrer-Policy'] = policy
    return response
```

## Permissions Policy

Control browser features and APIs that your site can use.

```python
class PermissionsPolicyBuilder:
    """Build Permissions-Policy headers (formerly Feature-Policy)"""
    
    # Available directives
    DIRECTIVES = {
        'accelerometer', 'ambient-light-sensor', 'autoplay', 'battery',
        'camera', 'cross-origin-isolated', 'display-capture', 'document-domain',
        'encrypted-media', 'execution-while-not-rendered', 'execution-while-out-of-viewport',
        'fullscreen', 'geolocation', 'gyroscope', 'keyboard-map', 'magnetometer',
        'microphone', 'midi', 'navigation-override', 'payment', 'picture-in-picture',
        'publickey-credentials-get', 'screen-wake-lock', 'sync-xhr', 'usb',
        'web-share', 'xr-spatial-tracking'
    }
    
    def __init__(self):
        self.policies = {}
    
    def deny_all(self, directive):
        """Deny directive for all origins"""
        if directive in self.DIRECTIVES:
            self.policies[directive] = []
        return self
    
    def allow_self(self, directive):
        """Allow directive for same origin only"""
        if directive in self.DIRECTIVES:
            self.policies[directive] = ['self']
        return self
    
    def allow_origins(self, directive, origins):
        """Allow directive for specific origins"""
        if directive in self.DIRECTIVES:
            if isinstance(origins, str):
                origins = [origins]
            # Add quotes around 'self' and 'none'
            formatted_origins = []
            for origin in origins:
                if origin in ['self', 'none']:
                    formatted_origins.append(f"'{origin}'")
                else:
                    formatted_origins.append(origin)
            self.policies[directive] = formatted_origins
        return self
    
    def build(self):
        """Build Permissions-Policy header value"""
        policy_parts = []
        
        for directive, origins in self.policies.items():
            if origins:
                origins_str = ' '.join(origins)
                policy_parts.append(f"{directive}=({origins_str})")
            else:
                policy_parts.append(f"{directive}=()")
        
        return ', '.join(policy_parts)

class PermissionsPolicyProfiles:
    """Pre-configured permission policies"""
    
    @staticmethod
    def strict_policy():
        """Deny most features for maximum security"""
        return (PermissionsPolicyBuilder()
                .deny_all('camera')
                .deny_all('microphone')
                .deny_all('geolocation')
                .deny_all('payment')
                .deny_all('usb')
                .deny_all('midi')
                .deny_all('sync-xhr')
                .allow_self('fullscreen')
                .allow_self('picture-in-picture'))
    
    @staticmethod
    def media_app_policy():
        """Policy for media-rich applications"""
        return (PermissionsPolicyBuilder()
                .allow_self('camera')
                .allow_self('microphone')
                .allow_self('autoplay')
                .allow_self('fullscreen')
                .allow_self('picture-in-picture')
                .deny_all('geolocation')
                .deny_all('payment'))
    
    @staticmethod
    def ecommerce_policy():
        """Policy for e-commerce sites"""
        return (PermissionsPolicyBuilder()
                .allow_self('payment')
                .allow_self('fullscreen')
                .deny_all('camera')
                .deny_all('microphone')
                .deny_all('geolocation')
                .deny_all('usb'))
    
    @staticmethod
    def content_site_policy():
        """Policy for content sites"""
        return (PermissionsPolicyBuilder()
                .allow_self('fullscreen')
                .allow_self('picture-in-picture')
                .deny_all('camera')
                .deny_all('microphone')
                .deny_all('geolocation')
                .deny_all('payment')
                .deny_all('usb'))

# Usage examples
strict_policy = PermissionsPolicyProfiles.strict_policy().build()
# Returns: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), midi=(), sync-xhr=(), fullscreen=(self), picture-in-picture=(self)"

media_policy = PermissionsPolicyProfiles.media_app_policy().build()
# Returns: "camera=(self), microphone=(self), autoplay=(self), fullscreen=(self), picture-in-picture=(self), geolocation=(), payment=()"
```

## Cross-Origin Headers

Control cross-origin interactions for APIs and resources.

```python
class CORSBuilder:
    """Build CORS headers"""
    
    def __init__(self):
        self.allowed_origins = []
        self.allowed_methods = ['GET', 'POST']
        self.allowed_headers = []
        self.exposed_headers = []
        self.max_age = 3600
        self.allow_credentials = False
    
    def allow_origins(self, origins):
        """Set allowed origins"""
        if isinstance(origins, str):
            origins = [origins]
        self.allowed_origins = origins
        return self
    
    def allow_methods(self, methods):
        """Set allowed HTTP methods"""
        if isinstance(methods, str):
            methods = [methods]
        self.allowed_methods = methods
        return self
    
    def allow_headers(self, headers):
        """Set allowed request headers"""
        if isinstance(headers, str):
            headers = [headers]
        self.allowed_headers = headers
        return self
    
    def expose_headers(self, headers):
        """Set headers exposed to client"""
        if isinstance(headers, str):
            headers = [headers]
        self.exposed_headers = headers
        return self
    
    def set_max_age(self, seconds):
        """Set preflight cache duration"""
        self.max_age = seconds
        return self
    
    def allow_credentials(self, allow=True):
        """Allow cookies/credentials in CORS requests"""
        self.allow_credentials = allow
        return self
    
    def build_headers(self, request_origin=None, request_method=None):
        """Build CORS headers for response"""
        headers = {}
        
        # Access-Control-Allow-Origin
        if '*' in self.allowed_origins:
            headers['Access-Control-Allow-Origin'] = '*'
        elif request_origin in self.allowed_origins:
            headers['Access-Control-Allow-Origin'] = request_origin
        
        # Access-Control-Allow-Methods
        if self.allowed_methods:
            headers['Access-Control-Allow-Methods'] = ', '.join(self.allowed_methods)
        
        # Access-Control-Allow-Headers
        if self.allowed_headers:
            headers['Access-Control-Allow-Headers'] = ', '.join(self.allowed_headers)
        
        # Access-Control-Expose-Headers
        if self.exposed_headers:
            headers['Access-Control-Expose-Headers'] = ', '.join(self.exposed_headers)
        
        # Access-Control-Max-Age
        headers['Access-Control-Max-Age'] = str(self.max_age)
        
        # Access-Control-Allow-Credentials
        if self.allow_credentials:
            headers['Access-Control-Allow-Credentials'] = 'true'
        
        return headers

class CrossOriginEmbedderPolicy:
    """Cross-Origin-Embedder-Policy header"""
    
    @staticmethod
    def require_corp():
        """Require Cross-Origin-Resource-Policy"""
        return 'require-corp'
    
    @staticmethod
    def credentialless():
        """Allow credentialless requests"""
        return 'credentialless'

class CrossOriginOpenerPolicy:
    """Cross-Origin-Opener-Policy header"""
    
    @staticmethod
    def unsafe_none():
        """Default behavior"""
        return 'unsafe-none'
    
    @staticmethod
    def same_origin_allow_popups():
        """Isolate except for popups"""
        return 'same-origin-allow-popups'
    
    @staticmethod
    def same_origin():
        """Full isolation"""
        return 'same-origin'

class CrossOriginResourcePolicy:
    """Cross-Origin-Resource-Policy header"""
    
    @staticmethod
    def same_site():
        """Allow same-site requests only"""
        return 'same-site'
    
    @staticmethod
    def same_origin():
        """Allow same-origin requests only"""
        return 'same-origin'
    
    @staticmethod
    def cross_origin():
        """Allow all cross-origin requests"""
        return 'cross-origin'

# Secure defaults for cross-origin headers
class CrossOriginSecurity:
    """Comprehensive cross-origin security"""
    
    @staticmethod
    def get_secure_headers():
        """Get secure cross-origin headers"""
        return {
            'Cross-Origin-Embedder-Policy': CrossOriginEmbedderPolicy.require_corp(),
            'Cross-Origin-Opener-Policy': CrossOriginOpenerPolicy.same_origin(),
            'Cross-Origin-Resource-Policy': CrossOriginResourcePolicy.same_origin()
        }
    
    @staticmethod
    def get_api_headers():
        """Get headers for API endpoints"""
        return {
            'Cross-Origin-Resource-Policy': CrossOriginResourcePolicy.cross_origin()
        }
```

## Implementation Examples

### Complete Security Headers Implementation

```python
from flask import Flask, request, g
from datetime import datetime
import secrets

class SecurityHeadersManager:
    """Comprehensive security headers management"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.csp_builder = CSPBuilder()
        self.hsts_manager = HSTSManager()
        self.referrer_policy = DynamicReferrerPolicy()
        self.permissions_policy = PermissionsPolicyProfiles.strict_policy()
        self.clickjacking_protection = ClickjackingProtection('strict')
    
    def get_base_security_headers(self):
        """Get basic security headers for all responses"""
        headers = {}
        
        # HSTS (only for HTTPS)
        if request.is_secure:
            headers['Strict-Transport-Security'] = self.hsts_manager.get_current_hsts_header()
        
        # Content type security
        headers['X-Content-Type-Options'] = ContentTypeSecurity.nosniff_header()
        
        # Referrer policy
        headers['Referrer-Policy'] = self.referrer_policy.get_policy_for_path(request.path)
        
        # Permissions policy
        headers['Permissions-Policy'] = self.permissions_policy.build()
        
        # Frame protection
        headers.update(self.clickjacking_protection.get_headers())
        
        # Cross-origin security
        headers.update(CrossOriginSecurity.get_secure_headers())
        
        return headers
    
    def get_csp_header(self, nonce_script=None, nonce_style=None):
        """Get CSP header with optional nonces"""
        if self.config.get('environment') == 'development':
            csp = CSPProfiles.development_csp()
        else:
            csp = CSPProfiles.strict_csp()
            
            # Add nonces if provided
            if nonce_script:
                csp.set_script_src(['self', f"'nonce-{nonce_script}'"])
            if nonce_style:
                csp.set_style_src(['self', f"'nonce-{nonce_style}'"])
        
        return csp.build()
    
    def apply_headers(self, response):
        """Apply all security headers to response"""
        # Base security headers
        for header, value in self.get_base_security_headers().items():
            response.headers[header] = value
        
        # CSP header
        csp_value = self.get_csp_header(
            getattr(g, 'script_nonce', None),
            getattr(g, 'style_nonce', None)
        )
        response.headers['Content-Security-Policy'] = csp_value
        
        return response

# Flask application with complete security headers
def create_secure_app():
    app = Flask(__name__)
    
    # Configuration
    app.config.update({
        'environment': 'production',  # or 'development'
        'csp_report_uri': '/csp-report',
        'hsts_enabled': True
    })
    
    security_headers = SecurityHeadersManager(app.config)
    nonce_manager = CSPNonceManager()
    
    @app.before_request
    def before_request():
        """Generate nonces and prepare security context"""
        g.script_nonce = nonce_manager.generate_nonce()
        g.style_nonce = nonce_manager.generate_nonce()
    
    @app.after_request
    def after_request(response):
        """Apply security headers to all responses"""
        return security_headers.apply_headers(response)
    
    @app.route('/')
    def index():
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure App</title>
            <style nonce="{{ g.style_nonce }}">
                body { font-family: Arial, sans-serif; }
            </style>
        </head>
        <body>
            <h1>Security Headers Demo</h1>
            <p>This page is protected by comprehensive security headers.</p>
            <script nonce="{{ g.script_nonce }}">
                console.log('Secure inline script executed');
            </script>
        </body>
        </html>
        '''
    
    @app.route('/api/data')
    def api_data():
        """API endpoint with appropriate CORS headers"""
        response = jsonify({'data': 'secure api response'})
        
        # Override cross-origin policy for API
        response.headers.update(CrossOriginSecurity.get_api_headers())
        
        return response
    
    @app.route('/csp-report', methods=['POST'])
    def csp_report():
        """CSP violation reporting endpoint"""
        try:
            report_data = request.get_json()
            # Process CSP violation (implementation not shown)
            app.logger.warning(f"CSP Violation: {report_data}")
            return '', 204
        except Exception:
            return '', 400
    
    return app

# Example usage
if __name__ == '__main__':
    app = create_secure_app()
    
    # Test the headers
    with app.test_client() as client:
        response = client.get('/')
        print("Security Headers:")
        for header, value in response.headers:
            if any(keyword in header.lower() for keyword in 
                  ['security', 'content-security', 'frame-options', 'referrer', 'permissions']):
                print(f"{header}: {value}")

# Security headers testing utility
class SecurityHeadersTester:
    """Test security headers implementation"""
    
    def __init__(self, app):
        self.app = app
    
    def test_all_headers(self):
        """Test all security headers"""
        with self.app.test_client() as client:
            response = client.get('/')
            
            required_headers = [
                'Content-Security-Policy',
                'Strict-Transport-Security',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Referrer-Policy',
                'Permissions-Policy'
            ]
            
            results = {}
            for header in required_headers:
                results[header] = {
                    'present': header in response.headers,
                    'value': response.headers.get(header, 'Missing')
                }
            
            return results
    
    def check_csp_violations(self, test_payloads):
        """Test CSP against known attack payloads"""
        violations = []
        
        for payload in test_payloads:
            # This would need actual browser testing
            # or CSP policy parsing
            violations.append({
                'payload': payload,
                'blocked': True  # Placeholder
            })
        
        return violations

# Usage
app = create_secure_app()
tester = SecurityHeadersTester(app)
header_results = tester.test_all_headers()

for header, result in header_results.items():
    status = "✅" if result['present'] else "❌"
    print(f"{status} {header}: {result['value']}")
```

## Conclusion

Security headers provide essential defense-in-depth protection:

> [!TIP]
> **Implementation Strategy**
> 1. Start with basic headers (HSTS, X-Frame-Options, X-Content-Type-Options)
> 2. Implement CSP in report-only mode first
> 3. Gradually strengthen policies based on violation reports
> 4. Test thoroughly across all browsers and devices

### Essential Security Headers Checklist

- ✅ **Content-Security-Policy**: Prevent XSS and injection attacks
- ✅ **Strict-Transport-Security**: Enforce HTTPS connections
- ✅ **X-Frame-Options**: Prevent clickjacking attacks
- ✅ **X-Content-Type-Options**: Prevent MIME sniffing
- ✅ **Referrer-Policy**: Control referrer information leakage
- ✅ **Permissions-Policy**: Restrict browser feature access

> [!WARNING]
> **Common Pitfalls**
> - Don't set `unsafe-inline` or `unsafe-eval` in CSP without good reason
> - Test HSTS thoroughly before enabling preload
> - CSP can break legitimate functionality if too restrictive
> - Some headers conflict with certain features (e.g., iframes)

Remember: Security headers are one layer of defense. Always implement proper server-side validation and security controls as well.

The next chapter will cover [Configuration Security](configuration-security.md) - securing your deployment and infrastructure.