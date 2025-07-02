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
- [Tamper-Proof User Inputs](#tamper-proof-user-inputs)
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

### Input Validation Strategy

```python
class InputValidator:
    def __init__(self):
        self.validators = {}
    
    def add_validator(self, field_name, validator_func):
        self.validators[field_name] = validator_func
    
    def validate(self, data):
        errors = {}
        validated_data = {}
        
        for field_name, value in data.items():
            if field_name in self.validators:
                try:
                    validated_data[field_name] = self.validators[field_name](value)
                except ValueError as e:
                    errors[field_name] = str(e)
            else:
                # Reject unknown fields
                errors[field_name] = "Unknown field"
        
        if errors:
            raise ValidationError(errors)
        
        return validated_data

# Example validators
def validate_email(email):
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValueError("Invalid email format")
    if len(email) > 254:  # RFC 5321 limit
        raise ValueError("Email too long")
    return email.lower().strip()

def validate_phone(phone):
    import re
    # Remove all non-digit characters
    cleaned = re.sub(r'[^\d]', '', phone)
    if len(cleaned) < 10 or len(cleaned) > 15:
        raise ValueError("Invalid phone number length")
    return cleaned

# Usage
validator = InputValidator()
validator.add_validator('email', validate_email)
validator.add_validator('phone', validate_phone)

try:
    validated = validator.validate({
        'email': 'user@example.com',
        'phone': '+1-555-123-4567'
    })
except ValidationError as e:
    print(f"Validation errors: {e.errors}")
```

## Cross-Site Scripting (XSS)

XSS occurs when untrusted user input is included in web pages without proper validation or escaping.

### Types of XSS

1. **Stored/Persistent XSS**: Malicious script stored in database
2. **Reflected XSS**: Script reflected back from server
3. **DOM-based XSS**: Script executed via DOM manipulation

### XSS Prevention

```python
import html
import re
from urllib.parse import quote

class XSSProtection:
    # Dangerous HTML tags that should be stripped
    DANGEROUS_TAGS = [
        'script', 'object', 'embed', 'form', 'input', 'button',
        'select', 'textarea', 'iframe', 'frame', 'frameset',
        'applet', 'base', 'link', 'style'
    ]
    
    # Dangerous attributes
    DANGEROUS_ATTRS = [
        'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus',
        'onblur', 'onchange', 'onsubmit', 'onreset', 'onselect',
        'onabort', 'onkeydown', 'onkeypress', 'onkeyup',
        'onmousedown', 'onmousemove', 'onmouseout', 'onmouseup'
    ]
    
    @staticmethod
    def escape_html(text):
        """Escape HTML characters for safe display"""
        if not isinstance(text, str):
            text = str(text)
        return html.escape(text, quote=True)
    
    @staticmethod
    def escape_js(text):
        """Escape for safe inclusion in JavaScript"""
        if not isinstance(text, str):
            text = str(text)
        
        # Escape special JavaScript characters
        text = text.replace('\\', '\\\\')
        text = text.replace('"', '\\"')
        text = text.replace("'", "\\'")
        text = text.replace('\n', '\\n')
        text = text.replace('\r', '\\r')
        text = text.replace('\t', '\\t')
        text = text.replace('<', '\\u003c')
        text = text.replace('>', '\\u003e')
        
        return text
    
    @staticmethod
    def sanitize_html(html_content, allowed_tags=None):
        """Remove dangerous HTML tags and attributes"""
        if allowed_tags is None:
            allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li']
        
        # This is a simplified example. Use libraries like bleach for production
        import re
        
        # Remove dangerous tags
        for tag in XSSProtection.DANGEROUS_TAGS:
            pattern = f'<{tag}[^>]*>.*?</{tag}>'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE | re.DOTALL)
            
            # Remove self-closing dangerous tags
            pattern = f'<{tag}[^>]*/?>'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE)
        
        # Remove dangerous attributes
        for attr in XSSProtection.DANGEROUS_ATTRS:
            pattern = f'{attr}\\s*=\\s*["\'][^"\']*["\']'
            html_content = re.sub(pattern, '', html_content, flags=re.IGNORECASE)
        
        return html_content

# Usage examples
xss = XSSProtection()

# For HTML context
user_comment = "<script>alert('XSS')</script>Hello World"
safe_comment = xss.escape_html(user_comment)
# Output: &lt;script&gt;alert('XSS')&lt;/script&gt;Hello World

# For JavaScript context
user_name = "'; alert('XSS'); //"
safe_name = xss.escape_js(user_name)
# Output: \\'; alert(\\'XSS\\'); //

# For rich text (using bleach library - recommended)
import bleach

def sanitize_rich_text(content):
    allowed_tags = ['p', 'br', 'strong', 'em', 'u', 'ol', 'ul', 'li', 'a']
    allowed_attributes = {'a': ['href', 'title']}
    
    return bleach.clean(
        content,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=True
    )
```

### Content Security Policy (CSP) for XSS Protection

```html
<!-- Prevent inline scripts and styles -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               script-src 'self'; 
               style-src 'self' 'unsafe-inline'; 
               img-src 'self' data:;">
```

## SQL Injection

SQL injection occurs when user input is directly included in SQL queries without proper sanitization.

### Vulnerable Code Examples

```python
# NEVER DO THIS - Vulnerable to SQL injection
def get_user_by_id(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)

def login(username, password):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    return db.execute(query)
```

### Secure Implementation

```python
import sqlite3
from typing import Optional, List, Dict, Any

class SecureDatabase:
    def __init__(self, db_path: str):
        self.db_path = db_path
    
    def get_connection(self):
        return sqlite3.connect(self.db_path)
    
    def execute_query(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute a query with parameterized inputs"""
        with self.get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """Execute an update/insert/delete query"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount

# Secure implementations
class UserService:
    def __init__(self, db: SecureDatabase):
        self.db = db
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID using parameterized query"""
        if not isinstance(user_id, int) or user_id <= 0:
            raise ValueError("Invalid user ID")
        
        query = "SELECT id, username, email, created_at FROM users WHERE id = ?"
        results = self.db.execute_query(query, (user_id,))
        return results[0] if results else None
    
    def authenticate_user(self, username: str, password_hash: str) -> Optional[Dict[str, Any]]:
        """Authenticate user with parameterized query"""
        if not username or not password_hash:
            return None
        
        query = """
            SELECT id, username, email, created_at 
            FROM users 
            WHERE username = ? AND password_hash = ?
        """
        results = self.db.execute_query(query, (username, password_hash))
        return results[0] if results else None
    
    def search_users(self, search_term: str) -> List[Dict[str, Any]]:
        """Search users safely"""
        if not search_term or len(search_term) < 2:
            return []
        
        # Use LIKE with wildcards, but still parameterized
        search_pattern = f"%{search_term}%"
        query = """
            SELECT id, username, email 
            FROM users 
            WHERE username LIKE ? OR email LIKE ?
            LIMIT 50
        """
        return self.db.execute_query(query, (search_pattern, search_pattern))

# Usage with ORM (SQLAlchemy example)
from sqlalchemy import text

def get_user_orders(db_session, user_id: int):
    """Secure query using SQLAlchemy"""
    query = text("""
        SELECT o.id, o.total, o.created_at, u.username
        FROM orders o
        JOIN users u ON o.user_id = u.id
        WHERE u.id = :user_id
        ORDER BY o.created_at DESC
    """)
    
    return db_session.execute(query, {'user_id': user_id}).fetchall()
```

### Dynamic Query Building (Advanced)

```python
class QueryBuilder:
    def __init__(self):
        self.reset()
    
    def reset(self):
        self.query_parts = []
        self.params = []
        self.where_conditions = []
    
    def select(self, columns):
        if isinstance(columns, str):
            columns = [columns]
        
        # Validate column names (whitelist)
        allowed_columns = ['id', 'username', 'email', 'created_at', 'status']
        for col in columns:
            if col not in allowed_columns:
                raise ValueError(f"Column '{col}' not allowed")
        
        self.query_parts.append(f"SELECT {', '.join(columns)}")
        return self
    
    def from_table(self, table):
        # Validate table name
        allowed_tables = ['users', 'orders', 'products']
        if table not in allowed_tables:
            raise ValueError(f"Table '{table}' not allowed")
        
        self.query_parts.append(f"FROM {table}")
        return self
    
    def where(self, column, operator, value):
        allowed_columns = ['id', 'username', 'email', 'status']
        allowed_operators = ['=', '!=', '>', '<', '>=', '<=', 'LIKE', 'IN']
        
        if column not in allowed_columns:
            raise ValueError(f"Column '{column}' not allowed")
        if operator not in allowed_operators:
            raise ValueError(f"Operator '{operator}' not allowed")
        
        if operator == 'IN':
            if not isinstance(value, (list, tuple)):
                raise ValueError("IN operator requires list/tuple")
            placeholders = ','.join(['?' for _ in value])
            self.where_conditions.append(f"{column} IN ({placeholders})")
            self.params.extend(value)
        else:
            self.where_conditions.append(f"{column} {operator} ?")
            self.params.append(value)
        
        return self
    
    def build(self):
        if self.where_conditions:
            self.query_parts.append(f"WHERE {' AND '.join(self.where_conditions)}")
        
        query = ' '.join(self.query_parts)
        params = tuple(self.params)
        
        self.reset()
        return query, params

# Usage
builder = QueryBuilder()
query, params = (builder
    .select(['id', 'username', 'email'])
    .from_table('users')
    .where('status', '=', 'active')
    .where('id', '>', 100)
    .build())

print(f"Query: {query}")
print(f"Params: {params}")
# Output: SELECT id, username, email FROM users WHERE status = ? AND id = ?
# Params: ('active', 100)
```

## Command Injection

Command injection occurs when user input is passed to system commands.

### Vulnerable Examples

```python
import os
import subprocess

# DANGEROUS - Don't do this
def ping_host(hostname):
    os.system(f"ping -c 4 {hostname}")

def get_file_info(filename):
    return subprocess.run(f"ls -la {filename}", shell=True, capture_output=True)
```

### Secure Implementation

```python
import subprocess
import shlex
import re
from pathlib import Path

class SecureCommandExecutor:
    # Whitelist of allowed commands
    ALLOWED_COMMANDS = {
        'ping': '/bin/ping',
        'ls': '/bin/ls',
        'grep': '/bin/grep'
    }
    
    @staticmethod
    def validate_hostname(hostname):
        """Validate hostname format"""
        pattern = r'^[a-zA-Z0-9.-]+$'
        if not re.match(pattern, hostname):
            raise ValueError("Invalid hostname format")
        if len(hostname) > 253:
            raise ValueError("Hostname too long")
        return hostname
    
    @staticmethod
    def validate_filename(filename):
        """Validate filename and prevent directory traversal"""
        # Remove any path components
        filename = Path(filename).name
        
        # Check for dangerous characters
        if re.search(r'[;&|`$(){}[\]<>]', filename):
            raise ValueError("Invalid characters in filename")
        
        return filename
    
    def ping_host(self, hostname):
        """Safely ping a host"""
        hostname = self.validate_hostname(hostname)
        
        # Use subprocess with argument list (not shell=True)
        try:
            result = subprocess.run(
                ['/bin/ping', '-c', '4', hostname],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            raise ValueError("Ping command timed out")
    
    def list_file(self, filename):
        """Safely list file information"""
        filename = self.validate_filename(filename)
        
        # Ensure file exists and is in allowed directory
        safe_path = Path('/safe/directory') / filename
        if not safe_path.exists():
            raise FileNotFoundError("File not found")
        
        try:
            result = subprocess.run(
                ['/bin/ls', '-la', str(safe_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            raise ValueError("Command timed out")
    
    def search_in_file(self, pattern, filename):
        """Safely search for pattern in file"""
        filename = self.validate_filename(filename)
        
        # Validate search pattern
        if len(pattern) > 100:
            raise ValueError("Search pattern too long")
        if re.search(r'[;&|`$(){}[\]<>]', pattern):
            raise ValueError("Invalid characters in search pattern")
        
        safe_path = Path('/safe/directory') / filename
        if not safe_path.exists():
            raise FileNotFoundError("File not found")
        
        try:
            result = subprocess.run(
                ['/bin/grep', pattern, str(safe_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            raise ValueError("Search timed out")

# Usage
executor = SecureCommandExecutor()

try:
    result = executor.ping_host("google.com")
    print(result)
except ValueError as e:
    print(f"Error: {e}")
```

## File Upload Security

File uploads are a common attack vector. Implement multiple layers of protection.

### Secure File Upload Implementation

```python
import os
import mimetypes
import hashlib
from pathlib import Path
from PIL import Image
import magic

class SecureFileUpload:
    # Allowed file types
    ALLOWED_EXTENSIONS = {
        'image': ['jpg', 'jpeg', 'png', 'gif', 'webp'],
        'document': ['pdf', 'txt', 'docx', 'xlsx'],
        'archive': ['zip', 'tar', 'gz']
    }
    
    ALLOWED_MIME_TYPES = {
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf', 'text/plain',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/zip'
    }
    
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    
    def __init__(self, upload_directory):
        self.upload_directory = Path(upload_directory)
        self.upload_directory.mkdir(exist_ok=True)
    
    def validate_file(self, file_path, expected_type=None):
        """Comprehensive file validation"""
        file_path = Path(file_path)
        
        # Check file size
        if file_path.stat().st_size > self.MAX_FILE_SIZE:
            raise ValueError("File too large")
        
        # Check file extension
        extension = file_path.suffix.lower().lstrip('.')
        if expected_type:
            if extension not in self.ALLOWED_EXTENSIONS.get(expected_type, []):
                raise ValueError(f"Invalid file extension for {expected_type}")
        
        # Check MIME type using python-magic
        mime_type = magic.from_file(str(file_path), mime=True)
        if mime_type not in self.ALLOWED_MIME_TYPES:
            raise ValueError(f"Invalid MIME type: {mime_type}")
        
        # Additional validation for images
        if expected_type == 'image':
            self._validate_image(file_path)
        
        return True
    
    def _validate_image(self, file_path):
        """Additional validation for image files"""
        try:
            with Image.open(file_path) as img:
                # Verify it's a valid image
                img.verify()
                
                # Check image dimensions
                img = Image.open(file_path)  # Reopen after verify()
                width, height = img.size
                
                if width > 4000 or height > 4000:
                    raise ValueError("Image dimensions too large")
                
                # Remove EXIF data for privacy
                if hasattr(img, '_getexif'):
                    img = img.copy()
                    if img._getexif():
                        # Strip EXIF data
                        img.save(file_path, quality=95, optimize=True)
        
        except Exception as e:
            raise ValueError(f"Invalid image file: {e}")
    
    def generate_safe_filename(self, original_filename):
        """Generate a safe filename"""
        # Get extension
        extension = Path(original_filename).suffix.lower()
        
        # Generate unique filename
        hash_input = f"{original_filename}{os.urandom(16)}"
        filename_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
        
        return f"{filename_hash}{extension}"
    
    def upload_file(self, file_data, original_filename, file_type=None):
        """Securely upload a file"""
        # Generate safe filename
        safe_filename = self.generate_safe_filename(original_filename)
        file_path = self.upload_directory / safe_filename
        
        # Write file data
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        try:
            # Validate the uploaded file
            self.validate_file(file_path, file_type)
            
            return {
                'filename': safe_filename,
                'path': str(file_path),
                'size': file_path.stat().st_size,
                'mime_type': magic.from_file(str(file_path), mime=True)
            }
        
        except Exception as e:
            # Remove file if validation fails
            if file_path.exists():
                file_path.unlink()
            raise e

# Flask example
from flask import Flask, request, jsonify
import tempfile

app = Flask(__name__)
uploader = SecureFileUpload('/secure/uploads')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Read file data
        file_data = file.read()
        
        # Check file size before processing
        if len(file_data) > uploader.MAX_FILE_SIZE:
            return jsonify({'error': 'File too large'}), 400
        
        # Upload and validate
        result = uploader.upload_file(
            file_data,
            file.filename,
            file_type='image'  # or get from request
        )
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_info': result
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400
```

## Server-Side Request Forgery (SSRF)

SSRF occurs when an application fetches URLs provided by users without proper validation.

### Vulnerable Code

```python
import requests

# DANGEROUS - Don't do this
def fetch_url(url):
    response = requests.get(url)
    return response.text

def proxy_request(target_url):
    # Attacker could access internal services
    return requests.get(target_url)
```

### Secure Implementation

```python
import requests
import ipaddress
from urllib.parse import urlparse
import socket

class SecureURLFetcher:
    # Allowed protocols
    ALLOWED_PROTOCOLS = ['http', 'https']
    
    # Blocked private IP ranges
    BLOCKED_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),      # Private
        ipaddress.ip_network('172.16.0.0/12'),   # Private
        ipaddress.ip_network('192.168.0.0/16'),  # Private
        ipaddress.ip_network('127.0.0.0/8'),     # Loopback
        ipaddress.ip_network('169.254.0.0/16'),  # Link-local
        ipaddress.ip_network('::1/128'),         # IPv6 loopback
        ipaddress.ip_network('fe80::/10'),       # IPv6 link-local
    ]
    
    # Allowed domains (whitelist approach)
    ALLOWED_DOMAINS = [
        'api.github.com',
        'httpbin.org',
        'jsonplaceholder.typicode.com'
    ]
    
    def validate_url(self, url):
        """Validate URL for SSRF protection"""
        try:
            parsed = urlparse(url)
            
            # Check protocol
            if parsed.scheme not in self.ALLOWED_PROTOCOLS:
                raise ValueError(f"Protocol '{parsed.scheme}' not allowed")
            
            # Check if domain is in whitelist
            if parsed.hostname not in self.ALLOWED_DOMAINS:
                raise ValueError(f"Domain '{parsed.hostname}' not allowed")
            
            # Resolve hostname to IP
            ip = socket.gethostbyname(parsed.hostname)
            ip_addr = ipaddress.ip_address(ip)
            
            # Check if IP is in blocked ranges
            for network in self.BLOCKED_NETWORKS:
                if ip_addr in network:
                    raise ValueError(f"IP address {ip} is not allowed")
            
            # Check port (if specified)
            port = parsed.port
            if port and port not in [80, 443, 8080, 8443]:
                raise ValueError(f"Port {port} not allowed")
            
            return True
            
        except socket.gaierror:
            raise ValueError("Cannot resolve hostname")
        except Exception as e:
            raise ValueError(f"Invalid URL: {e}")
    
    def fetch_url(self, url, timeout=10):
        """Safely fetch URL content"""
        self.validate_url(url)
        
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,  # Prevent redirect-based bypasses
                headers={'User-Agent': 'SecureBot/1.0'}
            )
            
            # Check response size
            if len(response.content) > 1024 * 1024:  # 1MB limit
                raise ValueError("Response too large")
            
            return {
                'status_code': response.status_code,
                'content': response.text,
                'headers': dict(response.headers)
            }
            
        except requests.exceptions.RequestException as e:
            raise ValueError(f"Request failed: {e}")

# Usage
fetcher = SecureURLFetcher()

try:
    result = fetcher.fetch_url('https://api.github.com/users/octocat')
    print(result['content'])
except ValueError as e:
    print(f"Error: {e}")
```

## Tamper-Proof User Inputs

Protect against client-side manipulation of critical data.

### Hidden Form Fields Protection

```python
import hmac
import hashlib
import json
from datetime import datetime, timedelta

class FormProtection:
    def __init__(self, secret_key):
        self.secret_key = secret_key
    
    def sign_data(self, data):
        """Create tamper-proof signature for data"""
        data_json = json.dumps(data, sort_keys=True)
        signature = hmac.new(
            self.secret_key.encode(),
            data_json.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return {
            'data': data,
            'signature': signature,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def verify_data(self, signed_data, max_age_minutes=60):
        """Verify data hasn't been tampered with"""
        try:
            data = signed_data['data']
            signature = signed_data['signature']
            timestamp = datetime.fromisoformat(signed_data['timestamp'])
            
            # Check age
            if datetime.utcnow() - timestamp > timedelta(minutes=max_age_minutes):
                raise ValueError("Data expired")
            
            # Verify signature
            data_json = json.dumps(data, sort_keys=True)
            expected_signature = hmac.new(
                self.secret_key.encode(),
                data_json.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                raise ValueError("Invalid signature")
            
            return data
            
        except (KeyError, ValueError) as e:
            raise ValueError(f"Invalid signed data: {e}")

# Usage in web framework
from flask import session

form_protection = FormProtection('your-secret-key')

@app.route('/checkout')
def checkout():
    # Sign critical data
    order_data = {
        'user_id': current_user.id,
        'total': 99.99,
        'discount': 10.00
    }
    
    signed_data = form_protection.sign_data(order_data)
    session['order_signature'] = signed_data
    
    return render_template('checkout.html', order=order_data)

@app.route('/process_order', methods=['POST'])
def process_order():
    try:
        # Verify the data hasn't been tampered with
        signed_data = session.get('order_signature')
        if not signed_data:
            raise ValueError("Missing order signature")
        
        original_data = form_protection.verify_data(signed_data)
        
        # Use the verified data, not user input
        process_payment(
            user_id=original_data['user_id'],
            total=original_data['total'],
            discount=original_data['discount']
        )
        
        return jsonify({'status': 'success'})
        
    except ValueError as e:
        return jsonify({'error': 'Invalid order data'}), 400
```

## Best Practices

### Input Validation Checklist

1. **Validate all inputs** at the application boundary
2. **Use whitelisting** instead of blacklisting
3. **Validate data type, length, format, and range**
4. **Sanitize for the output context** (HTML, SQL, shell, etc.)
5. **Use parameterized queries** for database operations
6. **Avoid shell commands** when possible
7. **Implement file upload restrictions** (type, size, content)
8. **Use CSP headers** to prevent XSS
9. **Log validation failures** for monitoring
10. **Fail securely** with generic error messages

### Context-Specific Escaping

```python
class ContextEscaper:
    @staticmethod
    def html_escape(text):
        """Escape for HTML context"""
        return html.escape(str(text), quote=True)
    
    @staticmethod
    def js_escape(text):
        """Escape for JavaScript string context"""
        text = str(text)
        return (text
                .replace('\\', '\\\\')
                .replace('"', '\\"')
                .replace("'", "\\'")
                .replace('\n', '\\n')
                .replace('\r', '\\r')
                .replace('\t', '\\t')
                .replace('<', '\\u003c')
                .replace('>', '\\u003e'))
    
    @staticmethod
    def css_escape(text):
        """Escape for CSS context"""
        import re
        text = str(text)
        return re.sub(r'[^a-zA-Z0-9\-_]', 
                     lambda m: f'\\{ord(m.group(0)):06x}', 
                     text)
    
    @staticmethod
    def url_escape(text):
        """Escape for URL context"""
        from urllib.parse import quote
        return quote(str(text), safe='')

# Usage in templates (Jinja2 example)
from jinja2 import Environment

def create_secure_jinja_env():
    env = Environment()
    
    # Add custom filters
    env.filters['html_escape'] = ContextEscaper.html_escape
    env.filters['js_escape'] = ContextEscaper.js_escape
    env.filters['css_escape'] = ContextEscaper.css_escape
    env.filters['url_escape'] = ContextEscaper.url_escape
    
    return env
```

## Conclusion

Input validation and sanitization are your first line of defense against many attacks. Remember:

- **Never trust any input** from users, APIs, or external sources
- **Validate early and often** in your application pipeline
- **Use context-appropriate escaping** for output
- **Implement defense in depth** with multiple validation layers
- **Log and monitor** validation failures
- **Keep security libraries updated** (like bleach for HTML sanitization)

The next chapter covers [Cryptography: Encoding vs Encryption vs Hashing](cryptography.md) - understanding the fundamental building blocks of security.