[Back to Contents](README.md)

# Passwords: dadada, 123456 and cute@123

> [!WARNING]
> **Fun fact**: "123456" and "password" are still among the most common passwords in 2025.

Passwords remain the most common authentication method despite their well-known weaknesses. This chapter covers how to implement secure password policies, storage mechanisms, and alternatives to traditional password-based authentication.

## Table of Contents
- [The Password Problem](#the-password-problem)
- [Password Policies](#password-policies)
- [Secure Password Storage](#secure-password-storage)
- [Password Strength Assessment](#password-strength-assessment)
- [Breach Detection](#breach-detection)
- [Password Reset Security](#password-reset-security)
- [Life Without Passwords](#life-without-passwords)
- [Implementation Examples](#implementation-examples)

## The Password Problem

### Why Passwords Are Problematic

| Problem | Impact | Example |
|---------|--------|---------|
| **Human Nature** | Predictable choices | "password123", birthdays |
| **Reuse** | Single breach = multiple accounts | Same password everywhere |
| **Attacks** | Automated cracking | Brute force, credential stuffing |
| **Storage** | Plain text disasters | Storing passwords unencrypted |
| **Transmission** | Network interception | HTTP instead of HTTPS |

### Common Password Patterns

```python
# Analysis of common password patterns
COMMON_PATTERNS = {
    'sequential': ['123456', '654321', 'abcdef'],
    'keyboard': ['qwerty', 'asdfgh', 'zxcvbn'],
    'dictionary': ['password', 'admin', 'login'],
    'personal': ['name123', 'birthday', 'petname'],
    'substitution': ['p@ssw0rd', '3@sY', 'h3ll0'],
    'years': ['2023', '2024', '1990', '1985']
}

def analyze_password_weakness(password):
    """Analyze common password weaknesses"""
    issues = []
    
    # Check length
    if len(password) < 8:
        issues.append("Too short (less than 8 characters)")
    
    # Check for common patterns
    password_lower = password.lower()
    for pattern_type, patterns in COMMON_PATTERNS.items():
        for pattern in patterns:
            if pattern in password_lower:
                issues.append(f"Contains common {pattern_type} pattern: {pattern}")
    
    # Check character diversity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if not has_upper:
        issues.append("No uppercase letters")
    if not has_lower:
        issues.append("No lowercase letters")
    if not has_digit:
        issues.append("No digits")
    if not has_special:
        issues.append("No special characters")
    
    return issues

# Example usage
weak_passwords = ['123456', 'password', 'qwerty123', 'admin', 'cute@123']
for pwd in weak_passwords:
    issues = analyze_password_weakness(pwd)
    print(f"Password '{pwd}' issues: {issues}")
```

## Password Policies

### Modern Password Policy Guidelines

Based on NIST 800-63B and industry best practices:

```python
import re
import math
from typing import List, Dict, Tuple

class ModernPasswordPolicy:
    def __init__(self):
        # NIST-compliant policy
        self.min_length = 8
        self.max_length = 128  # Allow long passwords
        self.require_complexity = False  # NIST recommends against complexity requirements
        self.check_breaches = True
        self.allow_unicode = True
        self.block_common = True
        
        # Common passwords list (subset for demo)
        self.common_passwords = {
            '123456', 'password', 'qwerty', 'admin', 'letmein',
            'welcome', '123456789', 'password123', 'admin123'
        }
    
    def validate_password(self, password: str, username: str = None) -> Tuple[bool, List[str]]:
        """Validate password against modern security guidelines"""
        errors = []
        
        # Length check
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        if len(password) > self.max_length:
            errors.append(f"Password must be no more than {self.max_length} characters long")
        
        # Check against common passwords
        if self.block_common and password.lower() in self.common_passwords:
            errors.append("Password is too common")
        
        # Check if password contains username
        if username and username.lower() in password.lower():
            errors.append("Password cannot contain username")
        
        # Check for sequential characters (basic check)
        if self._has_sequential_chars(password):
            errors.append("Password contains sequential characters")
        
        # Check for repeated characters
        if self._has_repeated_chars(password):
            errors.append("Password has too many repeated characters")
        
        return len(errors) == 0, errors
    
    def _has_sequential_chars(self, password: str, min_sequence: int = 4) -> bool:
        """Check for sequential characters like '1234' or 'abcd'"""
        for i in range(len(password) - min_sequence + 1):
            sequence = password[i:i + min_sequence]
            if self._is_sequential(sequence):
                return True
        return False
    
    def _is_sequential(self, s: str) -> bool:
        """Check if string is sequential"""
        if len(s) < 2:
            return False
        
        # Check ascending sequence
        ascending = all(ord(s[i]) == ord(s[i-1]) + 1 for i in range(1, len(s)))
        # Check descending sequence
        descending = all(ord(s[i]) == ord(s[i-1]) - 1 for i in range(1, len(s)))
        
        return ascending or descending
    
    def _has_repeated_chars(self, password: str, max_repeat: int = 3) -> bool:
        """Check for repeated characters"""
        for i in range(len(password) - max_repeat + 1):
            if len(set(password[i:i + max_repeat])) == 1:
                return True
        return False
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy (information theory)"""
        # Character set sizes
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32  # Approximate special chars
        
        if charset_size == 0:
            return 0
        
        return len(password) * math.log2(charset_size)
    
    def suggest_improvements(self, password: str) -> List[str]:
        """Suggest password improvements"""
        suggestions = []
        
        if len(password) < 12:
            suggestions.append("Consider using a longer password (12+ characters)")
        
        if not re.search(r'[a-z]', password):
            suggestions.append("Add lowercase letters")
        if not re.search(r'[A-Z]', password):
            suggestions.append("Add uppercase letters")
        if not re.search(r'[0-9]', password):
            suggestions.append("Add numbers")
        if not re.search(r'[^a-zA-Z0-9]', password):
            suggestions.append("Add special characters")
        
        entropy = self.calculate_entropy(password)
        if entropy < 50:
            suggestions.append(f"Increase complexity (current entropy: {entropy:.1f} bits)")
        
        return suggestions

# Usage example
policy = ModernPasswordPolicy()

test_passwords = [
    'password123',
    'MyS3cur3P@ssw0rd!',
    '1234567890',
    'correct-horse-battery-staple',
    'P@ssw0rd'
]

for pwd in test_passwords:
    is_valid, errors = policy.validate_password(pwd)
    entropy = policy.calculate_entropy(pwd)
    suggestions = policy.suggest_improvements(pwd)
    
    print(f"\nPassword: {pwd}")
    print(f"Valid: {is_valid}")
    print(f"Entropy: {entropy:.1f} bits")
    if errors:
        print(f"Errors: {errors}")
    if suggestions:
        print(f"Suggestions: {suggestions}")
```

### Enterprise Password Policy

```python
class EnterprisePasswordPolicy(ModernPasswordPolicy):
    """Enhanced policy for enterprise environments"""
    
    def __init__(self):
        super().__init__()
        self.min_length = 12
        self.password_history_count = 12  # Remember last 12 passwords
        self.max_age_days = 90  # Force change every 90 days
        self.min_age_hours = 24  # Prevent immediate changes
        self.lockout_threshold = 5  # Lock after 5 failed attempts
        self.lockout_duration_minutes = 30
    
    def validate_password_history(self, new_password: str, password_history: List[str]) -> bool:
        """Check against password history"""
        # In production, compare against hashed passwords
        return new_password not in password_history[-self.password_history_count:]
    
    def check_password_age(self, last_change_date) -> Tuple[bool, str]:
        """Check if password needs to be changed"""
        from datetime import datetime, timedelta
        
        if not last_change_date:
            return False, "Password age unknown"
        
        age = datetime.now() - last_change_date
        max_age = timedelta(days=self.max_age_days)
        
        if age > max_age:
            return False, f"Password expired (age: {age.days} days)"
        
        days_until_expiry = (max_age - age).days
        if days_until_expiry <= 7:
            return True, f"Password expires in {days_until_expiry} days"
        
        return True, "Password age acceptable"
```

## Secure Password Storage

### Never Store Plaintext Passwords

```python
import argon2
import bcrypt
import hashlib
import secrets
from datetime import datetime, timedelta

class SecurePasswordStorage:
    def __init__(self, algorithm='argon2id'):
        self.algorithm = algorithm
        
        if algorithm == 'argon2id':
            # Recommended parameters for 2025
            self.argon2_hasher = argon2.PasswordHasher(
                time_cost=3,       # iterations
                memory_cost=65536, # memory in KB (64MB)
                parallelism=1,     # threads
                hash_len=32,       # hash length
                salt_len=16        # salt length
            )
    
    def hash_password(self, password: str) -> str:
        """Hash password using secure algorithm"""
        if self.algorithm == 'argon2id':
            return self.argon2_hasher.hash(password)
        elif self.algorithm == 'bcrypt':
            # bcrypt with cost factor 12
            salt = bcrypt.gensalt(rounds=12)
            return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        try:
            if self.algorithm == 'argon2id':
                return self.argon2_hasher.verify(hashed, password)
            elif self.algorithm == 'bcrypt':
                return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception:
            return False
        return False
    
    def needs_rehash(self, hashed: str) -> bool:
        """Check if hash needs to be updated (parameters changed)"""
        if self.algorithm == 'argon2id':
            try:
                return self.argon2_hasher.check_needs_rehash(hashed)
            except Exception:
                return True
        elif self.algorithm == 'bcrypt':
            # bcrypt doesn't have built-in rehash check
            # You could implement cost factor checking here
            return False
        return False

class PasswordDatabase:
    """Secure password storage with additional security features"""
    
    def __init__(self):
        self.storage = SecurePasswordStorage('argon2id')
        self.users = {}  # In production, use proper database
    
    def create_user(self, username: str, password: str) -> bool:
        """Create new user with secure password storage"""
        if username in self.users:
            return False
        
        # Hash password
        password_hash = self.storage.hash_password(password)
        
        # Store user data
        self.users[username] = {
            'password_hash': password_hash,
            'created_at': datetime.now(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None,
            'password_history': [password_hash],
            'last_password_change': datetime.now()
        }
        
        return True
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate user with rate limiting and lockout"""
        if username not in self.users:
            # Prevent username enumeration - still do password verification
            self.storage.hash_password(password)
            return False, "Invalid credentials"
        
        user = self.users[username]
        
        # Check if account is locked
        if user['locked_until'] and datetime.now() < user['locked_until']:
            return False, "Account temporarily locked"
        
        # Verify password
        if self.storage.verify_password(password, user['password_hash']):
            # Successful login
            user['last_login'] = datetime.now()
            user['failed_attempts'] = 0
            user['locked_until'] = None
            
            # Check if password needs rehashing
            if self.storage.needs_rehash(user['password_hash']):
                user['password_hash'] = self.storage.hash_password(password)
            
            return True, "Authentication successful"
        else:
            # Failed login
            user['failed_attempts'] += 1
            
            # Lock account after 5 failed attempts
            if user['failed_attempts'] >= 5:
                user['locked_until'] = datetime.now() + timedelta(minutes=30)
                return False, "Account locked due to repeated failures"
            
            return False, "Invalid credentials"
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, str]:
        """Change user password with security checks"""
        if username not in self.users:
            return False, "User not found"
        
        user = self.users[username]
        
        # Verify old password
        if not self.storage.verify_password(old_password, user['password_hash']):
            return False, "Current password incorrect"
        
        # Check password history (prevent reuse)
        new_hash = self.storage.hash_password(new_password)
        for old_hash in user['password_history']:
            if self.storage.verify_password(new_password, old_hash):
                return False, "Cannot reuse recent password"
        
        # Update password
        user['password_hash'] = new_hash
        user['password_history'].append(new_hash)
        user['last_password_change'] = datetime.now()
        
        # Keep only last 12 passwords in history
        user['password_history'] = user['password_history'][-12:]
        
        return True, "Password changed successfully"

# Usage example
db = PasswordDatabase()

# Create user
success = db.create_user("john_doe", "MyS3cur3P@ssw0rd!")
print(f"User created: {success}")

# Authenticate
auth_success, message = db.authenticate_user("john_doe", "MyS3cur3P@ssw0rd!")
print(f"Authentication: {auth_success}, {message}")

# Change password
change_success, change_message = db.change_password(
    "john_doe", 
    "MyS3cur3P@ssw0rd!", 
    "MyN3wS3cur3P@ssw0rd!"
)
print(f"Password change: {change_success}, {change_message}")
```

## Password Strength Assessment

### Real-time Strength Meter

```python
import math
import re
from typing import Dict, List

class PasswordStrengthMeter:
    def __init__(self):
        # Common password patterns
        self.common_patterns = [
            r'(012|123|234|345|456|567|678|789|890)',  # Sequential numbers
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk)',  # Sequential letters
            r'(qwe|wer|ert|rty|tyu|yui|uio|iop)',     # Keyboard patterns
            r'(.)\1{2,}',                              # Repeated characters
            r'(pass|word|admin|user|test|demo)',       # Common words
        ]
        
        # Character sets
        self.char_sets = {
            'lowercase': r'[a-z]',
            'uppercase': r'[A-Z]',
            'digits': r'[0-9]',
            'special': r'[^a-zA-Z0-9]',
            'unicode': r'[^\x00-\x7F]'
        }
    
    def assess_strength(self, password: str) -> Dict:
        """Comprehensive password strength assessment"""
        if not password:
            return {'score': 0, 'strength': 'Very Weak', 'feedback': ['Password is empty']}
        
        score = 0
        feedback = []
        bonus_points = 0
        penalty_points = 0
        
        # Length analysis
        length = len(password)
        if length >= 8:
            score += 25
        elif length >= 6:
            score += 10
            feedback.append("Password could be longer")
        else:
            feedback.append("Password is too short")
        
        # Character diversity
        char_types_used = 0
        for char_type, pattern in self.char_sets.items():
            if re.search(pattern, password):
                char_types_used += 1
                score += 15
        
        if char_types_used < 3:
            feedback.append("Use a mix of letters, numbers, and symbols")
        
        # Length bonus
        if length >= 12:
            bonus_points += 10
        if length >= 16:
            bonus_points += 10
        
        # Pattern penalties
        for pattern in self.common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                penalty_points += 15
                feedback.append("Avoid common patterns")
                break
        
        # Calculate entropy
        entropy = self._calculate_entropy(password)
        if entropy >= 60:
            bonus_points += 20
        elif entropy >= 40:
            bonus_points += 10
        elif entropy < 25:
            penalty_points += 20
            feedback.append("Password is too predictable")
        
        # Apply bonuses and penalties
        score = max(0, min(100, score + bonus_points - penalty_points))
        
        # Determine strength level
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        # Additional feedback
        if not feedback:
            feedback.append("Password looks good!")
        
        return {
            'score': score,
            'strength': strength,
            'entropy': entropy,
            'length': length,
            'char_types': char_types_used,
            'feedback': feedback
        }
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy"""
        if not password:
            return 0
        
        # Determine character set size
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        return len(password) * math.log2(charset_size)
    
    def generate_strong_password(self, length: int = 16) -> str:
        """Generate a cryptographically strong password"""
        import secrets
        import string
        
        # Ensure character diversity
        chars = (
            string.ascii_lowercase +
            string.ascii_uppercase +
            string.digits +
            "!@#$%^&*()-_=+[]{}|;:,.<>?"
        )
        
        # Generate password ensuring at least one character from each set
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()-_=+")
        ]
        
        # Fill remaining length
        for _ in range(length - 4):
            password.append(secrets.choice(chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)

# Usage examples
meter = PasswordStrengthMeter()

test_passwords = [
    'password',
    'Password123',
    'P@ssw0rd123',
    'MyS3cur3P@ssw0rd!',
    'correct-horse-battery-staple',
    'Tr0ub4dor&3'
]

for pwd in test_passwords:
    result = meter.assess_strength(pwd)
    print(f"\nPassword: {pwd}")
    print(f"Strength: {result['strength']} (Score: {result['score']}/100)")
    print(f"Entropy: {result['entropy']:.1f} bits")
    print(f"Feedback: {result['feedback']}")

# Generate strong password
strong_pwd = meter.generate_strong_password(16)
print(f"\nGenerated strong password: {strong_pwd}")
print(f"Assessment: {meter.assess_strength(strong_pwd)}")
```

## Breach Detection

### Check Against Known Breaches

```python
import hashlib
import requests
from typing import Optional

class BreachChecker:
    """Check passwords against known data breaches using k-anonymity"""
    
    def __init__(self):
        self.hibp_api_url = "https://api.pwnedpasswords.com/range/"
    
    def check_password_breach(self, password: str) -> Tuple[bool, int]:
        """
        Check if password appears in known breaches using k-anonymity model
        Returns (is_breached, occurrence_count)
        """
        # Hash the password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        # Use k-anonymity: only send first 5 characters
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]
        
        try:
            # Query HaveIBeenPwned API
            response = requests.get(
                f"{self.hibp_api_url}{hash_prefix}",
                timeout=5,
                headers={'User-Agent': 'SecurePasswordChecker/1.0'}
            )
            
            if response.status_code == 200:
                # Parse response
                for line in response.text.splitlines():
                    suffix, count = line.split(':')
                    if suffix == hash_suffix:
                        return True, int(count)
                
                # Hash not found in breaches
                return False, 0
            else:
                # API error - fail safely (assume not breached)
                return False, -1
                
        except Exception:
            # Network error - fail safely
            return False, -1
    
    def check_password_safety(self, password: str) -> Dict:
        """Comprehensive password safety check"""
        is_breached, count = self.check_password_breach(password)
        
        result = {
            'is_safe': not is_breached,
            'breach_count': count,
            'recommendation': ''
        }
        
        if is_breached:
            if count > 100:
                result['recommendation'] = f"This password has been seen {count:,} times in data breaches. Change it immediately!"
            elif count > 10:
                result['recommendation'] = f"This password has been seen {count} times in breaches. Consider changing it."
            else:
                result['recommendation'] = f"This password appears in data breaches {count} time(s). Recommend changing."
        else:
            if count == -1:
                result['recommendation'] = "Could not check breach status (API error). Use with caution."
            else:
                result['recommendation'] = "Password not found in known breaches."
        
        return result

# Offline breach checker (for high-security environments)
class OfflineBreachChecker:
    """Check passwords against local breach database"""
    
    def __init__(self, bloom_filter_path: Optional[str] = None):
        """
        Initialize with bloom filter of breached password hashes
        In production, you'd load a bloom filter from file
        """
        self.bloom_filter = set()  # Simplified - use real bloom filter
        
        # Load common breached passwords (simplified example)
        common_breached = [
            'password', '123456', 'qwerty', 'admin', 'letmein',
            'welcome', 'monkey', '1234567890', 'password123'
        ]
        
        for pwd in common_breached:
            hash_value = hashlib.sha256(pwd.encode()).hexdigest()
            self.bloom_filter.add(hash_value)
    
    def is_breached(self, password: str) -> bool:
        """Check if password hash exists in breach database"""
        hash_value = hashlib.sha256(password.encode()).hexdigest()
        return hash_value in self.bloom_filter

# Usage examples
breach_checker = BreachChecker()

# Test some passwords
test_passwords = ['password', 'MyS3cur3P@ssw0rd!', '123456']

for pwd in test_passwords:
    safety = breach_checker.check_password_safety(pwd)
    print(f"\nPassword: {pwd}")
    print(f"Safe: {safety['is_safe']}")
    print(f"Breach count: {safety['breach_count']}")
    print(f"Recommendation: {safety['recommendation']}")
```

## Password Reset Security

### Secure Reset Implementation

```python
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple

class SecurePasswordReset:
    def __init__(self, token_expiry_minutes: int = 15):
        self.token_expiry_minutes = token_expiry_minutes
        self.reset_tokens = {}  # In production, use database
        self.rate_limits = {}   # Rate limiting storage
    
    def generate_reset_token(self, email: str) -> Tuple[bool, str]:
        """Generate secure password reset token"""
        # Rate limiting - max 3 requests per hour
        now = datetime.now()
        hour_key = f"{email}_{now.hour}"
        
        if hour_key in self.rate_limits:
            if self.rate_limits[hour_key] >= 3:
                return False, "Too many reset requests. Try again later."
        else:
            self.rate_limits[hour_key] = 0
        
        self.rate_limits[hour_key] += 1
        
        # Generate cryptographically secure token
        token = secrets.token_urlsafe(32)
        
        # Hash token for storage (never store plaintext tokens)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Store token with expiration
        self.reset_tokens[token_hash] = {
            'email': email,
            'created_at': now,
            'expires_at': now + timedelta(minutes=self.token_expiry_minutes),
            'used': False
        }
        
        # Clean up expired tokens
        self._cleanup_expired_tokens()
        
        return True, token
    
    def validate_reset_token(self, token: str) -> Tuple[bool, Optional[str]]:
        """Validate reset token and return email if valid"""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        if token_hash not in self.reset_tokens:
            return False, None
        
        token_data = self.reset_tokens[token_hash]
        
        # Check if token is expired
        if datetime.now() > token_data['expires_at']:
            del self.reset_tokens[token_hash]
            return False, None
        
        # Check if token is already used
        if token_data['used']:
            return False, None
        
        return True, token_data['email']
    
    def use_reset_token(self, token: str, new_password: str) -> Tuple[bool, str]:
        """Use reset token to change password"""
        is_valid, email = self.validate_reset_token(token)
        
        if not is_valid:
            return False, "Invalid or expired reset token"
        
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Mark token as used
        self.reset_tokens[token_hash]['used'] = True
        
        # In production, update user's password in database
        # Also invalidate all existing sessions for the user
        
        return True, f"Password reset successful for {email}"
    
    def _cleanup_expired_tokens(self):
        """Remove expired tokens"""
        now = datetime.now()
        expired_tokens = [
            token_hash for token_hash, data in self.reset_tokens.items()
            if now > data['expires_at']
        ]
        
        for token_hash in expired_tokens:
            del self.reset_tokens[token_hash]

# Email notification system
class PasswordResetNotifier:
    """Handle secure password reset notifications"""
    
    @staticmethod
    def send_reset_email(email: str, reset_token: str, base_url: str):
        """Send password reset email (mock implementation)"""
        reset_url = f"{base_url}/reset-password?token={reset_token}"
        
        # In production, use proper email service
        email_content = f"""
        Subject: Password Reset Request
        
        A password reset was requested for your account.
        
        If you requested this reset, click the link below:
        {reset_url}
        
        This link will expire in 15 minutes.
        
        If you didn't request this reset, please ignore this email.
        Your password will not be changed unless you click the link above.
        
        For security, this email was sent from an automated system.
        Do not reply to this email.
        """
        
        print(f"Email sent to {email}:")
        print(email_content)
    
    @staticmethod
    def send_reset_confirmation(email: str):
        """Send confirmation after successful password reset"""
        email_content = f"""
        Subject: Password Successfully Reset
        
        Your password has been successfully reset.
        
        If this wasn't you, please contact support immediately.
        
        Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        print(f"Confirmation sent to {email}:")
        print(email_content)

# Usage example
reset_system = SecurePasswordReset()
notifier = PasswordResetNotifier()

# Request password reset
email = "user@example.com"
success, token_or_message = reset_system.generate_reset_token(email)

if success:
    print(f"Reset token generated: {token_or_message}")
    notifier.send_reset_email(email, token_or_message, "https://example.com")
    
    # Simulate user clicking reset link
    new_password = "MyNewS3cur3P@ssw0rd!"
    reset_success, message = reset_system.use_reset_token(token_or_message, new_password)
    
    if reset_success:
        notifier.send_reset_confirmation(email)
        print(f"Reset successful: {message}")
    else:
        print(f"Reset failed: {message}")
else:
    print(f"Reset request failed: {token_or_message}")
```

## Life Without Passwords

### Passwordless Authentication Methods

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import json
import base64
from typing import Dict, Optional

class PasswordlessAuth:
    """Implementation of passwordless authentication methods"""
    
    def __init__(self):
        self.magic_links = {}
        self.webauthn_credentials = {}
    
    # Magic Link Authentication
    def generate_magic_link(self, email: str) -> str:
        """Generate secure magic link for authentication"""
        # Generate secure token
        token = secrets.token_urlsafe(32)
        
        # Store token with short expiration (5 minutes)
        self.magic_links[token] = {
            'email': email,
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(minutes=5),
            'used': False
        }
        
        return f"https://example.com/auth/magic?token={token}"
    
    def verify_magic_link(self, token: str) -> Tuple[bool, Optional[str]]:
        """Verify magic link token"""
        if token not in self.magic_links:
            return False, None
        
        link_data = self.magic_links[token]
        
        # Check expiration
        if datetime.now() > link_data['expires_at']:
            del self.magic_links[token]
            return False, None
        
        # Check if already used
        if link_data['used']:
            return False, None
        
        # Mark as used
        link_data['used'] = True
        
        return True, link_data['email']
    
    # WebAuthn/FIDO2 Simulation
    def register_webauthn_credential(self, user_id: str, credential_data: Dict) -> bool:
        """Register WebAuthn credential for user"""
        if user_id not in self.webauthn_credentials:
            self.webauthn_credentials[user_id] = []
        
        # In production, properly validate credential data
        credential = {
            'id': credential_data.get('id'),
            'public_key': credential_data.get('public_key'),
            'counter': 0,
            'created_at': datetime.now()
        }
        
        self.webauthn_credentials[user_id].append(credential)
        return True
    
    def verify_webauthn_assertion(self, user_id: str, assertion_data: Dict) -> bool:
        """Verify WebAuthn assertion"""
        if user_id not in self.webauthn_credentials:
            return False
        
        # In production, implement full WebAuthn verification
        # This is a simplified simulation
        credential_id = assertion_data.get('credential_id')
        
        for credential in self.webauthn_credentials[user_id]:
            if credential['id'] == credential_id:
                # Verify signature, counter, etc.
                return True
        
        return False

# Social Login Integration
class SocialAuth:
    """Social authentication provider integration"""
    
    def __init__(self):
        self.oauth_providers = {
            'google': {
                'client_id': 'google_client_id',
                'client_secret': 'google_client_secret',
                'auth_url': 'https://accounts.google.com/oauth2/auth',
                'token_url': 'https://oauth2.googleapis.com/token',
                'userinfo_url': 'https://www.googleapis.com/oauth2/v2/userinfo'
            },
            'github': {
                'client_id': 'github_client_id',
                'client_secret': 'github_client_secret',
                'auth_url': 'https://github.com/login/oauth/authorize',
                'token_url': 'https://github.com/login/oauth/access_token',
                'userinfo_url': 'https://api.github.com/user'
            }
        }
    
    def get_authorization_url(self, provider: str, redirect_uri: str, state: str) -> str:
        """Generate OAuth authorization URL"""
        if provider not in self.oauth_providers:
            raise ValueError(f"Unsupported provider: {provider}")
        
        config = self.oauth_providers[provider]
        
        params = {
            'client_id': config['client_id'],
            'redirect_uri': redirect_uri,
            'state': state,
            'scope': 'email profile',
            'response_type': 'code'
        }
        
        query_string = '&'.join(f"{k}={v}" for k, v in params.items())
        return f"{config['auth_url']}?{query_string}"
    
    def exchange_code_for_user_info(self, provider: str, code: str, redirect_uri: str) -> Optional[Dict]:
        """Exchange authorization code for user information"""
        # In production, implement full OAuth flow
        # This is a simulation
        
        if provider == 'google':
            return {
                'id': '123456789',
                'email': 'user@gmail.com',
                'name': 'John Doe',
                'verified_email': True
            }
        elif provider == 'github':
            return {
                'id': 987654321,
                'login': 'johndoe',
                'email': 'john@example.com',
                'name': 'John Doe'
            }
        
        return None

# Biometric Authentication Simulation
class BiometricAuth:
    """Biometric authentication methods"""
    
    def __init__(self):
        self.biometric_templates = {}
    
    def enroll_fingerprint(self, user_id: str, fingerprint_data: bytes) -> bool:
        """Enroll fingerprint template"""
        # In production, use proper biometric SDK
        template_hash = hashlib.sha256(fingerprint_data).hexdigest()
        
        if user_id not in self.biometric_templates:
            self.biometric_templates[user_id] = {}
        
        self.biometric_templates[user_id]['fingerprint'] = template_hash
        return True
    
    def verify_fingerprint(self, user_id: str, fingerprint_data: bytes) -> bool:
        """Verify fingerprint against enrolled template"""
        if user_id not in self.biometric_templates:
            return False
        
        template_hash = hashlib.sha256(fingerprint_data).hexdigest()
        stored_hash = self.biometric_templates[user_id].get('fingerprint')
        
        return template_hash == stored_hash

# Complete passwordless system
class PasswordlessSystem:
    """Complete passwordless authentication system"""
    
    def __init__(self):
        self.passwordless_auth = PasswordlessAuth()
        self.social_auth = SocialAuth()
        self.biometric_auth = BiometricAuth()
        self.users = {}
    
    def create_user(self, email: str, auth_method: str, auth_data: Dict) -> bool:
        """Create user with passwordless authentication"""
        if email in self.users:
            return False
        
        user = {
            'email': email,
            'created_at': datetime.now(),
            'auth_methods': [auth_method],
            'last_login': None
        }
        
        if auth_method == 'webauthn':
            success = self.passwordless_auth.register_webauthn_credential(email, auth_data)
            if not success:
                return False
        elif auth_method == 'biometric':
            success = self.biometric_auth.enroll_fingerprint(email, auth_data['fingerprint'])
            if not success:
                return False
        
        self.users[email] = user
        return True
    
    def authenticate_user(self, email: str, auth_method: str, auth_data: Dict) -> Tuple[bool, str]:
        """Authenticate user using passwordless method"""
        if email not in self.users:
            return False, "User not found"
        
        user = self.users[email]
        
        if auth_method not in user['auth_methods']:
            return False, "Authentication method not registered"
        
        if auth_method == 'magic_link':
            token = auth_data.get('token')
            success, verified_email = self.passwordless_auth.verify_magic_link(token)
            if success and verified_email == email:
                user['last_login'] = datetime.now()
                return True, "Authentication successful"
        
        elif auth_method == 'webauthn':
            success = self.passwordless_auth.verify_webauthn_assertion(email, auth_data)
            if success:
                user['last_login'] = datetime.now()
                return True, "Authentication successful"
        
        elif auth_method == 'biometric':
            success = self.biometric_auth.verify_fingerprint(email, auth_data['fingerprint'])
            if success:
                user['last_login'] = datetime.now()
                return True, "Authentication successful"
        
        return False, "Authentication failed"

# Usage examples
passwordless = PasswordlessSystem()

# Create user with WebAuthn
webauthn_data = {
    'id': 'credential_123',
    'public_key': 'public_key_data'
}
success = passwordless.create_user("user@example.com", "webauthn", webauthn_data)
print(f"User created with WebAuthn: {success}")

# Authenticate with WebAuthn
auth_data = {
    'credential_id': 'credential_123',
    'signature': 'signature_data'
}
auth_success, message = passwordless.authenticate_user("user@example.com", "webauthn", auth_data)
print(f"WebAuthn authentication: {auth_success}, {message}")

# Generate magic link
magic_link = passwordless.passwordless_auth.generate_magic_link("user@example.com")
print(f"Magic link: {magic_link}")
```

## Implementation Examples

### Complete Password Management System

```python
# Integration example combining all components
class ComprehensivePasswordSystem:
    def __init__(self):
        self.policy = ModernPasswordPolicy()
        self.storage = SecurePasswordStorage('argon2id')
        self.strength_meter = PasswordStrengthMeter()
        self.breach_checker = BreachChecker()
        self.reset_system = SecurePasswordReset()
        self.users = {}
    
    def register_user(self, username: str, email: str, password: str) -> Tuple[bool, List[str]]:
        """Complete user registration with all security checks"""
        errors = []
        
        # Check if user exists
        if username in self.users:
            errors.append("Username already exists")
            return False, errors
        
        # Validate password policy
        is_valid, policy_errors = self.policy.validate_password(password, username)
        if not is_valid:
            errors.extend(policy_errors)
        
        # Check password strength
        strength = self.strength_meter.assess_strength(password)
        if strength['score'] < 60:
            errors.append(f"Password strength too low: {strength['strength']}")
        
        # Check for breaches
        breach_result = self.breach_checker.check_password_safety(password)
        if not breach_result['is_safe']:
            errors.append("Password found in data breaches")
        
        if errors:
            return False, errors
        
        # Create user
        password_hash = self.storage.hash_password(password)
        self.users[username] = {
            'email': email,
            'password_hash': password_hash,
            'created_at': datetime.now(),
            'last_login': None,
            'failed_attempts': 0,
            'locked_until': None,
            'password_history': [password_hash],
            'last_password_change': datetime.now()
        }
        
        return True, ["User registered successfully"]
    
    def authenticate_user(self, username: str, password: str) -> Tuple[bool, str]:
        """Authenticate user with all security measures"""
        if username not in self.users:
            # Prevent timing attacks
            self.storage.hash_password(password)
            return False, "Invalid credentials"
        
        user = self.users[username]
        
        # Check if account is locked
        if user['locked_until'] and datetime.now() < user['locked_until']:
            return False, "Account temporarily locked"
        
        # Verify password
        if self.storage.verify_password(password, user['password_hash']):
            # Successful login
            user['last_login'] = datetime.now()
            user['failed_attempts'] = 0
            user['locked_until'] = None
            return True, "Authentication successful"
        else:
            # Failed login
            user['failed_attempts'] += 1
            if user['failed_attempts'] >= 5:
                user['locked_until'] = datetime.now() + timedelta(minutes=30)
                return False, "Account locked due to repeated failures"
            return False, "Invalid credentials"
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, List[str]]:
        """Complete password change with all security checks"""
        errors = []
        
        if username not in self.users:
            return False, ["User not found"]
        
        user = self.users[username]
        
        # Verify old password
        if not self.storage.verify_password(old_password, user['password_hash']):
            return False, ["Current password incorrect"]
        
        # All the same checks as registration
        is_valid, policy_errors = self.policy.validate_password(new_password, username)
        if not is_valid:
            errors.extend(policy_errors)
        
        strength = self.strength_meter.assess_strength(new_password)
        if strength['score'] < 60:
            errors.append(f"Password strength too low: {strength['strength']}")
        
        breach_result = self.breach_checker.check_password_safety(new_password)
        if not breach_result['is_safe']:
            errors.append("Password found in data breaches")
        
        # Check password history
        for old_hash in user['password_history']:
            if self.storage.verify_password(new_password, old_hash):
                errors.append("Cannot reuse recent password")
                break
        
        if errors:
            return False, errors
        
        # Update password
        new_hash = self.storage.hash_password(new_password)
        user['password_hash'] = new_hash
        user['password_history'].append(new_hash)
        user['password_history'] = user['password_history'][-12:]  # Keep last 12
        user['last_password_change'] = datetime.now()
        
        return True, ["Password changed successfully"]

# Usage
system = ComprehensivePasswordSystem()

# Register user
success, messages = system.register_user(
    "john_doe", 
    "john@example.com", 
    "MyVeryS3cur3P@ssw0rd!"
)
print(f"Registration: {success}, Messages: {messages}")

# Authenticate
auth_success, auth_message = system.authenticate_user("john_doe", "MyVeryS3cur3P@ssw0rd!")
print(f"Authentication: {auth_success}, {auth_message}")
```

## Conclusion

While passwords remain widely used, implementing them securely requires:

1. **Strong policies** based on modern guidelines (NIST 800-63B)
2. **Secure storage** using Argon2id or bcrypt
3. **Strength assessment** with real-time feedback
4. **Breach detection** to prevent compromised passwords
5. **Secure reset mechanisms** with proper rate limiting
6. **Migration to passwordless** when possible

The future of authentication is moving toward passwordless methods:
- **WebAuthn/FIDO2** for strong, phishing-resistant authentication
- **Magic links** for simple, secure access
- **Biometric authentication** for convenient security
- **Social login** for reduced password burden

The next chapter will cover [Public Key Cryptography](public-key-cryptography.md) - the foundation of modern secure communications.