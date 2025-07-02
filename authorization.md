[Back to Contents](README.md)

# Authorization: What am I allowed to do?

> [!NOTE] 
> **Remember**: Authentication = "Who are you?" • Authorization = "What can you do?"

Authorization determines what actions an authenticated user is permitted to perform. While authentication verifies "who you are," authorization controls "what you can do." This chapter covers various authorization models, token-based systems, and best practices for implementing secure access control.

## Table of Contents
- [Authorization vs Authentication](#authorization-vs-authentication)
- [Access Control Models](#access-control-models)
- [Token-based Authorization](#token-based-authorization)
- [OAuth 2.0 and OpenID Connect](#oauth-20-and-openid-connect)
- [JSON Web Tokens (JWT)](#json-web-tokens-jwt)
- [Best Practices](#best-practices)
- [Common Vulnerabilities](#common-vulnerabilities)

## Authorization vs Authentication

| Authentication | Authorization |
|---------------|---------------|
| Verifies identity | Verifies permissions |
| "Who are you?" | "What can you do?" |
| Login credentials | Access policies |
| Happens first | Happens after authentication |

> [!IMPORTANT]
> Both are required for security. Authentication without authorization is like having a door lock but no rules about who can enter which rooms.

## Access Control Models

### Role-Based Access Control (RBAC)

RBAC assigns permissions to roles, and users inherit permissions through their roles.

```python
class Role:
    def __init__(self, name, permissions):
        self.name = name
        self.permissions = set(permissions)

class User:
    def __init__(self, username, roles):
        self.username = username
        self.roles = roles
    
    def has_permission(self, permission):
        for role in self.roles:
            if permission in role.permissions:
                return True
        return False

# Example usage
admin_role = Role('admin', ['read', 'write', 'delete', 'manage_users'])
user_role = Role('user', ['read', 'write'])

admin_user = User('admin', [admin_role])
regular_user = User('john', [user_role])

# Check permissions
admin_user.has_permission('delete')  # True
regular_user.has_permission('delete')  # False
```

### Attribute-Based Access Control (ABAC)

ABAC uses attributes of users, resources, and environment to make access decisions.

```python
class ABACPolicy:
    def __init__(self, name, condition, effect):
        self.name = name
        self.condition = condition  # Function that evaluates attributes
        self.effect = effect  # 'ALLOW' or 'DENY'

def evaluate_policy(user, resource, action, environment, policies):
    context = {
        'user': user,
        'resource': resource,
        'action': action,
        'environment': environment
    }
    
    for policy in policies:
        if policy.condition(context):
            return policy.effect == 'ALLOW'
    
    return False  # Default deny

# Example policy: Users can only access their own resources
def own_resource_policy(context):
    return context['resource'].owner_id == context['user'].id

policy = ABACPolicy(
    'own_resource',
    own_resource_policy,
    'ALLOW'
)
```

### Access Control Lists (ACL)

ACLs specify which users or groups have access to specific resources.

```python
class ACL:
    def __init__(self):
        self.permissions = {}  # {(user/group, resource): [permissions]}
    
    def grant(self, principal, resource, permissions):
        key = (principal, resource)
        if key not in self.permissions:
            self.permissions[key] = set()
        self.permissions[key].update(permissions)
    
    def revoke(self, principal, resource, permissions):
        key = (principal, resource)
        if key in self.permissions:
            self.permissions[key] -= set(permissions)
    
    def check_permission(self, principal, resource, permission):
        key = (principal, resource)
        return key in self.permissions and permission in self.permissions[key]

# Example usage
acl = ACL()
acl.grant('user:john', 'document:123', ['read', 'write'])
acl.grant('group:editors', 'document:123', ['read', 'write', 'delete'])

# Check access
acl.check_permission('user:john', 'document:123', 'read')  # True
acl.check_permission('user:john', 'document:123', 'delete')  # False
```

## Token-based Authorization

Token-based authorization uses tokens to represent and verify user permissions.

### API Keys

Simple tokens for API access:

```python
import secrets
import hashlib
from datetime import datetime, timedelta

class APIKey:
    def __init__(self, user_id, name, permissions=None, expires_at=None):
        self.key = secrets.token_urlsafe(32)
        self.key_hash = hashlib.sha256(self.key.encode()).hexdigest()
        self.user_id = user_id
        self.name = name
        self.permissions = permissions or []
        self.created_at = datetime.utcnow()
        self.expires_at = expires_at
        self.active = True
    
    def is_valid(self):
        if not self.active:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True
    
    def has_permission(self, permission):
        return permission in self.permissions

# Usage
api_key = APIKey(
    user_id=123,
    name="Analytics API Key",
    permissions=['read:analytics', 'write:analytics'],
    expires_at=datetime.utcnow() + timedelta(days=365)
)
```

### Bearer Tokens

Tokens sent in the Authorization header:

```python
from flask import request, jsonify, g
from functools import wraps

def require_auth(required_permission=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid authorization header'}), 401
            
            token = auth_header.split(' ')[1]
            
            # Validate token
            user = validate_token(token)
            if not user:
                return jsonify({'error': 'Invalid token'}), 401
            
            # Check permissions
            if required_permission and not user.has_permission(required_permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            g.current_user = user
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Usage
@app.route('/api/users')
@require_auth('read:users')
def get_users():
    return jsonify({'users': []})
```

## OAuth 2.0 and OpenID Connect

### OAuth 2.0 Flow

OAuth 2.0 provides authorization without sharing credentials.

```python
import requests
from urllib.parse import urlencode

class OAuthClient:
    def __init__(self, client_id, client_secret, auth_url, token_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_url = auth_url
        self.token_url = token_url
    
    def get_authorization_url(self, redirect_uri, scope, state):
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state  # CSRF protection
        }
        return f"{self.auth_url}?{urlencode(params)}"
    
    def exchange_code_for_tokens(self, code, redirect_uri):
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        response = requests.post(self.token_url, data=data)
        response.raise_for_status()
        
        return response.json()

# Usage
oauth_client = OAuthClient(
    client_id='your_client_id',
    client_secret='your_client_secret',
    auth_url='https://provider.com/oauth/authorize',
    token_url='https://provider.com/oauth/token'
)

# Generate authorization URL
auth_url = oauth_client.get_authorization_url(
    redirect_uri='https://yourapp.com/callback',
    scope='read:profile write:profile',
    state='random_state_string'
)
```

### OAuth 2.0 Security Best Practices

1. **Always use HTTPS**
2. **Validate state parameter** (CSRF protection)
3. **Use PKCE for public clients**
4. **Validate redirect URIs**
5. **Implement proper token storage**
6. **Use appropriate grant types**

```python
import secrets
import hashlib
import base64

class PKCEClient:
    def __init__(self, client_id, auth_url, token_url):
        self.client_id = client_id
        self.auth_url = auth_url
        self.token_url = token_url
    
    def generate_pkce_pair(self):
        # Generate code verifier
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate code challenge
        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).decode('utf-8').rstrip('=')
        
        return code_verifier, code_challenge
    
    def get_authorization_url(self, redirect_uri, scope, state, code_challenge):
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }
        return f"{self.auth_url}?{urlencode(params)}"
```

## JSON Web Tokens (JWT)

JWTs are self-contained tokens that carry user information and permissions.

### JWT Structure

A JWT consists of three parts separated by dots:
- **Header**: Token type and signing algorithm
- **Payload**: Claims (user data and permissions)
- **Signature**: Verification signature

```python
import jwt
import datetime
from datetime import timedelta

class JWTManager:
    def __init__(self, secret_key, algorithm='HS256'):
        self.secret_key = secret_key
        self.algorithm = algorithm
    
    def generate_token(self, user_id, permissions, expires_in=timedelta(hours=1)):
        payload = {
            'user_id': user_id,
            'permissions': permissions,
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + expires_in,
            'iss': 'your-app-name'  # Issuer
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def validate_token(self, token):
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={'verify_exp': True}
            )
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def refresh_token(self, token):
        payload = self.validate_token(token)
        if payload:
            # Remove old timestamps
            payload.pop('iat', None)
            payload.pop('exp', None)
            
            # Generate new token
            return self.generate_token(
                payload['user_id'],
                payload['permissions']
            )
        return None

# Usage
jwt_manager = JWTManager('your-secret-key')

# Generate token
token = jwt_manager.generate_token(
    user_id=123,
    permissions=['read:profile', 'write:profile']
)

# Validate token
payload = jwt_manager.validate_token(token)
if payload:
    print(f"User ID: {payload['user_id']}")
    print(f"Permissions: {payload['permissions']}")
```

### JWT Security Considerations

**Pros:**
- Self-contained
- Stateless
- Cross-domain support
- Standardized format

**Cons:**
- Cannot be revoked easily
- Larger than session tokens
- Vulnerable if secret is compromised
- Payload is visible (base64 encoded)

**Best Practices:**
1. **Use strong secrets** (at least 256 bits)
2. **Set appropriate expiration times**
3. **Don't store sensitive data in payload**
4. **Use HTTPS only**
5. **Implement token refresh mechanism**
6. **Consider token blacklisting for logout**

## Best Practices

### 1. Principle of Least Privilege

Grant minimum permissions necessary:

```python
class Permission:
    def __init__(self, resource, action, conditions=None):
        self.resource = resource
        self.action = action
        self.conditions = conditions or []
    
    def check(self, context):
        # Check if all conditions are met
        for condition in self.conditions:
            if not condition(context):
                return False
        return True

# Example: User can only edit their own posts
def own_post_condition(context):
    return context['resource'].author_id == context['user'].id

edit_own_post = Permission(
    resource='post',
    action='edit',
    conditions=[own_post_condition]
)
```

### 2. Defense in Depth

Implement multiple layers of authorization:

```python
def check_authorization(user, resource, action):
    # Layer 1: Authentication check
    if not user.is_authenticated():
        return False
    
    # Layer 2: Rate limiting
    if not rate_limiter.check(user.id, action):
        return False
    
    # Layer 3: Role-based check
    if not user.has_role_permission(action):
        return False
    
    # Layer 4: Resource-specific check
    if not resource.allows_user_action(user, action):
        return False
    
    # Layer 5: Time-based restrictions
    if not is_within_allowed_hours(user, action):
        return False
    
    return True
```

### 3. Secure Token Storage

Store tokens securely:

```python
# Client-side storage options
token_storage_options = {
    'memory': {
        'security': 'High',
        'persistence': 'None',
        'xss_risk': 'Low'
    },
    'httponly_cookie': {
        'security': 'High',
        'persistence': 'Medium',
        'xss_risk': 'Low'
    },
    'localstorage': {
        'security': 'Low',
        'persistence': 'High',
        'xss_risk': 'High'
    }
}

# Recommended: HttpOnly cookies for web apps
@app.route('/login', methods=['POST'])
def login():
    # ... authenticate user ...
    
    token = generate_jwt_token(user)
    
    response = make_response(jsonify({'status': 'success'}))
    response.set_cookie(
        'auth_token',
        token,
        httponly=True,
        secure=True,
        samesite='Strict',
        max_age=3600
    )
    
    return response
```

### 4. Implement Proper Logout

Invalidate tokens on logout:

```python
class TokenBlacklist:
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def blacklist_token(self, token):
        # Extract expiration from token
        payload = jwt.decode(token, verify=False)
        exp = payload.get('exp')
        
        if exp:
            # Store token hash in blacklist until expiration
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            ttl = exp - datetime.utcnow().timestamp()
            self.redis.setex(f"blacklist:{token_hash}", int(ttl), "1")
    
    def is_blacklisted(self, token):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return self.redis.exists(f"blacklist:{token_hash}")

# Usage in logout endpoint
@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('auth_token')
    if token:
        token_blacklist.blacklist_token(token)
    
    response = make_response(jsonify({'status': 'logged out'}))
    response.set_cookie('auth_token', '', expires=0)
    return response
```

## Common Vulnerabilities

### 1. Insecure Direct Object References (IDOR)

```python
# Vulnerable code
@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify(user.to_dict())

# Secure code
@app.route('/api/users/<int:user_id>')
@require_auth()
def get_user(user_id):
    # Check if current user can access this user
    if not can_access_user(g.current_user, user_id):
        abort(403)
    
    user = User.query.get(user_id)
    return jsonify(user.to_dict())

def can_access_user(current_user, target_user_id):
    # Users can access their own data
    if current_user.id == target_user_id:
        return True
    
    # Admins can access any user
    if current_user.has_role('admin'):
        return True
    
    return False
```

### 2. Privilege Escalation

```python
# Vulnerable: Not checking current permissions
@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
def update_user_role(user_id):
    new_role = request.json.get('role')
    user = User.query.get(user_id)
    user.role = new_role
    db.session.commit()
    return jsonify({'status': 'success'})

# Secure: Proper permission checks
@app.route('/api/users/<int:user_id>/role', methods=['PUT'])
@require_auth('manage:users')
def update_user_role(user_id):
    new_role = request.json.get('role')
    
    # Validate new role
    if new_role not in VALID_ROLES:
        abort(400, 'Invalid role')
    
    # Check if current user can assign this role
    if not g.current_user.can_assign_role(new_role):
        abort(403, 'Cannot assign this role')
    
    # Prevent users from modifying their own roles
    if g.current_user.id == user_id:
        abort(403, 'Cannot modify own role')
    
    user = User.query.get(user_id)
    user.role = new_role
    db.session.commit()
    
    return jsonify({'status': 'success'})
```

### 3. Token Leakage

```python
# Secure token handling
class SecureTokenHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def log_request(self, request):
        # Never log authorization headers
        headers = dict(request.headers)
        headers.pop('Authorization', None)
        headers.pop('Cookie', None)
        
        self.logger.info(f"Request: {request.method} {request.path}", extra={
            'headers': headers,
            'user_id': getattr(g, 'current_user', {}).get('id')
        })
    
    def handle_error(self, error):
        # Don't include tokens in error responses
        if 'token' in str(error).lower():
            return {'error': 'Authentication error'}, 401
        return {'error': str(error)}, 500
```

## Testing Authorization

```python
import pytest
from unittest.mock import patch

class TestAuthorization:
    def test_user_can_access_own_resource(self):
        user = User(id=1, role='user')
        resource = Resource(id=1, owner_id=1)
        
        assert can_access_resource(user, resource, 'read')
    
    def test_user_cannot_access_others_resource(self):
        user = User(id=1, role='user')
        resource = Resource(id=1, owner_id=2)
        
        assert not can_access_resource(user, resource, 'read')
    
    def test_admin_can_access_any_resource(self):
        admin = User(id=1, role='admin')
        resource = Resource(id=1, owner_id=2)
        
        assert can_access_resource(admin, resource, 'read')
    
    def test_jwt_token_validation(self):
        jwt_manager = JWTManager('test-secret')
        token = jwt_manager.generate_token(123, ['read:profile'])
        
        payload = jwt_manager.validate_token(token)
        assert payload['user_id'] == 123
        assert 'read:profile' in payload['permissions']
    
    def test_expired_token_rejected(self):
        jwt_manager = JWTManager('test-secret')
        
        with patch('datetime.datetime') as mock_datetime:
            # Create token that expires immediately
            mock_datetime.utcnow.return_value = datetime.datetime(2023, 1, 1)
            token = jwt_manager.generate_token(123, [], expires_in=timedelta(seconds=1))
            
            # Try to validate after expiration
            mock_datetime.utcnow.return_value = datetime.datetime(2023, 1, 1, 0, 0, 2)
            payload = jwt_manager.validate_token(token)
            
            assert payload is None
```

## Conclusion

Authorization is critical for protecting resources and ensuring users can only access what they're permitted to. Implement proper access controls, use secure token management, and regularly audit your authorization logic. Remember that authorization should be:

- **Consistent**: Applied uniformly across your application
- **Granular**: Providing fine-grained control when needed
- **Auditable**: All access decisions should be logged
- **Flexible**: Able to adapt to changing requirements

The next chapter will cover [Data Validation and Sanitization](data-validation.md) - protecting against malicious input and injection attacks.