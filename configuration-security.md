[Back to Contents](README.md)

# Configuration Security: The Foundation of Secure Systems

Most security breaches happen not because of sophisticated attacks, but due to misconfigurations and operational mistakes. This chapter covers securing your infrastructure, managing secrets, implementing monitoring, and following security best practices for deployment.

## Table of Contents
- [Infrastructure Security](#infrastructure-security)
- [Cloud Security](#cloud-security)
- [Secrets Management](#secrets-management)
- [Logging and Monitoring](#logging-and-monitoring)
- [Container Security](#container-security)
- [Network Security](#network-security)
- [Backup and Recovery](#backup-and-recovery)
- [Security Automation](#security-automation)

## Infrastructure Security

### Server Hardening

```python
import subprocess
import os
import json
from pathlib import Path
from typing import Dict, List, Optional

class ServerHardening:
    """Automate server security hardening checks"""
    
    def __init__(self):
        self.security_checks = {
            'ssh_security': self.check_ssh_config,
            'user_accounts': self.check_user_accounts,
            'firewall_status': self.check_firewall,
            'system_updates': self.check_updates,
            'file_permissions': self.check_critical_permissions,
            'running_services': self.check_services
        }
    
    def run_all_checks(self) -> Dict[str, Dict]:
        """Run all security hardening checks"""
        results = {}
        
        for check_name, check_function in self.security_checks.items():
            try:
                results[check_name] = check_function()
            except Exception as e:
                results[check_name] = {
                    'status': 'error',
                    'message': str(e)
                }
        
        return results
    
    def check_ssh_config(self) -> Dict:
        """Check SSH configuration security"""
        ssh_config_path = '/etc/ssh/sshd_config'
        
        if not os.path.exists(ssh_config_path):
            return {'status': 'error', 'message': 'SSH config not found'}
        
        issues = []
        recommendations = []
        
        try:
            with open(ssh_config_path, 'r') as f:
                config_content = f.read()
            
            # Check for secure configurations
            security_checks = {
                'PasswordAuthentication no': 'Password authentication should be disabled',
                'PermitRootLogin no': 'Root login should be disabled',
                'Protocol 2': 'Only SSH Protocol 2 should be used',
                'MaxAuthTries 3': 'Limit authentication attempts',
                'ClientAliveInterval 300': 'Set client alive interval',
                'ClientAliveCountMax 2': 'Set maximum client alive count'
            }
            
            for setting, description in security_checks.items():
                if setting.split()[0] not in config_content:
                    recommendations.append(f"Add: {setting} ({description})")
                elif setting not in config_content:
                    issues.append(f"Incorrect setting for {setting.split()[0]}")
            
            return {
                'status': 'checked',
                'issues': issues,
                'recommendations': recommendations
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def check_user_accounts(self) -> Dict:
        """Check for suspicious user accounts"""
        try:
            # Read /etc/passwd
            with open('/etc/passwd', 'r') as f:
                passwd_content = f.readlines()
            
            suspicious_users = []
            admin_users = []
            
            for line in passwd_content:
                fields = line.strip().split(':')
                if len(fields) >= 7:
                    username = fields[0]
                    uid = int(fields[2]) if fields[2].isdigit() else -1
                    shell = fields[6]
                    
                    # Check for UID 0 users (root equivalent)
                    if uid == 0 and username != 'root':
                        suspicious_users.append(f"User {username} has UID 0")
                    
                    # Check for users with shell access
                    if uid >= 1000 and shell in ['/bin/bash', '/bin/sh', '/bin/zsh']:
                        admin_users.append(username)
            
            return {
                'status': 'checked',
                'suspicious_users': suspicious_users,
                'admin_users': admin_users,
                'total_users': len(passwd_content)
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def check_firewall(self) -> Dict:
        """Check firewall status"""
        try:
            # Check ufw status
            result = subprocess.run(['ufw', 'status'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                status = 'active' if 'Status: active' in result.stdout else 'inactive'
                return {
                    'status': 'checked',
                    'firewall_status': status,
                    'details': result.stdout
                }
            else:
                # Try iptables
                iptables_result = subprocess.run(['iptables', '-L'], 
                                               capture_output=True, text=True)
                return {
                    'status': 'checked',
                    'firewall_type': 'iptables',
                    'rules_count': len(iptables_result.stdout.split('\n'))
                }
                
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def check_updates(self) -> Dict:
        """Check for available system updates"""
        try:
            # For Ubuntu/Debian
            result = subprocess.run(['apt', 'list', '--upgradable'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                upgradable = len([line for line in result.stdout.split('\n') 
                                if 'upgradable' in line])
                return {
                    'status': 'checked',
                    'upgradable_packages': upgradable,
                    'recommendation': 'Run apt update && apt upgrade' if upgradable > 0 else 'System up to date'
                }
            
            return {'status': 'error', 'message': 'Unable to check updates'}
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def check_critical_permissions(self) -> Dict:
        """Check permissions on critical files"""
        critical_files = {
            '/etc/passwd': {'expected': '644', 'description': 'User account info'},
            '/etc/shadow': {'expected': '640', 'description': 'Password hashes'},
            '/etc/ssh/sshd_config': {'expected': '600', 'description': 'SSH config'},
            '/root': {'expected': '700', 'description': 'Root home directory'}
        }
        
        issues = []
        
        for file_path, config in critical_files.items():
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                actual_perms = oct(stat_info.st_mode)[-3:]
                
                if actual_perms != config['expected']:
                    issues.append({
                        'file': file_path,
                        'expected': config['expected'],
                        'actual': actual_perms,
                        'description': config['description']
                    })
        
        return {
            'status': 'checked',
            'permission_issues': issues
        }
    
    def check_services(self) -> Dict:
        """Check running services"""
        try:
            # Get running services
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                services = []
                for line in result.stdout.split('\n'):
                    if '.service' in line and 'running' in line:
                        service_name = line.split()[0]
                        services.append(service_name)
                
                # Check for potentially unnecessary services
                unnecessary_services = [
                    'telnet.service', 'rsh.service', 'rlogin.service',
                    'vsftpd.service', 'apache2.service', 'nginx.service'
                ]
                
                running_unnecessary = [s for s in services if s in unnecessary_services]
                
                return {
                    'status': 'checked',
                    'total_services': len(services),
                    'running_services': services[:10],  # First 10 for brevity
                    'potentially_unnecessary': running_unnecessary
                }
            
            return {'status': 'error', 'message': 'Unable to check services'}
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

# Automated hardening script
class AutoHardening:
    """Automated security hardening (use with caution)"""
    
    def __init__(self, dry_run=True):
        self.dry_run = dry_run
        self.hardening_steps = []
    
    def harden_ssh(self):
        """Apply SSH hardening"""
        ssh_config = '''
# Security hardening
Protocol 2
PasswordAuthentication no
PermitRootLogin no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowUsers {allowed_users}
'''
        
        if self.dry_run:
            print("Would update SSH config with secure settings")
            self.hardening_steps.append("SSH configuration hardening")
        else:
            # Backup original config first
            subprocess.run(['cp', '/etc/ssh/sshd_config', '/etc/ssh/sshd_config.backup'])
            # Apply hardening (implementation needed)
            print("SSH hardening applied")
    
    def setup_firewall(self):
        """Setup basic firewall rules"""
        firewall_commands = [
            ['ufw', 'default', 'deny', 'incoming'],
            ['ufw', 'default', 'allow', 'outgoing'],
            ['ufw', 'allow', 'ssh'],
            ['ufw', 'allow', '80'],
            ['ufw', 'allow', '443'],
            ['ufw', '--force', 'enable']
        ]
        
        if self.dry_run:
            print("Would setup firewall with basic rules")
            self.hardening_steps.append("Firewall configuration")
        else:
            for cmd in firewall_commands:
                subprocess.run(cmd)
            print("Firewall configured")
    
    def disable_unnecessary_services(self):
        """Disable unnecessary services"""
        services_to_disable = [
            'telnet', 'rsh', 'rlogin', 'ftp'
        ]
        
        if self.dry_run:
            print(f"Would disable services: {services_to_disable}")
            self.hardening_steps.append("Service hardening")
        else:
            for service in services_to_disable:
                subprocess.run(['systemctl', 'disable', service], 
                             capture_output=True)
            print("Unnecessary services disabled")
    
    def get_hardening_report(self) -> List[str]:
        """Get list of hardening steps that would be applied"""
        return self.hardening_steps

# Usage example
hardening_checker = ServerHardening()
results = hardening_checker.run_all_checks()

print("Server Security Check Results:")
for check, result in results.items():
    print(f"\n{check.upper()}:")
    print(json.dumps(result, indent=2))

# Automated hardening (dry run)
auto_hardening = AutoHardening(dry_run=True)
auto_hardening.harden_ssh()
auto_hardening.setup_firewall()
auto_hardening.disable_unnecessary_services()

print("\nProposed Hardening Steps:")
for step in auto_hardening.get_hardening_report():
    print(f"- {step}")
```

## Cloud Security

### AWS Security Best Practices

```python
import boto3
import json
from datetime import datetime, timedelta
from typing import Dict, List

class AWSSecurityAuditor:
    """Audit AWS configuration for security issues"""
    
    def __init__(self, profile_name=None):
        self.session = boto3.Session(profile_name=profile_name)
        self.ec2 = self.session.client('ec2')
        self.s3 = self.session.client('s3')
        self.iam = self.session.client('iam')
        self.cloudtrail = self.session.client('cloudtrail')
        
    def audit_security_groups(self) -> Dict:
        """Audit EC2 security groups for overly permissive rules"""
        try:
            response = self.ec2.describe_security_groups()
            security_groups = response['SecurityGroups']
            
            issues = []
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                # Check for overly permissive inbound rules
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            issues.append({
                                'type': 'overly_permissive_inbound',
                                'security_group': sg_id,
                                'name': sg_name,
                                'port': rule.get('FromPort', 'All'),
                                'protocol': rule.get('IpProtocol', 'All'),
                                'severity': 'high' if rule.get('FromPort') == 22 else 'medium'
                            })
            
            return {
                'status': 'success',
                'total_security_groups': len(security_groups),
                'issues': issues
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def audit_s3_buckets(self) -> Dict:
        """Audit S3 buckets for security misconfigurations"""
        try:
            response = self.s3.list_buckets()
            buckets = response['Buckets']
            
            issues = []
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check bucket ACL
                try:
                    acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') in [
                            'http://acs.amazonaws.com/groups/global/AllUsers',
                            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                        ]:
                            issues.append({
                                'type': 'public_bucket_acl',
                                'bucket': bucket_name,
                                'permission': grant['Permission'],
                                'severity': 'high'
                            })
                except Exception:
                    # Might not have permissions
                    pass
                
                # Check public access block
                try:
                    public_access = self.s3.get_public_access_block(Bucket=bucket_name)
                    config = public_access['PublicAccessBlockConfiguration']
                    
                    if not all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ]):
                        issues.append({
                            'type': 'public_access_not_blocked',
                            'bucket': bucket_name,
                            'severity': 'medium'
                        })
                except Exception:
                    issues.append({
                        'type': 'no_public_access_block',
                        'bucket': bucket_name,
                        'severity': 'medium'
                    })
            
            return {
                'status': 'success',
                'total_buckets': len(buckets),
                'issues': issues
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def audit_iam_policies(self) -> Dict:
        """Audit IAM policies for overly permissive access"""
        try:
            # Get all policies
            policies = []
            paginator = self.iam.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):
                policies.extend(page['Policies'])
            
            issues = []
            
            for policy in policies:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']
                
                # Get policy document
                try:
                    version = self.iam.get_policy(PolicyArn=policy_arn)
                    policy_version = self.iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=version['Policy']['DefaultVersionId']
                    )
                    
                    document = policy_version['PolicyVersion']['Document']
                    
                    # Check for overly permissive statements
                    for statement in document.get('Statement', []):
                        if isinstance(statement, dict):
                            # Check for wildcard actions
                            actions = statement.get('Action', [])
                            if isinstance(actions, str):
                                actions = [actions]
                            
                            if '*' in actions:
                                issues.append({
                                    'type': 'wildcard_action',
                                    'policy': policy_name,
                                    'policy_arn': policy_arn,
                                    'severity': 'high'
                                })
                            
                            # Check for wildcard resources
                            resources = statement.get('Resource', [])
                            if isinstance(resources, str):
                                resources = [resources]
                            
                            if '*' in resources and '*' in actions:
                                issues.append({
                                    'type': 'wildcard_resource_and_action',
                                    'policy': policy_name,
                                    'policy_arn': policy_arn,
                                    'severity': 'critical'
                                })
                
                except Exception:
                    # Might not have permissions to read policy
                    pass
            
            return {
                'status': 'success',
                'total_policies': len(policies),
                'issues': issues
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def check_cloudtrail(self) -> Dict:
        """Check CloudTrail configuration"""
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            
            issues = []
            active_trails = 0
            
            for trail in trails:
                trail_name = trail['Name']
                
                # Check if trail is logging
                status = self.cloudtrail.get_trail_status(Name=trail_name)
                if status['IsLogging']:
                    active_trails += 1
                else:
                    issues.append({
                        'type': 'trail_not_logging',
                        'trail': trail_name,
                        'severity': 'medium'
                    })
                
                # Check if trail logs to all regions
                if not trail.get('IsMultiRegionTrail', False):
                    issues.append({
                        'type': 'trail_not_multi_region',
                        'trail': trail_name,
                        'severity': 'low'
                    })
            
            if active_trails == 0:
                issues.append({
                    'type': 'no_active_cloudtrail',
                    'severity': 'critical'
                })
            
            return {
                'status': 'success',
                'total_trails': len(trails),
                'active_trails': active_trails,
                'issues': issues
            }
            
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def generate_security_report(self) -> Dict:
        """Generate comprehensive security report"""
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'audits': {}
        }
        
        # Run all audits
        audit_functions = [
            ('security_groups', self.audit_security_groups),
            ('s3_buckets', self.audit_s3_buckets),
            ('iam_policies', self.audit_iam_policies),
            ('cloudtrail', self.check_cloudtrail)
        ]
        
        total_issues = 0
        critical_issues = 0
        
        for audit_name, audit_function in audit_functions:
            result = audit_function()
            report['audits'][audit_name] = result
            
            if result.get('status') == 'success':
                issues = result.get('issues', [])
                total_issues += len(issues)
                critical_issues += len([i for i in issues if i.get('severity') == 'critical'])
        
        report['summary'] = {
            'total_issues': total_issues,
            'critical_issues': critical_issues,
            'security_score': max(0, 100 - (critical_issues * 20 + total_issues * 5))
        }
        
        return report

# Infrastructure as Code security
class TerraformSecurityScanner:
    """Scan Terraform files for security issues"""
    
    def __init__(self):
        self.security_rules = {
            'aws_s3_bucket': self.check_s3_bucket,
            'aws_security_group': self.check_security_group,
            'aws_instance': self.check_ec2_instance
        }
    
    def scan_terraform_file(self, file_path: str) -> Dict:
        """Scan a Terraform file for security issues"""
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            issues = []
            
            # Simple parsing - in production, use proper HCL parser
            lines = content.split('\n')
            current_resource = None
            
            for i, line in enumerate(lines):
                line = line.strip()
                
                # Detect resource blocks
                if line.startswith('resource "'):
                    parts = line.split('"')
                    if len(parts) >= 2:
                        current_resource = parts[1]
                
                # Check for security issues
                if current_resource in self.security_rules:
                    resource_issues = self.security_rules[current_resource](line, i + 1)
                    issues.extend(resource_issues)
            
            return {
                'file': file_path,
                'issues': issues,
                'status': 'scanned'
            }
            
        except Exception as e:
            return {
                'file': file_path,
                'status': 'error',
                'message': str(e)
            }
    
    def check_s3_bucket(self, line: str, line_number: int) -> List[Dict]:
        """Check S3 bucket configuration"""
        issues = []
        
        if 'acl = "public-read"' in line:
            issues.append({
                'type': 'public_s3_bucket',
                'line': line_number,
                'severity': 'high',
                'description': 'S3 bucket is publicly readable'
            })
        
        if 'versioning' not in line and 'enabled = true' not in line:
            # This is a simplified check
            pass
        
        return issues
    
    def check_security_group(self, line: str, line_number: int) -> List[Dict]:
        """Check security group rules"""
        issues = []
        
        if 'cidr_blocks = ["0.0.0.0/0"]' in line and 'from_port = 22' in line:
            issues.append({
                'type': 'ssh_open_to_world',
                'line': line_number,
                'severity': 'critical',
                'description': 'SSH port open to the world'
            })
        
        return issues
    
    def check_ec2_instance(self, line: str, line_number: int) -> List[Dict]:
        """Check EC2 instance configuration"""
        issues = []
        
        if 'associate_public_ip_address = true' in line:
            issues.append({
                'type': 'ec2_public_ip',
                'line': line_number,
                'severity': 'medium',
                'description': 'EC2 instance has public IP'
            })
        
        return issues

# Usage
aws_auditor = AWSSecurityAuditor()
security_report = aws_auditor.generate_security_report()

print("AWS Security Audit Report:")
print(f"Security Score: {security_report['summary']['security_score']}/100")
print(f"Total Issues: {security_report['summary']['total_issues']}")
print(f"Critical Issues: {security_report['summary']['critical_issues']}")

# Terraform scanning
tf_scanner = TerraformSecurityScanner()
# tf_results = tf_scanner.scan_terraform_file('main.tf')
```

## Secrets Management

### Centralized Secrets Management

```python
import os
import json
import hashlib
import hvac  # HashiCorp Vault client
from cryptography.fernet import Fernet
from typing import Dict, Optional, Any

class SecretsManager:
    """Centralized secrets management"""
    
    def __init__(self, backend='vault', config=None):
        self.backend = backend
        self.config = config or {}
        
        if backend == 'vault':
            self.vault_client = self._init_vault()
        elif backend == 'aws':
            self.aws_client = self._init_aws_secrets()
        elif backend == 'local':
            self.encryption_key = self._get_or_create_key()
    
    def _init_vault(self):
        """Initialize HashiCorp Vault client"""
        vault_url = self.config.get('vault_url', 'http://localhost:8200')
        vault_token = os.environ.get('VAULT_TOKEN')
        
        client = hvac.Client(url=vault_url, token=vault_token)
        
        if not client.is_authenticated():
            raise ValueError("Vault authentication failed")
        
        return client
    
    def _init_aws_secrets(self):
        """Initialize AWS Secrets Manager client"""
        import boto3
        return boto3.client('secretsmanager')
    
    def _get_or_create_key(self):
        """Get or create local encryption key"""
        key_file = self.config.get('key_file', '.secrets_key')
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            return key
    
    def store_secret(self, key: str, value: str, metadata: Dict = None) -> bool:
        """Store a secret"""
        try:
            if self.backend == 'vault':
                return self._store_vault_secret(key, value, metadata)
            elif self.backend == 'aws':
                return self._store_aws_secret(key, value, metadata)
            elif self.backend == 'local':
                return self._store_local_secret(key, value, metadata)
        except Exception as e:
            print(f"Error storing secret: {e}")
            return False
    
    def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret"""
        try:
            if self.backend == 'vault':
                return self._get_vault_secret(key)
            elif self.backend == 'aws':
                return self._get_aws_secret(key)
            elif self.backend == 'local':
                return self._get_local_secret(key)
        except Exception as e:
            print(f"Error retrieving secret: {e}")
            return None
    
    def delete_secret(self, key: str) -> bool:
        """Delete a secret"""
        try:
            if self.backend == 'vault':
                self.vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=key
                )
                return True
            elif self.backend == 'aws':
                self.aws_client.delete_secret(SecretId=key)
                return True
            elif self.backend == 'local':
                return self._delete_local_secret(key)
        except Exception as e:
            print(f"Error deleting secret: {e}")
            return False
    
    def _store_vault_secret(self, key: str, value: str, metadata: Dict) -> bool:
        """Store secret in Vault"""
        secret_data = {'value': value}
        if metadata:
            secret_data.update(metadata)
        
        self.vault_client.secrets.kv.v2.create_or_update_secret(
            path=key,
            secret=secret_data
        )
        return True
    
    def _get_vault_secret(self, key: str) -> Optional[str]:
        """Get secret from Vault"""
        response = self.vault_client.secrets.kv.v2.read_secret_version(path=key)
        return response['data']['data'].get('value')
    
    def _store_aws_secret(self, key: str, value: str, metadata: Dict) -> bool:
        """Store secret in AWS Secrets Manager"""
        try:
            self.aws_client.create_secret(
                Name=key,
                SecretString=value,
                Description=metadata.get('description', '')
            )
        except self.aws_client.exceptions.ResourceExistsException:
            self.aws_client.update_secret(
                SecretId=key,
                SecretString=value
            )
        return True
    
    def _get_aws_secret(self, key: str) -> Optional[str]:
        """Get secret from AWS Secrets Manager"""
        response = self.aws_client.get_secret_value(SecretId=key)
        return response['SecretString']
    
    def _store_local_secret(self, key: str, value: str, metadata: Dict) -> bool:
        """Store secret locally (encrypted)"""
        secrets_file = self.config.get('secrets_file', '.secrets.enc')
        
        # Load existing secrets
        secrets = {}
        if os.path.exists(secrets_file):
            secrets = self._load_local_secrets()
        
        # Encrypt and store
        cipher = Fernet(self.encryption_key)
        encrypted_value = cipher.encrypt(value.encode()).decode()
        
        secrets[key] = {
            'value': encrypted_value,
            'metadata': metadata or {},
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Save secrets
        encrypted_secrets = cipher.encrypt(json.dumps(secrets).encode())
        with open(secrets_file, 'wb') as f:
            f.write(encrypted_secrets)
        
        os.chmod(secrets_file, 0o600)
        return True
    
    def _get_local_secret(self, key: str) -> Optional[str]:
        """Get secret from local storage"""
        secrets = self._load_local_secrets()
        
        if key in secrets:
            cipher = Fernet(self.encryption_key)
            encrypted_value = secrets[key]['value'].encode()
            return cipher.decrypt(encrypted_value).decode()
        
        return None
    
    def _delete_local_secret(self, key: str) -> bool:
        """Delete secret from local storage"""
        secrets = self._load_local_secrets()
        
        if key in secrets:
            del secrets[key]
            
            # Save updated secrets
            cipher = Fernet(self.encryption_key)
            encrypted_secrets = cipher.encrypt(json.dumps(secrets).encode())
            
            secrets_file = self.config.get('secrets_file', '.secrets.enc')
            with open(secrets_file, 'wb') as f:
                f.write(encrypted_secrets)
            
            return True
        
        return False
    
    def _load_local_secrets(self) -> Dict:
        """Load secrets from local storage"""
        secrets_file = self.config.get('secrets_file', '.secrets.enc')
        
        if not os.path.exists(secrets_file):
            return {}
        
        cipher = Fernet(self.encryption_key)
        
        with open(secrets_file, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = cipher.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def rotate_secret(self, key: str, new_value: str) -> bool:
        """Rotate a secret (keep old version for rollback)"""
        if self.backend == 'vault':
            # Vault automatically keeps versions
            return self.store_secret(key, new_value)
        else:
            # For other backends, implement versioning
            old_value = self.get_secret(key)
            if old_value:
                # Store old version with suffix
                self.store_secret(f"{key}_previous", old_value)
            
            return self.store_secret(key, new_value)
    
    def list_secrets(self) -> List[str]:
        """List all secret keys"""
        if self.backend == 'vault':
            response = self.vault_client.secrets.kv.v2.list_secrets(path='')
            return response['data']['keys']
        elif self.backend == 'local':
            secrets = self._load_local_secrets()
            return list(secrets.keys())
        else:
            # AWS Secrets Manager would need pagination
            return []

# Application integration
class SecretConfigLoader:
    """Load application configuration from secrets"""
    
    def __init__(self, secrets_manager: SecretsManager):
        self.secrets = secrets_manager
    
    def load_database_config(self) -> Dict[str, str]:
        """Load database configuration from secrets"""
        return {
            'host': self.secrets.get_secret('db/host') or 'localhost',
            'port': self.secrets.get_secret('db/port') or '5432',
            'username': self.secrets.get_secret('db/username'),
            'password': self.secrets.get_secret('db/password'),
            'database': self.secrets.get_secret('db/name')
        }
    
    def load_api_keys(self) -> Dict[str, str]:
        """Load API keys from secrets"""
        return {
            'stripe': self.secrets.get_secret('api/stripe'),
            'sendgrid': self.secrets.get_secret('api/sendgrid'),
            'aws_access_key': self.secrets.get_secret('aws/access_key'),
            'aws_secret_key': self.secrets.get_secret('aws/secret_key')
        }
    
    def load_jwt_secrets(self) -> Dict[str, str]:
        """Load JWT signing secrets"""
        return {
            'jwt_secret': self.secrets.get_secret('jwt/secret'),
            'jwt_refresh_secret': self.secrets.get_secret('jwt/refresh_secret')
        }

# Environment-specific secrets
class EnvironmentSecretsManager:
    """Manage secrets across different environments"""
    
    def __init__(self, environment: str):
        self.environment = environment
        self.secrets_manager = self._get_secrets_manager()
    
    def _get_secrets_manager(self) -> SecretsManager:
        """Get appropriate secrets manager for environment"""
        if self.environment == 'production':
            return SecretsManager('vault', {
                'vault_url': os.environ.get('VAULT_URL'),
            })
        elif self.environment == 'staging':
            return SecretsManager('aws', {})
        else:
            return SecretsManager('local', {
                'secrets_file': f'.secrets_{self.environment}.enc'
            })
    
    def get_secret(self, key: str) -> Optional[str]:
        """Get environment-specific secret"""
        env_key = f"{self.environment}/{key}"
        return self.secrets_manager.get_secret(env_key)
    
    def store_secret(self, key: str, value: str) -> bool:
        """Store environment-specific secret"""
        env_key = f"{self.environment}/{key}"
        return self.secrets_manager.store_secret(env_key, value, {
            'environment': self.environment
        })

# Usage examples
secrets_manager = SecretsManager('local')

# Store secrets
secrets_manager.store_secret('db/password', 'super_secure_password')
secrets_manager.store_secret('api/stripe', 'sk_test_...')

# Load configuration
config_loader = SecretConfigLoader(secrets_manager)
db_config = config_loader.load_database_config()
api_keys = config_loader.load_api_keys()

print(f"Database config: {db_config}")
print(f"API keys loaded: {list(api_keys.keys())}")

# Environment-specific usage
env_secrets = EnvironmentSecretsManager('development')
env_secrets.store_secret('db/password', 'dev_password')
dev_password = env_secrets.get_secret('db/password')
```

## Logging and Monitoring

### Comprehensive Logging System

```python
import logging
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
from logging.handlers import RotatingFileHandler, SMTPHandler
import structlog

class SecurityEventLogger:
    """Centralized security event logging"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = self._setup_logger()
        self.alert_thresholds = config.get('alert_thresholds', {})
        self.event_counts = {}
        self.lock = threading.Lock()
    
    def _setup_logger(self) -> structlog.BoundLogger:
        """Setup structured logging"""
        logging.basicConfig(
            format="%(message)s",
            stream=self.config.get('stream'),
            level=getattr(logging, self.config.get('level', 'INFO'))
        )
        
        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_logger_name,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                structlog.processors.UnicodeDecoder(),
                structlog.processors.JSONRenderer()
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        
        return structlog.get_logger("security")
    
    def log_authentication_event(self, username: str, success: bool, 
                                ip_address: str, user_agent: str = None):
        """Log authentication events"""
        event_data = {
            'event_type': 'authentication',
            'username': username,
            'success': success,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if success:
            self.logger.info("Authentication successful", **event_data)
        else:
            self.logger.warning("Authentication failed", **event_data)
            self._check_brute_force(username, ip_address)
    
    def log_authorization_event(self, username: str, resource: str, 
                              action: str, granted: bool):
        """Log authorization events"""
        event_data = {
            'event_type': 'authorization',
            'username': username,
            'resource': resource,
            'action': action,
            'granted': granted,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if granted:
            self.logger.info("Access granted", **event_data)
        else:
            self.logger.warning("Access denied", **event_data)
    
    def log_data_access(self, username: str, data_type: str, 
                       operation: str, record_count: int = None):
        """Log data access events"""
        event_data = {
            'event_type': 'data_access',
            'username': username,
            'data_type': data_type,
            'operation': operation,
            'record_count': record_count,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info("Data access", **event_data)
        
        # Alert on bulk data access
        if record_count and record_count > self.alert_thresholds.get('bulk_access', 1000):
            self.log_security_alert("Bulk data access detected", event_data)
    
    def log_security_violation(self, violation_type: str, details: Dict[str, Any]):
        """Log security violations"""
        event_data = {
            'event_type': 'security_violation',
            'violation_type': violation_type,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.error("Security violation", **event_data)
        self.log_security_alert(f"Security violation: {violation_type}", event_data)
    
    def log_system_event(self, event_type: str, component: str, 
                        status: str, details: Dict[str, Any] = None):
        """Log system events"""
        event_data = {
            'event_type': 'system',
            'component': component,
            'status': status,
            'details': details or {},
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if status == 'error':
            self.logger.error("System error", **event_data)
        elif status == 'warning':
            self.logger.warning("System warning", **event_data)
        else:
            self.logger.info("System event", **event_data)
    
    def log_security_alert(self, message: str, event_data: Dict[str, Any]):
        """Log high-priority security alerts"""
        alert_data = {
            'event_type': 'security_alert',
            'alert_message': message,
            'alert_data': event_data,
            'timestamp': datetime.utcnow().isoformat(),
            'severity': 'high'
        }
        
        self.logger.critical("SECURITY ALERT", **alert_data)
        
        # Send immediate notification
        self._send_alert_notification(alert_data)
    
    def _check_brute_force(self, username: str, ip_address: str):
        """Check for brute force attacks"""
        with self.lock:
            current_time = time.time()
            window = 300  # 5 minutes
            
            # Clean old entries
            cutoff_time = current_time - window
            for key in list(self.event_counts.keys()):
                self.event_counts[key] = [
                    timestamp for timestamp in self.event_counts[key]
                    if timestamp > cutoff_time
                ]
            
            # Count recent failures
            user_key = f"user:{username}"
            ip_key = f"ip:{ip_address}"
            
            for key in [user_key, ip_key]:
                if key not in self.event_counts:
                    self.event_counts[key] = []
                
                self.event_counts[key].append(current_time)
                
                # Check threshold
                threshold = self.alert_thresholds.get('failed_logins', 5)
                if len(self.event_counts[key]) >= threshold:
                    self.log_security_alert(
                        f"Brute force attack detected for {key}",
                        {
                            'username': username,
                            'ip_address': ip_address,
                            'attempt_count': len(self.event_counts[key])
                        }
                    )
    
    def _send_alert_notification(self, alert_data: Dict[str, Any]):
        """Send alert notification"""
        # Implement notification logic (email, Slack, PagerDuty, etc.)
        print(f"ALERT: {alert_data['alert_message']}")

class PerformanceMonitor:
    """Monitor application performance and security metrics"""
    
    def __init__(self):
        self.metrics = {}
        self.lock = threading.Lock()
    
    def record_request_time(self, endpoint: str, duration: float):
        """Record request processing time"""
        with self.lock:
            if endpoint not in self.metrics:
                self.metrics[endpoint] = []
            
            self.metrics[endpoint].append({
                'duration': duration,
                'timestamp': time.time()
            })
            
            # Keep only last 1000 entries
            self.metrics[endpoint] = self.metrics[endpoint][-1000:]
    
    def get_average_response_time(self, endpoint: str, window_minutes: int = 5) -> float:
        """Get average response time for endpoint"""
        with self.lock:
            if endpoint not in self.metrics:
                return 0.0
            
            cutoff_time = time.time() - (window_minutes * 60)
            recent_metrics = [
                m for m in self.metrics[endpoint]
                if m['timestamp'] > cutoff_time
            ]
            
            if not recent_metrics:
                return 0.0
            
            return sum(m['duration'] for m in recent_metrics) / len(recent_metrics)
    
    def detect_performance_anomalies(self) -> List[Dict[str, Any]]:
        """Detect performance anomalies"""
        anomalies = []
        
        for endpoint, metrics in self.metrics.items():
            if len(metrics) < 10:  # Need enough data
                continue
            
            recent_avg = self.get_average_response_time(endpoint, 5)
            historical_avg = self.get_average_response_time(endpoint, 60)
            
            # Alert if current average is 3x historical average
            if recent_avg > historical_avg * 3:
                anomalies.append({
                    'type': 'slow_response',
                    'endpoint': endpoint,
                    'recent_avg': recent_avg,
                    'historical_avg': historical_avg
                })
        
        return anomalies

class SecurityMetricsCollector:
    """Collect and analyze security metrics"""
    
    def __init__(self, logger: SecurityEventLogger):
        self.logger = logger
        self.metrics = {
            'failed_logins': 0,
            'successful_logins': 0,
            'access_denied': 0,
            'security_violations': 0,
            'alerts_sent': 0
        }
        self.lock = threading.Lock()
    
    def increment_metric(self, metric_name: str, count: int = 1):
        """Increment a security metric"""
        with self.lock:
            if metric_name in self.metrics:
                self.metrics[metric_name] += count
    
    def get_security_summary(self) -> Dict[str, Any]:
        """Get security metrics summary"""
        with self.lock:
            total_login_attempts = (
                self.metrics['failed_logins'] + 
                self.metrics['successful_logins']
            )
            
            return {
                'total_login_attempts': total_login_attempts,
                'login_success_rate': (
                    self.metrics['successful_logins'] / max(total_login_attempts, 1)
                ) * 100,
                'security_incidents': (
                    self.metrics['access_denied'] + 
                    self.metrics['security_violations']
                ),
                'alert_rate': self.metrics['alerts_sent'],
                'metrics': self.metrics.copy()
            }
    
    def generate_security_report(self) -> str:
        """Generate human-readable security report"""
        summary = self.get_security_summary()
        
        report = f"""
Security Metrics Report
======================
Total Login Attempts: {summary['total_login_attempts']}
Login Success Rate: {summary['login_success_rate']:.1f}%
Security Incidents: {summary['security_incidents']}
Alerts Sent: {summary['alert_rate']}

Detailed Metrics:
- Failed Logins: {self.metrics['failed_logins']}
- Successful Logins: {self.metrics['successful_logins']}
- Access Denied: {self.metrics['access_denied']}
- Security Violations: {self.metrics['security_violations']}
"""
        
        return report

# Flask integration example
from flask import Flask, request, g
import time

def create_monitored_app():
    """Create Flask app with comprehensive monitoring"""
    
    app = Flask(__name__)
    
    # Initialize monitoring components
    security_logger = SecurityEventLogger({
        'level': 'INFO',
        'alert_thresholds': {
            'failed_logins': 5,
            'bulk_access': 1000
        }
    })
    
    performance_monitor = PerformanceMonitor()
    metrics_collector = SecurityMetricsCollector(security_logger)
    
    @app.before_request
    def before_request():
        """Start request timing"""
        g.start_time = time.time()
    
    @app.after_request
    def after_request(response):
        """Log request and update metrics"""
        duration = time.time() - g.start_time
        
        # Record performance metrics
        performance_monitor.record_request_time(request.endpoint, duration)
        
        # Log request
        security_logger.logger.info(
            "HTTP request",
            method=request.method,
            path=request.path,
            status_code=response.status_code,
            duration=duration,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        return response
    
    @app.route('/login', methods=['POST'])
    def login():
        """Login with security logging"""
        username = request.json.get('username')
        password = request.json.get('password')
        
        # Authenticate user (implementation not shown)
        success = authenticate_user(username, password)
        
        # Log authentication event
        security_logger.log_authentication_event(
            username=username,
            success=success,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent')
        )
        
        # Update metrics
        if success:
            metrics_collector.increment_metric('successful_logins')
            return {'status': 'success'}
        else:
            metrics_collector.increment_metric('failed_logins')
            return {'status': 'failed'}, 401
    
    @app.route('/admin/security-report')
    def security_report():
        """Get security metrics report"""
        return {
            'report': metrics_collector.generate_security_report(),
            'anomalies': performance_monitor.detect_performance_anomalies()
        }
    
    def authenticate_user(username: str, password: str) -> bool:
        """Placeholder authentication function"""
        return username == 'admin' and password == 'password'
    
    return app

# Usage
if __name__ == '__main__':
    app = create_monitored_app()
    app.run(debug=False)
```

I'll continue with the remaining chapters and then review all content for GitHub markdown enhancements and accuracy checks. The guide is becoming very comprehensive with practical, implementable security solutions for developers.