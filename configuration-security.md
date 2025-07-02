[Back to Contents](README.md)

# Configuration Security: Secure Infrastructure and Deployment

> [!WARNING]
> **95% of cloud security failures** are due to customer misconfiguration, not provider vulnerabilities. - Gartner

Most security breaches happen not because of sophisticated attacks, but due to misconfigurations and operational mistakes. A single misconfigured server, an exposed database, or a forgotten debug flag can compromise an entire organization. This chapter covers the essential practices for securing your infrastructure and deployment processes.

## Table of Contents
- [The Configuration Security Problem](#the-configuration-security-problem)
- [Cloud Security Fundamentals](#cloud-security-fundamentals)
- [Secrets Management](#secrets-management)
- [Monitoring and Logging](#monitoring-and-logging)
- [Container Security](#container-security)
- [Network Security](#network-security)
- [Deployment Security](#deployment-security)
- [Security Automation](#security-automation)

## The Configuration Security Problem

### Why Configuration Matters

Configuration security failures make headlines regularly:
- **Capital One (2019)**: Misconfigured firewall led to 100 million records exposed
- **Elasticsearch instances**: Thousands of unsecured databases exposed on the internet
- **AWS S3 buckets**: Countless data breaches from publicly accessible storage

> [!IMPORTANT]
> **Security by Default**: Systems should be secure out of the box, but reality requires careful configuration.

### Common Configuration Mistakes

| Mistake | Impact | Example |
|---------|--------|---------|
| **Default credentials** | Full system compromise | admin/admin, root/password |
| **Open ports** | Unauthorized access | Database ports exposed to internet |
| **Debug mode in production** | Information disclosure | Stack traces with sensitive data |
| **Missing encryption** | Data interception | Unencrypted database connections |
| **Excessive permissions** | Privilege escalation | Applications running as root |

## Cloud Security Fundamentals

### AWS Security Essentials

**Identity and Access Management (IAM)**
- Use principle of least privilege for all roles and policies
- Enable MFA for all users, especially admin accounts
- Rotate access keys regularly and remove unused keys
- Use IAM roles instead of embedding credentials in code

**Network Security**
- Use Virtual Private Clouds (VPCs) to isolate resources
- Configure security groups as virtual firewalls
- Use private subnets for databases and internal services
- Implement network access control lists (NACLs) for additional protection

**Storage Security**
- Enable encryption at rest for all S3 buckets
- Use bucket policies to restrict access
- Enable S3 access logging and monitoring
- Never make buckets publicly readable unless absolutely necessary

### Azure Security Configuration

**Azure Active Directory**
- Enable conditional access policies
- Implement privileged identity management (PIM)
- Use managed identities for Azure services
- Enable continuous access evaluation

**Network Security**
- Use Azure Virtual Networks for isolation
- Implement network security groups properly
- Use Azure Firewall for advanced protection
- Enable DDoS protection standard

### Google Cloud Security

**Identity and Access Management**
- Use Google Cloud IAM with primitive and predefined roles
- Implement organization policies for governance
- Use service accounts with minimal permissions
- Enable audit logging for all services

## Secrets Management

### The Problem with Secrets

Secrets (passwords, API keys, certificates) are often the weakest link in security:

```bash
# ❌ NEVER DO THIS - Secrets in code
DATABASE_URL="postgresql://user:password123@db.example.com/mydb"
API_KEY="sk_live_abcd1234567890"

# ❌ NEVER DO THIS - Secrets in environment files committed to git
echo "SECRET_KEY=super-secret-key" >> .env
git add .env  # DON'T!
```

### Proper Secrets Management

**Use Dedicated Secrets Management Systems:**
- **AWS Secrets Manager**: Automatic rotation, encryption at rest
- **HashiCorp Vault**: Dynamic secrets, fine-grained access control
- **Azure Key Vault**: Integration with Azure services
- **Google Secret Manager**: Native GCP integration

**Best Practices:**
- Never store secrets in code repositories
- Use different secrets for different environments (dev/staging/prod)
- Implement automatic secret rotation where possible
- Audit secret access regularly
- Use short-lived credentials when possible

### Environment-Specific Configuration

```yaml
# docker-compose.yml - Using secrets properly
version: '3.8'
services:
  app:
    image: myapp:latest
    environment:
      - DATABASE_URL_FILE=/run/secrets/db_url
    secrets:
      - db_url

secrets:
  db_url:
    external: true  # Managed outside of compose file
```

## Monitoring and Logging

### Security Logging Strategy

**What to Log:**
- Authentication attempts (successful and failed)
- Authorization failures
- Administrative actions
- System configuration changes
- Network connection attempts
- File access and modifications

**Log Security Requirements:**
- **Integrity**: Logs cannot be modified by attackers
- **Availability**: Logs are always accessible when needed
- **Confidentiality**: Logs don't contain sensitive data
- **Retention**: Logs are kept for appropriate time periods

### Centralized Logging

Implement centralized logging to:
- Detect attacks across multiple systems
- Comply with regulatory requirements
- Enable forensic analysis after incidents
- Monitor system performance and health

**Popular Solutions:**
- **ELK Stack** (Elasticsearch, Logstash, Kibana)
- **Splunk** for enterprise environments
- **Fluentd** for cloud-native applications
- **AWS CloudWatch** for AWS infrastructure

### Security Monitoring

**Key Metrics to Monitor:**
- Failed authentication attempts
- Unusual network traffic patterns
- Resource consumption anomalies
- Configuration changes
- Certificate expiration dates
- Vulnerability scan results

> [!TIP]
> **Alert Fatigue**: Set up intelligent alerting to avoid overwhelming security teams with false positives.

## Container Security

### Docker Security Fundamentals

**Image Security:**
- Use official base images from trusted registries
- Keep base images updated with latest security patches
- Scan images for vulnerabilities before deployment
- Use minimal base images (Alpine, distroless)

**Runtime Security:**
- Run containers as non-root users
- Use read-only filesystems where possible
- Limit container capabilities
- Implement resource limits (CPU, memory, disk)

```dockerfile
# Dockerfile security best practices
FROM node:18-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Copy and install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Copy application code
COPY --chown=nextjs:nodejs . .

# Switch to non-root user
USER nextjs

# Expose port and start
EXPOSE 3000
CMD ["npm", "start"]
```

### Kubernetes Security

**Pod Security:**
- Use Pod Security Standards to enforce security policies
- Implement network policies to control traffic
- Use service accounts with minimal permissions
- Enable admission controllers for policy enforcement

**Cluster Security:**
- Enable RBAC (Role-Based Access Control)
- Use network segmentation
- Regularly update Kubernetes and node operating systems
- Implement secrets management properly

## Network Security

### Firewall Configuration

**Principles:**
- Default deny all traffic
- Allow only necessary ports and protocols
- Use principle of least privilege
- Document all firewall rules

**Common Secure Configurations:**
```bash
# Basic UFW (Ubuntu Firewall) configuration
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp  # HTTP
ufw allow 443/tcp # HTTPS
ufw enable
```

### VPN and Remote Access

**Best Practices:**
- Use modern VPN protocols (WireGuard, IKEv2)
- Implement certificate-based authentication
- Use multi-factor authentication for VPN access
- Monitor and log all VPN connections
- Implement split tunneling carefully

### Network Segmentation

Divide your network into security zones:
- **DMZ**: Public-facing services
- **Internal**: Employee workstations and internal services
- **Restricted**: Sensitive systems and databases
- **Management**: Network infrastructure and monitoring

## Deployment Security

### CI/CD Security

**Pipeline Security:**
- Secure your build environment
- Use signed commits and verify signatures
- Implement security scanning in pipelines
- Use dedicated service accounts for deployments

**Example GitHub Actions Security:**
```yaml
name: Secure CI/CD Pipeline

on:
  push:
    branches: [main]
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Security scan
      run: |
        # Dependency scanning
        npm audit --audit-level high
        
        # SAST scanning
        docker run --rm -v "$PWD:/app" \
          returntocorp/semgrep:latest --config=auto /app
        
        # Docker image scanning
        docker build -t myapp .
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
          aquasec/trivy:latest image myapp
```

### Blue-Green Deployments

Implement blue-green deployments for:
- Zero-downtime deployments
- Quick rollback capability
- Testing in production-like environment
- Reduced deployment risk

### Immutable Infrastructure

**Benefits:**
- Consistent, reproducible deployments
- Easier rollbacks and disaster recovery
- Reduced configuration drift
- Better security posture through rebuilding vs patching

## Security Automation

### Infrastructure as Code (IaC)

Use tools like Terraform, CloudFormation, or Ansible to:
- Version control your infrastructure
- Apply security policies consistently
- Enable security reviews of infrastructure changes
- Automate compliance checking

### Automated Security Scanning

**Types of Scanning:**
- **SAST** (Static Application Security Testing): Scan source code
- **DAST** (Dynamic Application Security Testing): Test running applications
- **Container Scanning**: Analyze container images
- **Infrastructure Scanning**: Check cloud configurations

### Security Policy as Code

```yaml
# Example Open Policy Agent (OPA) policy
package kubernetes.admission

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.containers[_].securityContext.runAsRoot == true
    msg := "Containers cannot run as root"
}

deny[msg] {
    input.request.kind.kind == "Pod"
    input.request.object.spec.hostNetwork == true
    msg := "Pods cannot use host networking"
}
```

## Configuration Security Checklist

### Server Hardening
- [ ] Disable unnecessary services and ports
- [ ] Update operating system and applications regularly
- [ ] Configure strong password policies
- [ ] Enable and configure firewall
- [ ] Set up intrusion detection/prevention systems
- [ ] Implement file integrity monitoring
- [ ] Configure secure remote access (SSH keys, disable root login)

### Application Security
- [ ] Disable debug mode in production
- [ ] Remove development/testing accounts
- [ ] Configure secure session management
- [ ] Implement proper error handling
- [ ] Set up security headers
- [ ] Enable audit logging
- [ ] Configure rate limiting

### Database Security
- [ ] Change default passwords
- [ ] Restrict network access
- [ ] Enable encryption at rest and in transit
- [ ] Implement backup encryption
- [ ] Set up database activity monitoring
- [ ] Configure proper user permissions
- [ ] Enable audit logging

### Cloud Security
- [ ] Enable multi-factor authentication
- [ ] Configure identity and access management properly
- [ ] Use encryption for data at rest and in transit
- [ ] Set up monitoring and alerting
- [ ] Implement network security controls
- [ ] Enable audit logging
- [ ] Regular security assessments

## Incident Response Planning

**Preparation:**
- Document incident response procedures
- Identify key personnel and contact information
- Set up communication channels
- Prepare forensic tools and environments

**Detection and Analysis:**
- Monitor security logs continuously
- Set up automated alerting
- Establish severity classification
- Document evidence properly

**Containment and Recovery:**
- Isolate affected systems quickly
- Preserve evidence for investigation
- Implement temporary fixes
- Plan and execute recovery procedures

> [!IMPORTANT]
> **Practice Makes Perfect**: Regular incident response drills help identify gaps and improve response times.

## Conclusion

Configuration security is an ongoing process that requires constant attention and regular updates. The key is to:

- **Automate** security configurations where possible
- **Monitor** systems continuously for changes and anomalies
- **Document** all configurations and changes
- **Test** security controls regularly
- **Update** systems and configurations promptly
- **Train** teams on secure configuration practices

Remember: Security is not just about the latest threats and attacks—it's often about getting the basics right. Proper configuration management and operational security practices will protect you from the vast majority of attacks.

---

*"Most hackers are lazy. They go after the easy targets first."* - Kevin Mitnick

Make sure your systems are not the easy targets by implementing these configuration security practices consistently across your infrastructure.