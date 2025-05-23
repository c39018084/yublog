# YuBlog - Passwordless Secure Blogging Platform

A self-hosted, highly secure blogging platform with passwordless authentication supporting YubiKey (FIDO2/WebAuthn) and QR code scanning for mobile device authentication.

## 🔐 Security Features

- **Passwordless Authentication**: No passwords stored or used anywhere
- **YubiKey Support**: Full FIDO2/WebAuthn implementation
- **QR Code Authentication**: Mobile device push notification-based confirmation
- **End-to-End Security**: Following OWASP best practices
- **Self-Hosted**: No external cloud dependencies
- **Zero Trust Architecture**: Principle of least privilege throughout

## 🏗️ Architecture

- **Backend**: Python Flask with security-first design
- **Frontend**: React with WebAuthn integration
- **Database**: PostgreSQL with encryption at rest
- **Authentication**: WebAuthn + Custom QR/Push system
- **Deployment**: Docker Compose for easy self-hosting

## 📁 Project Structure

```
yublog/
├── docs/                     # Technical documentation
├── backend/                  # Flask API server
├── frontend/                 # React web application
├── mobile/                   # Mobile app for QR authentication
├── database/                 # Database schemas and migrations
├── docker/                   # Docker configurations
├── tests/                    # Comprehensive test suite
├── security/                 # Security configurations and tools
└── deployment/               # Deployment scripts and guides
```

## 🚀 Quick Start

```bash
# Clone and setup
git clone <repository>
cd yublog

# Start with Docker Compose
docker-compose up -d

# Or manual setup (see deployment/SETUP.md for details)
```

## 📖 Documentation

- [Technical Design Document](docs/TECHNICAL_DESIGN.md)
- [API Documentation](docs/API.md)
- [Security Implementation](docs/SECURITY.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

## 🛡️ Security Compliance

- OWASP Top 10 mitigation
- NIST Cybersecurity Framework alignment
- ISO 27001 security controls
- GDPR privacy compliance ready

---

**Built with security-first principles for complete self-hosting autonomy.**
