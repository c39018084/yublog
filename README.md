# YuBlog - Passwordless Secure Blogging Platform

A self-hosted, highly secure blogging platform with passwordless authentication supporting YubiKey (FIDO2/WebAuthn) and QR code scanning for mobile device authentication.

## 🔒 Security Features

- **Passwordless Authentication**: No passwords stored or used anywhere
- **YubiKey Support**: FIDO2/WebAuthn hardware security keys
- **QR Code Authentication**: Mobile device authentication via QR scanning
- **End-to-End Encryption**: TLS 1.3 with modern cipher suites
- **Rate Limiting**: Protection against brute force attacks
- **Audit Logging**: Complete security event tracking
- **Session Management**: Secure JWT-based sessions with Redis storage

## ⚠️ IMPORTANT SECURITY NOTICE

**BEFORE DEPLOYING TO PRODUCTION:**

1. **NEVER use the default passwords** in docker-compose files
2. **ALWAYS create your own .env file** with strong, unique credentials
3. **GENERATE new JWT secrets** using: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
4. **Use proper SSL certificates** from a trusted Certificate Authority
5. **Enable firewall** and restrict access to necessary ports only
6. **Regular security updates** and monitoring

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

### Prerequisites

- Docker and Docker Compose
- YubiKey or compatible FIDO2 security key
- Modern web browser with WebAuthn support

### Development Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd yublog
   ```

2. **Create environment file**:
   ```bash
   cp environment.example .env
   # Edit .env with your secure credentials
   ```

3. **Generate secure secrets**:
   ```bash
   # Generate JWT secret
   python -c "import secrets; print('JWT_SECRET_KEY=' + secrets.token_urlsafe(32))"
   
   # Generate Flask secret
   python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"
   ```

4. **Start the application**:
   ```bash
   # Simple development setup
   docker-compose -f docker-compose.simple.yml up -d
   
   # Or full production setup
   docker-compose up -d
   ```

5. **Access the application**:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5000

## 🔧 Configuration

### Environment Variables

Copy `environment.example` to `.env` and configure:

- `DB_PASSWORD`: Strong database password
- `REDIS_PASSWORD`: Strong Redis password  
- `JWT_SECRET_KEY`: Cryptographically secure JWT secret
- `SECRET_KEY`: Cryptographically secure Flask secret
- `WEBAUTHN_RP_ID`: Your domain name
- `WEBAUTHN_RP_NAME`: Your application name
- `WEBAUTHN_ORIGIN`: Your application URL

### Production Deployment

For production deployment:

1. Use proper SSL certificates
2. Configure firewall rules
3. Set up monitoring and logging
4. Regular security updates
5. Backup strategy implementation

## 📚 Documentation

- [Technical Design](docs/TECHNICAL_DESIGN.md)
- [Security Architecture](docs/SECURITY.md)
- [API Documentation](docs/API.md)
- [Deployment Guide](docs/DEPLOYMENT.md)

## 🛡️ Security

This project prioritizes security:

- Zero password storage
- Hardware-based authentication
- Modern cryptographic standards
- Comprehensive audit logging
- Regular security reviews

Report security issues to: [security contact]

## 📄 License

MIT License - see LICENSE file for details.

---

**Built with security-first principles for complete self-hosting autonomy.**
