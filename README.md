# YuBlog - Passwordless Secure Blogging Platform

A self-hosted, highly secure blogging platform with passwordless authentication using YubiKey (FIDO2/WebAuthn) for ultimate security without passwords.

## 🔒 Security Features

- **Passwordless Authentication**: No passwords stored or used anywhere
- **YubiKey Support**: Full FIDO2/WebAuthn hardware security key integration
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
- **Authentication**: WebAuthn/FIDO2 only (YubiKey, Touch ID, Windows Hello)
- **Deployment**: Docker Compose for easy self-hosting

## 📁 Project Structure

```
yublog/
├── docs/                     # Technical documentation
├── backend/                  # Flask API server
├── backend-js/               # Alternative Node.js backend
├── frontend/                 # React web application
├── database/                 # Database schemas and migrations
├── docker/                   # Docker configurations
├── tests/                    # Comprehensive test suite
├── security/                 # Security configurations and tools
└── deployment/               # Deployment scripts and guides
```

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- YubiKey or compatible FIDO2 security key (Touch ID, Windows Hello, etc.)
- Modern web browser with WebAuthn support

### Supported Authenticators

- **Hardware Keys**: YubiKey 5 Series, SoloKeys, Google Titan
- **Platform Authenticators**: Touch ID (macOS), Windows Hello, Android Fingerprint
- **Mobile**: Any FIDO2-compatible mobile device

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

6. **Register your authenticator**:
   - Navigate to http://localhost:3000/auth
   - Choose "Register with YubiKey"
   - Follow the browser prompts to register your security key

## 🔧 Configuration

### Environment Variables

Copy `environment.example` to `.env` and configure:

- `DB_PASSWORD`: Strong database password
- `REDIS_PASSWORD`: Strong Redis password  
- `JWT_SECRET_KEY`: Cryptographically secure JWT secret
- `SECRET_KEY`: Cryptographically secure Flask secret
- `WEBAUTHN_RP_ID`: Your domain name (e.g., localhost for development)
- `WEBAUTHN_RP_NAME`: Your application name
- `WEBAUTHN_ORIGIN`: Your application URL (e.g., http://localhost:3000)

### Production Deployment

For production deployment:

1. Use proper SSL certificates (Required for WebAuthn)
2. Configure firewall rules
3. Set up monitoring and logging
4. Regular security updates
5. Backup strategy implementation

## 🛠️ Development Status

### ✅ **Currently Implemented:**
- WebAuthn/FIDO2 authentication (YubiKey, Touch ID, Windows Hello)
- React frontend with modern UI
- Flask backend with security best practices
- Blog creation, editing, and management
- User profile management
- Comprehensive security headers
- Rate limiting and audit logging
- Docker containerization

### 🚧 **Planned Features:**
- QR Code authentication for mobile devices
- Mobile companion app
- Advanced blog themes
- Plugin system
- Multi-user support with roles
- Social features (comments, sharing)

## 📚 Documentation

- [Technical Design](docs/TECHNICAL_DESIGN.md)
- [Docker Setup Guide](docs/Docker/)

## 🛡️ Security

This project prioritizes security:

- Zero password storage or transmission
- Hardware-based authentication only
- Modern cryptographic standards (WebAuthn/FIDO2)
- Comprehensive audit logging
- Security headers and CSP
- Regular security reviews

## 🆘 Troubleshooting

### WebAuthn Issues:
1. **HTTPS Required**: WebAuthn requires HTTPS in production
2. **Browser Support**: Use Chrome, Firefox, Safari, or Edge
3. **Security Key**: Ensure your YubiKey/device supports FIDO2
4. **Domain Mismatch**: Check WEBAUTHN_RP_ID matches your domain

### Common Problems:
- **"WebAuthn not supported"**: Update your browser or use a compatible device
- **"Registration failed"**: Check browser console and ensure HTTPS
- **"Touch your security key"**: Press the button on your YubiKey when prompted

## 📄 License

MIT License - see LICENSE file for details.

---

**Built with security-first principles for complete self-hosting autonomy.**
