# YuBlog - Passwordless Secure Blogging Platform

A self-hosted, highly secure blogging platform with passwordless authentication using YubiKey (FIDO2/WebAuthn) for ultimate security without passwords.

## 🔒 Security Features

- **Passwordless Authentication**: No passwords stored or used anywhere
- **YubiKey Support**: Full FIDO2/WebAuthn hardware security key integration
- **Multi-Device Support**: Add/remove multiple security devices per account
- **Device Management**: View device usage, creation dates, and manage security keys
- **Account Spam Prevention**: 34-day cooldown between device registrations to prevent account spamming
- **Device Registration Tracking**: AAGUID-based device identification and registration limits
- **Smart Device Policies**: Different rules for account creation vs. adding devices to existing accounts
- **Admin Privileges**: First registered user automatically receives administrator privileges
- **End-to-End Encryption**: TLS 1.3 with modern cipher suites
- **Rate Limiting**: Protection against brute force attacks
- **Audit Logging**: Complete security event tracking with device registration monitoring
- **Session Management**: Secure JWT-based sessions with Redis storage

## ⚠️ IMPORTANT SECURITY NOTICE

**BEFORE DEPLOYING TO PRODUCTION:**

1. **NEVER use the default passwords** in docker-compose files
2. **ALWAYS create your own .env file** with strong, unique credentials
3. **GENERATE new JWT secrets** using: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
4. **GENERATE new SSL certificates** - NEVER use development certificates in production
5. **Use proper SSL certificates** from a trusted Certificate Authority
6. **Enable firewall** and restrict access to necessary ports only
7. **Regular security updates** and monitoring

**SSL Certificate Security:**
- Development SSL certificates are in `.gitignore` and NOT tracked in git
- For production, generate new certificates: `openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes`
- Use Let's Encrypt or proper CA certificates for public deployment

## ⚙️ Technical Architecture

- **Frontend**: React 18 with modern security practices
- **Backend**: Express.js with native WebAuthn implementation (primary) + Flask alternative
- **Database**: PostgreSQL with encrypted connections
- **Cache**: Redis for sessions and rate limiting
- **Authentication**: Custom WebAuthn server (no external auth libraries)
- **Security**: Native CBOR decoding, COSE key handling, crypto verification
- **Deployment**: Docker with Nginx reverse proxy and SSL termination

## 📁 Project Structure

```
yublog/
├── frontend/              # React frontend application
│   ├── public/           # Static assets
│   │   ├── components/   # Reusable UI components
│   │   ├── pages/        # Page components
│   │   ├── hooks/        # Custom React hooks
│   │   └── utils/        # WebAuthn utilities
│   └── package.json      # Frontend dependencies
├── backend-js/           # Express.js backend (PRIMARY)
│   ├── src/              # Source code
│   │   ├── index.js      # Main Express server
│   │   ├── webauthn.js   # Native WebAuthn implementation
│   │   └── database.js   # Database connection and queries
│   ├── package.json      # Node.js dependencies
│   └── Dockerfile        # Express backend container
├── backend/              # Flask backend (ALTERNATIVE)
│   ├── app.py            # Main Flask application
│   ├── auth_routes.py    # Authentication endpoints
│   ├── blog_routes.py    # Blog management endpoints
│   ├── requirements.txt  # Python dependencies
│   └── Dockerfile        # Flask backend container
├── database/             # Database setup and migrations
│   └── init.sql          # Database schema initialization
├── docker/               # Docker configuration
│   └── nginx/            # Nginx reverse proxy config
├── docs/                 # Documentation
│   └── TECHNICAL_DESIGN.md # Technical specifications
├── docker-compose.yml    # Full stack with Express.js backend + Nginx
├── docker-compose.simple.yml # Simple setup with Express.js backend (no Nginx)
├── docker-compose.flask.yml # Alternative Flask backend setup (for testing)
└── README.md             # This file
```

## 🚀 Quick Start

### Automated Setup (Recommended)

The easiest way to get started with development:

```bash
# Clone the repository
git clone https://github.com/c39018084/yublog.git
cd yublog

# Run automated setup (creates .env, SSL certs, directories)
make setup

# Start all services
make up

# Check status
docker-compose ps
```

### Option 1: Full Stack with Express.js Backend (Recommended)

The default setup uses Express.js with native WebAuthn implementation:

```bash
# Clone the repository
git clone https://github.com/c39018084/yublog.git
cd yublog

# Set up development environment
./scripts/setup-dev.sh

# Start the full stack (Express.js + React + PostgreSQL + Redis + Nginx)
docker-compose up -d

# Check status
docker-compose ps
```

### Option 2: Simple Setup with Express.js Backend

For a simpler development setup (no Nginx, direct port access):

```bash
# Use the simple composition with Express.js backend
docker-compose -f docker-compose.simple.yml up -d
```

### Option 3: Flask Backend (Alternative)

If you specifically want to use the Flask backend for testing or development:

```bash
# Option A: Full Flask stack (isolated)
docker-compose -f docker-compose.flask.yml up -d
# Access at http://localhost:3001 (frontend) and http://localhost:5001 (API)

# Option B: Manual Flask setup
docker-compose -f docker-compose.simple.yml up -d db redis

# Then run Flask backend manually
cd backend
pip install -r requirements.txt
python app.py

# Frontend in another terminal
cd frontend
npm install
npm start
```

**Access the application:**
- **Frontend**: https://localhost (nginx reverse proxy)
- **API**: https://localhost/api/health (nginx reverse proxy)
- **Direct Development Access**: 
  - Frontend: http://localhost:3000 (simple setup only)
  - Backend: http://localhost:5000 (simple setup only)
- **Database**: localhost:5432 (development access)

### Development Commands

**🚀 Quick Development Workflow (Recommended):**

```bash
# Most common: restart with fresh code after making changes
./dev.sh                # Quick restart (default command)
./dev.sh restart        # Same as above
./dev.sh logs           # Watch backend logs in real-time
./dev.sh status         # Check service status
./dev.sh rebuild        # Full rebuild (when dependencies change)
```

**📋 Makefile Commands:**

```bash
make help           # Show all available commands
make setup          # Set up development environment
make up             # Start all services
make down           # Stop all services

# Development workflow (ensures code changes are picked up):
make dev-restart    # Quick restart with code refresh (recommended)
make dev-rebuild    # Full rebuild with cache clearing
make dev-clean      # Nuclear option: clean everything and rebuild
make dev-logs       # Show backend logs in real-time

# Debugging:
make logs           # Show service logs
make status         # Show service status and resource usage
make clean          # Clean up Docker resources
```

**💡 Development Workflow Tips:**

- **After making code changes**: Run `./dev.sh` (fastest)
- **After changing dependencies**: Run `./dev.sh rebuild`
- **If something seems broken**: Run `make dev-clean` (nuclear option)
- **To watch logs while developing**: Run `./dev.sh logs`

### Database Reset (Fresh Start)

To reset the database and apply the new security features:

```bash
# Reset database with new security schema (Docker)
./scripts/reset-database-docker.sh

# Or manually with Docker
docker-compose down -v
docker-compose up -d db redis
./scripts/reset-database-docker.sh
```

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

## 🔑 Device Management

YuBlog supports comprehensive security device management for enhanced security and convenience:

### Multiple Device Support
- **Add Multiple Devices**: Register multiple YubiKeys, Touch ID, Windows Hello, etc.
- **Device Names**: Assign custom names to identify your devices easily
- **Usage Tracking**: See when each device was last used for authentication
- **Device History**: Track device creation dates and usage patterns

### Device Registration Rules
- **Account Creation**: First device registers user account (34-day cooldown)
- **Additional Devices**: Different rules for adding devices to existing accounts
- **Smart Policies**: Prevents account spam while allowing legitimate multi-device usage
- **Immediate Availability**: Add/remove devices from existing accounts without cooldown

### Device Security Features
- **Device Identification**: Uses AAGUID and attestation certificates for unique identification
- **Tampering Protection**: Cryptographic verification prevents device information spoofing
- **Trusted Devices**: Enhanced security for verified hardware manufacturers
- **Security Levels**: Devices categorized as high/medium/low security based on verification

### Managing Your Devices
1. **View Devices**: Go to Profile → Security Devices
2. **Add Device**: Click "Add New Device" and follow WebAuthn prompts
3. **Remove Device**: Click the delete button next to any device (confirmation required)
4. **Device Info**: See device names, creation dates, and last usage

### Device Management APIs
For developers integrating with YuBlog:

```bash
# List user devices
GET /api/user/devices

# Add new device
POST /api/user/devices/webauthn/begin
POST /api/user/devices/webauthn/complete

# Remove device
DELETE /api/user/devices/:deviceId
```

## 🛠️ Development Status

### ✅ **Currently Implemented:**
- WebAuthn/FIDO2 authentication (YubiKey, Touch ID, Windows Hello)
- React frontend with modern UI
- Express.js backend with native WebAuthn implementation
- Flask backend alternative with security best practices
- Blog creation, editing, and management
- User profile management
- **Multi-device support with add/remove functionality**
- **Device management UI with confirmation modals**
- **Device registration spam prevention (34-day cooldown)**
- **Smart device policies (different rules for account creation vs. adding devices)**
- **Automatic admin privileges for first user**
- **AAGUID-based device tracking and identification**
- **Device deletion and re-addition without cooldown for existing accounts**
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

- [Security Features](docs/SECURITY_FEATURES.md) - **NEW: Account spam prevention & admin privileges**
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

### 🔐 Account Spam Prevention

YuBlog implements sophisticated device-based account spam prevention:

- **Device Identification**: Uses AAGUID (Authenticator Attestation GUID) to uniquely identify security keys
- **34-Day Cooldown**: Each device can only create one account every 34 days
- **Attestation Tracking**: Tracks attestation certificate hashes for additional device verification
- **Automatic Blocking**: Prevents rapid account creation with the same device
- **User-Friendly Messages**: Clear explanations when registration is blocked with countdown timers

### 🛡️ AAGUID Anti-Spoofing Protection

**Advanced Security Feature**: YuBlog implements industry-leading AAGUID spoofing protection to prevent sophisticated attacks:

#### How AAGUID Spoofing Works (Attack Vector):
1. **Packet Interception**: Attacker intercepts WebAuthn registration packets
2. **AAGUID Modification**: Modifies the AAGUID in the attestation object
3. **Cooldown Bypass**: Attempts to bypass the 34-day device registration cooldown
4. **Multiple Account Creation**: Creates unlimited accounts with the same physical device

#### Our Protection Mechanisms:
- **Attestation Signature Verification**: Cryptographically verifies that attestation data hasn't been tampered with
- **Certificate Chain Validation**: Validates attestation certificates against known manufacturer chains
- **Trusted Device Database**: Maintains whitelist of known trusted security key manufacturers:
  - YubiKey 5 Series (`149a20218ef6413396b881f8d5b7f1f5`)
  - Windows Hello (`f8a011f38c0a4d15800617111f9edc7d`)
  - Touch ID (`08987058cadc4b81b6e130de50dcbe96`)
  - Chrome Touch ID (`9ddd1817af5a4672a2b93e3dd95000aa`)
- **Device Fingerprinting**: Additional cryptographic device identification beyond AAGUID
- **Security Level Assessment**: Categorizes devices as high/medium/low security based on verification
- **Real-time Tamper Detection**: Detects and logs any attempts to modify device information

#### Technical Implementation:
```javascript
// Enhanced device verification prevents AAGUID spoofing
const deviceInfo = extractDeviceInfo(attestationObject);
if (deviceInfo.securityLevel === 'high' && deviceInfo.attestationVerified) {
  // Trusted device with verified attestation
  await recordDeviceRegistration(deviceInfo);
} else {
  // Additional verification required for unverified devices
  console.warn('Unverified device attempted registration');
}
```

This protection ensures that even sophisticated attackers cannot bypass our spam prevention by manipulating device identification data.

### 👑 Admin Privileges

- **First User Admin**: The first user to register automatically receives administrator privileges
- **Audit Trail**: All admin privilege grants are logged for security monitoring
- **Database Trigger**: Automatic privilege assignment via PostgreSQL trigger

### 📊 Enhanced Monitoring

- **Device Registration Logs**: Track all device registration attempts and blocks
- **Audit Events**: Comprehensive logging of security events including:
  - Account creation attempts
  - Device registration blocks
  - Admin privilege grants
  - Authentication attempts
- **Security Analytics**: Monitor patterns to detect potential abuse

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
