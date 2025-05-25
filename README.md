# YuBlog - Passwordless Secure Blogging Platform

A self-hosted, highly secure blogging platform with passwordless authentication using YubiKey (FIDO2/WebAuthn) for ultimate security without passwords.

## 🔒 Security Features

- **Passwordless Authentication**: No passwords stored or used anywhere
- **YubiKey Support**: Full FIDO2/WebAuthn hardware security key integration
- **End-to-End Encryption**: TLS 1.3 with modern cipher suites
- **Rate Limiting**: Protection against brute force attacks
- **Audit Logging**: Complete security event tracking
- **Session Management**: Secure JWT-based sessions with Redis storage
- **No Personally Identifiable Information**: No need to worry about PII

## ⚠️ IMPORTANT SECURITY NOTICE

**BEFORE DEPLOYING TO PRODUCTION:**

1. **NEVER use the default passwords** in docker-compose files
2. **ALWAYS create your own .env file** with strong, unique credentials
3. **GENERATE new JWT secrets** using: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
4. **Use proper SSL certificates** from a trusted Certificate Authority
5. **Enable firewall** and restrict access to necessary ports only
6. **Regular security updates** and monitoring

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
│   ├── src/              # React components and logic
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

### Option 1: Full Stack with Express.js Backend (Recommended)

The default setup uses Express.js with native WebAuthn implementation:

```bash
# Clone the repository
git clone https://github.com/yourusername/yublog.git
cd yublog

# Copy environment file and configure
cp environment.example .env
# Edit .env with your settings

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
- Frontend: https://localhost (or http://localhost:3000 in dev mode)
- API Documentation: https://localhost/api/health
- Database: localhost:5432 (in dev mode)

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
