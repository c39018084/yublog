# YuBlog User Manual

**Version 1.0**  
**Date: December 2024**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Account Registration](#account-registration)
4. [Signing In](#signing-in)
5. [Dashboard Overview](#dashboard-overview)
6. [Creating and Managing Posts](#creating-and-managing-posts)
7. [Security Device Management](#security-device-management)
8. [Account Settings](#account-settings)
9. [Security Features](#security-features)
10. [Troubleshooting](#troubleshooting)
11. [FAQ](#faq)

---

## Introduction

Welcome to **YuBlog** - a secure, modern blogging platform that prioritizes your privacy and security. YuBlog uses advanced WebAuthn technology with hardware security keys to provide passwordless authentication that's both convenient and secure.

### Key Features
- **Passwordless Authentication**: No passwords to remember or lose
- **Hardware Security Keys**: Support for YubiKeys, Touch ID, Face ID, and Windows Hello
- **Rich Blog Editor**: Create beautiful posts with our intuitive editor
- **Real-time Dashboard**: Track your posts, drafts, and device security
- **Privacy-First**: Your data is encrypted and secure
- **34-Day Device Protection**: Prevents spam and abuse

---

## Getting Started

### System Requirements
- **Browser**: Chrome 67+, Firefox 60+, Safari 13+, or Edge 18+
- **Security Device**: Hardware security key (YubiKey), Touch ID, Face ID, Windows Hello, or similar WebAuthn-compatible authenticator
- **Internet Connection**: Required for all operations

### Supported Security Devices
- **YubiKey Series**: 5, 5C, 5 NFC, 5C NFC, Bio Series
- **Apple Devices**: Touch ID, Face ID (on supported Mac/iOS devices)
- **Windows**: Windows Hello (fingerprint, face recognition, PIN)
- **Android**: Fingerprint sensors, face unlock
- **Other**: Any FIDO2/WebAuthn compatible authenticator

---

## Account Registration

### Step 1: Access the Registration Page
1. Visit the YuBlog website
2. Click **"Sign In"** in the top navigation
3. The authentication page will load

### Step 2: Create Your Account
1. Click **"Create New Account"** 
2. Fill in your details:
   - **Username**: 3-50 characters, letters, numbers, hyphens, and underscores only
   - **Email**: Optional but recommended for account recovery
   - **Display Name**: Optional, how your name appears on posts

### Step 3: Register Your Security Device
1. Click **"Create Account"**
2. You'll see a prompt to use your security device
3. **For Hardware Keys**: Insert your key and touch the metal contact
4. **For Biometric**: Use your fingerprint, face, or PIN as prompted
5. **For Mobile**: Follow your device's authentication prompts

### Step 4: Account Created!
- You'll see a success message with setup confirmation
- Your account is immediately ready to use
- You can start creating posts right away

### Important Notes
- **34-Day Rule**: Each security device can only create one account every 34 days
- **Device Blocking**: If blocked, you'll see exactly when you can try again
- **No Passwords**: You'll never need to remember a password

---

## Signing In

### Quick Sign-In Process
1. Go to the YuBlog website
2. Click **"Sign In"**
3. Enter your **username**
4. Click **"Sign In with Security Key"**
5. Use your security device when prompted
6. You're signed in!

### What Happens During Sign-In
- Your browser connects to your security device
- The device verifies your identity (touch, biometric, PIN)
- A secure token is created for your session
- You're automatically redirected to your dashboard

### Troubleshooting Sign-In
- **Device not detected**: Ensure it's properly connected/enabled
- **Wrong username**: Check spelling and case sensitivity
- **Timeout**: The process times out after 60 seconds - try again
- **Browser issues**: Try refreshing the page

---

## Dashboard Overview

Your dashboard is your command center for managing your YuBlog experience.

### Dashboard Statistics
- **Total Posts**: All posts you've created
- **Published Posts**: Posts visible to the public
- **Draft Posts**: Unpublished posts you're working on
- **Security Devices**: Number of registered authentication devices

### Quick Actions
- **Create New Post**: Start writing immediately
- **Manage Devices**: Add or remove security devices
- **View Analytics**: Coming soon - post performance metrics
- **My Posts**: Access all your posts for editing

### Navigation
- **Dashboard**: Your main overview page
- **Create**: Write new blog posts
- **Blog**: View all public posts
- **Profile**: Manage account settings and devices

---

## Creating and Managing Posts

### Creating a New Post

#### Method 1: From Dashboard
1. Click **"Create New Post"** on your dashboard
2. The post editor will open

#### Method 2: From Navigation
1. Click **"Create"** in the top navigation
2. The post editor will open

### Using the Post Editor

#### Basic Information
- **Title**: Your post's headline (required)
- **Content**: Your post body (required, supports Markdown)
- **Tags**: Optional keywords for categorization

#### Content Formatting
The editor supports **Markdown syntax**:
- `# Heading 1`, `## Heading 2`, etc.
- `**bold text**` for **bold**
- `*italic text*` for *italic*
- `[Link text](URL)` for links
- `![Alt text](image-URL)` for images
- Code blocks with triple backticks

#### Publishing Options
- **Save as Draft**: Keep working on it later
- **Publish**: Make it live immediately
- **Preview**: See how it will look (coming soon)

### Managing Existing Posts

#### From Your Profile
1. Go to **Profile** → **My Posts** tab
2. You'll see all your posts with options to:
   - **Edit**: Modify the post content
   - **View**: See the published version
   - **Delete**: Permanently remove the post

#### Post Status
- **Published**: ✅ Live and visible to everyone
- **Draft**: 📝 Only visible to you

#### Editing Posts
1. Click the **edit icon** (pencil) next to any post
2. Make your changes in the editor
3. Click **"Update Post"** to save changes
4. Published posts update immediately

---

## Security Device Management

YuBlog supports multiple security devices for enhanced security and convenience.

### Adding Additional Devices

#### Why Add Multiple Devices?
- **Backup**: Don't get locked out if you lose a device
- **Convenience**: Use different devices on different computers
- **Family**: Share account access securely (not recommended)

#### How to Add a Device
1. Go to **Profile** → **Security Devices** tab
2. Click **"Add Device"**
3. Enter a descriptive name (e.g., "YubiKey 5C", "MacBook Touch ID")
4. Click **"Add Device"**
5. Use your new security device when prompted

#### Device Restrictions
- **Same 34-day rule applies**: Each physical device can only be added once every 34 days
- **Spam prevention**: This prevents abuse of the platform
- **Blocked devices**: You'll see exactly when you can try again

### Managing Your Devices

#### Viewing Your Devices
Each device shows:
- **Device Name**: The name you gave it
- **Date Added**: When you registered it
- **Last Used**: When you last signed in with it
- **Counter**: Internal security counter (technical detail)

#### Removing Devices
1. Click the **red trash icon** next to any device
2. Confirm the removal
3. The device is immediately revoked

#### Security Best Practices
- **Keep at least 2 devices**: For backup access
- **Remove lost devices**: Immediately remove devices you've lost
- **Use descriptive names**: "Work YubiKey", "Personal Touch ID", etc.
- **Regular review**: Check your devices monthly

---

## Account Settings

### Profile Information

#### Viewing Your Profile
Go to **Profile** → **Profile** tab to see:
- **Username**: Cannot be changed after registration
- **Email**: Can be updated (coming soon)
- **Display Name**: How you appear on posts
- **Account Created**: When you joined YuBlog

#### Updating Your Information
Currently, most profile information is set during registration. Updates coming in future versions.

### Security Settings

#### Session Management
- Sessions expire after 24 hours of inactivity
- You can sign out manually from any page
- All devices share the same account but have separate sessions

#### Audit Log
YuBlog maintains detailed security logs (admin access only):
- Sign-in attempts and successes
- Device additions and removals
- Post creation and modifications
- Security events and blocks

---

## Security Features

### WebAuthn Technology
YuBlog uses the **WebAuthn standard** (also called FIDO2):
- **Phishing-resistant**: Works only on legitimate YuBlog sites
- **No shared secrets**: Your device never sends passwords over the internet
- **Strong cryptography**: Military-grade security
- **Privacy-preserving**: No tracking across sites

### Device Spam Prevention
The **34-day restriction** prevents:
- **Account farming**: Creating many accounts quickly
- **Spam operations**: Large-scale abuse
- **Resource abuse**: Overloading our systems

### Data Protection
- **Encrypted storage**: All data encrypted at rest
- **Secure transmission**: HTTPS everywhere
- **Minimal data collection**: We only store what's necessary
- **No tracking**: No third-party trackers or analytics

### Session Security
- **Short-lived tokens**: Sessions expire automatically
- **IP tracking**: Unusual locations are logged
- **Device fingerprinting**: Detects session hijacking attempts
- **Automatic logout**: After 24 hours of inactivity

---

## Troubleshooting

### Common Issues and Solutions

#### "WebAuthn not supported"
**Problem**: Your browser doesn't support WebAuthn  
**Solution**: Update to a modern browser (Chrome 67+, Firefox 60+, Safari 13+, Edge 18+)

#### "Device not detected"
**Problem**: Security device isn't working  
**Solutions**:
- **Hardware keys**: Ensure properly inserted and try different USB ports
- **Touch ID/Face ID**: Check that it's enabled in System Preferences
- **Windows Hello**: Verify it's set up in Windows Settings
- **Try a different device**: Use another registered security device

#### "Registration blocked"
**Problem**: Device was recently used to create an account  
**Solution**: Wait until the displayed date (maximum 34 days) or use a different device

#### "Challenge expired"
**Problem**: Took too long to complete authentication  
**Solution**: Refresh the page and try again (you have 60 seconds)

#### "Posts not saving"
**Problem**: Post creation/editing fails  
**Solutions**:
- Check your internet connection
- Ensure you're still signed in
- Try refreshing the page
- Check that title and content are filled

#### "Can't sign in"
**Problem**: Authentication keeps failing  
**Solutions**:
- Verify your username spelling
- Try a different security device
- Clear browser cache and cookies
- Check for browser updates

### Getting Help

#### Self-Service Options
1. **Refresh the page**: Solves many temporary issues
2. **Try a different browser**: Rules out browser-specific problems
3. **Check device settings**: Ensure security features are enabled
4. **Wait and retry**: Some issues are temporary

#### Contact Support
If problems persist:
- **Technical issues**: Use the contact form on our website
- **Account problems**: Email support with your username
- **Security concerns**: Report immediately via our security contact

---

## FAQ

### General Questions

**Q: Do I need to remember a password?**  
A: No! YuBlog is completely passwordless. You only need your security device.

**Q: What if I lose my security device?**  
A: If you have multiple devices registered, use another one. If not, contact support for account recovery.

**Q: Can I use YuBlog on my phone?**  
A: Yes! Most modern phones support WebAuthn through biometrics or built-in security chips.

**Q: Is YuBlog free?**  
A: Yes, YuBlog is currently free to use with no limits on posts or devices.

### Security Questions

**Q: How secure is YuBlog compared to password-based sites?**  
A: Much more secure! WebAuthn prevents phishing, credential stuffing, and password breaches.

**Q: Can someone hack my account if they steal my device?**  
A: They would need both your device AND your biometric (fingerprint/face) or PIN, making it extremely difficult.

**Q: Why the 34-day device restriction?**  
A: This prevents spam and abuse while being reasonable for legitimate users.

**Q: Do you store my biometric data?**  
A: No! Biometrics never leave your device. We only receive cryptographic proofs.

### Technical Questions

**Q: What browsers work with YuBlog?**  
A: Chrome 67+, Firefox 60+, Safari 13+, Edge 18+, and other modern browsers with WebAuthn support.

**Q: Can I use YuBlog offline?**  
A: No, YuBlog requires an internet connection for all operations.

**Q: Does YuBlog work with my company's security policies?**  
A: YuBlog follows enterprise security standards and should work with most corporate networks.

**Q: Can I export my data?**  
A: Data export features are planned for future releases.

### Usage Questions

**Q: How many posts can I create?**  
A: There's no limit on the number of posts you can create.

**Q: Can I collaborate with other users?**  
A: Collaboration features are planned for future releases.

**Q: Can I customize my blog's appearance?**  
A: Theme customization is planned for future releases.

**Q: Do you support custom domains?**  
A: Custom domain support is planned for future releases.

---

## Conclusion

YuBlog represents the future of secure, passwordless web applications. By combining modern security technology with an intuitive user experience, we've created a platform that's both highly secure and easy to use.

### Key Takeaways
- **No passwords needed**: Just your security device
- **Multiple device support**: Add backups for convenience
- **34-day protection**: Prevents spam while allowing legitimate use
- **Rich content creation**: Full Markdown support for beautiful posts
- **Privacy-focused**: Minimal data collection and strong encryption

### Support and Community
- **Documentation**: This manual and our technical docs
- **Support**: Contact us through the website for any issues
- **Updates**: We regularly improve security and add features
- **Feedback**: We welcome suggestions for improvements

Welcome to the passwordless future with YuBlog!

---

*This manual was last updated in December 2024. Features and procedures may change as YuBlog evolves.* 