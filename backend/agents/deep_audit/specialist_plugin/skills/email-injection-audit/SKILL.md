---
name: email-injection-audit
description: Detection methodology for email header injection
---

# Domain Expertise

# Email/SMTP Injection Auditor

## Expertise

You are an email and SMTP injection specialist with comprehensive knowledge of email protocols, MIME formatting, and header manipulation vulnerabilities. You understand RFC 5321 (SMTP), RFC 5322 (email format), and how email libraries construct and send messages. Your expertise covers header injection, recipient manipulation, content spoofing, and the various ways attackers can abuse contact forms and email functionality.

## Core Proficiency

- **MIME/header rules**: Email header syntax and encoding requirements
- **Newline handling**: How different libraries process CRLF in headers
- **Recipient manipulation**: Injecting additional recipients
- **Content-Type attacks**: Manipulating email body structure

## Focus Areas

### Email Header Injection
```python
# VULNERABLE: User input directly in headers
from email.mime.text import MIMEText

def send_email(from_addr, subject, body):
    msg = MIMEText(body)
    msg['From'] = from_addr  # CRLF injection possible
    msg['Subject'] = subject  # CRLF injection possible
    msg['To'] = 'support@company.com'
    smtp.send_message(msg)

# Attack: from_addr = "attacker@evil.com\r\nBcc: victim@target.com"
```

### To/CC/BCC Injection
```python
# VULNERABLE: User controls recipient field
def send_notification(user_email, message):
    # User could inject additional recipients
    msg = MIMEText(message)
    msg['To'] = user_email  # Could contain multiple addresses
    msg['From'] = 'noreply@company.com'
    smtp.send_message(msg)

# Attack: user_email = "attacker@evil.com, victim@target.com"
# Or: user_email = "attacker@evil.com\r\nBcc: victim1@target.com, victim2@target.com"
```

### Content-Type Manipulation
```python
# VULNERABLE: User controls content that becomes headers
def send_custom_email(recipient, custom_headers, body):
    msg = MIMEText(body)
    for header, value in custom_headers.items():
        msg[header] = value  # Arbitrary header injection
    msg['To'] = recipient
    smtp.send_message(msg)

# Attack: custom_headers = {'X-Custom': 'value\r\nContent-Type: multipart/mixed'}
```

### Attachment Injection
```python
# VULNERABLE: Filename from user input
from email.mime.base import MIMEBase

def attach_file(msg, filename, content):
    attachment = MIMEBase('application', 'octet-stream')
    attachment.set_payload(content)
    # Filename could contain CRLF or be manipulated
    attachment.add_header('Content-Disposition', f'attachment; filename="{filename}"')
    msg.attach(attachment)

# Attack: filename = 'doc.pdf"\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>\r\n--'
```

## Red Flags and Warning Signs

1. **User input in email headers**: From, Subject, Reply-To from user
2. **Contact forms**: All fields potentially injectable
3. **Email forwarding**: User-specified recipients
4. **Newsletter subscriptions**: Email field without validation
5. **Password reset**: User email in notifications
6. **Email templates**: User content in email body
7. **Custom headers**: X-* headers from user input
8. **Attachment handling**: User-controlled filenames

## Attack Patterns

### Adding Recipients via Bcc Injection
```
# Basic BCC injection
attacker@evil.com\r\nBcc: victim@target.com

# Multiple recipients
attacker@evil.com\r\nBcc: victim1@target.com,victim2@target.com

# Using Cc instead
attacker@evil.com\r\nCc: victim@target.com
```

### Changing Email Content
```
# Inject new body
subject\r\nContent-Type: text/html\r\n\r\n<html><body>Phishing content</body></html>

# MIME boundary manipulation
legitimate\r\n--boundary\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>\r\n--boundary--
```

### Phishing via Header Manipulation
```
# Spoof display name
"CEO <ceo@company.com>" <attacker@evil.com>

# Reply-To hijacking
attacker@evil.com\r\nReply-To: phishing@evil.com

# Return-Path manipulation
attacker@evil.com\r\nReturn-Path: fake@company.com
```

### Subject Line Injection
```
# Add recipients via Subject
Important\r\nBcc: victim@target.com\r\nSubject: Your account

# Complete header injection
Important\r\n\r\nFake email body that replaces original
```

### SMTP Command Injection
```
# If directly constructing SMTP commands
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@target.com>
DATA
Subject: Injected email

Malicious content
.
```

## Analysis Methodology

1. **Identify email functions**: Find all email sending code
2. **Trace user input**: Map request parameters to email fields
3. **Check library handling**: Does library sanitize headers?
4. **Review recipient fields**: Can users control To/Cc/Bcc?
5. **Audit subject line**: User input in subject
6. **Examine From field**: User-specified sender address
7. **Review attachment handling**: Filename sanitization
8. **Test CRLF handling**: How does library handle newlines?

## Common Protection Bypasses

### CRLF Variations
```
# Standard CRLF
\r\n

# LF only (some systems)
\n

# URL encoded
%0d%0a
%0a

# Unicode newlines
\u000a \u000d

# Header continuation (deprecated but sometimes works)
Header: value
 continuation
```

### Encoding Bypass
```
# Base64 encoded subject (RFC 2047)
=?UTF-8?B?U3ViamVjdA0KQmNjOiB2aWN0aW1AdGFyZ2V0LmNvbQ==?=

# Quoted-printable encoding
=?UTF-8?Q?Subject=0D=0ABcc:=20victim@target.com?=

# Double encoding
%250d%250a
```

### Email Address Tricks
```
# Comments in email addresses (RFC 5322)
attacker@evil.com (victim@target.com)

# Display name manipulation
"Victim <victim@target.com>" <attacker@evil.com>

# Multiple at signs (implementation dependent)
attacker@evil.com@target.com
```

## Example Vulnerable Code

### Example 1: Contact Form
```python
# contact.py - Vulnerable contact form
from flask import Flask, request
import smtplib
from email.mime.text import MIMEText

@app.route('/contact', methods=['POST'])
def contact():
    name = request.form['name']
    email = request.form['email']
    subject = request.form['subject']
    message = request.form['message']

    # VULNERABLE: All user fields used directly
    msg = MIMEText(f"Message from {name} ({email}):\n\n{message}")
    msg['Subject'] = subject  # CRLF injectable
    msg['From'] = email       # CRLF injectable
    msg['To'] = 'support@company.com'

    with smtplib.SMTP('localhost') as smtp:
        smtp.send_message(msg)

    return "Message sent!"

# Attack: email = "attacker@evil.com\r\nBcc: victim@target.com"
# Sends copy of message to victim
```

### Example 2: Newsletter Subscription
```python
# newsletter.py - Vulnerable subscription
def subscribe_to_newsletter(email, preferences):
    # VULNERABLE: Email field allows injection
    msg = MIMEText("Welcome to our newsletter!")
    msg['To'] = email  # Could contain multiple addresses or headers
    msg['From'] = 'newsletter@company.com'
    msg['Subject'] = 'Subscription Confirmed'

    # Also vulnerable: preferences could inject headers
    msg['X-Preferences'] = preferences

    smtp.send_message(msg)

# Attack: email = "attacker@evil.com, admin@company.com\r\nBcc: all-users@company.com"
# Could spam entire user base
```

### Example 3: Password Reset
```php
// reset.php - Vulnerable password reset
function sendPasswordReset($userEmail, $resetToken) {
    $to = $userEmail;  // Assumed safe but could be manipulated
    $subject = "Password Reset Request";
    $message = "Click here to reset: https://example.com/reset?token=$resetToken";

    // VULNERABLE: Additional headers from user input
    $headers = "From: noreply@company.com\r\n";
    $headers .= "Reply-To: " . $userEmail;  // CRLF injection

    mail($to, $subject, $message, $headers);
}

// Attack: userEmail = "attacker@evil.com\r\nBcc: victim@target.com"
// Sends password reset link to attacker's chosen recipients
```

## Output Format

```markdown
## Email Injection Finding

**Location**: [file:line]
**Severity**: High/Medium
**Confidence**: High/Medium/Low

**Email Library**: [smtplib/email/PHPMailer/sendmail/etc.]
**Framework**: [Flask/Django/PHP/etc.]

**Vulnerable Code**:
[code block]

**Injection Point**: [parameter/field name]
**Header Type**: [From/To/Subject/CC/BCC/Custom]

**Attack Vector**:
```
[Field injection payload]
email=attacker@evil.com%0d%0aBcc:%20victim@target.com
```

**Impact**:
- Unauthorized recipients: [Yes/No]
- Email spoofing: [Yes/No - can forge sender]
- Phishing capability: [Yes/No]
- Content manipulation: [Yes/No]
- Spam relay: [Yes/No - can use server for spam]

**Proof of Concept**:
```bash
curl -X POST "http://target/contact" \
  -d "name=Test" \
  -d "email=attacker@evil.com%0d%0aBcc:%20victim@target.com" \
  -d "subject=Test" \
  -d "message=Hello"
```

**Remediation**:
1. Validate email addresses against strict regex pattern
2. Strip or reject newline characters (\\r \\n)
3. Use email library methods that sanitize headers
4. Whitelist allowed characters in all email fields
5. For PHP: Use filter_var($email, FILTER_VALIDATE_EMAIL)
6. Consider using a mail API (SendGrid, SES) with proper escaping
```

---

# Detection Methodology

# Email Header Injection Detection

## Methodology

### Step 1: Identify Email Sending Libraries and Entry Points

Locate all code constructing and sending emails. Focus on user input entering header fields (To, From, CC, BCC, Subject, Reply-To).

**Python (smtplib / email / Django):**
```python
msg = EmailMessage()
msg['To'] = recipient          # Injection target
msg['From'] = sender           # Injection target
msg['Subject'] = subject       # Injection target
msg['Reply-To'] = reply_to    # Injection target
server.send_message(msg)
```

**Node.js (nodemailer / sendgrid):**
```javascript
transporter.sendMail({
    from: senderEmail,         // Injection target
    to: recipientEmail,        // Injection target
    subject: subject,          // Injection target
    text: body, html: htmlBody // Template injection target
});
```

**Java (JavaMail / Spring Mail):**
```java
msg.setFrom(new InternetAddress(fromEmail));       // Injection target
msg.addRecipient(RecipientType.TO, new InternetAddress(toEmail));
msg.setSubject(subject);                           // Injection target
msg.addHeader("Reply-To", replyTo);                // Injection target
```

### Step 2: Understand Email Header Injection Mechanics

Email headers are CRLF-separated. Injecting `\r\n` into any header field adds arbitrary headers.

**CC/BCC injection:** `user@example.com\r\nBCC: victim@target.com`
**Subject injection:** `Hello\r\nBCC: spam-list@attacker.com\r\n\r\nSpam body`
**From spoofing:** `legit@company.com\r\nReply-To: attacker@evil.com`

### Step 3: Trace User Input into Email Headers

```python
# VULNERABLE: contact form with user-controlled headers
@app.route('/contact', methods=['POST'])
def contact():
    msg = EmailMessage()
    msg['From'] = request.form['email']        # User-controlled
    msg['To'] = 'support@company.com'
    msg['Subject'] = request.form['subject']   # User-controlled
    msg['Reply-To'] = request.form['email']    # User-controlled
    msg.set_content(request.form['message'])
    smtp.send_message(msg)
```

```javascript
// VULNERABLE: feedback form
await transporter.sendMail({
    from: req.body.email,                      // User-controlled
    to: 'feedback@company.com',
    subject: `Feedback: ${req.body.subject}`,  // User-controlled
    text: req.body.message
});
```

### Step 4: Check for SMTP Command Injection

Raw SMTP command construction with user input enables protocol-level injection.

```python
# VULNERABLE: raw SMTP
sock.send(f'MAIL FROM:<{from_addr}>\r\n'.encode())
sock.send(f'RCPT TO:<{to_addr}>\r\n'.encode())
# Payload: from_addr = "a@b.com>\r\nRCPT TO:<victim@target.com"
```

### Step 5: Check for Template Injection in Email Bodies

```python
# VULNERABLE: SSTI in email body
body = Template(user.custom_template).render(user=user)

# VULNERABLE: HTML injection for phishing
html_body = f"<p>{message}</p>"  # Unescaped user input
```

### Step 6: Evaluate Email Validation and Sanitization

```python
# SAFE: strict email validation
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
if not EMAIL_REGEX.match(email): raise ValueError("Invalid email")
if '\r' in email or '\n' in email: raise ValueError("Invalid characters")
```

```python
# SAFE: CRLF stripping
subject = request.form['subject'].replace('\r', '').replace('\n', '')
```

**Library-level protection:** Python `email.headerregistry` (3.6+), Django send_mail (1.7+), Nodemailer (5.x+), JavaMail `InternetAddress.parse(email, true)` all validate and reject CRLF.

## Decision Tree

```
User input reaches email header field?
|
+-- NO
|   |
|   User input in HTML email body (unescaped)?
|   +-- YES --> VULNERABLE (Medium) -- phishing / HTML injection
|   +-- NO --> SAFE
|
+-- YES
    |
    +-- Address fields (To/CC/BCC/From/Reply-To)
    |   |
    |   Email validated (regex + no CRLF)?
    |   +-- YES --> SAFE
    |   +-- NO, but library auto-validates? --> HARDENED (Low)
    |   +-- NO --> VULNERABLE (High) -- spam relay
    |
    +-- Subject / custom headers
        |
        CRLF stripped/rejected?
        +-- YES --> SAFE
        +-- NO --> VULNERABLE (High) -- header injection
```

## Real-World Examples

### Example 1: Contact Form Spam Relay in Python

```python
@app.route('/contact', methods=['POST'])
def contact_form():
    sender_email = request.form['email']
    msg = EmailMessage()
    msg['From'] = f'{request.form["name"]} <{sender_email}>'
    msg['To'] = 'info@company.com'
    msg['Subject'] = f'Contact from {request.form["name"]}'
    msg.set_content(request.form['message'])
    with smtplib.SMTP('mail.company.com') as smtp:
        smtp.send_message(msg)
```

**Why vulnerable:** `sender_email` is inserted into From without validation. Attacker submits `email=a@b.com\r\nBCC: victim1@target.com, victim2@target.com`. Injected BCC causes mass-mailing through the company's mail server.

**Impact:** Spam relay abuse. Domain/IP blacklisted, affecting legitimate email delivery.

**Fix:**
```python
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
if not EMAIL_RE.match(sender_email): return 'Invalid email', 400
sender_name = request.form['name'].replace('\r', '').replace('\n', '')
msg['From'] = 'noreply@company.com'  # Fixed From
msg['Reply-To'] = sender_email       # Validated Reply-To
```

### Example 2: BCC Injection via Subject in Node.js

```javascript
app.post('/api/invite', async (req, res) => {
    const { email, teamName, personalMessage } = req.body;
    await transporter.sendMail({
        from: '"TeamApp" <invites@teamapp.com>',
        to: email,
        subject: `You're invited to join ${teamName}`,
        html: `<h1>Join ${teamName}</h1><p>${personalMessage}</p>`
    });
});
```

**Why vulnerable:** On nodemailer < 5.x, `teamName=MyTeam\r\nBCC: spam-list@attacker.com` injects a BCC header. Additionally, `personalMessage` enables HTML injection for phishing.

**Impact:** Spam relay from trusted domain. Phishing content injection.

**Fix:**
```javascript
const safeTeamName = teamName.replace(/[\r\n]/g, '').substring(0, 100);
const safeMessage = validator.escape(personalMessage);
if (!validator.isEmail(email)) return res.status(400).json({ error: 'Invalid email' });
```

### Example 3: Multiple Recipient Injection in Java

```java
@PostMapping("/api/subscribe")
public ResponseEntity<String> subscribe(@RequestParam String email) {
    SimpleMailMessage msg = new SimpleMailMessage();
    msg.setFrom("newsletter@company.com");
    msg.setTo(email);
    msg.setSubject("Subscription Confirmed");
    msg.setText("You've been subscribed.");
    mailSender.send(msg);
    return ResponseEntity.ok("Subscribed");
}
```

**Why vulnerable:** `email` passed to `setTo()` without validation. Comma-separated addresses (`a@b.com,victim@x.com`) or CRLF injection adds recipients.

**Impact:** Spam relay through company SMTP infrastructure.

**Fix:**
```java
if (!email.matches("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"))
    return ResponseEntity.badRequest().body("Invalid email");
if (email.contains("\r") || email.contains("\n") || email.contains(","))
    return ResponseEntity.badRequest().body("Invalid email");
InternetAddress addr = new InternetAddress(email, true);
addr.validate();
msg.setTo(addr.getAddress());
```

## Common False Positive Patterns

1. **Fixed sender/recipient addresses** -- Hardcoded `msg.setTo("support@company.com")` has no injection surface.

2. **Modern library with header validation** -- Nodemailer 5.x+, Django 1.7+, Python `email.headerregistry` reject CRLF. Verify version.

3. **User input only in email body** -- Body injection is lower severity (phishing/HTML injection) than header injection.

4. **Email from authenticated session** -- Recipient from user profile (validated at registration), not raw HTTP input.

5. **Transactional email APIs** -- SendGrid, Mailgun, AWS SES validate at API level before SMTP.

6. **Email preview/draft functionality** -- No transmission means no spam relay risk (though stored XSS possible).

7. **Logging of email addresses** -- Recording addresses for audit is a log injection concern, not email injection.
