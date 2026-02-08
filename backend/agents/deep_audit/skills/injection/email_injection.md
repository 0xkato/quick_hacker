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
