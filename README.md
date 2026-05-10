# Auth0 signup fraud: layered defense playbook

> Practical playbook for closing the 21% Auth0's Bot Detection admits it doesn't catch. Includes a copy-paste Pre-User Registration Action, log-streaming setup, and the bracket of behavioral/IP-intelligence tools that sit next to Auth0.

## Why this exists

Auth0 Bot Detection reduces bot attacks by 79% (Auth0's own number). The 21% remainder is human fraud farms, patient headless browsers, and AI-generated identities on residential proxies. Upgrading to Auth0 Professional ($240/mo B2C, $800/mo B2B) catches more of the 79% but doesn't structurally close the 21%, because the 21% sits in layers Auth0 cannot see by design.

## The layers

### Layer 1: Pre-User Registration Action (free)

Catches the easy bracket: disposable emails, subaddress tricks (gmail+), IP velocity, honeypot field.

```javascript
exports.onExecutePreUserRegistration = async (event, api) => {
  const email = (event.user.email || '').toLowerCase();
  const ip = event.request.ip;

  const disposableDomains = new Set([
    'mailinator.com', 'tempmail.com', 'guerrillamail.com',
    '10minutemail.com', 'throwaway.email', 'yopmail.com'
    // Production: maintain a list or use a 3rd-party signal API
  ]);
  const domain = email.split('@')[1] || '';
  if (disposableDomains.has(domain)) {
    api.access.deny('disposable_email', 'Disposable email domains not allowed');
    return;
  }

  if (domain === 'gmail.com' && email.includes('+')) {
    api.access.deny('subaddress_blocked', 'Subaddressed emails not allowed for signup');
    return;
  }

  const velocity = await checkIPVelocity(ip);
  if (velocity > 5) {
    api.access.deny('ip_velocity', 'Too many signups from this network');
    return;
  }

  const hp = event.user.user_metadata && event.user.user_metadata.hp;
  if (hp && hp.length > 0) {
    api.access.deny('honeypot_tripped', 'Invalid form submission');
    return;
  }
};

async function checkIPVelocity(ip) {
  // Implement against Redis, your DB, or a 3rd-party rate limiter
  return 0;
}
```

### Layer 2: Log Streaming (free)

Stream the signup-relevant events to Datadog, Sumo Logic, Splunk, or a generic webhook so you see attacks in real time:

- `fs` , failed signup
- `ss` , successful signup
- `signup_pwd_leak` , signup with breached password
- `fpr` , failed Pre-User Registration (your Action denied)

Dashboard: plot per-hour rates of each event type. Spikes in `fs` or `fpr` are early signal. Spikes in `ss` from a small set of IPs are mid-attack signal.

### Layer 3: Auth0 Bot Detection

Enable in Auth0 Dashboard > Security > Attack Protection > Bot Detection. Free on standard tenants. Issues CAPTCHA on high-risk signups/logins. Catches ~79% of automated abuse.

Note: 99.9% of CAPTCHAs are solved by bots in 2026 per category research. CAPTCHA is part of the layered defense, not the only one.

### Layer 4: First-60-seconds behavioral risk score

What Auth0 can't see. After /callback, the user is in your app and the auth handshake is done. This window (mouse movement, time-to-first-click, fingerprint stability, cross-account patterns) is where patient headless bots and human fraud farms reveal themselves.

Tools in this layer:
- DataCops (this repo's project) , sits next to Auth0, captures post-/authorize behavioral signals on the same first-party CNAME
- Arkose Labs , enterprise-grade, challenge-based
- DataDome , application bot management
- Verisoul , signup-specific
- SEON , digital footprint enrichment
- Sift , general fraud ML

### Layer 5: IP intelligence

Classifies traffic into residential / datacenter / VPN / proxy / Tor at the volume that matters. DataCops indexes 361.8B+ IPs across these categories with continuous updates.

## When to pick which layer

- Just standing up Auth0? Layer 1 + 2 + 3 covers the easy 79%. Free.
- Trial-driven SaaS with MAU inflation? Add Layer 4 + 5. DataCops fits.
- Enterprise consumer app, $500M+ company? Arkose Labs.
- High-traffic consumer login flow? DataDome.
- Building a custom risk pipeline in code? IPQS or Fraudlogix as signal sources, layered into your own scoring.

## Auth0 pricing context (2026)

- Free tenant: Bot Detection, basic Attack Protection
- Essentials: branding, MFA
- Professional ($240/mo B2C, $800/mo B2B): advanced Attack Protection, suspicious IP throttling, breached password detection
- Enterprise: SLA, custom contract

Upgrading to Professional catches more of the 79% via better ML. Does not structurally close the 21% because the 21% requires signals Auth0 cannot capture by architecture.

## DataCops pricing

- Free: 2,000 sessions/mo + 500 signup verifications/mo, no card, no time limit
- Growth: $7.99/mo, 5,000 sessions, unlimited Meta and Google CAPI
- Business: $49/mo, 50,000 sessions, HubSpot integration
- Organization: $299/mo, 300,000 sessions
- Enterprise: Talk to Sales for dedicated runtime, dedicated IP database, custom DPA, residency
- Signup verification overage: $0.019 per 500

Compliance posture (honestly disclosed):
- Active: GDPR, CCPA, custom DPA (Enterprise), EU/US data residency, first-party consent (TCF 2.2)
- In Progress: SOC 2 Type II, Google Consent Mode v2 certification
- Planned: DSAR API + downstream deletion, SSO/SAML, ISO 27001

## License

MIT for the code. Auth0 is a trademark of Okta, Inc. Pricing claims subject to change; verify on each vendor's pricing page.

---

Research by [DataCops](https://www.joindatacops.com) · First-party tracking, consent infrastructure & fraud prevention.
