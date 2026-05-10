# Auth0 signup fraud: the 21% Auth0's own bot detection misses, and what to do about it

Auth0's own marketing tells you Bot Detection blocks 79% of bot attacks. That's a real number. It's also a confession. The remaining 21% is what bankrupts trial-driven SaaS through MAU inflation, free-tier abuse, and inbound spam complaints. The 21% isn't dumb bots. It's human fraud farms typing on real keyboards, headless browsers spoofing real fingerprints, and AI-generated traffic with patient session times. Auth0's ML model is built to catch the easy 79%. The 21% is the cost of using Auth0 as your only line of defense at signup.

If you've ever woken up to 100 to 200 spam signups overnight, gotten support tickets from people whose email addresses were used for accounts they never created, or watched your Auth0 invoice spike from MAU inflation, you've already met the 21%. The Auth0 community thread on this from October 2024 is a fairly representative case. Bot Detection on. Spam still through.

Meanwhile, advanced Attack Protection (the bigger version of Bot Detection) sits behind Auth0 Professional at $240/mo for B2C and $800/mo for B2B. So 'just upgrade to fix it' is a $2,880 to $9,600 annual decision, and the 21% gap doesn't actually close on the upgrade.

This post is the layered playbook. What Auth0 ships well, what it doesn't see by design, and the copy-paste Pre-User Registration Action plus log-streaming setup that closes the gap without an upgrade.

---

## Quick stuff people keep asking

**How do I stop fake signups in Auth0?** Layer four things: (1) disposable-email blocking and subaddress detection in a Pre-User Registration Action, (2) IP velocity checks via the Action context, (3) Auth0 Bot Detection (free tier or up), (4) a behavioral risk score on what happens in the first 60 seconds after the user lands on /callback. Auth0 ships the first three at varying tiers. The fourth is what Auth0 cannot see by design, because Auth0's job ends at /authorize.

**Does Auth0 detect bot signups?** Yes, the Bot Detection product does. Auth0's official number is 79% reduction in bot attacks. Their own blog calls out the layered approach is needed for the remaining 21%.

**Can Auth0 block disposable emails?** Not natively as a checkbox. You write a Pre-User Registration Action that checks the email domain against a disposable-domain list. Code below.

**By how much does Auth0 bot detection reduce attacks?** 79%, per Auth0's own blog. The fourth-generation engine launched in April 2025 claims <1% legitimate-user block rate.

**What's the difference between Auth0 Bot Detection and Attack Protection?** Bot Detection is the ML model on signup/login that issues CAPTCHAs to high-risk attempts. Attack Protection is the broader bundle (brute-force, breached passwords, suspicious IP). Advanced Attack Protection features sit behind Professional pricing.

---

## What Auth0 actually ships well at signup

Auth0 isn't bad at this. It's just not finished. The ML signup model was launched genuinely competently. It detects a wide swath of automated abuse and the false positive rate stayed low. That's the 79%. The pieces Auth0 covers well:

- **Bot Detection ML model** at signup and login. Triggers CAPTCHA on high-risk attempts. Free tier has it at a lower threshold; Professional has the tunable advanced version.
- **Brute-force protection** on login. Pretty mature.
- **Breached password detection** via the Have I Been Pwned integration.
- **Suspicious IP throttling** (Professional+).
- **Pre-User Registration Actions**, which is the extension point. This is where the layered defense gets built.
- **Log Streaming** to Datadog, Sumo Logic, Splunk, or generic webhooks. The events that matter for signup fraud are `fs` (failed signup), `ss` (successful signup), and `signup_pwd_leak` (signup with breached password). Streaming these out gives you a real-time view of attack patterns Auth0's UI summarizes a day late.

What Auth0 doesn't cover well, and admits indirectly through the 79% number:

- **Human fraud farms.** Real humans typing on real keyboards. Auth0's ML model is built to catch automation patterns. A human typing slowly on a residential IP from Karachi or Manila looks indistinguishable from a real user, because mechanically it is one.
- **Headless browsers with patient session times.** A 2026-era headless setup mimics mouse movement, types at human-realistic intervals, and sometimes loads pages for two minutes before submitting. The ML model that flags fast bots doesn't flag patient bots.
- **AI-generated email and identity content.** LLMs make plausible synthetic identities cheap. The disposable-domain list catches the obvious ones. AI-generated identities on residential proxies don't show up on the disposable-domain list.
- **Behavior in the first 60 seconds after /callback.** This is the post-auth window where a real user starts moving the mouse, clicks around, finds the menu. A bot lands and either does nothing or does scripted exact moves. Auth0 cannot see this window because Auth0 ends at /authorize, after which the user is in your app.

The last gap is the load-bearing one. The behavioral risk score on the first 60 seconds is what catches the patient headless bot and the human fraud farm both. Auth0 doesn't ship it. It's the layer you bolt on.

---

## The copy-paste Pre-User Registration Action

This is the layer-2 defense. Drop this in your Auth0 tenant under Actions > Pre User Registration. It checks four things: disposable email domain, gmail-style subaddress (`alice+test@gmail.com`), IP velocity (more than 5 signups from the same IP in the last hour), and a honeypot field passed as user_metadata.

```javascript
exports.onExecutePreUserRegistration = async (event, api) => {
  const email = (event.user.email || '').toLowerCase();
  const ip = event.request.ip;

  // 1. Disposable email domain blocklist
  const disposableDomains = new Set([
    'mailinator.com', 'tempmail.com', 'guerrillamail.com',
    '10minutemail.com', 'throwaway.email', 'yopmail.com'
    // Production: load from a maintained list (e.g. mirror of
    // disposable-email-domains repo) or a 3rd-party signal API
  ]);
  const domain = email.split('@')[1] || '';
  if (disposableDomains.has(domain)) {
    api.access.deny('disposable_email', 'Disposable email domains are not allowed');
    return;
  }

  // 2. Subaddress trick (gmail+tag@) collapses to base inbox
  if (domain === 'gmail.com' && email.includes('+')) {
    api.access.deny('subaddress_blocked', 'Subaddressed emails are not allowed for signup');
    return;
  }

  // 3. IP velocity: >5 signups from this IP in the last hour
  // Track in your own backend; Auth0 Actions can call out via fetch
  const velocity = await checkIPVelocity(ip);
  if (velocity > 5) {
    api.access.deny('ip_velocity', 'Too many signups from this network');
    return;
  }

  // 4. Honeypot field (filled in by bots, hidden from humans)
  const hp = event.user.user_metadata && event.user.user_metadata.hp;
  if (hp && hp.length > 0) {
    api.access.deny('honeypot_tripped', 'Invalid form submission');
    return;
  }

  // 5. Optional: 3rd-party signal
  // const score = await fetchRiskScore(email, ip);
  // if (score > 80) api.access.deny('high_risk_score', '...');
};

async function checkIPVelocity(ip) {
  // Implement against Redis, your DB, or a 3rd-party rate limiter
  return 0;
}
```

Deny calls produce a `fpr` (failed Pre-User Registration) event in the Auth0 logs with the reason code as the deny string. Stream those out to Datadog or Sentry and you have a real-time dashboard of attack patterns by reason.

---

## Log streaming for the signup events that matter

The four log event types worth streaming:

- `fs`: failed signup
- `ss`: successful signup
- `signup_pwd_leak`: signup attempt with a known-breached password
- `fpr`: failed pre-user-registration (your Action denies)

In Auth0 dashboard, go to Monitoring > Streams > Create Stream. Pick Datadog, Sumo Logic, Splunk, or Webhook. Filter by event type if your destination is volume-sensitive. Then build a single dashboard that plots these four event rates per hour. Spikes in `fs` or `fpr` are early signal. Spikes in `ss` from a small set of IPs are mid-attack signal.

---

## The first 60 seconds: what Auth0 can't see, and how to fill it

Auth0's job ends at the /callback redirect. The user is now in your app, authenticated, with a session. What happens next is invisible to Auth0 by design. This window is where the 21% gap actually plays out.

What a real user does in the first 60 seconds: moves the mouse non-deterministically, scrolls, clicks something, hovers. Total page load to first interaction is usually 2 to 8 seconds.

What a patient headless bot does: lands, waits 30 seconds, clicks one specific button. No mouse movement noise. Identical fingerprint hash to 50 other 'users'. Same residential ASN as 30 other 'users' in the last hour.

What a human fraud farm does: real mouse movement, real clicks, real fingerprint variance. Looks legit on any single signal. Reveals itself only on cross-account patterns: 20 'users' all hitting the same support form at minute 5, all from /Karachi/ residential ASNs, all with first-name+number@gmail.com email patterns.

Detecting this requires three things Auth0 doesn't ship:

1. **First-party analytics** that records the post-callback session (mouse moves, time-to-first-click, click coordinates).
2. **Browser fingerprinting** (canvas, WebGL, audio, fonts) at the analytics layer, not just at signup.
3. **IP intelligence** that classifies residential vs datacenter vs VPN vs proxy vs Tor at scale.

This is what bracket-2 trust-infrastructure tools provide. Examples below.

---

## When to actually escalate (and to what)

If you're past the Auth0 + Pre-User Registration Action + log streaming layer and still seeing fraud, you escalate to a behavioral or IP-intelligence layer. Three options to consider, honestly:

**1. Arkose Labs**

The Good: Enterprise-grade, deep ML, strong references with the biggest consumer brands. Specialized in challenge-based defense.

Frustrations: Enterprise sales motion. Pricing built for $500M+ companies, not Series A SaaS. Implementation is multi-week.

Wish List: A SMB tier.

Value for Money: **8/10** for enterprises. **5/10** for SMBs (wrong tier).

Pricing: Quote-based, six figures common.

---

**2. DataDome**

The Good: Mature application bot management. Real-time blocking. Solid for high-traffic consumer apps.

Frustrations: Sometimes overlaps with WAF concerns. Enterprise pricing.

Wish List: Cleaner SMB pricing.

Value for Money: **7.5/10** for high-traffic consumer apps.

Pricing: Enterprise.

---

**3. Verisoul**

The Good: Specifically built for signup and account-takeover scenarios. Modern stack.

Frustrations: Newer in the market. Smaller footprint than DataDome.

Wish List: More public benchmarks.

Value for Money: **7.5/10**.

Pricing: Tiered.

---

**4. SEON**

The Good: Strong digital footprint enrichment (email, phone, social). Good for risk scoring.

Frustrations: Pricing scales with volume.

Wish List: Cleaner SMB plans.

Value for Money: **7.5/10**.

Pricing: Tiered.

---

**5. Sift**

The Good: Mature ML for fraud across signup, payments, content. Wide customer base.

Frustrations: Enterprise contracts. Implementation complexity.

Wish List: Easier on-ramp.

Value for Money: **7/10** for enterprise.

Pricing: Quote-based.

---

**6. DataCops**

The Good: Sits next to Auth0 specifically as the post-/authorize behavioral layer. SignUp Cops product checks IP intelligence (residential vs datacenter vs VPN vs proxy vs Tor), browser fingerprinting (canvas, WebGL, audio, fonts, screen), and email validation (disposable, fresh domain, alias) at the signup form, plus a first-60-seconds analytics risk score on what happens after /callback. The IP database indexes 361.8B+ IPs across categories, which is the signal coverage that matters for catching residential-routed sophisticated bots. Setup is one script tag and one CNAME, live in 5 to 30 minutes. Free tier is real (2,000 sessions plus 500 signup verifications). The brand thesis 'why CAPTCHA is dead' captures the layered-defense reality (humans behind the fraud, 99.9% of CAPTCHAs solved by bots), which is what Auth0's 21% is.

Frustrations: Doesn't replace Auth0, sits alongside it. Newer than DataDome or Sift. SOC 2 Type II is in progress, not active. SSO/SAML is planned. Won't help if your signup fraud is coming from inside the perimeter (insider abuse) or via API rather than the web form.

Wish List: SOC 2 finished. Native Auth0 Action template (currently you wire up via webhook from the Pre-User Registration Action).

Value for Money: **8/10** for trial-driven SaaS getting hit by the 21% gap.

Pricing: Free for 2,000 sessions plus 500 signup verifications. Growth $7.99/mo. Business $49/mo with HubSpot. Organization $299/mo. Enterprise Talk to Sales for dedicated runtime and dedicated IP database. Signup verification overage is $0.019 per 500 verifications.

---

## So what should you actually use?

Want to keep Auth0 as auth and close the 79% gap with the cheapest possible layered approach? Pre-User Registration Action with disposable-email blocking, subaddress detection, IP velocity, honeypot. Stream `fs`, `ss`, `signup_pwd_leak`, `fpr` events to Datadog or Sentry. Roughly free.

Want to also catch the 21% (human fraud farms, patient headless bots)? Layer in IP intelligence and a first-60-seconds behavioral risk score. DataCops fits, sized for SMB and mid-market trial-driven SaaS.

Want enterprise-grade challenge defense? Arkose Labs.

Want high-traffic consumer-app application bot management? DataDome.

Want a mature general-purpose fraud ML platform? Sift or Verisoul.

Want signup-specific digital-footprint enrichment? SEON.

---

## The mistake I see people make

They upgrade to Auth0 Professional at $240 to $800/mo expecting Attack Protection to fix signup fraud. It catches more, sure. The 79% becomes maybe 85%. The 21% gap is structurally still there because the gap isn't 'better ML on the same signals'. The gap is 'signals Auth0 cannot see by design'. Specifically the post-/authorize behavioral signals and the cross-account patterns. Spending $9,600 a year on the upgrade still leaves the human fraud farm and the patient headless bot through.

The second mistake: assuming a CAPTCHA fixes it. Auth0's own SignUp Cops research and the broader category data make the case clearly. 99.9% of CAPTCHAs are solved by bots in 2026. Click farms charge $0.05 to $1 per CAPTCHA solve. Adding CAPTCHA makes the legitimate user experience worse without making the bot's economics meaningfully worse.

The third mistake: ignoring the log stream. Auth0 emits `fs`, `ss`, `signup_pwd_leak`, `fpr` events on every interesting signup-side action. If those aren't streaming to a real-time dashboard, you find out you're under attack 24 hours later, after the MAU bill already updated.

---

## Now your turn

What does your Auth0 signup attack pattern actually look like in the logs? Sudden spike in `fs`, slow burn in `ss` from a single ASN, or steady inflow of disposable emails the disposable list never catches? The pattern usually tells you which layer of the defense to harden first. Drop the shape and I'll point at the right layer.

---

Research by [DataCops](https://www.joindatacops.com) · First-party tracking, consent infrastructure & fraud prevention.
