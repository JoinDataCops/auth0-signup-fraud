# Auth0 signup fraud

Auth0 says its Bot Detection cuts bot attacks by 79 percent. That is a real number and it is published on their own blog. **It is also the number that should make you nervous, not relieved.** Because 79 percent reduction means 21 percent gets through, and the 21 percent that gets through Auth0's bot detection is not the dumb traffic. It is the human fraud farms and the sophisticated headless browsers that were always going to be the hard part.

I will be blunt about what Auth0 actually gives you here. Auth0 is excellent identity infrastructure. Its Attack Protection suite (Bot Detection, Brute Force Protection, Suspicious IP Throttling, Breached Password Detection) is solid for what it targets, which is credential attacks and crude automation. **What it is not is a signup-fraud system.** It blunts the volume. It does not see the fake human who signs up once, looks completely normal, and is there to abuse your free tier or your referral program.

This is not a "rip out Auth0" post. **Keep Auth0.** This is a post about the 21 percent, and about a copy-paste Auth0 Action you can ship today to catch a real slice of it. [DataCops](/signup-cops) shows up once, at the end, because the last layer of this problem is one Auth0 was never built to touch. See also [signup fraud detection](/resources/signup-fraud-detection).

## Quick stuff people keep asking

**How do you stop fake signups in Auth0?** Layer it. Turn on Bot Detection in Attack Protection, add an Auth0 Action on the pre-registration or post-login flow that checks [disposable email](/resources/best-disposable-email-blocker), plus-address abuse, and IP velocity, and pipe your Attack Protection logs somewhere you actually watch. No single switch does it.

**Does Auth0 detect bot signups?** Partially. Bot Detection adds a CAPTCHA-style challenge when it sees suspicious patterns, and Auth0 reports a 79 percent reduction in bot attacks. It catches volumetric automation. It does not catch human fraud farms or well-built headless browsers that pass the challenge.

**What is Auth0 Attack Protection?** Auth0's bundle of defensive features: Bot Detection, Brute Force Protection, Suspicious IP Throttling, and Breached Password Detection. It is aimed at credential attacks and automated abuse. It is on by default for newer tenants but worth verifying in your dashboard.

**How does Auth0 Bot Detection work?** It scores incoming auth traffic for bot-like signals and, when risk is high, injects a CAPTCHA challenge before letting the request through. The model leans on IP reputation and request patterns. The weak point in 2026 is that CAPTCHA is widely solved by bots and bypassed by paid human solvers.

**Can Auth0 block disposable emails?** Not natively in a strong way. There is no built-in maintained disposable-domain blocklist. You add it yourself with an Action that checks the signup email against a disposable-domain list before the account is created.

**How do I write an Auth0 Action to detect signup fraud?** Use a pre-user-registration or post-login Action. In the handler, inspect the email and the request context, check the email domain against a disposable list, detect plus-addressing and dot-trick variants, count recent signups from the same IP, and either deny or attach a risk flag to app_metadata. Code is below.

**By how much does Auth0 Bot Detection reduce attacks?** Auth0's published figure is 79 percent. Treat it as a volume reduction on crude automation, not a fraud-elimination number. Plan explicitly for the remaining 21 percent, which is the sophisticated and human-driven fraud.

## The gap: Auth0 stops the noise, not the fraud that looks human

Here is the structural limit, stated plainly.

Auth0's Attack Protection is built to defend the authentication event. Is this request automated. Is this credential stuffing. Is this IP hammering the login endpoint. Is this password in a known breach. Good questions, well answered. But they are all attack-shaped questions. They assume the threat is volume, speed, and stolen credentials.

A growing share of signup fraud in 2026 is none of those things. It is a [fake account](/resources/best-fake-account-detection-2026) that is created slowly, once, by a real human in a fraud farm or by a headless browser tuned to look human. It solves the CAPTCHA, because CAPTCHA solve rates by bots and paid solvers now sit in the 90 to 99 percent range. It does not trigger brute-force throttling, because it only signs up once. Its password is not breached, because it is freshly generated. Every Attack Protection check waves it through, correctly by the rules it was given, because none of those checks was designed to ask the real question: is this a genuine future customer or a fake one.

That is the 21 percent. It is not leftover noise. It is the actual adversary, and it is the part Auth0 leaves to you.

Here is the proof of how bad the leftover can be. An AI startup called PillarlabAI ran a signup honeypot. The result was 3,000 signups, 77 percent of them fraudulent, and 650 of those accounts traced back to a single [device fingerprint](/alternative/fingerprintjs-alternative). One machine, 650 identities. Now ask what Auth0 Bot Detection would have done with that. Some of the 650 might have tripped IP velocity if they shared an address. But a competent operator rotates IPs, rotates emails, and paces the signups. The fingerprint stays constant while everything Auth0 inspects keeps changing. Auth0 sees 650 unremarkable registrations. The honeypot saw one fraud ring.

So you build the missing layer yourself. Here is a pre-user-registration Auth0 Action that does real work:

```javascript
const DISPOSABLE = new Set([
  'mailinator.com','guerrillamail.com','10minutemail.com',
  'tempmail.com','trashmail.com','yopmail.com','sharklasers.com'
]);

exports.onExecutePreUserRegistration = async (event, api) => {
  const email = (event.user.email || '').toLowerCase();
  const [local, domain] = email.split('@');

  // 1. Disposable email domain
  if (DISPOSABLE.has(domain)) {
    api.access.deny('disposable_email', 'Disposable email addresses are not allowed.');
    return;
  }

  // 2. Subaddress and dot-trick abuse (one inbox, many signups)
  const canonical = local.split('+')[0].replace(/\./g, '');
  api.user.setAppMetadata('email_canonical', canonical + '@' + domain);

  // 3. IP velocity - needs your own counter store
  const ip = event.request.ip;
  const recent = await countRecentSignupsFromIP(ip); // your KV / Redis lookup
  if (recent >= 5) {
    api.access.deny('ip_velocity', 'Too many signups from this network.');
    return;
  }

  // 4. Risk score instead of hard block - let downstream decide
  let risk = 0;
  if (recent >= 2) risk += 30;
  if (local.includes('+')) risk += 20;
  if (/\d{4,}/.test(local)) risk += 15; // long digit runs
  api.user.setAppMetadata('signup_risk_score', risk);
};
```

The canonical-email field collapses `jane+promo1@gmail.com` and `j.ane@gmail.com` into one identity so you can catch one inbox spinning up many accounts. The IP-velocity check needs a small counter store you maintain, Redis or a KV namespace, because Auth0 will not count for you. And critically, not everything is a hard deny. The risk score is the right move for ambiguous cases: stamp it on app_metadata and let your application decide whether to gate features, hold for review, or watch.

Then send your Attack Protection logs somewhere you watch them. Auth0's log stream pushes to Datadog, Sentry, or any webhook. Alert on `f` event codes for failed signups, on bursts from one IP range, on disposable-email denials clustering. Log analysis is reactive, it tells you about fraud after the account exists, so treat it as your audit trail, not your front door.

But here is the layer the Action still cannot reach, and this is the honest core of it. A fake signup that clears every check above does not just sit quietly in your user table. It fires a conversion event. Your analytics counts it. Your [CAPI](/conversion-api) feed reports it to [Meta](/meta-conversion-api) and Google as a real signup. The ad platforms then optimize to find more traffic that looks like the source of that signup. The bot taught your ad spend to go buy more bots. That is the compounding failure, and it is not an Auth0 problem, because Auth0 sits at the auth layer and never sees your analytics or your ad pipeline. It is an architecture problem. The signup-fraud signal and the analytics-and-CAPI pipeline are two separate systems that never compare notes.

That separation is the gap DataCops is built to close. DataCops runs a first-party pipeline on your own subdomain, so signup events, analytics, and CAPI to Meta, Google, TikTok, and LinkedIn all live in one place instead of three. Bot filtering runs at ingestion against a 361.8 billion-plus IP database that separates residential from datacenter, VPN, proxy, and Tor. SignUp Cops adds identity intelligence at the signup moment itself, the device, network, and email-freshness context Auth0 does not surface, and it does that as context you can act on rather than a black-box block. The free tier covers 2,000 signup verifications a month. It pairs with Auth0, it does not replace it: Auth0 stays your identity layer, DataCops makes sure the fake signups Auth0 missed do not go on to poison your measurement and your ad budget. DataCops is a newer brand than [Sift](/alternative/sift-alternative) or [SEON](/alternative/seon-alternative) and its [SOC 2](/enterprise) Type II is still in progress, so regulated buyers should weigh that. But on the specific failure here, fraud signal that never reaches analytics and CAPI, one pipeline beats three disconnected ones.

## Decision guide

**Crude bot volume hammering your signup endpoint?** Auth0 Bot Detection plus the IP-velocity check in the Action. This is the case Auth0 handles well.

**Disposable and plus-addressed emails flooding in?** The Action above. Auth0 has no strong native disposable-email control, so this is on you.

**Fake signups that look completely human and pass every Auth0 check?** That is the 21 percent. You need device, network, and email-freshness intelligence at signup, which is the SignUp Cops layer.

**Need an audit trail of fraud attempts?** Stream Auth0 Attack Protection logs to Datadog or Sentry and alert on failed-signup bursts. Reactive, but essential for forensics.

**Fake signups quietly wrecking your Meta and Google ROAS?** This is the architecture problem. The signup-fraud signal has to reach the same pipeline as analytics and CAPI, or the ad platforms keep optimizing toward bots.

**Small team, no fraud budget yet?** Ship the Auth0 Action today, it costs nothing. Then add a verification layer on a free tier before the fraud compounds into your ad spend.

## You secured the door and left the windows open

The mistake is reading "79 percent reduction in bot attacks" as "signup fraud handled." It is not. It is "the easy 79 percent handled, the hard 21 percent is your problem now." And the hard 21 percent is the fraud that looks like a customer, signs up once, passes the CAPTCHA, and then teaches your ad platforms to go find more of itself.

Auth0 guards the authentication event. It does that well. It was never built to ask whether a signup is a real future customer, and it was never built to keep a fake one out of your analytics and your CAPI feed. Those are different jobs, on a different layer.

So go count. Of the signups that cleared Auth0 last month, how many ever became real users, and how many are still sitting there, fake, already reported to Meta and Google as conversions? If you cannot answer that, your bot detection is working exactly as advertised, and it is still not enough.

---

Research by [DataCops](https://www.joindatacops.com) — first-party tracking, consent infrastructure, fraud prevention, and server-side CAPI for Meta, Google, TikTok, and LinkedIn.
