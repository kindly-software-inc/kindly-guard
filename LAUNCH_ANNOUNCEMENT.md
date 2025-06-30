# Launch Announcements for KindlyGuard v0.1.0

## HackerNews (Show HN)

**Title**: Show HN: KindlyGuard – Open-source MCP server protecting AI from unicode/injection attacks

**First Comment**:
```
Hi HN! I've been working on KindlyGuard to help protect our AI development workflows from security threats.

Like many of you, I've been integrating AI assistants into my daily work. But I noticed these tools often process untrusted data without much scrutiny - from random GitHub repos to user inputs. This got me thinking about the security implications.

KindlyGuard is my attempt to add a protective layer. It's a lightweight server that:
- Catches unicode tricks (like invisible characters and BiDi attacks)
- Blocks injection attempts before they reach your AI
- Shows you what's being blocked with a real-time shield display

Technical bits you might find interesting:
- Written in Rust for safety and performance
- Achieves ~125k req/s with sub-millisecond latency
- Uses the MCP protocol so it works with various AI tools
- No unsafe code in the public API

I've been using it in my own workflow and it's caught some interesting attempts already. The unicode detection especially - you'd be surprised what can hide in seemingly innocent text!

It's MIT/Apache licensed and I'd love to hear your thoughts or experiences with AI security.

GitHub: https://github.com/kindlyguard/kindly-guard

Happy to answer questions!
```

## Reddit - r/rust

**Title**: Introducing KindlyGuard: A security-focused MCP server written in Rust

**Post**:
```
Hello fellow Rustaceans!

I wanted to share a project I've been working on - KindlyGuard, a security tool for AI assistants.

**The Story**: I've been using AI tools more in my development workflow, and it struck me how much untrusted data flows through them. Code from random repos, user inputs, clipboard contents - it all gets processed without much filtering. This felt like a security gap waiting to be exploited.

**What I Built**: KindlyGuard is a security gateway that sits between AI assistants and potential threats. It scans interactions for unicode attacks, injection attempts, and other risks.

**Why Rust**: 
- Needed performance (processing every AI interaction)
- Wanted memory safety for a security tool
- The type system helps catch security bugs at compile time

**Some Rust patterns used**:
- Trait-based design for extensibility
- Lock-free atomics for statistics
- Zero-copy parsing where possible
- Comprehensive error handling with Result everywhere

**Current Performance**:
- 125k requests/second
- 0.8ms p99 latency
- ~42MB memory usage

The code is open source (MIT/Apache-2.0) and I've tried to keep it clean and well-documented. Would really appreciate feedback from the community - both on the security aspects and the Rust implementation.

GitHub: https://github.com/kindlyguard/kindly-guard

What's your experience with security in AI tools? Have you noticed any concerning patterns?
```

## Reddit - r/opensource

**Title**: [Announcement] KindlyGuard v0.1.0 - Helping protect AI assistants from security threats

**Post**:
```
Hi r/opensource community!

I'm happy to share the first release of KindlyGuard, a project born from a simple observation: as we integrate AI assistants into our workflows, we're potentially exposing them (and ourselves) to new security risks.

**The Motivation**: I kept seeing AI tools process untrusted data - random code snippets, user inputs, data from various sources. It felt like we needed a friendly guardian watching over these interactions.

**What KindlyGuard Does**:
- Scans AI interactions for security threats
- Blocks unicode attacks and injection attempts  
- Provides a visual shield showing what's being protected
- Runs locally, keeping your data private

**Open Source Philosophy**:
- MIT/Apache-2.0 dual license (use what works for you)
- Minimal dependencies, all audited
- Clear documentation
- Welcoming to contributors of all levels

**Getting Started is Simple**:
```
cargo install kindly-guard-server
kindly-guard --stdio
```

I believe security tools should be accessible to everyone. That's why I've focused on making it easy to use with sensible defaults - no complex configuration needed to get started.

Would love to hear your thoughts and experiences. How are you handling security with AI tools in your projects?

GitHub: https://github.com/kindlyguard/kindly-guard
```

## Reddit - r/selfhosted

**Title**: KindlyGuard - Self-hosted security gateway for AI assistants (protecting our local AI setups!)

**Post**:
```
Hey r/selfhosted friends!

I've just released KindlyGuard v0.1.0 - a tool I built to add security to self-hosted AI workflows.

**Why I Built This**: Like many here, I prefer keeping things local. But I realized my local AI setup was processing all sorts of untrusted data without any protection. KindlyGuard adds that missing security layer.

**Perfect for Self-Hosters**:
- Runs entirely on your machine
- No external connections or telemetry
- Low resource usage (~50MB RAM)
- Simple YAML configuration
- Includes systemd service files

**What It Protects Against**:
- Unicode tricks (invisible text, direction changes)
- Injection attempts (SQL, command, prompt)
- Path traversal attacks
- Accidental token/credential exposure

**Quick Setup**:
```bash
# Install and run
cargo install kindly-guard-server
kindly-guard --stdio

# Or build from source
git clone https://github.com/kindlyguard/kindly-guard
cd kindly-guard
cargo build --release
```

The real-time shield display is pretty neat - shows you exactly what threats are being blocked. Great for monitoring dashboards!

I built this because I believe we should be able to use AI tools safely without sacrificing privacy or control. Hope it helps others in the community too.

Would love to hear about your AI self-hosting setups and any security concerns you've had!

GitHub: https://github.com/kindlyguard/kindly-guard
```

## Twitter/X Thread

```
🛡️ Introducing KindlyGuard - a friendly guardian for your AI assistants!

After seeing AI tools process untrusted data without much scrutiny, I built an open-source security layer to help keep our workflows safe.

A short thread 🧵

1/ We're all using AI more in our daily work. But these tools often handle random code, user inputs, and data from various sources. 

This felt like a security gap that needed a gentle solution.

2/ KindlyGuard watches over AI interactions, catching:
• Hidden unicode characters
• Injection attempts
• Path traversal tricks
• Other sneaky threats

All while maintaining super fast performance (sub-millisecond checks!)

3/ Built with Rust for safety and speed, but designed to be friendly:
• Simple one-line install
• No complex configuration needed
• Visual shield shows protection status
• Works with any MCP-compatible AI

4/ It's completely open source (MIT/Apache-2.0) because I believe security tools should be accessible to everyone.

The goal isn't to scare anyone - it's to help our community use AI tools with confidence.

5/ Try it out:
```
cargo install kindly-guard-server
kindly-guard --stdio
```

GitHub: github.com/kindlyguard/kindly-guard

I'd love to hear about your experiences with AI security. Let's help each other stay safe! 💙
```

## Dev.to Article (Intro)

**Title**: "Building KindlyGuard: A Friendly Security Layer for AI Assistants"

**Introduction**:
```markdown
Hey fellow developers! 👋

I want to share a project that came from a simple realization: we're trusting AI assistants with a lot of unfiltered data, and maybe we should add some gentle protection.

## The "Aha" Moment

Picture this: You're using an AI assistant to help debug code. You paste in a snippet from Stack Overflow, some logs from production, maybe some user-submitted data. The AI processes it all without question.

Then it hit me - what if someone hides malicious instructions in that data? What about unicode tricks that make code look different than it behaves? These aren't hypothetical risks - they're real techniques being used in the wild.

## Enter KindlyGuard

Instead of fearing AI tools, I wanted to build something that helps us use them safely. KindlyGuard is like a friendly security guard who:
- Quietly checks everything going to your AI
- Blocks the bad stuff
- Shows you what's happening with a nice visual display
- Doesn't get in your way

The name says it all - it's meant to be kind, not paranoid. Security with a smile! 😊
```

---

These announcements now emphasize:
- Community protection and helping others
- Approachable, friendly tone
- Practical benefits without fear-mongering  
- Genuine desire to contribute to developer safety
- Inclusive language welcoming all skill levels