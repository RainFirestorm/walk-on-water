# Changelog

All notable changes to Be Still and Know are documented here.

---

## [1.0.0] — 2026-05-30 · Initial Release

### Core Application
- Single-file static PWA — zero dependencies, zero build step
- KJV Bible reader — all 66 books, every chapter, verse by verse
- Search any verse by reference (e.g. "John 3:16", "Psalm 23:1-6")
- Rotating quick-pick verse chips — 7 random verses every 7 seconds
- Favorites system — star any verse, appears in scrolling ticker banner
- Saved verses persist via AES-GCM encrypted localStorage

### Bible Reader
- Full chapter navigation — all 66 books, 1,189 chapters
- Book dropdown + chapter selector + prev/next buttons
- Per-verse star (★) to save to favorites
- Per-verse pencil (✏) to open Notes editor pre-filled with that verse
- Per-verse highlight button — 5 colors (yellow, blue, green, pink, purple)
- Per-verse Day badge — shows which 30-Day Plan day covers that passage
- Read Aloud — Web Speech API with voice selection and 6 speed settings
- Font size control (A- / A+) stored per-device
- Bookmark — saves current chapter position
- Compare Translations — KJV, WEB, and BBE side-by-side
- Cross-references panel — curated related verses per selected verse
- Reading progress bar — chapters/verses/words read vs. total Bible
- Remaining stats — chapters/verses/words/estimated time remaining

### Verse of the Day
- Auto-fetches a fresh KJV verse every day
- 64-verse curated pool, deterministic daily rotation
- Click to open that verse in the Bible Reader

### 30-Day Bible Reading Plan
- Complete Old and New Testament in 30 days
- Each day: title, scripture reference, theme, concept tags, focus question, key verse
- Per-day metadata: chapters, verses, words, estimated reading time
- Get Started button — opens Reader at the correct starting reference
- Overall progress bar (0–30 days)
- Cumulative stats: total chapters/verses/words read + % of Bible complete
- Remaining stats: chapters/verses/words/time left to finish
- localStorage persistence across sessions

### Biblical History Timeline
- **Old Testament tab** — 35 dated events from Creation to Malachi
- **New Testament & Church tab** — 18 events from the Birth of Christ to Revelation
- **7 Days of Creation tab** — complete Genesis 1 day-by-day with KJV text, concept tags, and commentary
- Click any event reference to open it in the Bible Reader

### Family Tree
- Complete genealogy from Adam to Jesus (Matthew 1 lineage)
- Every generation filled in — no "several generations" skips
- Seth's line (Genesis 5): Enosh → Kenan → Mahalalel → Jared → Enoch → Methuselah → Lamech → Noah
- Shem's line (Genesis 11): Arphaxad → Shelah → Eber → Peleg → Reu → Serug → Nahor → Terah → Abraham
- Judah's line (Ruth 4, Matthew 1): Perez → Hezron → Ram → Amminadab → Nahshon → Salmon + Rahab
- Royal line: David → Solomon → 14 kings of Judah → Jechoniah → post-exile line → Joseph & Mary → Jesus
- Hover for tooltip; click any name for biographical popup with live KJV verse fetch
- All 12 tribes of Israel displayed

### Word Search
- Full KJV concordance via bolls.life API
- Keyword highlighting in results
- Click any result to open in the Bible Reader
- Shows result count, capped at 200 displayed

### Notes & Insights
- Per-verse journaling — reference and verse text pre-filled from Reader
- Full CRUD — create, edit, delete
- Notes list sorted newest-first
- Opens directly from Reader via ✏ button

### Prayer Journal
- Dated prayer entries with title and body
- Status: Praying / Answered
- Filter by status
- Full CRUD — create, edit, delete, mark answered

### Generate Verse
- Random verse from 38-verse curated pool
- Fetches live KJV text
- Save to favorites or open in Reader

### Security
- AES-GCM 256-bit encryption on all localStorage data
- Encryption key stored as non-extractable CryptoKey in IndexedDB
- Content Security Policy enforced via meta tag
- DOM-based HTML sanitizer on all API responses
- Input sanitizer on user-typed content
- Fonts self-hosted (removed Google Fonts CDN)
- No-referrer policy
- X-Content-Type-Options: nosniff
- No tracking, no analytics, no accounts, no cookies

### PWA
- manifest.json — installable on iPhone, Android, and desktop
- Service Worker — offline caching of core assets
- Favicon — gold ✝ cross

### Accessibility / UX
- Mobile hamburger menu (screens < 700px)
- Reading streak tracker with 🔥 chip
- Recently Viewed — "Continue: Romans 8" chip on landing page
- Parchment background (CC0, Pexels)
- Self-hosted typography: Cinzel Decorative, Cinzel, Lora (SIL OFL)
- Disclaimer and attribution in footer

---

## Format

This changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
