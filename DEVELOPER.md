# Be Still and Know — Developer Documentation

> KJV Bible Study App · Zero dependencies · Static PWA

---

## Architecture Overview

**Be Still and Know** is a zero-dependency, single-origin static web application. No build step, no framework, no server. Everything runs in the browser using vanilla HTML, CSS, and JavaScript.

```
User → Browser → index.html + app.js → bible-api.com / bolls.life / Web Speech API
                                      ↓
                                localStorage (AES-GCM encrypted via SubtleCrypto)
                                IndexedDB (encryption key storage)
```

---

## File Structure

```
be-still-and-know/
│
├── index.html              # Full HTML structure + CSS (841 + 890 lines)
├── app.js                  # All application logic — 2,065 lines
├── manifest.json           # PWA manifest — makes app installable on mobile
├── sw.js                   # Service Worker — offline caching
├── wallpaper.jpg           # Background (CC0, Pexels — Pixabay contributor)
│
└── fonts/                  # Self-hosted (SIL Open Font License)
    ├── cinzel.woff2
    ├── cinzel-decorative-400.woff2
    ├── cinzel-decorative-700.woff2
    └── lora.woff2
```

---

## Lines of Code by Language

| Language   | File               | Lines  |
|------------|--------------------|--------|
| HTML5      | index.html         | 841    |
| CSS3       | index.html (style) | 890    |
| JavaScript | app.js + sw.js     | 2,065  |
| JSON       | manifest.json      | 18     |
| **Total**  |                    | **3,814** |

---

## Technology Stack

| Technology         | Purpose                          | Cost |
|--------------------|----------------------------------|------|
| HTML5 / CSS3 / JS  | Structure, style, logic          | Free |
| bible-api.com      | KJV verse + chapter fetch        | Free, no API key |
| bolls.life         | Full-Bible word search           | Free, no API key |
| Web Speech API     | Read-aloud with voice selection  | Browser-native |
| SubtleCrypto API   | AES-GCM localStorage encryption  | Browser-native |
| IndexedDB          | Encryption key storage           | Browser-native |
| localStorage       | All user data (encrypted)        | Browser-native |
| Service Worker     | Offline caching (PWA)            | Browser-native |
| Google Fonts → Self-hosted | Typography (Cinzel, Lora) | Self-hosted woff2 |
| GitHub Pages       | Public hosting                   | Free |

---

## Security Implementation

### Content Security Policy
```html
<meta http-equiv="Content-Security-Policy" content="
  default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  connect-src 'self' https://bible-api.com https://bolls.life;
  font-src 'self';
  img-src 'self' data: blob: https://images.pexels.com;
  worker-src 'self';
  manifest-src 'self';
">
```

### localStorage Encryption (AES-GCM)
All user data is encrypted at rest using `SubtleCrypto.encrypt()` with AES-GCM 256-bit keys. The encryption key is stored in `IndexedDB` as a non-extractable `CryptoKey` — it never touches `localStorage` or source code.

```js
// Key generation (first load only)
const key = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
);
// Stored in IndexedDB → never exported
```

```js
// Write
async function secureSet(lsKey, value) { ... }

// Read
async function secureGet(lsKey, fallback) { ... }
```

### HTML Sanitizer
All API responses are passed through a DOM-based sanitizer before being rendered:
```js
function sanitize(str) {
  const d = document.createElement('div');
  d.textContent = String(str ?? '');
  return d.innerHTML; // All HTML entities escaped
}
```

### User Input Cleaner
```js
function cleanInput(str, maxLen = 10000) {
  return String(str ?? '').replace(/[<>]/g, '').slice(0, maxLen);
}
```

---

## localStorage Keys (all AES-GCM encrypted)

| Key               | Contents                              |
|-------------------|---------------------------------------|
| `wow_favorites`   | Starred verses `[{ref, text, meaning}]` |
| `wow_notes`       | Scripture journal entries             |
| `wow_prayers`     | Prayer journal with answered status   |
| `wow_highlights`  | Per-verse color highlights            |
| `wow_tracker`     | 30-day reading plan checkboxes        |
| `wow_read_log`    | Every chapter opened (progress tracking) |
| `wow_streak`      | Daily reading streak                  |
| `wow_bookmark`    | Saved reader position                 |
| `wow_recent`      | Last 5 chapters visited               |

---

## API Reference

### bible-api.com — Verse Lookup
```
GET https://bible-api.com/{reference}?translation=kjv
```
- Free, no API key, CORS-enabled
- Returns: `{ reference, text, verses: [{verse, text}] }`
- Used by: Verse search, Bible Reader, Generate Verse, VotD, Person popup, Compare

### bible-api.com — Compare Translations
```
GET https://bible-api.com/{reference}?translation=web  (World English Bible)
GET https://bible-api.com/{reference}?translation=bbe  (Bible in Basic English)
```

### bolls.life — Word Search
```
GET https://bolls.life/search/KJV/{query}/
```
- Free, no API key
- Returns: `[{pk, book, chapter, verse, text}]`
- Book numbers: 1 (Genesis) → 66 (Revelation)

---

## Feature Modules (app.js)

| Module                   | Key Functions                                      |
|--------------------------|----------------------------------------------------|
| Security                 | `sanitize()`, `secureSet()`, `secureGet()`, `cleanInput()` |
| Verse Lookup             | `searchToReader()`, `fetchAndDisplay()`, `findMeaning()` |
| Bible Reader             | `readerInit()`, `readerLoadChapter()`, `readerRenderVerses()` |
| Audio                    | `readerToggleAudio()`, `readerSpeakNext()`, `initVoices()` |
| Highlights               | `setHighlight()`, `buildHighlightPicker()` |
| Cross-References         | `showXrefs()` — XREFS object (24 curated verse maps) |
| Compare Translations     | `openCompare()` |
| Favorites                | `saveVerse()`, `renderFavorites()`, `renderTicker()` |
| Notes                    | `openNoteEditor()`, `saveNote()`, `renderNotes()` |
| Prayer Journal           | `openPrayerEditor()`, `savePrayer()`, `renderPrayers()` |
| 30-Day Tracker           | `renderTracker()`, `toggleDay()` — PLAN_30[30] |
| Verse of the Day         | `loadVotd()` — VOTD_POOL[64] |
| Word Search              | `runWordSearch()` — bolls.life API |
| Reading Progress         | `markChapterRead()`, `updateReadStats()`, `getReadStats()` |
| Reading Streak           | `updateStreak()`, `renderStatusBar()` |
| Bookmarks                | `toggleBookmark()`, `updateBookmarkBtn()` |
| Family Tree              | `renderTree()`, `openPersonModal()` — TREE_PEOPLE{} |
| Biblical Timeline        | `renderBibtl()` — BIBTL_OT[35] + BIBTL_NT[18] |
| Creation Timeline        | `renderTimeline()` — CREATION_DAYS[7] |
| Generate Verse           | `generateVerse()` — VERSE_POOL[38] |
| Modal Engine             | `openModal()`, `closeModal()`, `overlayClose()` |
| PWA                      | Service Worker registration, manifest.json |

---

## Key Data Objects (app.js)

| Object / Array     | Size  | Description                          |
|--------------------|-------|--------------------------------------|
| `MEANINGS`         | 24    | Hand-written modern reflections per verse |
| `VERSE_POOL`       | 64    | Curated verses for VotD + Generator  |
| `PLAN_30`          | 30    | 30-day Bible reading plan with metadata |
| `BOOK_DAY_MAP`     | 66    | Maps each Bible book → 30-day plan day |
| `DAY_STARTS`       | 30    | Starting reference for each plan day |
| `XREFS`            | 24    | Cross-reference map (verse → related verses) |
| `TREE_PEOPLE`      | 55+   | Biographical data for family tree nodes |
| `BIBTL_OT`         | 35    | Old Testament timeline events with dates |
| `BIBTL_NT`         | 18    | New Testament / Church timeline events |
| `CREATION_DAYS`    | 7     | Seven days of creation with KJV text |
| `BIBLE_BOOKS`      | 66    | All books with chapter counts |
| `BOLLS_BOOKS`      | 66    | Book names indexed 1-66 for bolls.life |

---

## Deployment

### Two-Repo Setup (Private source + Public GitHub Pages)

```bash
# Private source repo
git init
git remote add origin https://github.com/YOUR_USERNAME/be-still-and-know-source.git
git add .
git push -u origin main

# Public deploy repo (only user-facing files)
cd /tmp && mkdir bsak-deploy && cd bsak-deploy
git init
git remote add origin https://github.com/YOUR_USERNAME/be-still-and-know.git
cp /Users/brandondavis/walk-on-water/{index.html,app.js,manifest.json,sw.js,wallpaper.jpg} .
mkdir fonts && cp /Users/brandondavis/walk-on-water/fonts/*.woff2 fonts/
git add . && git commit -m "Deploy"
git push -u origin main
```

Then: **GitHub → be-still-and-know repo → Settings → Pages → main / root → Save**

Live URL: `https://YOUR_USERNAME.github.io/be-still-and-know/`

### PWA Installation (Mobile)
- **iPhone/iPad**: Safari → Share → Add to Home Screen
- **Android**: Chrome → Install App banner (auto-detected) or ⋮ → Add to Home Screen
- **Desktop**: Address bar install icon (Chrome/Edge)

---

## Legal

- **KJV Bible text**: Public domain (1611)
- **Background image**: CC0 via Pexels (Pixabay contributor)
- **Fonts (Cinzel, Lora)**: SIL Open Font License
- **Disclaimer**: This is a personal devotional tool. Reflections do not constitute spiritual, legal, or medical advice.

---

*Built with Claude Sonnet (Anthropic) · 3,814 lines across 4 languages · Zero dependencies*
