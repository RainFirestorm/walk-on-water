/* ════════════════════════════════════════════════════════════
   SECURITY — HTML SANITIZER + ENCRYPTED STORAGE
════════════════════════════════════════════════════════════ */
// DOM-based sanitizer: converts any string to safe escaped HTML
function sanitize(str) {
  const d = document.createElement('div');
  d.textContent = String(str ?? '');
  return d.innerHTML;
}

// AES-GCM encryption via SubtleCrypto (browser-native, zero dependencies)
const _enc = new TextEncoder();
const _dec = new TextDecoder();

async function _getKey() {
  // Key stored in IndexedDB — never exposed in localStorage or source
  return new Promise((resolve, reject) => {
    const req = indexedDB.open('_bsak_sec', 1);
    req.onupgradeneeded = e => {
      e.target.result.createObjectStore('k');
    };
    req.onsuccess = async e => {
      const db = e.target.result;
      const tx = db.transaction('k', 'readwrite');
      const store = tx.objectStore('k');
      const get = store.get('aes');
      get.onsuccess = async () => {
        if (get.result) { resolve(get.result); return; }
        // Generate new key — stored as non-extractable CryptoKey
        const key = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );
        store.put(key, 'aes');
        resolve(key);
      };
      get.onerror = reject;
    };
    req.onerror = reject;
  });
}

async function secureSet(lsKey, value) {
  try {
    const key = await _getKey();
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, _enc.encode(JSON.stringify(value))
    );
    const packed = JSON.stringify({
      iv:  Array.from(iv),
      ct:  Array.from(new Uint8Array(ct))
    });
    localStorage.setItem(lsKey, packed);
  } catch(e) {
    // Fallback to plain if SubtleCrypto unavailable (old browsers)
    localStorage.setItem(lsKey, JSON.stringify(value));
  }
}

async function secureGet(lsKey, fallback = null) {
  try {
    const raw = localStorage.getItem(lsKey);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw);
    if (!parsed.iv || !parsed.ct) return parsed; // legacy plain value
    const key = await _getKey();
    const iv  = new Uint8Array(parsed.iv);
    const ct  = new Uint8Array(parsed.ct);
    const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return JSON.parse(_dec.decode(pt));
  } catch(e) {
    // If decryption fails (e.g. key changed), return fallback
    return fallback;
  }
}

// Input validator — strips non-printable and dangerous characters from user text
function cleanInput(str, maxLen = 10000) {
  return String(str ?? '').replace(/[<>]/g, '').slice(0, maxLen);
}


/* ════════════════════════════════════════════════════════════
   DATA
════════════════════════════════════════════════════════════ */
const MEANINGS = {
  "john 3:16":"This is the heart of the Gospel. God's love was so vast He gave His only Son — not to judge the world, but to save it. Believing in Jesus means trusting that His sacrifice restores your relationship with God and gives you life that death cannot end.",
  "john 3:16-17":"God's mission was never condemnation — it was rescue. He stepped into history through Jesus not as a judge, but as a Savior. Belief here means wholehearted trust that transforms how you live.",
  "matthew 16:24":"To follow Jesus is a surrender of self-rule. 'Deny yourself' means releasing the belief that you are the center of your own story. 'Take up your cross' means embracing a life of sacrifice and trust even when the path is hard.",
  "matthew 16:24-26":"Jesus reframes what it means to win or lose in life. Gaining the whole world means nothing if your soul drifts from God. True gain is found in losing yourself for Christ's sake — a counterintuitive exchange that leads to the only life worth living.",
  "matthew 14:29-31":"Peter walked on water — as long as his eyes were on Jesus. The moment he focused on the storm, he sank. This is not a story of failure: it is a story of a man who stepped out of a boat when everyone else stayed seated. Jesus catches him anyway.",
  "psalm 23:1-6":"The Lord as Shepherd means you are never responsible for finding your own way alone. 'Green pastures' and 'still waters' represent rest and restoration. Even in death's shadow, the Shepherd walks ahead of you.",
  "psalm 23":"'The Lord is my Shepherd' — five words that reorder your entire existence. You are not navigating life alone. He leads, restores, protects, and accompanies you even through the valley of the shadow of death.",
  "romans 8:28":"This does not promise that everything will feel good — it promises that God weaves all things, including your pain and failures, into a purposeful pattern for those who love Him. Nothing in your life is wasted in God's hands.",
  "philippians 4:13":"Paul wrote this from prison, not a stage of triumph. 'All things' is not a promise of athletic success — it is the testimony of a man who learned contentment in chains and freedom alike, because Christ was his constant strength.",
  "isaiah 40:31":"Waiting on God is an active, trusting posture. Those who wait exchange depleted strength for God's inexhaustible energy. The eagle metaphor speaks to effortless power — not striving harder, but being lifted by something greater than yourself.",
  "proverbs 3:5-6":"Trust with your whole heart means surrendering the illusion that your own logic is sufficient to navigate life. 'Lean not on your own understanding' is not anti-intellectual — it is a humility that acknowledges God sees paths you cannot.",
  "jeremiah 29:11":"Spoken to Israel in exile. God's declaration was not that suffering would end immediately, but that His plans had never been cancelled. 'A future and a hope' means your current circumstances are not your final chapter.",
  "john 14:6":"Jesus doesn't offer one path among many — He declares Himself the singular way into relationship with God. The Father is not a distant deity reached by religious effort, but a Person known through a Person.",
  "galatians 2:20":"The Christian life is not self-improvement — it is death and resurrection. The 'I' that lived for self-justification has been crucified with Christ. What lives now is animated by faith in a Jesus who loved you personally.",
  "ephesians 2:8-9":"Salvation is a gift, not a wage. You cannot earn it through religious performance or good deeds — which also means you cannot lose it by failing to measure up. Grace, received through faith, leaves no room for spiritual pride.",
  "matthew 5:3-12":"The Beatitudes describe a kingdom that runs upside-down from the world's values. The poor in spirit, the mourning, the meek — these are not the world's winners, but they are citizens of God's kingdom.",
  "1 corinthians 13:4-8":"Love here is not a feeling — it is a sustained decision. Paul's description strips sentimentality away and reveals love as patient endurance, active kindness, and the refusal to keep score. It 'never fails' because it is rooted in God's own character.",
  "joshua 1:9":"God commands courage, but does not leave the command hollow. The foundation is the promise that precedes it: 'I am with you.' Courage is not the absence of fear; it is moving forward because God goes with you.",
  "luke 1:37":"Spoken to Mary when the impossible was being asked of her. This is not a motivational statement — it is a declaration about the nature of God. The one who spoke galaxies into existence is not constrained by your circumstances.",
  "2 timothy 1:7":"The spirit of fear is not from God. In its place, God gives power (the ability to act), love (the motivation to act rightly), and a sound mind (the clarity to think clearly under pressure).",
  "matthew 6:33":"Seek the kingdom first. Jesus is redirecting anxiety toward a different priority. When your deepest pursuit is God's kingdom, the things the world anxiously chases are added as byproducts, not withheld as rewards.",
  "hebrews 11:1":"Faith is not wishful thinking — it is confident assurance in what has not yet been seen. Biblical faith is not the absence of evidence; it is trust in the character of a God whose track record is resurrection.",
  "john 11:25-26":"Jesus speaks these words at a grave. He is not offering a theological position — He is making a claim about His own identity. To believe in Him is to already possess a quality of life that death cannot fully extinguish."
};

const VERSE_POOL = [
  "John 3:16","Psalm 23:1-6","Romans 8:28","Philippians 4:13","Isaiah 40:31",
  "Proverbs 3:5-6","Jeremiah 29:11","Matthew 6:33","Joshua 1:9","Hebrews 11:1",
  "2 Timothy 1:7","Galatians 2:20","Ephesians 2:8-9","Matthew 5:3-12","John 14:6",
  "Luke 1:37","1 Corinthians 13:4-8","Matthew 14:29-31","John 11:25-26",
  "Matthew 16:24-26","Psalm 46:1","Romans 12:2","Colossians 3:23","1 John 4:8",
  "Micah 6:8","Matthew 11:28-30","Revelation 21:4","Romans 5:8","Acts 1:8",
  "Psalm 119:105","Lamentations 3:22-23","Deuteronomy 31:6","Isaiah 41:10",
  "2 Chronicles 7:14","Ephesians 3:20","Romans 1:16","1 Peter 5:7","Mark 11:24"
];

const PLAN_30 = [
  /* ── OLD TESTAMENT ─────────────────────────────────── */
  {
    title:"God Creates — Order Out of Nothing",
    ref:"Genesis 1–11",
    meta:{chapters:11,verses:306,words:9500},
    theme:"Theme: Sovereignty & Design. God speaks light, sky, land, life, and humanity into being — and calls it very good. Then sin enters, Cain kills Abel, and the flood judges a broken world. Yet grace threads through every judgment.",
    focus:"Ask yourself: What does it mean that you are made in the image of God (imago Dei)? How does the fall explain the brokenness you see in yourself and the world?",
    concepts:["Creation ex nihilo","Imago Dei","The Fall","Protoevangelium (Gen 3:15)","Cain & Abel","The Flood","Noah's Covenant — rainbow"],
    keyVerse:"Genesis 1:27 — So God created man in his own image, in the image of God created he him."
  },
  {
    title:"Abraham — Called Out of Comfort",
    ref:"Genesis 12–25",
    meta:{chapters:14,verses:367,words:11400},
    theme:"Theme: Faith & Covenant. God calls Abram from Ur with an impossible promise. He believes, and it is counted as righteousness. The covenant of circumcision is established. Isaac — the child of promise — is born and nearly sacrificed.",
    focus:"Ask yourself: What has God called you to leave behind? What does it mean to believe God before you see the promise fulfilled?",
    concepts:["The Abrahamic Covenant","Righteousness by faith","Sodom & Lot","Hagar & Ishmael","Jehovah-Jireh","The near-sacrifice of Isaac"],
    keyVerse:"Genesis 15:6 — And he believed in the LORD; and he counted it to him for righteousness."
  },
  {
    title:"Jacob, Israel & Joseph",
    ref:"Genesis 26–50",
    meta:{chapters:25,verses:860,words:19100},
    theme:"Theme: Struggle, Providence & Forgiveness. Jacob wrestles with God and is renamed Israel. Joseph is betrayed, sold, imprisoned — yet God's hand is in every chapter. 'You meant evil against me, but God meant it for good.'",
    focus:"Ask yourself: Where are you striving in your own strength instead of surrendering? How has God used a painful season to position you somewhere you couldn't have reached otherwise?",
    concepts:["Jacob at Peniel — renamed Israel","12 sons = 12 tribes","Joseph's coat & betrayal","Prison to palace","Providence in suffering","Forgiveness over betrayal"],
    keyVerse:"Genesis 50:20 — But as for you, ye thought evil against me; but God meant it unto good."
  },
  {
    title:"Moses & The Great Exodus",
    ref:"Exodus 1–18",
    meta:{chapters:18,verses:534,words:16600},
    theme:"Theme: Deliverance & God's Name. A burning bush that is not consumed. Ten plagues. The Passover lamb. The parting of the Red Sea. God reveals His name — I AM — and His power over every false god.",
    focus:"Ask yourself: What 'Egypt' holds you captive today? How does the Passover lamb point forward to Jesus as the Lamb of God who takes away the sin of the world?",
    concepts:["I AM — God's name revealed","The Ten Plagues","The Passover","Blood on the doorpost","The Red Sea crossing","Manna & water in the wilderness"],
    keyVerse:"Exodus 12:13 — And when I see the blood, I will pass over you."
  },
  {
    title:"The Law, Tabernacle & Holiness",
    ref:"Exodus 19–40 & Leviticus",
    meta:{chapters:49,verses:1553,words:46600},
    theme:"Theme: God's Presence & Covenant Life. The Ten Commandments are given at Sinai. The Tabernacle is designed as God's dwelling place among His people. Leviticus reveals the cost of holiness — blood sacrifice — pointing directly to the cross.",
    focus:"Ask yourself: How does the sacrificial system deepen your understanding of what Jesus accomplished? The veil torn at the cross (Matt 27:51) — what does direct access to God mean for you today?",
    concepts:["The Ten Commandments","The golden calf — idolatry","The Tabernacle design","Five offerings","Day of Atonement — Yom Kippur","The scapegoat","Be ye holy, for I am holy"],
    keyVerse:"Leviticus 17:11 — For the life of the flesh is in the blood: and I have given it to you upon the altar to make an atonement."
  },
  {
    title:"Numbers — Wilderness & Unbelief",
    ref:"Numbers 1–36",
    meta:{chapters:36,verses:1288,words:32900},
    theme:"Theme: Faithlessness & Its Cost. Israel stands at the edge of the promised land and refuses to enter out of fear. Forty years of wandering follow. Yet God's provision — manna, water, the bronze serpent — never stops.",
    focus:"Ask yourself: What promised land is fear keeping you from? How does God's faithfulness in the wilderness challenge the idea that His blessing depends on your performance?",
    concepts:["Census of Israel","12 spies — 2 faithful","40 years as consequence","Balaam's donkey","The bronze serpent (John 3:14)","Korah's rebellion"],
    keyVerse:"Numbers 14:8 — If the LORD delight in us, then he will bring us into this land, and give it us."
  },
  {
    title:"Deuteronomy — Remember, Love, Choose Life",
    ref:"Deuteronomy 1–34",
    meta:{chapters:34,verses:959,words:28500},
    theme:"Theme: Memory, Covenant Renewal & Love. Moses preaches his farewell sermon to a new generation. His message: Remember what God has done. Love Him with everything. Choose life. Then he dies on Mount Nebo within sight of the land.",
    focus:"Ask yourself: What has God done in your past that you are in danger of forgetting? How does the Shema — 'Hear O Israel, the LORD is our God, the LORD is one' — shape what it means to love God?",
    concepts:["The Shema — Deut 6:4-9","Covenant blessings & curses","Cities of refuge","Moses not entering the land","Joshua commissioned","'Choose life' — Deut 30:19"],
    keyVerse:"Deuteronomy 6:5 — And thou shalt love the LORD thy God with all thine heart, and with all thy soul, and with all thy might."
  },
  {
    title:"Joshua & Judges — Faith, Failure, Cycles",
    ref:"Joshua 1–24 & Judges 1–21",
    meta:{chapters:45,verses:1276,words:37800},
    theme:"Theme: Obedience, Compromise & Mercy. Joshua leads Israel across the Jordan. Jericho falls at a shout. The land is divided. Then Judges shows the terrible cycle of sin: Israel turns from God, is oppressed, cries out, and is delivered — only to repeat.",
    focus:"Ask yourself: Where is God calling you to step out in obedient faith before the waters part? Which judge's story resonates most — Deborah's courage, Gideon's doubt, Samson's wasted potential?",
    concepts:["Crossing the Jordan","Walls of Jericho","Rahab — faith in unlikely places","The sin cycle (sin→oppression→cry→deliverance)","Deborah the judge-prophetess","Gideon's fleece","Samson — strength without character"],
    keyVerse:"Joshua 1:9 — Be strong and of a good courage; be not afraid, neither be thou dismayed: for the LORD thy God is with thee."
  },
  {
    title:"Ruth, Samuel & The Birth of the Kingdom",
    ref:"Ruth 1–4 & 1 Samuel 1–31",
    meta:{chapters:35,verses:895,words:27600},
    theme:"Theme: Hesed, Calling & Obedience. Ruth's loyalty pictures covenant love. Hannah's prayer births a prophet. Samuel anoints Saul — who starts in humility and ends in disobedience. 'To obey is better than sacrifice.'",
    focus:"Ask yourself: Who in your life needs someone to say 'Where you go I will go'? Where in your own life are you offering God religious activity as a substitute for actual obedience?",
    concepts:["Ruth's hesed — steadfast love","Boaz as kinsman-redeemer","Hannah's faith-filled prayer","Samuel the last judge","Israel demands a king","Saul — talent without character","David anointed"],
    keyVerse:"1 Samuel 15:22 — Behold, to obey is better than sacrifice, and to hearken than the fat of rams."
  },
  {
    title:"David — The Shepherd King",
    ref:"2 Samuel 1–24 & 1 Kings 1–11",
    meta:{chapters:35,verses:985,words:30000},
    theme:"Theme: Calling, Sin, Repentance & the Eternal Throne. David kills Goliath, unites the kingdom, and receives God's eternal covenant. Then Bathsheba, murder, and Absalom's revolt. Psalm 51 is the world's greatest prayer of repentance. Solomon builds the Temple.",
    focus:"Ask yourself: What giant in your life requires the faith David had — confidence not in your strength but in God's name? What does David's restoration after adultery and murder say about how far God's grace reaches?",
    concepts:["David and Goliath","The Davidic Covenant (2 Sam 7)","Bathsheba & Uriah","Psalm 51 — true repentance","Absalom's revolt","Solomon's wisdom","The Temple built"],
    keyVerse:"Psalm 51:10 — Create in me a clean heart, O God; and renew a right spirit within me."
  },
  {
    title:"The Divided Kingdom — Idolatry & Exile",
    ref:"1 Kings 12–22 & 2 Kings 1–25",
    meta:{chapters:36,verses:1039,words:31300},
    theme:"Theme: Compromise, Prophets & Judgment. The kingdom splits. Elijah stands alone on Carmel. The northern kingdom falls to Assyria (722 BC). Judah endures longer through reformers like Hezekiah and Josiah — but Babylon comes. Jerusalem burns.",
    focus:"Ask yourself: How does Elijah's exhaustion after Carmel and God's gentle response in the cave speak to you in burnout? What does the fall of Jerusalem teach about the long-term cost of spiritual compromise?",
    concepts:["Kingdom splits — Israel vs Judah","Ahab & Jezebel","Elijah on Mount Carmel","The still small voice","Elisha's miracles","Fall of Israel 722 BC","Fall of Jerusalem 586 BC"],
    keyVerse:"1 Kings 19:12 — And after the fire a still small voice."
  },
  {
    title:"Chronicles, Return from Exile & Esther",
    ref:"1–2 Chronicles, Ezra, Nehemiah & Esther",
    meta:{chapters:98,verses:2617,words:69900},
    theme:"Theme: Temple, Restoration & Providence. Chronicles retells the story through the lens of the Temple. Cyrus decrees freedom. Ezra restores the Word. Nehemiah rebuilds the wall in 52 days. Esther risks everything — 'for such a time as this.'",
    focus:"Ask yourself: What wall in your life needs to be rebuilt despite opposition? How does Esther's courage — using her position to save others — challenge you to leverage your own influence for good?",
    concepts:["The Temple — God's dwelling","Cyrus's decree — God uses pagan kings","Rebuilding the temple","Nehemiah's prayer and action","Esther's courage","'For such a time as this' (Esth 4:14)"],
    keyVerse:"Nehemiah 8:10 — The joy of the LORD is your strength."
  },
  {
    title:"Job — Suffering & the Silence of God",
    ref:"Job 1–42",
    meta:{chapters:42,verses:1070,words:18100},
    theme:"Theme: Theodicy — Why the Righteous Suffer. Job loses everything. His friends offer tidy theological explanations that God rejects. God answers from a whirlwind — not with answers, but with presence. The question isn't 'Why?' but 'Who?'",
    focus:"Ask yourself: Have you ever demanded an explanation from God in your suffering? How does God's response — 'Where were you when I laid the foundations?' — both humble you and strangely comfort you?",
    concepts:["The wager in heaven","Job's three friends — bad theology","Elihu's partial truth","God speaks from the whirlwind","Restoration without explanation","'I know that my redeemer liveth'"],
    keyVerse:"Job 19:25 — For I know that my redeemer liveth, and that he shall stand at the latter day upon the earth."
  },
  {
    title:"Psalms — The Full Range of the Heart (I)",
    ref:"Psalms 1–75",
    meta:{chapters:75,verses:1061,words:22000},
    theme:"Theme: Prayer Without a Filter. The Psalms give vocabulary for every human emotion before God — joy, despair, rage, gratitude, doubt, and awe. Lament Psalms teach that it is not faithless to cry out; it is the beginning of honesty with God.",
    focus:"Ask yourself: Which Psalm captures where you are right now? Notice how most lament Psalms arc toward praise — what happens when you bring raw honesty to God rather than polished prayers?",
    concepts:["Psalm 1 — two paths","Psalm 22 — the cry of the cross","Psalm 23 — the Shepherd","Psalm 46 — Be still","Psalm 51 — repentance","Messianic Psalms (2, 22, 45, 72, 110)"],
    keyVerse:"Psalm 46:10 — Be still, and know that I am God."
  },
  {
    title:"Psalms (II), Proverbs & Wisdom",
    ref:"Psalms 76–150 & Proverbs 1–31",
    meta:{chapters:106,verses:2315,words:59000},
    theme:"Theme: Praise, Ascent & Daily Wisdom. Psalm 73 opens in doubt and ends in worship. The Songs of Ascent are pilgrim songs. Psalm 119 is a 176-verse love letter to Scripture. Proverbs applies God's wisdom to money, words, sex, friendship, and work.",
    focus:"Ask yourself: How does worship — entering the sanctuary of God (Ps 73:17) — actually change your perspective on injustice? In what area of daily life do you most need practical wisdom from Proverbs?",
    concepts:["Psalm 73 — doubt resolved in worship","Songs of Ascent (120–134)","Psalm 119 — Word as lamp","Psalm 150 — everything that breathes","Fear of the LORD = wisdom","Proverbs on the tongue, money, and character"],
    keyVerse:"Psalm 119:105 — Thy word is a lamp unto my feet, and a light unto my path."
  },
  {
    title:"Ecclesiastes, Song of Solomon & Isaiah I",
    ref:"Ecclesiastes 1–12, Song of Solomon & Isaiah 1–39",
    meta:{chapters:67,verses:1631,words:45900},
    theme:"Theme: Meaning, Love & Prophecy. Ecclesiastes strips away every earthly substitute for God. Song of Solomon celebrates covenant love. Isaiah calls Judah to repentance and delivers the most detailed Messianic prophecy in the Old Testament.",
    focus:"Ask yourself: Where in your life are you chasing 'vanity of vanities' — achievement, pleasure, or knowledge as ultimate meaning? How does Isaiah 7:14 (a virgin shall conceive) and the 'Holy, holy, holy' vision shape your understanding of Jesus?",
    concepts:["Vanity of vanities","Fear God — the whole duty of man","Covenant love in Song of Solomon","Isaiah's throne-room vision","Isaiah 7:14 — the virgin birth foretold","Woe to those who call evil good"],
    keyVerse:"Ecclesiastes 12:13 — Fear God, and keep his commandments: for this is the whole duty of man."
  },
  {
    title:"Isaiah II & Jeremiah — Comfort & Weeping",
    ref:"Isaiah 40–66 & Jeremiah 1–52",
    meta:{chapters:79,verses:2273,words:80000},
    theme:"Theme: The Suffering Servant & The New Covenant. Isaiah 40–66 is called the New Testament of the OT. Isaiah 53 describes the crucifixion in stunning detail — 700 years early. Jeremiah weeps over a people who will not turn, yet promises a new covenant written on the heart.",
    focus:"Ask yourself: Read Isaiah 53 slowly and list every detail. Then open Luke 22–23 and compare. How does the precision of prophecy affect your faith? How does Jeremiah 29:11 — written to exiles — speak to your own sense of being displaced or stuck?",
    concepts:["Isaiah 40 — comfort my people","The four Servant Songs","Isaiah 53 — the cross foretold","Jeremiah the weeping prophet","The new covenant (Jer 31:31)","Jeremiah 29:11 — plans for a future","Jerusalem's fall"],
    keyVerse:"Isaiah 53:5 — But he was wounded for our transgressions, he was bruised for our iniquities."
  },
  {
    title:"Lamentations, Ezekiel, Daniel & Minor Prophets",
    ref:"Lamentations, Ezekiel, Daniel & Hosea–Malachi",
    meta:{chapters:101,verses:2824,words:79100},
    theme:"Theme: Grief, Visions, Faithfulness & Hope. Lamentations mourns Jerusalem's fall. Ezekiel sees the chariot, the valley of dry bones, and the future Temple. Daniel remains uncompromised in Babylon. The Minor Prophets call Israel home with warnings, justice, and staggering grace.",
    focus:"Ask yourself: Where in your life do you need the dry-bones resurrection of Ezekiel 37? How does Daniel's integrity in a hostile culture — refusing to stop praying even under threat of death — challenge how you live your faith publicly?",
    concepts:["Lamentations — grief as worship","Ezekiel's chariot vision","Valley of dry bones","Daniel in the lion's den","Hosea — God as faithful husband","Amos — justice for the poor","Micah 6:8","Malachi — the closing call"],
    keyVerse:"Micah 6:8 — And what doth the LORD require of thee, but to do justly, and to love mercy, and to walk humbly with thy God?"
  },
  /* ── NEW TESTAMENT — GOSPELS ──────────────────────── */
  {
    title:"Matthew — The King and His Kingdom",
    ref:"Matthew 1–28",
    meta:{chapters:28,verses:1071,words:23700},
    theme:"Theme: Jesus as the Jewish Messiah. Matthew writes to Jews and proves that Jesus is the long-awaited King. The Sermon on the Mount is the new Torah. The Great Commission is the new mandate. The kingdom of heaven runs on values the world calls foolish.",
    focus:"Ask yourself: Which Beatitude describes your spiritual condition right now? How does 'Blessed are the poor in spirit' redefine success in God's kingdom? What does it mean to 'make disciples of all nations' in your own daily life?",
    concepts:["Genealogy — Son of David","The Sermon on the Mount","The Beatitudes","Lord's Prayer","Parables of the Kingdom","The Transfiguration","The Olivet Discourse","The Great Commission"],
    keyVerse:"Matthew 6:33 — But seek ye first the kingdom of God, and his righteousness; and all these things shall be added unto you."
  },
  {
    title:"Mark — The Servant Who Suffers",
    ref:"Mark 1–16",
    meta:{chapters:16,verses:678,words:15200},
    theme:"Theme: Jesus the Servant in Urgent Action. Mark's breathless pace — 'immediately' appears 41 times — shows a Jesus who came not to be served but to serve. The cross is not an accident; it is the whole point.",
    focus:"Ask yourself: Mark 8:34 — 'Take up your cross and follow me.' What does daily cross-carrying look like in your specific life this week? How does Jesus' question 'Who do you say that I am?' demand a personal, not theoretical, answer?",
    concepts:["'Immediately' — urgency in Mark","Servant Christology","Parables in secret","The feeding of the 5,000","Peter's confession at Caesarea Philippi","The Transfiguration","Gethsemane","The torn veil"],
    keyVerse:"Mark 10:45 — For even the Son of man came not to be ministered unto, but to minister, and to give his life a ransom for many."
  },
  {
    title:"Luke — The Son of Man for All People",
    ref:"Luke 1–24",
    meta:{chapters:24,verses:1151,words:25900},
    theme:"Theme: Jesus as the Universal Savior. Luke writes to Theophilus with careful historical detail. His Jesus reaches the poor, women, Samaritans, and sinners the other Gospels barely mention. The prodigal son, the good Samaritan, and Zacchaeus are all only in Luke.",
    focus:"Ask yourself: The prodigal son has two lost sons — the rebel and the self-righteous elder. Which one are you more like right now? How does Luke's resurrection account — 'Did not our heart burn within us?' — describe how Scripture is supposed to affect us?",
    concepts:["The Magnificat — Mary's song","The prodigal son","The good Samaritan","Zacchaeus in the tree","The rich man and Lazarus","The road to Emmaus","'Did not our hearts burn?'"],
    keyVerse:"Luke 19:10 — For the Son of man is come to seek and to save that which was lost."
  },
  {
    title:"John — The Word Made Flesh",
    ref:"John 1–21",
    meta:{chapters:21,verses:879,words:19100},
    theme:"Theme: Eternal Life Through Belief in the Son of God. John's soaring prologue — 'In the beginning was the Word' — announces a cosmic claim. The seven 'I Am' statements, the Upper Room Discourse, and the most detailed resurrection appearances in Scripture.",
    focus:"Ask yourself: Jesus prays in John 17 that believers would be one as He and the Father are one. What does unity in the Body of Christ look like in your own relationships? How do the resurrection appearances to Mary, Thomas, and Peter each speak to different types of doubt or failure?",
    concepts:["In the beginning was the Word","Seven signs","Seven I AM statements","Nicodemus — born again","The woman at the well","Lazarus raised","The Upper Room Discourse","Mary at the tomb","Thomas's confession","Peter restored"],
    keyVerse:"John 14:6 — Jesus saith unto him, I am the way, the truth, and the life: no man cometh unto the Father, but by me."
  },
  /* ── NEW TESTAMENT — ACTS ─────────────────────────── */
  {
    title:"Acts 1–14 — Pentecost & the Church Explodes",
    ref:"Acts 1–14",
    meta:{chapters:14,verses:496,words:12000},
    theme:"Theme: The Spirit Poured Out & the Church Is Born. Jesus ascends with a promise. Tongues of fire fall. Three thousand are saved in a day. Stephen is martyred. Saul of Tarsus meets Jesus on a road and is forever changed. The Gospel crosses into Gentile territory.",
    focus:"Ask yourself: Acts 1:8 says 'You will be my witnesses in Jerusalem, Judea, Samaria, and to the ends of the earth.' Starting where you are — what does your Jerusalem look like right now? What would it take to cross into your 'Samaria'?",
    concepts:["The Ascension","Pentecost — the Spirit poured out","Peter's sermon — 3,000 saved","The early church community","Stephen's martyrdom","Saul's conversion on the Damascus road","Peter and Cornelius — Gentiles included","Paul's first missionary journey"],
    keyVerse:"Acts 1:8 — But ye shall receive power, after that the Holy Ghost is come upon you: and ye shall be witnesses unto me."
  },
  {
    title:"Acts 15–28 — Paul to the Ends of the Earth",
    ref:"Acts 15–28",
    meta:{chapters:14,verses:511,words:12300},
    theme:"Theme: The Gospel Reaches Rome. The Jerusalem Council settles the law vs. grace question. Paul travels through Macedonia (Philippi, Thessalonica, Corinth), is arrested in Jerusalem, appeals to Caesar, survives a shipwreck, and arrives in Rome — exactly as God promised.",
    focus:"Ask yourself: Paul says in Acts 20:24 that he does not count his life precious — only finishing the race matters. What would change in your life if you held it that loosely? How does Paul's courage before kings and governors challenge your comfort in sharing your faith?",
    concepts:["The Jerusalem Council","Paul's second and third journeys","Lydia — first European convert","Paul and Silas in prison — singing at midnight","The Areopagus sermon in Athens","Paul's arrest in Jerusalem","Defense before kings","Shipwreck on Malta","Paul reaches Rome"],
    keyVerse:"Acts 20:24 — But none of these things move me, neither count I my life dear unto myself, so that I might finish my course with joy."
  },
  /* ── NEW TESTAMENT — PAUL'S LETTERS ──────────────── */
  {
    title:"Romans & Galatians — Justified by Faith",
    ref:"Romans 1–16 & Galatians 1–6",
    meta:{chapters:22,verses:582,words:12500},
    theme:"Theme: The Righteousness of God Through Faith. Romans is the greatest theological letter ever written. All humanity is guilty before God. Justification is by faith alone. Nothing can separate us from God's love. Galatians fights for the same truth against those adding law to grace.",
    focus:"Ask yourself: Romans 12:1-2 — 'Present your bodies a living sacrifice.' What does that look like concretely in your daily life? Galatians 2:20 says it is no longer you who live, but Christ. What does that substitution mean for how you face today?",
    concepts:["All have sinned — Rom 3:23","Justified by faith — Rom 5:1","No condemnation — Rom 8:1","Nothing separates — Rom 8:38-39","Living sacrifice — Rom 12:1-2","Galatians — freedom from the law","Fruit of the Spirit — Gal 5:22-23"],
    keyVerse:"Romans 8:1 — There is therefore now no condemnation to them which are in Christ Jesus."
  },
  {
    title:"1 & 2 Corinthians — The Messy, Glorious Church",
    ref:"1 Corinthians 1–16 & 2 Corinthians 1–13",
    meta:{chapters:29,verses:694,words:15600},
    theme:"Theme: Love, Weakness & the Cross. Corinth is a church full of division, immorality, and pride. Paul's answer to all of it: the cross. 1 Cor 13 defines love as a decision, not a feeling. 2 Cor reveals a Paul crushed and comforted — power made perfect in weakness.",
    focus:"Ask yourself: 1 Cor 13 — run through the 'love is patient, love is kind' list with your name: 'I am patient, I am kind...' Where does it break down? 2 Cor 12:9 — how has God's strength shown up in your weakness?",
    concepts:["The cross as foolishness to the world","Divisions in the church","Sexual purity","The Lord's Supper","Spiritual gifts","Love — 1 Cor 13","The resurrection body — 1 Cor 15","Paul's thorn in the flesh","Strength in weakness"],
    keyVerse:"2 Corinthians 12:9 — My grace is sufficient for thee: for my strength is made perfect in weakness."
  },
  {
    title:"Ephesians, Philippians & Colossians — Prison Letters",
    ref:"Ephesians 1–6, Philippians 1–4 & Colossians 1–4",
    meta:{chapters:16,verses:354,words:7200},
    theme:"Theme: Who You Are in Christ. Written from prison, these letters soar. Ephesians reveals the cosmic mystery of the Church — the body of Christ. Philippians is relentless joy written in chains. Colossians declares that Christ is supreme over all things — visible and invisible.",
    focus:"Ask yourself: Philippians 4:11 — Paul says he has 'learned' contentment, not received it automatically. What is contentment costing you to learn right now? Ephesians 2:10 says you are God's 'workmanship' — created for good works prepared in advance. What might those be?",
    concepts:["Seated with Christ in heavenly places","The armour of God","'To live is Christ, to die is gain'","'I can do all things through Christ'","'Think on these things' — Phil 4:8","Christ the image of the invisible God","The fullness of God dwelling in Christ"],
    keyVerse:"Philippians 4:13 — I can do all things through Christ which strengtheneth me."
  },
  {
    title:"Thessalonians, Timothy, Titus & Philemon",
    ref:"1–2 Thessalonians, 1–2 Timothy, Titus & Philemon",
    meta:{chapters:22,verses:403,words:8100},
    theme:"Theme: The Return of Christ & Faithful Leadership. Paul addresses the church's confusion about the Second Coming, equips Timothy and Titus to lead local churches, and writes the most personal letter in the NT — asking Philemon to receive his runaway slave Onesimus as a brother.",
    focus:"Ask yourself: 1 Tim 4:12 — 'Let no man despise thy youth' — where do you discount yourself from influence? How does the Philemon letter — Paul asking Philemon to forgive and restore — challenge your own willingness to restore broken relationships?",
    concepts:["The Day of the Lord","The man of lawlessness","Qualifications for elders and deacons","'Fight the good fight of faith'","Guard what has been entrusted","Godliness with contentment","The Philemon appeal — receive him as me"],
    keyVerse:"1 Timothy 6:12 — Fight the good fight of faith, lay hold on eternal life, whereunto thou art also called."
  },
  {
    title:"Hebrews — Jesus Is Better",
    ref:"Hebrews 1–13",
    meta:{chapters:13,verses:303,words:6900},
    theme:"Theme: The Supremacy of Christ Over Everything. Hebrews is written to Jewish Christians tempted to return to the old system. The answer to every temptation: Jesus is better — better than angels, better than Moses, better than Aaron, better than the old covenant. He is the final word.",
    focus:"Ask yourself: Hebrews 12:1 — 'Lay aside every weight and the sin which so easily entangles.' What specific weight is slowing your race right now? Hebrews 11 — the hall of faith — these people lived by promise, not by sight. What promise of God are you living by today?",
    concepts:["Jesus — the final Word","Better than angels and Moses","Jesus our great High Priest","Melchizedek","The new and better covenant","The Hall of Faith — Hebrews 11","Running with endurance — Heb 12","Jesus the author and finisher of faith"],
    keyVerse:"Hebrews 12:1-2 — Let us run with patience the race that is set before us, looking unto Jesus the author and finisher of our faith."
  },
  {
    title:"The General Epistles — Faith, Suffering & Love",
    ref:"James, 1–2 Peter, 1–2–3 John & Jude",
    meta:{chapters:20,verses:431,words:9200},
    theme:"Theme: Practical Faith, Perseverance & Abiding in Love. James insists faith without works is dead. Peter prepares suffering churches for the fiery trial. John declares that anyone who does not love does not know God — for God is love. Jude sounds the alarm against false teaching.",
    focus:"Ask yourself: James 1:22 — 'Be doers of the word and not hearers only.' What truth have you been hearing but not yet doing? 1 Pet 5:7 — 'Casting all your care upon him, for he careth for you.' What specific anxiety can you hand over today?",
    concepts:["Faith without works is dead — James 2","Taming the tongue — James 3","The fiery trial — 1 Pet 4:12","'A royal priesthood' — 1 Pet 2:9","God is light — 1 John 1","God is love — 1 John 4","Abide in Christ — 1 John 2","Contend for the faith — Jude"],
    keyVerse:"1 John 4:8 — He that loveth not knoweth not God; for God is love."
  },
  {
    title:"Revelation — All Things New",
    ref:"Revelation 1–22",
    meta:{chapters:22,verses:404,words:12000},
    theme:"Theme: The Victory of the Lamb & New Creation. Revelation is not a newspaper in code — it is a letter of hope to persecuted churches. The Lamb who was slain is worthy. Every tear will be wiped away. Death itself will die. God will dwell with His people forever. The story that began in Genesis ends in a garden-city where the tree of life grows again.",
    focus:"Ask yourself: Revelation 2–3 — Jesus addresses seven real churches with specific praise and rebuke. Which letter sounds most like it was written to you? How does the vision of Revelation 21:3 — 'God himself shall be with them, and be their God' — fulfill and complete the entire story of Scripture?",
    concepts:["Letters to the seven churches","The Lamb worthy to open the scroll","The four horsemen","The great multitude — no one can number","Babylon the great","The Marriage Supper of the Lamb","The Millennium","The Great White Throne","The New Jerusalem","The tree of life restored"],
    keyVerse:"Revelation 21:4 — And God shall wipe away all tears from their eyes; and there shall be no more death, neither sorrow, nor crying, neither shall there be any more pain."
  }
];

const TREE_PEOPLE = {
  "God":              {desc:"The eternal Creator — Father, Son, and Holy Spirit. The source of all life and the covenant Keeper throughout Scripture.", ref:"Genesis 1:1"},
  "Adam":             {desc:"The first man, formed from dust. Placed in the Garden to keep it. His disobedience brought sin and death into the world.", ref:"Genesis 2:7"},
  "Eve":              {desc:"The first woman, created from Adam's rib. The mother of all the living.", ref:"Genesis 3:20"},
  "Cain":             {desc:"Adam's firstborn. A farmer who murdered his brother Abel out of jealousy. Marked by God, he went to the land of Nod.", ref:"Genesis 4:1"},
  "Abel":             {desc:"Adam's second son. A shepherd whose offering was accepted by God. Killed by Cain — the first death in Scripture.", ref:"Genesis 4:2"},
  "Seth":             {desc:"Adam's third son, born after Abel's murder. The covenant bloodline flows through Seth toward Noah.", ref:"Genesis 4:25"},
  "Enosh":            {desc:"Son of Seth. 'Then men began to call upon the name of the LORD.' His birth marks the beginning of public worship.", ref:"Genesis 4:26"},
  "Kenan":            {desc:"Son of Enosh. Part of the unbroken lineage from Seth to Noah recorded in Genesis 5.", ref:"Genesis 5:9"},
  "Mahalalel":        {desc:"Son of Kenan. His name means 'praise of God.' He lived 895 years according to the genealogy of Genesis 5.", ref:"Genesis 5:12"},
  "Jared":            {desc:"Son of Mahalalel and father of Enoch. He lived 962 years — second longest life recorded in Scripture.", ref:"Genesis 5:15"},
  "Enoch":            {desc:"Son of Jared. One of the most remarkable figures in Scripture — 'he walked with God, and he was not; for God took him.' He never died.", ref:"Genesis 5:22-24"},
  "Methuselah":       {desc:"Son of Enoch. He holds the record for the longest human life in Scripture — 969 years. His name may mean 'his death shall bring it,' and he died the year of the flood.", ref:"Genesis 5:27"},
  "Lamech":           {desc:"Son of Methuselah and father of Noah. He named his son Noah, saying 'This one shall comfort us from our work and toil.'", ref:"Genesis 5:29"},
  "Noah":             {desc:"A righteous man in a corrupt generation. He built the ark, survived the flood, and received the first rainbow covenant from God.", ref:"Genesis 6:9"},
  "Shem":             {desc:"Noah's firstborn. Ancestor of the Semitic peoples — the line that leads to Abraham, David, and Jesus.", ref:"Genesis 10:21"},
  "Ham":              {desc:"Noah's second son. Ancestor of the peoples of Africa and Canaan, including Egypt.", ref:"Genesis 10:6"},
  "Japheth":          {desc:"Noah's third son. Ancestor of the peoples of Europe and Asia Minor.", ref:"Genesis 10:5"},
  "Arphaxad":         {desc:"Son of Shem, born two years after the flood. The covenant line from Shem to Abraham passes through him.", ref:"Genesis 11:10"},
  "Shelah":           {desc:"Son of Arphaxad. Part of the post-flood genealogy connecting Shem's line toward Abraham.", ref:"Genesis 11:12"},
  "Eber":             {desc:"Son of Shelah. Some scholars believe the word 'Hebrew' derives from his name. He lived 464 years.", ref:"Genesis 11:14"},
  "Peleg":            {desc:"Son of Eber. 'In his days the earth was divided' — likely a reference to the confusion of languages at Babel and the scattering of nations.", ref:"Genesis 11:16"},
  "Reu":              {desc:"Son of Peleg. Part of the narrowing covenant line between the flood and Abraham.", ref:"Genesis 11:18"},
  "Serug":            {desc:"Son of Reu. Grandfather of Terah and great-grandfather of Abraham.", ref:"Genesis 11:20"},
  "Nahor":            {desc:"Son of Serug and grandfather of Abraham. His family remained in Mesopotamia when Abraham was called to Canaan.", ref:"Genesis 11:22"},
  "Terah":            {desc:"Son of Nahor and father of Abraham, Nahor (II), and Haran. He began the journey from Ur of the Chaldeans but stopped and died in Haran.", ref:"Genesis 11:26"},
  "Abraham":          {desc:"The founding patriarch. God called him from Ur, gave him the covenant of circumcision, and promised all nations would be blessed through his seed. Counted righteous by faith.", ref:"Genesis 12:1-3"},
  "Sarah":            {desc:"Abraham's wife. Barren for decades, she miraculously gave birth to Isaac at age 90 — proof that nothing is too hard for God.", ref:"Genesis 17:15"},
  "Hagar":            {desc:"Sarah's Egyptian handmaid, given to Abraham. She bore Ishmael. When cast out, God heard her cry in the wilderness.", ref:"Genesis 16:1"},
  "Ishmael":          {desc:"Abraham's firstborn through Hagar. God blessed him with twelve princes and made him a great nation — ancestor of many Arab peoples.", ref:"Genesis 16:15"},
  "Isaac":            {desc:"The promised son born to Abraham and Sarah. Nearly sacrificed on Moriah, he foreshadows Christ. Father of Jacob and Esau.", ref:"Genesis 21:3"},
  "Rebekah":          {desc:"Isaac's wife, found at the well. She bore the twins Esau and Jacob, and secured the covenant blessing for Jacob.", ref:"Genesis 24:15"},
  "Esau":             {desc:"Isaac's firstborn twin. Sold his birthright for stew. Ancestor of the Edomites.", ref:"Genesis 25:25"},
  "Jacob":            {desc:"The younger twin who became Israel. Wrestled with God at Peniel, walked away limping and renamed. Father of the twelve tribes.", ref:"Genesis 32:28"},
  "Leah":             {desc:"Jacob's first wife. Though unloved at first, she was the mother of Judah — through whom the Messiah would come.", ref:"Genesis 29:23"},
  "Rachel":           {desc:"Jacob's beloved wife. She bore Joseph and Benjamin, and died giving birth near Bethlehem.", ref:"Genesis 29:18"},
  "Judah":            {desc:"Jacob's fourth son by Leah. God chose his line for the messianic promise despite his moral failures. 'The scepter shall not depart from Judah.'", ref:"Genesis 49:10"},
  "Tamar":            {desc:"Judah's daughter-in-law who disguised herself to secure justice and continue the covenant line. Mother of Perez, an ancestor of Jesus.", ref:"Genesis 38:6"},
  "Perez":            {desc:"Son of Judah and Tamar. God wove this morally complex birth into the messianic bloodline. Listed in Matthew 1 and Luke 3.", ref:"Genesis 38:29"},
  "Hezron":           {desc:"Son of Perez, grandson of Judah. One of those who went down to Egypt with Jacob. Listed in the genealogy of Ruth 4 and Matthew 1.", ref:"Ruth 4:18"},
  "Ram":              {desc:"Son of Hezron. Also called Aram in Matthew 1. Part of the covenant chain linking Perez to David.", ref:"Ruth 4:19"},
  "Amminadab":        {desc:"Son of Ram. His daughter Elisheba married Aaron the high priest. He was a leader of Judah during the wilderness period.", ref:"Ruth 4:19-20"},
  "Nahshon":          {desc:"Son of Amminadab. He was the appointed leader of the tribe of Judah during the Exodus and wilderness years — an honored position.", ref:"Ruth 4:20"},
  "Salmon":           {desc:"Son of Nahshon. He married Rahab the harlot of Jericho, who hid the Israelite spies and was saved by the scarlet cord. Their union pictures grace.", ref:"Ruth 4:20-21"},
  "Rahab":            {desc:"A Canaanite woman of Jericho who hid the Israelite spies and was saved with her family when Jericho fell. She married Salmon and is one of four women named in Jesus' genealogy in Matthew 1.", ref:"Joshua 2:1"},
  "Boaz":             {desc:"Son of Salmon and Rahab. A wealthy landowner of Bethlehem who married Ruth, the Moabite widow. A kinsman-redeemer and type of Christ.", ref:"Ruth 2:1"},
  "Ruth":             {desc:"A Moabite widow whose loyalty — 'Where you go I will go' — brought her into the covenant people. Great-grandmother of King David, named in Jesus' genealogy.", ref:"Ruth 1:16"},
  "Obed":             {desc:"Son of Boaz and Ruth. His birth brought joy to Naomi, who had returned to Bethlehem empty. He became the grandfather of David.", ref:"Ruth 4:17"},
  "Jesse":            {desc:"Son of Obed, father of David. Isaiah prophesied: 'A shoot shall come forth from the stump of Jesse.' He had eight sons; God chose the youngest.", ref:"1 Samuel 16:1"},
  "David":            {desc:"Israel's greatest king — shepherd, psalmist, warrior, and flawed sinner. God promised his throne would endure forever. Fulfilled in Jesus, the Son of David.", ref:"1 Samuel 16:13"},
  "Bathsheba":        {desc:"Originally wife of Uriah. Taken by David in his greatest sin. After repentance, she became mother of Solomon. She appears in Matthew's genealogy.", ref:"2 Samuel 11:3"},
  "Solomon":          {desc:"Son of David and Bathsheba. Wisest man who ever lived. Built the First Temple. His later idolatry split the kingdom after his death.", ref:"1 Kings 3:12"},
  "Rehoboam":         {desc:"Son of Solomon. His harsh response to the people's plea split the united kingdom into Israel (north) and Judah (south) permanently.", ref:"1 Kings 12:1"},
  "Abijah":           {desc:"Son of Rehoboam. King of Judah. He defeated Jeroboam's larger army, trusting in the God of his fathers. Listed in Matthew 1.", ref:"1 Chronicles 3:10"},
  "Asa":              {desc:"Son of Abijah. A godly king of Judah who removed idols and trusted God against overwhelming odds — until he trusted Syria instead of God in his last years.", ref:"1 Kings 15:11"},
  "Jehoshaphat":      {desc:"Son of Asa. A righteous king who appointed judges, removed Baal worship, and famously sent singers ahead of his army as they cried 'Praise the LORD!'", ref:"1 Kings 22:43"},
  "Jehoram":          {desc:"Son of Jehoshaphat. He married Athaliah, daughter of Ahab and Jezebel, and led Judah into Baal worship. A stark warning about the influence of a godless spouse.", ref:"2 Kings 8:16"},
  "Uzziah":           {desc:"Also called Azariah. Son of Amaziah. A long-reigning and generally righteous king of Judah who became leprous after entering the temple to burn incense — a role reserved for priests alone.", ref:"2 Kings 15:1-3"},
  "Jotham":           {desc:"Son of Uzziah. He became king after his father was struck with leprosy. Jotham was a faithful king who built the Upper Gate of the temple and grew mighty.", ref:"2 Kings 15:32-34"},
  "Ahaz":             {desc:"Son of Jotham. One of the wicked kings of Judah. He sacrificed his own son in fire, shut the temple doors, and invited Assyria's domination. Yet the Messiah's line ran through him.", ref:"2 Kings 16:2"},
  "Hezekiah":         {desc:"Son of Ahaz. One of Judah's greatest kings. He broke down pagan altars, reopened the temple, prayed against Sennacherib's army, and God struck 185,000 Assyrians in a night.", ref:"2 Kings 18:5"},
  "Manasseh":         {desc:"Son of Hezekiah. The longest-reigning and initially most wicked king of Judah — he reversed all his father's reforms. Yet in captivity he repented, and God restored him. A picture of radical grace.", ref:"2 Kings 21:1"},
  "Amon":             {desc:"Son of Manasseh. He did not follow his father's repentance but returned to Manasseh's early wickedness. He reigned only two years before being assassinated by his servants.", ref:"2 Kings 21:19"},
  "Josiah":           {desc:"Son of Amon. One of the greatest reforming kings of Judah. When the Book of the Law was rediscovered in the temple, Josiah wept, repented, and led the most sweeping reformation in Israel's history.", ref:"2 Kings 22:2"},
  "Jechoniah":        {desc:"Also called Jeconiah or Coniah. Son of Jehoiakim. He was taken to Babylon by Nebuchadnezzar and cursed — no descendant would sit on David's throne (Jer 22:30). Joseph, as legal father of Jesus, satisfied the royal lineage without passing the curse biologically.", ref:"Matthew 1:11"},
  "Shealtiel":        {desc:"Son of Jechoniah. Born in Babylonian exile. Through him the post-exile messianic line continued. He is listed in both Matthew 1 and Luke 3.", ref:"Matthew 1:12"},
  "Zerubbabel":       {desc:"Son of Shealtiel. The governor of Judah who led the first wave of exiles back from Babylon and oversaw the laying of the Second Temple's foundation. A messianic figure and type of Christ.", ref:"Ezra 3:2"},
  "Abiud":            {desc:"Son of Zerubbabel. Listed in Matthew's genealogy. He lived in the post-exilic period as the covenant line continued quietly through history.", ref:"Matthew 1:13"},
  "Eliakim":          {desc:"Son of Abiud. Part of the post-exilic generations maintaining the Davidic line through the silent centuries between the Old and New Testaments.", ref:"Matthew 1:13"},
  "Azor":             {desc:"Son of Eliakim. The covenant bloodline continues through the intertestamental period — the 400 years when no prophet spoke.", ref:"Matthew 1:13"},
  "Zadok":            {desc:"Son of Azor. Not the famous high priest Zadok of David's time, but a later descendant carrying the Davidic line forward.", ref:"Matthew 1:14"},
  "Achim":            {desc:"Son of Zadok. One of the quiet, faithful generations carrying the messianic lineage through the centuries of silence.", ref:"Matthew 1:14"},
  "Eliud":            {desc:"Son of Achim. The lineage is maintained in obscurity — no kings, no prophets, just faithful fathers and sons keeping a bloodline alive for God's appointed moment.", ref:"Matthew 1:14"},
  "Eleazar":          {desc:"Son of Eliud. Part of the unbroken chain from Abraham to Jesus in Matthew's genealogy. Every name is a testimony to God's faithfulness across generations.", ref:"Matthew 1:15"},
  "Matthan":          {desc:"Son of Eleazar. Grandfather of Joseph, husband of Mary. The lineage is almost complete.", ref:"Matthew 1:15"},
  "Jacob (father of Joseph)": {desc:"Son of Matthan. Father of Joseph, the husband of Mary. Not the patriarch Jacob/Israel, but a later descendant sharing that honored name.", ref:"Matthew 1:15-16"},
  "Mary":             {desc:"A young woman of Nazareth chosen by God to bear the Son of God. Her response — 'Let it be to me according to your word' — is one of Scripture's great acts of faith.", ref:"Luke 1:30-31"},
  "Joseph (husband of Mary)": {desc:"Son of Jacob (Matthan's son). A righteous carpenter of Nazareth, descended from David through Solomon. He took Mary as his wife and raised Jesus as his own son, providing legal royal lineage while the Virgin Birth preserved sinless human nature.", ref:"Matthew 1:20"},
  "Jesus":            {desc:"The Son of God and Son of Man. The Word made flesh. Born of the virgin Mary in Bethlehem, He fulfilled every messianic prophecy, died for the sins of the world, rose on the third day, and is seated at the right hand of the Father. He is the point of the entire genealogy — and of all history.", ref:"John 1:1, 14"}
};

/* ════════════════════════════════════════════════════════════
   STARS
════════════════════════════════════════════════════════════ */
(function(){
  const el = document.getElementById('stars');
  for(let i=0;i<120;i++){
    const s=document.createElement('div');s.className='star';
    s.style.cssText=`left:${Math.random()*100}%;top:${Math.random()*65}%;--d:${2+Math.random()*4}s;--delay:${Math.random()*5}s;--op:${0.3+Math.random()*0.7};width:${Math.random()<0.1?3:2}px;height:${Math.random()<0.1?3:2}px;`;
    el.appendChild(s);
  }
})();

/* ════════════════════════════════════════════════════════════
   MODAL ENGINE
════════════════════════════════════════════════════════════ */
function openModal(id){
  document.getElementById(id).classList.add('open');
  document.body.style.overflow='hidden';
  if(id==='tracker-modal') renderTracker();
  if(id==='tree-modal') renderTree();
  if(id==='reader-modal'){ readerInit(); initVoices(); }
  if(id==='timeline-modal') renderTimeline();
  if(id==='gen-modal'){ document.getElementById('gen-result').style.display='none'; }
  if(id==='notes-modal'){ renderNotes(); }
  if(id==='prayer-modal'){ renderPrayers(); }
  if(id==='bibtl-modal'){ renderBibtl(); }
  if(id==='wordsearch-modal'){ setTimeout(()=>document.getElementById('ws-input')?.focus(),100); }
}
function closeModal(id){
  document.getElementById(id).classList.remove('open');
  document.body.style.overflow='';
}
function overlayClose(e,id){
  if(e.target===document.getElementById(id)) closeModal(id);
}
document.addEventListener('keydown',e=>{ if(e.key==='Escape') document.querySelectorAll('.modal-overlay.open').forEach(m=>m.classList.remove('open')); document.body.style.overflow=''; });

/* ════════════════════════════════════════════════════════════
   SEARCH → READER ROUTING
════════════════════════════════════════════════════════════ */
let favorites = JSON.parse(localStorage.getItem('wow_favorites')||'[]');
let currentVerse = null; // kept for generate verse / fav save compatibility

function normalizeRef(raw){ return raw.trim().replace(/\s+/g,' '); }

// Book name aliases → canonical BIBLE_BOOKS name
const BOOK_ALIASES = {
  'gen':'Genesis','genesis':'Genesis',
  'ex':'Exodus','exo':'Exodus','exodus':'Exodus',
  'lev':'Leviticus','leviticus':'Leviticus',
  'num':'Numbers','numbers':'Numbers',
  'deut':'Deuteronomy','dt':'Deuteronomy','deuteronomy':'Deuteronomy',
  'josh':'Joshua','joshua':'Joshua',
  'judg':'Judges','jdg':'Judges','judges':'Judges',
  'ruth':'Ruth',
  '1 sam':'1 Samuel','1sam':'1 Samuel','1 samuel':'1 Samuel',
  '2 sam':'2 Samuel','2sam':'2 Samuel','2 samuel':'2 Samuel',
  '1 kgs':'1 Kings','1kgs':'1 Kings','1 kings':'1 Kings',
  '2 kgs':'2 Kings','2kgs':'2 Kings','2 kings':'2 Kings',
  '1 chr':'1 Chronicles','1chr':'1 Chronicles','1 chronicles':'1 Chronicles',
  '2 chr':'2 Chronicles','2chr':'2 Chronicles','2 chronicles':'2 Chronicles',
  'ezra':'Ezra','neh':'Nehemiah','nehemiah':'Nehemiah','esther':'Esther','est':'Esther',
  'job':'Job',
  'ps':'Psalms','psa':'Psalms','psalm':'Psalms','psalms':'Psalms',
  'prov':'Proverbs','pro':'Proverbs','proverbs':'Proverbs',
  'eccl':'Ecclesiastes','ecc':'Ecclesiastes','ecclesiastes':'Ecclesiastes',
  'song':'Song of Solomon','sos':'Song of Solomon','song of songs':'Song of Solomon','song of solomon':'Song of Solomon',
  'isa':'Isaiah','isaiah':'Isaiah',
  'jer':'Jeremiah','jeremiah':'Jeremiah',
  'lam':'Lamentations','lamentations':'Lamentations',
  'ezek':'Ezekiel','ez':'Ezekiel','ezekiel':'Ezekiel',
  'dan':'Daniel','daniel':'Daniel',
  'hos':'Hosea','hosea':'Hosea','joel':'Joel','amos':'Amos',
  'ob':'Obadiah','obadiah':'Obadiah','jonah':'Jonah','jon':'Jonah',
  'mic':'Micah','micah':'Micah','nah':'Nahum','nahum':'Nahum',
  'hab':'Habakkuk','habakkuk':'Habakkuk','zeph':'Zephaniah','zephaniah':'Zephaniah',
  'hag':'Haggai','haggai':'Haggai','zech':'Zechariah','zechariah':'Zechariah',
  'mal':'Malachi','malachi':'Malachi',
  'matt':'Matthew','mt':'Matthew','matthew':'Matthew',
  'mk':'Mark','mark':'Mark',
  'lk':'Luke','luke':'Luke',
  'jn':'John','john':'John',
  'acts':'Acts',
  'rom':'Romans','romans':'Romans',
  '1 cor':'1 Corinthians','1cor':'1 Corinthians','1 corinthians':'1 Corinthians',
  '2 cor':'2 Corinthians','2cor':'2 Corinthians','2 corinthians':'2 Corinthians',
  'gal':'Galatians','galatians':'Galatians',
  'eph':'Ephesians','ephesians':'Ephesians',
  'phil':'Philippians','philippians':'Philippians',
  'col':'Colossians','colossians':'Colossians',
  '1 thess':'1 Thessalonians','1thess':'1 Thessalonians','1 thessalonians':'1 Thessalonians',
  '2 thess':'2 Thessalonians','2thess':'2 Thessalonians','2 thessalonians':'2 Thessalonians',
  '1 tim':'1 Timothy','1tim':'1 Timothy','1 timothy':'1 Timothy',
  '2 tim':'2 Timothy','2tim':'2 Timothy','2 timothy':'2 Timothy',
  'titus':'Titus','tit':'Titus',
  'philemon':'Philemon','phile':'Philemon','phm':'Philemon',
  'heb':'Hebrews','hebrews':'Hebrews',
  'jas':'James','james':'James',
  '1 pet':'1 Peter','1pet':'1 Peter','1 peter':'1 Peter',
  '2 pet':'2 Peter','2pet':'2 Peter','2 peter':'2 Peter',
  '1 jn':'1 John','1jn':'1 John','1 john':'1 John',
  '2 jn':'2 John','2jn':'2 John','2 john':'2 John',
  '3 jn':'3 John','3jn':'3 John','3 john':'3 John',
  'jude':'Jude',
  'rev':'Revelation','revelation':'Revelation','apoc':'Revelation'
};

function findBookIdx(name) {
  const lower = name.toLowerCase().trim().replace(/\.$/,'');
  // Direct alias lookup
  const canonical = BOOK_ALIASES[lower];
  if (canonical) {
    const idx = BIBLE_BOOKS.findIndex(b => b.n === canonical);
    if (idx >= 0) return idx;
  }
  // Starts-with match on book name
  const idx = BIBLE_BOOKS.findIndex(b =>
    b.n.toLowerCase().startsWith(lower) || lower.startsWith(b.n.toLowerCase().slice(0,4))
  );
  return idx;
}

function parseVerseRef(raw) {
  // Match: optional number prefix + book name + chapter + optional :verse
  // e.g. "John 3:16", "1 John 4:8", "Psalm 23", "Matthew 16:24-26"
  const m = raw.trim().match(/^(\d\s+)?([a-zA-Z][a-zA-Z\s]*?)\s+(\d+)(?::(\d+)(?:-\d+)?)?$/i);
  if (!m) return null;
  const bookName = ((m[1]||'') + m[2]).trim();
  return {
    bookName,
    chapter: parseInt(m[3]),
    verse: m[4] ? parseInt(m[4]) : 1
  };
}

let readerTargetVerse = 0; // verse number to highlight after chapter loads

function searchToReader(e, refOverride) {
  if (e) e.preventDefault();
  const raw = refOverride || document.getElementById('verse-input').value.trim();
  if (!raw) return;

  const parsed = parseVerseRef(raw);
  if (!parsed) { showToast('Format: "John 3:16" or "Psalm 23"'); return; }

  const bookIdx = findBookIdx(parsed.bookName);
  if (bookIdx < 0) { showToast('Book not found — try e.g. "Romans 8"'); return; }

  const totalChapters = BIBLE_BOOKS[bookIdx].c;
  const chapter = Math.min(Math.max(parsed.chapter, 1), totalChapters);

  // Set reader state
  readerBookIdx = bookIdx;
  readerChapter = chapter;
  readerTargetVerse = parsed.verse;

  openModal('reader-modal');
}

/* ════════════════════════════════════════════════════════════
   VERSE LOOKUP (kept for generate verse / person popup)
════════════════════════════════════════════════════════════ */
async function lookupVerse(e){ if(e)e.preventDefault(); const v=document.getElementById('verse-input').value.trim(); if(!v)return; searchToReader(null,v); }
function loadQuick(ref){ searchToReader(null, ref); }

async function fetchAndDisplay(ref){
  const refN=normalizeRef(ref);
  showLoading(true); hideCard(); hideError();
  const apiRef=refN.replace(/\s+/g,'+').toLowerCase();
  try{
    const res=await fetch(`https://bible-api.com/${apiRef}?translation=kjv`);
    if(!res.ok)throw new Error();
    const data=await res.json();
    if(data.error)throw new Error();
    let html='';
    if(data.verses&&data.verses.length>1){
      data.verses.forEach(v=>{ html+=`<sup class="verse-num">${v.verse}</sup>${v.text.trim()} `; });
    } else { html=data.text.trim(); }
    const meaning=findMeaning(refN,data.text);
    currentVerse={ref:data.reference,text:data.text,meaning,html};
    displayCard(data.reference,html,meaning);
  }catch(err){ showError('Verse not found — please check the reference. (e.g. "John 3:16")'); }
  finally{ showLoading(false); }
}

function findMeaning(refN,text){
  const key=refN.toLowerCase();
  if(MEANINGS[key])return MEANINGS[key];
  for(const k of Object.keys(MEANINGS)){ if(key.startsWith(k)||k.startsWith(key.split(':')[0].toLowerCase()))return MEANINGS[k]; }
  return generateReflection(refN,text);
}
function generateReflection(ref,text){
  const t=text.toLowerCase();
  let theme='God\'s faithfulness and truth';
  if(t.includes('love')||t.includes('loved'))theme='God\'s love';
  else if(t.includes('fear not')||t.includes('be not afraid'))theme='God\'s assurance against fear';
  else if(t.includes('pray'))theme='the power of prayer';
  else if(t.includes('holy spirit'))theme='the Holy Spirit\'s work';
  else if(t.includes('forgiv'))theme='forgiveness and restoration';
  else if(t.includes('peace'))theme='the peace of God';
  else if(t.includes('faith'))theme='a life of faith';
  else if(t.includes('strength')||t.includes('strong'))theme='strength found in God';
  else if(t.includes('grace'))theme='God\'s unearned grace';
  return `This passage speaks to ${theme}. Read it slowly — let the words move from your mind into your heart. Scripture was written not to be analyzed at arm's length but to transform from the inside out. Ask: what is God saying to me, right now, through these words?`;
}

function displayCard(ref,html,meaning){
  document.getElementById('ref-text').textContent=ref+'  ';
  document.getElementById('verse-text').innerHTML=html;
  document.getElementById('meaning-text').textContent=meaning;
  updateSaveBtn(ref);
  const card=document.getElementById('verse-card');
  card.style.display='block';
  card.style.animation='none'; card.offsetHeight;
  card.style.animation='card-appear 0.5s ease forwards';
  card.scrollIntoView({behavior:'smooth',block:'center'});
}
function hideCard(){ document.getElementById('verse-card').style.display='none'; }
function showLoading(v){ document.getElementById('loading').style.display=v?'block':'none'; }
function showError(msg){ const el=document.getElementById('error-msg');el.textContent=msg;el.style.display='block'; }
function hideError(){ document.getElementById('error-msg').style.display='none'; }
function updateSaveBtn(ref){
  const btn=document.getElementById('save-btn');
  const saved=favorites.some(f=>f.ref.toLowerCase()===ref.toLowerCase());
  btn.textContent=saved?'✓ Saved':'✦ Save to Favorites';
  btn.className=saved?'btn btn-saved':'btn btn-primary';
}

/* ════════════════════════════════════════════════════════════
   FAVORITES
════════════════════════════════════════════════════════════ */
function saveVerse(){
  if(!currentVerse)return;
  const{ref,text,meaning}=currentVerse;
  if(favorites.some(f=>f.ref.toLowerCase()===ref.toLowerCase())){ showToast('Already saved — '+ref); return; }
  favorites.unshift({ref,text,meaning});
  persistFavs();
}
function removeFavorite(ref){
  favorites=favorites.filter(f=>f.ref.toLowerCase()!==ref.toLowerCase());
  persistFavs();
  if(currentVerse&&currentVerse.ref.toLowerCase()===ref.toLowerCase()) updateSaveBtn(ref);
  showToast('Removed: '+ref);
}
function persistFavs(){
  localStorage.setItem('wow_favorites',JSON.stringify(favorites));
  renderFavorites(); renderTicker();
  if(currentVerse) updateSaveBtn(currentVerse.ref);
  showToast('✦ Saved: '+(favorites[0]?.ref||''));
}
function renderFavorites(){
  const list=document.getElementById('fav-list');
  list.innerHTML='';
  if(!favorites.length){ list.innerHTML='<div id="fav-empty">Your saved verses will appear here</div>'; return; }
  favorites.forEach(fav=>{
    const chip=document.createElement('div');chip.className='fav-chip';
    chip.innerHTML=`<span class="fav-chip-ref" onclick="loadFav('${escH(fav.ref)}')">${escH(fav.ref)}</span><button class="fav-chip-del" onclick="removeFavorite('${escH(fav.ref)}')">✕</button>`;
    list.appendChild(chip);
  });
}
function loadFav(ref){ document.getElementById('verse-input').value=ref; fetchAndDisplay(ref); }

/* ════════════════════════════════════════════════════════════
   TICKER
════════════════════════════════════════════════════════════ */
function renderTicker(){
  const track=document.getElementById('ticker-track');
  if(!favorites.length){
    track.innerHTML='<span style="font-family:\'Cinzel\',serif;font-size:0.68rem;color:rgba(201,168,76,0.35);padding:0 20px;font-style:italic;">Save a verse below to see it scroll here ✦</span>';
    track.style.animation='none'; return;
  }
  let html='';
  for(let copy=0;copy<2;copy++){
    favorites.forEach(fav=>{
      const snippet=fav.text.replace(/\n/g,' ').trim().slice(0,55)+(fav.text.length>55?'…':'');
      html+=`<span class="ticker-item" onclick="loadFav('${escH(fav.ref)}')">${escH(fav.ref)}</span><span class="ticker-sep">✦</span>`;
      html+=`<span class="ticker-item" style="color:rgba(240,226,192,0.5);font-family:'Lora',serif;font-style:italic;">${escH(snippet)}</span><span class="ticker-sep" style="padding:0 18px;">✦</span>`;
    });
  }
  track.innerHTML=html;
  track.style.animation=`ticker-scroll ${Math.max(30,favorites.length*18)}s linear infinite`;
}

/* ════════════════════════════════════════════════════════════
   GENERATE VERSE
════════════════════════════════════════════════════════════ */
let lastGenVerse=null;
async function generateVerse(){
  const btn=document.querySelector('#gen-modal .btn-primary');
  const ref=VERSE_POOL[Math.floor(Math.random()*VERSE_POOL.length)];
  document.getElementById('gen-result').style.display='none';
  document.getElementById('gen-ref').textContent='Seeking…';
  try{
    const apiRef=ref.replace(/\s+/g,'+').toLowerCase();
    const res=await fetch(`https://bible-api.com/${apiRef}?translation=kjv`);
    const data=await res.json();
    if(data.error)throw new Error();
    const meaning=findMeaning(ref,data.text);
    lastGenVerse={ref:data.reference,text:data.text,meaning};
    document.getElementById('gen-ref').textContent=data.reference;
    document.getElementById('gen-text').textContent='"'+data.text.trim()+'"';
    document.getElementById('gen-meaning').textContent=meaning;
    document.getElementById('gen-result').style.display='block';
  }catch(e){ document.getElementById('gen-ref').textContent='Unable to fetch — try again.'; }
}
function saveGenVerse(){
  if(!lastGenVerse)return;
  const{ref,text,meaning}=lastGenVerse;
  if(favorites.some(f=>f.ref.toLowerCase()===ref.toLowerCase())){ showToast('Already saved'); return; }
  favorites.unshift({ref,text,meaning});
  localStorage.setItem('wow_favorites',JSON.stringify(favorites));
  renderFavorites(); renderTicker();
  showToast('✦ Saved: '+ref);
}
function loadGenVerse(){
  if(!lastGenVerse)return;
  document.getElementById('verse-input').value=lastGenVerse.ref;
  closeModal('gen-modal');
  fetchAndDisplay(lastGenVerse.ref);
}

/* ════════════════════════════════════════════════════════════
   30-DAY TRACKER
════════════════════════════════════════════════════════════ */
let trackerState=JSON.parse(localStorage.getItem('wow_tracker')||'{}');
function renderTracker(){
  const list=document.getElementById('tracker-list');
  list.innerHTML='';
  let done=0;
  PLAN_30.forEach((day,i)=>{
    const key=`day_${i}`;
    const complete=!!trackerState[key];
    if(complete)done++;
    const el=document.createElement('div');
    el.className='tracker-day'+(complete?' completed':'');
    const tagsHtml = day.concepts.map(c=>`<span class="tracker-tag">${escH(c)}</span>`).join('');
    const m = day.meta || {chapters:0,verses:0,words:0};
    const mins = Math.round(m.words / 200);
    const timeStr = mins >= 60 ? `${Math.floor(mins/60)}h ${mins%60}m` : `${mins}m`;
    el.innerHTML=`
      <div class="tracker-check">${complete?'✓':''}</div>
      <div style="flex:1;">
        <div class="tracker-day-num">Day ${i+1} of 30</div>
        <div class="tracker-day-title">${escH(day.title)}</div>
        <div class="tracker-day-ref">${escH(day.ref)}</div>
        <div class="tracker-meta">
          <div class="tracker-meta-item"><span class="tracker-meta-val">${m.chapters}</span><span class="tracker-meta-label">Chapters</span></div>
          <div class="tracker-meta-item"><span class="tracker-meta-val">${m.verses.toLocaleString()}</span><span class="tracker-meta-label">Verses</span></div>
          <div class="tracker-meta-item"><span class="tracker-meta-val">${m.words.toLocaleString()}</span><span class="tracker-meta-label">Words</span></div>
          <div class="tracker-meta-item"><span class="tracker-meta-val">${timeStr}</span><span class="tracker-meta-label">Est. Time</span></div>
        </div>
        <div class="tracker-theme">${escH(day.theme)}</div>
        <div class="tracker-concepts">${tagsHtml}</div>
        <div class="tracker-focus">✦ ${escH(day.focus)}</div>
        <div class="tracker-key-verse">${escH(day.keyVerse)}</div>
        <button class="tracker-start-btn" onclick="event.stopPropagation();closeModal('tracker-modal');searchToReader(null,'${escH(DAY_STARTS[i]||day.ref.split(',')[0].trim())}')">
          📜 Get Started — ${escH(DAY_STARTS[i]||'')}
        </button>
      </div>`;
    el.onclick=()=>toggleDay(key,i);
    list.appendChild(el);
  });
  const pct=Math.round((done/30)*100);
  document.getElementById('tracker-bar').style.width=pct+'%';
  document.getElementById('tracker-count').textContent=`${done} / 30 days`;
  updateReadStats();
}
function toggleDay(key,i){
  trackerState[key]=!trackerState[key];
  localStorage.setItem('wow_tracker',JSON.stringify(trackerState));
  renderTracker();
  if(trackerState[key]) showToast(`Day ${i+1} complete ✦`);
}
function resetTracker(){
  if(!confirm('Reset all 30-day progress?'))return;
  trackerState={};localStorage.setItem('wow_tracker','{}');renderTracker();
}

/* ════════════════════════════════════════════════════════════
   FAMILY TREE
════════════════════════════════════════════════════════════ */
const TOOLTIP=document.getElementById('tree-tooltip');
const TOOLTIP_NAME=document.getElementById('tree-tooltip-name');
const TOOLTIP_BODY=document.getElementById('tree-tooltip-body');

function showTip(name,e){
  const p=TREE_PEOPLE[name]||{desc:'A figure in the Biblical narrative.',ref:''};
  TOOLTIP_NAME.textContent=name;
  TOOLTIP_BODY.innerHTML=(p.desc||'')+(p.ref?`<br><span style="color:var(--gold-dk);font-size:0.72rem;font-style:italic;">${p.ref}</span>`:'');
  TOOLTIP.classList.add('show');
  moveTip(e);
}
function moveTip(e){
  const x=Math.min(e.clientX+14,window.innerWidth-300);
  const y=Math.min(e.clientY+10,window.innerHeight-180);
  TOOLTIP.style.left=x+'px'; TOOLTIP.style.top=y+'px';
}
function hideTip(){ TOOLTIP.classList.remove('show'); }

function node(name,sub='',extraClass=''){
  const d=document.createElement('div');
  d.className='tree-node'+(extraClass?' '+extraClass:'');
  d.innerHTML=`<div class="tree-node-name">${escH(name)}</div>${sub?`<div class="tree-node-sub">${sub}</div>`:''}`;
  d.addEventListener('mouseenter',e=>showTip(name,e));
  d.addEventListener('mousemove',e=>moveTip(e));
  d.addEventListener('mouseleave',hideTip);
  d.addEventListener('click',e=>{ hideTip(); openPersonModal(name); });
  return d;
}
function conn(){ const d=document.createElement('div');d.className='tree-connector-v';return d; }
function hline(){ const d=document.createElement('div');d.style.cssText='height:2px;background:rgba(201,168,76,0.28);flex:1;min-width:16px;margin-top:24px;';return d; }
function era(label){ const d=document.createElement('div');d.className='tree-era-label';d.textContent=label;return d; }
function row(...items){
  const r=document.createElement('div');r.className='tree-row';r.style.cssText='display:flex;align-items:flex-start;justify-content:center;gap:0;flex-wrap:wrap;padding:0 8px;';
  items.forEach(i=>r.appendChild(i));return r;
}
function col(...items){
  const c=document.createElement('div');c.style.cssText='display:flex;flex-direction:column;align-items:center;';
  items.forEach(i=>c.appendChild(i));return c;
}
function couple(n1,n2){
  const d=document.createElement('div');d.className='tree-couple';
  const sep=document.createElement('span');sep.className='tree-couple-sep';sep.textContent='♥';
  d.appendChild(n1);d.appendChild(sep);d.appendChild(n2);return d;
}

function renderTree(){
  const container=document.getElementById('tree-container');
  if(container.children.length>0)return;

  // Helper: vertical chain of single nodes with connectors between
  function chain(...names){ names.forEach((n,i)=>{ container.appendChild(col(node(...(Array.isArray(n)?n:[n])))); if(i<names.length-1)container.appendChild(col(conn())); }); }
  function chainConn(...names){ names.forEach((n,i)=>{ container.appendChild(col(node(...(Array.isArray(n)?n:[n])),conn())); }); }

  // ── ERA 1: Creation ────────────────────────────────────────
  container.appendChild(era('Creation — In the Beginning'));
  container.appendChild(col(node('God','The Creator','highlight'),conn()));
  container.appendChild(col(couple(node('Adam','First Man'),node('Eve','First Woman')),conn()));

  container.appendChild(era('The First Families — Adam\'s Children'));
  container.appendChild(row(col(node('Cain','Firstborn')),hline(),col(node('Abel','Shepherd')),hline(),col(node('Seth','Covenant Line'))));

  // ── ERA 2: Seth → Noah (full line, Genesis 5) ──────────────
  container.appendChild(era('Seth\'s Line to Noah — Genesis 5'));
  container.appendChild(col(conn()));
  chainConn(
    ['Enosh','Son of Seth'],
    ['Kenan','Son of Enosh'],
    ['Mahalalel','Son of Kenan'],
    ['Jared','Son of Mahalalel'],
    ['Enoch','Walked with God — never died'],
    ['Methuselah','969 years — oldest man'],
    ['Lamech','Son of Methuselah']
  );
  container.appendChild(col(node('Noah','Righteous Man','highlight'),conn()));
  container.appendChild(era('Noah\'s Three Sons'));
  container.appendChild(row(col(node('Shem','Covenant Line')),hline(),col(node('Ham','Africa & Canaan')),hline(),col(node('Japheth','Europe & Asia'))));

  // ── ERA 3: Shem → Abraham (full line, Genesis 11) ──────────
  container.appendChild(era('Shem\'s Line to Abraham — Genesis 11'));
  container.appendChild(col(conn()));
  chainConn(
    ['Arphaxad','Son of Shem'],
    ['Shelah','Son of Arphaxad'],
    ['Eber','Son of Shelah'],
    ['Peleg','In his days the earth divided'],
    ['Reu','Son of Peleg'],
    ['Serug','Son of Reu'],
    ['Nahor','Son of Serug'],
    ['Terah','Son of Nahor — stopped in Haran']
  );

  // ── ERA 4: The Patriarchs ──────────────────────────────────
  container.appendChild(era('The Patriarchs — The Covenant of Promise'));
  container.appendChild(col(couple(node('Abraham','Father of Faith','highlight'),node('Sarah','Mother of Nations')),conn()));
  container.appendChild(row(
    col(node('Ishmael','Son of Hagar')),hline(),
    col(node('Isaac','Child of Promise','highlight'))
  ));
  const hagarNote=document.createElement('div');
  hagarNote.style.cssText='text-align:center;font-size:0.68rem;color:rgba(201,168,76,0.4);font-style:italic;margin:4px 0 10px;';
  hagarNote.textContent='(Ishmael born through Hagar, the handmaid — Genesis 16)';
  container.appendChild(hagarNote);

  container.appendChild(col(conn(),couple(node('Isaac'),node('Rebekah')),conn()));
  container.appendChild(row(col(node('Esau','Edomites')),hline(),col(node('Jacob','Israel — 12 Tribes','highlight'))));

  // ── ERA 5: The Twelve Tribes ───────────────────────────────
  container.appendChild(era('Israel & The Twelve Tribes — Genesis 29–30, 35'));
  container.appendChild(row(col(node('Leah','Wife 1 — mother of Judah'),conn()),hline(),col(node('Rachel','Beloved Wife'),conn())));
  container.appendChild(row(
    col(node('Reuben','Tribe 1')),hline(),col(node('Simeon','Tribe 2')),hline(),
    col(node('Levi','Tribe 3')),hline(),col(node('Judah','Tribe 4 ✦ Messianic','highlight')),hline(),
    col(node('Dan','Tribe 5')),hline(),col(node('Naphtali','Tribe 6'))
  ));
  container.appendChild(row(
    col(node('Gad','Tribe 7')),hline(),col(node('Asher','Tribe 8')),hline(),
    col(node('Issachar','Tribe 9')),hline(),col(node('Zebulun','Tribe 10')),hline(),
    col(node('Joseph','Tribe 11')),hline(),col(node('Benjamin','Tribe 12'))
  ));

  // ── ERA 6: Judah → Perez → Boaz (Ruth 4, Matthew 1) ───────
  container.appendChild(era('The Messianic Line — Judah Through Perez to Boaz (Ruth 4:18–21, Matthew 1:3–5)'));
  container.appendChild(col(conn(),couple(node('Judah'),node('Tamar','Daughter-in-law')),conn()));
  chainConn(
    ['Perez','Son of Judah & Tamar'],
    ['Hezron','Son of Perez'],
    ['Ram','Son of Hezron'],
    ['Amminadab','Son of Ram — leader of Judah'],
    ['Nahshon','Son of Amminadab — Exodus leader']
  );
  container.appendChild(col(couple(node('Salmon','Son of Nahshon'),node('Rahab','Harlot of Jericho — saved by faith','highlight')),conn()));

  // ── ERA 7: Boaz, Ruth, David ───────────────────────────────
  container.appendChild(era('Ruth & Boaz — Grace Enters the Bloodline (Ruth 1–4)'));
  container.appendChild(col(couple(node('Boaz','Kinsman-Redeemer','highlight'),node('Ruth','Moabite Widow','highlight')),conn()));
  chainConn(
    ['Obed','Son of Boaz & Ruth'],
    ['Jesse','Son of Obed — father of David']
  );

  // ── ERA 8: David → Solomon ─────────────────────────────────
  container.appendChild(era('King David — The Eternal Throne (2 Samuel 7)'));
  container.appendChild(col(couple(node('David','King of Israel','highlight'),node('Bathsheba','')),conn()));
  container.appendChild(col(node('Solomon','Wisest King — builds the Temple'),conn()));

  // ── ERA 9: The Royal Line — Solomon to Jechoniah (Matthew 1:6–11) ─
  container.appendChild(era('The Kings of Judah — Solomon to the Exile (Matthew 1:6–11, 1–2 Kings)'));
  container.appendChild(col(conn()));
  chainConn(
    ['Rehoboam','Son of Solomon — kingdom splits'],
    ['Abijah','Son of Rehoboam'],
    ['Asa','Son of Abijah — godly reformer'],
    ['Jehoshaphat','Son of Asa — sent singers to battle'],
    ['Jehoram','Son of Jehoshaphat — married Jezebel\'s daughter'],
    ['Uzziah','Son of Amaziah — struck with leprosy'],
    ['Jotham','Son of Uzziah — grew mighty'],
    ['Ahaz','Son of Jotham — wicked, shut the temple'],
    ['Hezekiah','Son of Ahaz — 185,000 Assyrians struck dead','highlight'],
    ['Manasseh','Son of Hezekiah — most wicked, then repented'],
    ['Amon','Son of Manasseh — assassinated after 2 years'],
    ['Josiah','Son of Amon — greatest reformer','highlight'],
    ['Jechoniah','Son of Jehoiakim — taken to Babylon (the curse)']
  );

  // ── ERA 10: Post-Exile Line — Jechoniah to Joseph (Matthew 1:12–16) ─
  container.appendChild(era('Post-Exile Generations — Babylon to Bethlehem (Matthew 1:12–16)'));
  container.appendChild(col(conn()));
  chainConn(
    ['Shealtiel','Son of Jechoniah — born in exile'],
    ['Zerubbabel','Son of Shealtiel — led return from Babylon','highlight'],
    ['Abiud','Son of Zerubbabel'],
    ['Eliakim','Son of Abiud'],
    ['Azor','Son of Eliakim'],
    ['Zadok','Son of Azor'],
    ['Achim','Son of Zadok'],
    ['Eliud','Son of Achim'],
    ['Eleazar','Son of Eliud'],
    ['Matthan','Son of Eleazar'],
    ['Jacob (father of Joseph)','Son of Matthan']
  );

  // ── ERA 11: The Fulfillment ────────────────────────────────
  container.appendChild(era('The Fulfillment — Jesus the Messiah (Matthew 1:16, Luke 1:31)'));
  container.appendChild(col(couple(node('Joseph (husband of Mary)','Legal royal heir — son of Jacob'),node('Mary','Mother of God — Theotokos','highlight')),conn()));
  container.appendChild(col(node('Jesus','Son of God · Son of Man · Son of David','highlight')));

  const crown=document.createElement('div');
  crown.style.cssText='text-align:center;margin-top:16px;font-family:"Cinzel",serif;font-size:0.72rem;letter-spacing:0.15em;color:rgba(201,168,76,0.5);line-height:1.8;';
  crown.innerHTML='✝ &nbsp; The Word made flesh &nbsp; — &nbsp; John 1:14 &nbsp; ✝<br><span style="font-size:0.6rem;letter-spacing:0.1em;color:rgba(201,168,76,0.3);">42 generations · Abraham to Jesus · Matthew 1:17</span>';
  container.appendChild(crown);
}


/* ════════════════════════════════════════════════════════════
   COPY / SHARE
════════════════════════════════════════════════════════════ */
function copyVerse(){
  if(!currentVerse)return;
  const txt=`${currentVerse.ref} (KJV)\n\n${currentVerse.text.trim()}`;
  navigator.clipboard.writeText(txt).then(()=>showToast('Verse copied!')).catch(()=>{
    const ta=document.createElement('textarea');ta.value=txt;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);showToast('Verse copied!');
  });
}
function shareVerse(){
  if(!currentVerse)return;
  const txt=`${currentVerse.ref} (KJV)\n\n${currentVerse.text.trim()}\n\n— Be Still and Know`;
  if(navigator.share){ navigator.share({title:currentVerse.ref,text:txt}).catch(()=>{}); }
  else copyVerse();
}

/* ════════════════════════════════════════════════════════════
   TOAST & UTIL
════════════════════════════════════════════════════════════ */
let toastTimer=null;
function showToast(msg){
  const t=document.getElementById('toast');t.textContent=msg;t.classList.add('show');
  clearTimeout(toastTimer);toastTimer=setTimeout(()=>t.classList.remove('show'),3000);
}
function escH(s){ return String(s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

/* ════════════════════════════════════════════════════════════
   CREATION TIMELINE DATA
════════════════════════════════════════════════════════════ */
const CREATION_DAYS = [
  {
    n: 1, icon: '💡', title: 'Light',
    verse: '"And God said, Let there be light: and there was light. And God saw the light, that it was good: and God divided the light from the darkness."',
    ref: 'Genesis 1:3–4',
    desc: 'Before anything visible existed, God spoke light into being — not the sun (created on Day 4), but a primordial, formless radiance. He then separated light from darkness, establishing the very first distinction in creation. Day and night begin. The rhythm of time itself is born.',
    created: ['Light', 'Darkness separated', 'Day and Night']
  },
  {
    n: 2, icon: '☁️', title: 'Sky & Waters',
    verse: '"And God said, Let there be a firmament in the midst of the waters, and let it divide the waters from the waters... and God called the firmament Heaven."',
    ref: 'Genesis 1:6–8',
    desc: 'God creates an expanse — the sky — dividing the waters above (clouds and atmosphere) from the waters below (oceans and seas). The Hebrew word for firmament is raqia, meaning a stretched-out expanse. Heaven is named. Atmosphere and weather systems come into existence.',
    created: ['The firmament (sky)', 'Waters above separated', 'Waters below gathered', 'Heaven named']
  },
  {
    n: 3, icon: '🌿', title: 'Land, Seas & Vegetation',
    verse: '"And God said, Let the dry land appear... and God called the dry land Earth; and the gathering together of the waters called he Seas... And God said, Let the earth bring forth grass, the herb yielding seed, and the fruit tree."',
    ref: 'Genesis 1:9–12',
    desc: 'God commands the waters to gather so that dry ground appears. Continents and oceans take shape. Then — before the sun exists — God commands the earth to bring forth plant life: grasses, herbs bearing seed, and fruit trees. Life emerges from the ground at the word of God alone.',
    created: ['Dry land (Earth)', 'Seas gathered', 'Grass and herbs', 'Fruit trees', 'Seed-bearing plants']
  },
  {
    n: 4, icon: '☀️', title: 'Sun, Moon & Stars',
    verse: '"And God said, Let there be lights in the firmament of the heaven to divide the day from the night; and let them be for signs, and for seasons, and for days, and years."',
    ref: 'Genesis 1:14–19',
    desc: 'God places two great lights in the sky — the greater light (sun) to rule the day and the lesser light (moon) to rule the night — and also the stars. These celestial bodies are not creators or gods (as surrounding cultures believed) but servants — placed by God to mark time, seasons, and calendars for humanity.',
    created: ['The Sun', 'The Moon', 'The Stars', 'Seasons and years', 'Signs in the heavens']
  },
  {
    n: 5, icon: '🐟', title: 'Fish & Birds',
    verse: '"And God said, Let the waters bring forth abundantly the moving creature that hath life, and fowl that may fly above the earth in the open firmament of heaven."',
    ref: 'Genesis 1:20–23',
    desc: 'The seas and skies fill with life. Every sea creature — from the great whales to the smallest fish — and every winged bird comes into being. God blesses them with the first recorded blessing in Scripture: "Be fruitful and multiply." Life explodes across two entire domains of creation.',
    created: ['Great sea creatures', 'All fish and sea life', 'All birds of every kind', 'First blessing — "Be fruitful"']
  },
  {
    n: 6, icon: '🦁', title: 'Animals & Mankind',
    verse: '"And God said, Let us make man in our image, after our likeness... So God created man in his own image, in the image of God created he him; male and female created he them."',
    ref: 'Genesis 1:26–27',
    desc: 'The most creative day. God first fills the land with every kind of animal — livestock, wild beasts, and creatures that move along the ground. Then comes the crown of creation: humanity. Unlike every other creative act, God pauses and says "Let us make man." The plural points to the triune God in council. Man is made in the image of God — the only creature in all creation given this distinction. Male and female, together, bear the image of God. They are given dominion over the earth.',
    created: ['Livestock and cattle', 'Wild animals', 'Creeping things', 'Man — in God\'s image', 'Woman', 'Dominion over creation']
  },
  {
    n: 7, icon: '✝️', title: 'Rest — The Sabbath',
    verse: '"And on the seventh day God ended his work which he had made; and he rested on the seventh day from all his work which he had made. And God blessed the seventh day, and sanctified it."',
    ref: 'Genesis 2:2–3',
    desc: 'God rests — not because He is tired, but to model a sacred rhythm of work and rest for His image-bearers. The seventh day is the only day in creation that is not closed with "and the evening and the morning were the Xth day." It remains open — an invitation into God\'s own rest. The Sabbath is the first thing in all Scripture that God calls holy. It is not a place or a person — it is a moment in time, set apart.',
    created: ['The Sabbath — holy rest', 'Sacred rhythm of seven', 'Creation completed and blessed']
  }
];

/* ════════════════════════════════════════════════════════════
   BIBLE BOOKS
════════════════════════════════════════════════════════════ */
const BIBLE_BOOKS = [
  {n:"Genesis",c:50},{n:"Exodus",c:40},{n:"Leviticus",c:27},{n:"Numbers",c:36},{n:"Deuteronomy",c:34},
  {n:"Joshua",c:24},{n:"Judges",c:21},{n:"Ruth",c:4},{n:"1 Samuel",c:31},{n:"2 Samuel",c:24},
  {n:"1 Kings",c:22},{n:"2 Kings",c:25},{n:"1 Chronicles",c:29},{n:"2 Chronicles",c:36},
  {n:"Ezra",c:10},{n:"Nehemiah",c:13},{n:"Esther",c:10},{n:"Job",c:42},{n:"Psalms",c:150},
  {n:"Proverbs",c:31},{n:"Ecclesiastes",c:12},{n:"Song of Solomon",c:8},{n:"Isaiah",c:66},
  {n:"Jeremiah",c:52},{n:"Lamentations",c:5},{n:"Ezekiel",c:48},{n:"Daniel",c:12},
  {n:"Hosea",c:14},{n:"Joel",c:3},{n:"Amos",c:9},{n:"Obadiah",c:1},{n:"Jonah",c:4},
  {n:"Micah",c:7},{n:"Nahum",c:3},{n:"Habakkuk",c:3},{n:"Zephaniah",c:3},{n:"Haggai",c:2},
  {n:"Zechariah",c:14},{n:"Malachi",c:4},
  {n:"Matthew",c:28},{n:"Mark",c:16},{n:"Luke",c:24},{n:"John",c:21},{n:"Acts",c:28},
  {n:"Romans",c:16},{n:"1 Corinthians",c:16},{n:"2 Corinthians",c:13},{n:"Galatians",c:6},
  {n:"Ephesians",c:6},{n:"Philippians",c:4},{n:"Colossians",c:4},{n:"1 Thessalonians",c:5},
  {n:"2 Thessalonians",c:3},{n:"1 Timothy",c:6},{n:"2 Timothy",c:4},{n:"Titus",c:3},
  {n:"Philemon",c:1},{n:"Hebrews",c:13},{n:"James",c:5},{n:"1 Peter",c:5},{n:"2 Peter",c:3},
  {n:"1 John",c:5},{n:"2 John",c:1},{n:"3 John",c:1},{n:"Jude",c:1},{n:"Revelation",c:22}
];

/* ════════════════════════════════════════════════════════════
   CREATION TIMELINE
════════════════════════════════════════════════════════════ */
function renderTimeline() {
  const wrap = document.getElementById('timeline-days');
  if (wrap.children.length) return;
  CREATION_DAYS.forEach(d => {
    const tags = d.created.map(t =>
      `<span style="display:inline-block;background:rgba(201,168,76,0.08);border:1px solid rgba(201,168,76,0.2);border-radius:2px;padding:2px 9px;font-family:'Cinzel',serif;font-size:0.6rem;letter-spacing:0.06em;color:rgba(201,168,76,0.7);margin:2px 3px 2px 0;">${escH(t)}</span>`
    ).join('');
    const el = document.createElement('div');
    el.className = `timeline-day${d.n===7?' timeline-day-7':''}`;
    el.innerHTML = `
      <div class="timeline-day-badge">
        <span class="timeline-day-num">Day</span>
        <span class="timeline-day-n">${d.n}</span>
        <span class="timeline-day-icon">${d.icon}</span>
      </div>
      <div class="timeline-day-content">
        <div class="timeline-day-title">${escH(d.title)}</div>
        <div class="timeline-day-verse">${escH(d.verse)}</div>
        <div class="timeline-day-ref">${escH(d.ref)}</div>
        <div style="margin:8px 0 6px;">${tags}</div>
        <div class="timeline-day-desc">${escH(d.desc)}</div>
      </div>`;
    wrap.appendChild(el);
  });
}

/* ════════════════════════════════════════════════════════════
   BOOK → 30-DAY PLAN MAPPING
════════════════════════════════════════════════════════════ */
// Index = BIBLE_BOOKS index, value = primary day number
const BOOK_DAY_MAP = [
  1,3,5,6,7,         // Genesis(split 1-3),Exodus(split 3-4),Lev,Num,Deut
  8,8,9,9,10,        // Josh,Judg,Ruth,1Sam,2Sam
  10,11,12,12,12,12,12, // 1Kgs,2Kgs,1Chr,2Chr,Ezra,Neh,Esth
  13,14,             // Job,Psalms(split 14-15)
  15,16,16,16,       // Prov,Eccl,SoS,Isa(split 16-17)
  17,18,18,18,       // Jer(17),Lam,Ezek,Dan
  18,18,18,18,18,18,18,18,18,18,18, // Minor Prophets
  19,20,21,22,23,    // Matt,Mark,Luke,John,Acts(split 23-24)
  25,26,26,25,27,27,27, // Rom,1Cor,2Cor,Gal,Eph,Phil,Col
  28,28,28,28,28,28, // 1Thess,2Thess,1Tim,2Tim,Titus,Phm
  29,29,29,29,29,29,29,29, // Heb,Jas,1Pet,2Pet,1Jn,2Jn,3Jn,Jude
  30                 // Revelation
];
// For books split across days, use chapter ranges
function getChapterDay(bookIdx, chapter) {
  let day = BOOK_DAY_MAP[bookIdx] || 1;
  // Genesis split: 1-11=1, 12-36=2, 37+=3
  if (bookIdx===0) day = chapter<=11?1:chapter<=36?2:3;
  // Exodus split: 1-12=3, 13+=4
  else if (bookIdx===1) day = chapter<=12?3:4;
  // Psalms split: 1-75=14, 76+=15
  else if (bookIdx===18) day = chapter<=75?14:15;
  // Isaiah split: 1-39=16, 40+=17
  else if (bookIdx===22) day = chapter<=39?16:17;
  // Acts split: 1-14=23, 15+=24
  else if (bookIdx===43) day = chapter<=14?23:24;
  return day;
}
function getDayColorClass(day) {
  if (day<=18) return 'rv-day-ot';
  if (day<=22) return 'rv-day-gsp';
  if (day<=24) return 'rv-day-act';
  if (day<=29) return 'rv-day-epi';
  return 'rv-day-rev';
}
// Starting reference for each day's "Get Started" button
const DAY_STARTS = [
  'Genesis 1','Genesis 12','Genesis 37','Exodus 1','Leviticus 1',
  'Numbers 1','Deuteronomy 1','Joshua 1','Ruth 1','2 Samuel 1',
  '1 Kings 12','1 Chronicles 1','Job 1','Psalms 1','Psalms 76',
  'Ecclesiastes 1','Isaiah 40','Lamentations 1',
  'Matthew 1','Mark 1','Luke 1','John 1',
  'Acts 1','Acts 15','Romans 1','1 Corinthians 1',
  'Ephesians 1','1 Thessalonians 1','Hebrews 1','Revelation 1'
];

/* ════════════════════════════════════════════════════════════
   READING LOG
════════════════════════════════════════════════════════════ */
let readLog = JSON.parse(localStorage.getItem('wow_read_log')||'{}');
const TOTAL_BIBLE_CHAPTERS = 1189;
const TOTAL_BIBLE_VERSES   = 31102;
const TOTAL_BIBLE_WORDS    = 783137;

function markChapterRead(bookIdx, chapter, verseCount, wordCount) {
  const key = `${bookIdx}:${chapter}`;
  if (!readLog[key]) {
    readLog[key] = { verses: verseCount, words: Math.round(verseCount * 25.2) };
    localStorage.setItem('wow_read_log', JSON.stringify(readLog));
  }
  updateReadStats();
}
function getReadStats() {
  const keys = Object.keys(readLog);
  return {
    chapters: keys.length,
    verses:   keys.reduce((s,k)=>s+(readLog[k].verses||0),0),
    words:    keys.reduce((s,k)=>s+(readLog[k].words||0),0)
  };
}
function fmtTime(mins) {
  if (mins < 60) return mins + 'm';
  return Math.floor(mins/60) + 'h ' + (mins%60) + 'm';
}
function updateReadStats() {
  const s = getReadStats();
  const pct = Math.min(100, (s.chapters / TOTAL_BIBLE_CHAPTERS * 100)).toFixed(1);
  const remCh = Math.max(0, TOTAL_BIBLE_CHAPTERS - s.chapters);
  const remV  = Math.max(0, TOTAL_BIBLE_VERSES   - s.verses);
  const remW  = Math.max(0, TOTAL_BIBLE_WORDS     - s.words);
  const remT  = fmtTime(Math.round(remW / 200));

  // Update reader progress bar
  const rbpBar = document.getElementById('rbp-bar');
  if (rbpBar) {
    rbpBar.style.width = pct + '%';
    document.getElementById('rbp-left').textContent = s.chapters.toLocaleString() + ' chapters read (' + pct + '%)';
    document.getElementById('rbp-chapters').textContent = s.chapters.toLocaleString();
    document.getElementById('rbp-verses').textContent = s.verses.toLocaleString();
    document.getElementById('rbp-words').textContent = s.words.toLocaleString();
    document.getElementById('rbp-rem-ch').textContent = remCh.toLocaleString();
    document.getElementById('rbp-rem-v').textContent  = remV.toLocaleString();
    document.getElementById('rbp-rem-w').textContent  = remW.toLocaleString();
    document.getElementById('rbp-rem-time').textContent = remT;
  }
  // Update tracker cumulative
  const tcC = document.getElementById('tc-chapters');
  if (tcC) {
    tcC.textContent = s.chapters.toLocaleString();
    document.getElementById('tc-verses').textContent = s.verses.toLocaleString();
    document.getElementById('tc-words').textContent = s.words.toLocaleString();
    document.getElementById('tc-pct').textContent = pct + '%';
    document.getElementById('tc-rem-ch').textContent = remCh.toLocaleString();
    document.getElementById('tc-rem-v').textContent  = remV.toLocaleString();
    document.getElementById('tc-rem-w').textContent  = remW.toLocaleString();
    document.getElementById('tc-rem-t').textContent  = '~' + remT;
  }
}

/* ════════════════════════════════════════════════════════════
   BIBLE READER
════════════════════════════════════════════════════════════ */
let readerBookIdx = 0;
let readerChapter = 1;
let readerVerses  = [];   // [{verse, text}]
let readerActive  = -1;   // currently selected verse index
let readerSpeaking = false;
let readerSpeakIdx = 0;
let readerRate    = 1;

function readerInit() {
  const bookSel = document.getElementById('reader-book-select');
  if (!bookSel.options.length) {
    BIBLE_BOOKS.forEach((b,i) => {
      const o = document.createElement('option');
      o.value = i; o.textContent = b.n;
      bookSel.appendChild(o);
    });
  }
  // Sync dropdowns to current state (may have been set by searchToReader)
  bookSel.value = readerBookIdx;
  readerBuildChapterSelect();
  readerLoadChapter();
}

function readerBuildChapterSelect() {
  const sel = document.getElementById('reader-chapter-select');
  sel.innerHTML = '';
  const total = BIBLE_BOOKS[readerBookIdx].c;
  for (let i = 1; i <= total; i++) {
    const o = document.createElement('option');
    o.value = i; o.textContent = `Ch. ${i}`;
    if (i === readerChapter) o.selected = true;
    sel.appendChild(o);
  }
  document.getElementById('reader-chapter-label').textContent =
    `Chapter ${readerChapter} of ${total}`;
  document.getElementById('reader-prev-ch').disabled = readerChapter <= 1;
  document.getElementById('reader-next-ch').disabled = readerChapter >= total;
}

function readerBookChanged() {
  readerStop();
  readerBookIdx = +document.getElementById('reader-book-select').value;
  readerChapter = 1;
  readerBuildChapterSelect();
  readerLoadChapter();
}
function readerChapterChanged() {
  readerStop();
  readerChapter = +document.getElementById('reader-chapter-select').value;
  readerBuildChapterSelect();
  readerLoadChapter();
}
function readerPrevChapter() {
  if (readerChapter <= 1) {
    if (readerBookIdx > 0) {
      readerBookIdx--;
      readerChapter = BIBLE_BOOKS[readerBookIdx].c;
      document.getElementById('reader-book-select').value = readerBookIdx;
    } else return;
  } else { readerChapter--; }
  readerStop();
  readerBuildChapterSelect();
  readerLoadChapter();
}
function readerNextChapter() {
  if (readerChapter >= BIBLE_BOOKS[readerBookIdx].c) {
    if (readerBookIdx < BIBLE_BOOKS.length - 1) {
      readerBookIdx++;
      readerChapter = 1;
      document.getElementById('reader-book-select').value = readerBookIdx;
    } else return;
  } else { readerChapter++; }
  readerStop();
  readerBuildChapterSelect();
  readerLoadChapter();
}

async function readerLoadChapter() {
  readerStop();
  readerVerses = []; readerActive = -1;
  document.getElementById('reader-verses').innerHTML = '';
  document.getElementById('reader-verse-controls').style.display = 'none';
  document.getElementById('reader-error').style.display = 'none';
  document.getElementById('reader-loading').style.display = 'block';

  const book = BIBLE_BOOKS[readerBookIdx].n;
  const apiRef = (book + '+' + readerChapter).replace(/\s+/g, '+').toLowerCase();
  try {
    const res = await fetch(`https://bible-api.com/${apiRef}?translation=kjv`);
    const data = await res.json();
    if (data.error || !data.verses) throw new Error();
    readerVerses = data.verses;
    readerRenderVerses();
    // Mark chapter as read and update progress
    const vCount = data.verses.length;
    markChapterRead(readerBookIdx, readerChapter, vCount, vCount * 25);
    updateReadStats();
    addRecentView(readerBookIdx, readerChapter);
    updateStreak();
    applyFont();
    updateBookmarkBtn();
    // Scroll to and highlight target verse if set from search
    if (readerTargetVerse > 0) {
      const targetIdx = readerVerses.findIndex(v => v.verse >= readerTargetVerse);
      const idx = targetIdx >= 0 ? targetIdx : 0;
      setTimeout(() => {
        readerSelectVerse(idx);
        document.getElementById(`rv-${idx}`)?.scrollIntoView({behavior:'smooth', block:'center'});
      }, 120);
      readerTargetVerse = 0;
    }
  } catch(e) {
    document.getElementById('reader-error').textContent =
      'Could not load chapter — check your connection and try again.';
    document.getElementById('reader-error').style.display = 'block';
  } finally {
    document.getElementById('reader-loading').style.display = 'none';
  }
}

function readerRenderVerses() {
  const container = document.getElementById('reader-verses');
  container.innerHTML = '';
  readerVerses.forEach((v, i) => {
    const ref = `${BIBLE_BOOKS[readerBookIdx].n} ${readerChapter}:${v.verse}`;
    const starred = favorites.some(f => f.ref.toLowerCase() === ref.toLowerCase());
    const row = document.createElement('div');
    row.className = 'reader-verse' + (i === readerActive ? ' active' : '');
    row.id = `rv-${i}`;
    const day = getChapterDay(readerBookIdx, readerChapter);
    const dayColorCls = getDayColorClass(day);
    const hasNote = notes.some(n => n.ref === ref);
    const hlKey = getHighlightKey(readerBookIdx, readerChapter, v.verse);
    const hlColor = highlights[hlKey];
    if(hlColor) row.classList.add('hl-'+hlColor);
    row.innerHTML = `
      <span class="rv-num">${v.verse}</span>
      <span class="rv-text">${escH(v.text.trim())}</span>
      <button class="rv-star${starred?' starred':''}" title="${starred?'Remove from favorites':'Save to favorites'}"
        onclick="readerStarVerse(${i},this)">★</button>
      ${buildHighlightPicker(readerBookIdx, readerChapter, v)}
      <button class="rv-note-btn${hasNote?' noted':''}" title="${hasNote?'Edit note':'Add note'}"
        onclick="readerOpenNote('${escH(ref)}','${escH(v.text.trim().replace(/'/g,'&#39;'))}')">✏</button>
      <span class="rv-pipe">|</span>
      <span class="rv-day-badge ${dayColorCls}" title="30-Day Plan: Day ${day}" onclick="closeModal('reader-modal');openModal('tracker-modal')">Day ${day}</span>`;
    row.addEventListener('click', e => { if(!e.target.classList.contains('rv-star')) readerSelectVerse(i); });
    container.appendChild(row);
  });
}

function readerSelectVerse(i) {
  // Show cross-refs for selected verse
  if(readerVerses[i]){
    const book=BIBLE_BOOKS[readerBookIdx].n;
    showXrefs(`${book} ${readerChapter}:${readerVerses[i].verse}`);
  }
  readerActive = i;
  document.querySelectorAll('.reader-verse').forEach((el,j) => {
    el.classList.toggle('active', j === i);
  });
  document.getElementById('reader-verse-controls').style.display = 'flex';
  document.getElementById('reader-verse-label').textContent =
    `Verse ${readerVerses[i].verse} of ${readerVerses.length}`;
  document.getElementById(`rv-${i}`).scrollIntoView({block:'nearest',behavior:'smooth'});
}
function readerPrevVerse() { if (readerActive > 0) readerSelectVerse(readerActive - 1); }
function readerNextVerse() { if (readerActive < readerVerses.length - 1) readerSelectVerse(readerActive + 1); }

function readerStarVerse(i, btn) {
  const v = readerVerses[i];
  const book = BIBLE_BOOKS[readerBookIdx].n;
  const ref = `${book} ${readerChapter}:${v.verse}`;
  const text = v.text.trim();
  const alreadySaved = favorites.some(f => f.ref.toLowerCase() === ref.toLowerCase());
  if (alreadySaved) {
    favorites = favorites.filter(f => f.ref.toLowerCase() !== ref.toLowerCase());
    btn.classList.remove('starred');
    btn.title = 'Save to favorites';
    showToast('Removed: ' + ref);
  } else {
    favorites.unshift({ ref, text, meaning: findMeaning(ref, text) });
    btn.classList.add('starred');
    btn.title = 'Remove from favorites';
    showToast('✦ Saved: ' + ref);
  }
  localStorage.setItem('wow_favorites', JSON.stringify(favorites));
  renderFavorites(); renderTicker();
}

/* Voices */
let readerVoice = null;
function initVoices() {
  const sel = document.getElementById('reader-voice-select');
  if (!sel) return;
  function populate() {
    const voices = speechSynthesis.getVoices();
    if (!voices.length) return;
    // Keep current selection if re-populating
    const prev = sel.value;
    sel.innerHTML = '<option value="">Default Voice</option>';
    // Prefer English voices first, then others
    const en = voices.filter(v => v.lang.startsWith('en'));
    const other = voices.filter(v => !v.lang.startsWith('en'));
    [...en, ...other].forEach(v => {
      const o = document.createElement('option');
      o.value = v.name;
      o.textContent = `${v.name} (${v.lang})`;
      if (v.name === prev) o.selected = true;
      sel.appendChild(o);
    });
    // Default to first English voice if nothing selected
    if (!prev && en.length) {
      sel.value = en[0].name;
      readerVoice = en[0];
    }
  }
  populate();
  speechSynthesis.onvoiceschanged = populate;
}
function setVoice(sel) {
  const voices = speechSynthesis.getVoices();
  readerVoice = voices.find(v => v.name === sel.value) || null;
}

/* Audio */
function readerToggleAudio() {
  if (readerSpeaking) { readerStop(); return; }
  if (!readerVerses.length) return;
  readerSpeaking = true;
  readerSpeakIdx = readerActive >= 0 ? readerActive : 0;
  document.getElementById('reader-audio-play').textContent = '⏸ Pause';
  readerSpeakNext();
}
function readerSpeakNext() {
  if (!readerSpeaking || readerSpeakIdx >= readerVerses.length) {
    readerStop(); return;
  }
  const v = readerVerses[readerSpeakIdx];
  readerSelectVerse(readerSpeakIdx);
  document.getElementById(`rv-${readerSpeakIdx}`).classList.add('speaking');
  document.getElementById('reader-audio-status').textContent =
    `Reading verse ${v.verse}…`;

  const utt = new SpeechSynthesisUtterance(v.text.trim());
  utt.rate = readerRate;
  utt.lang = readerVoice ? readerVoice.lang : 'en-US';
  if (readerVoice) utt.voice = readerVoice;
  utt.onend = () => {
    document.getElementById(`rv-${readerSpeakIdx}`)?.classList.remove('speaking');
    readerSpeakIdx++;
    setTimeout(readerSpeakNext, 180);
  };
  utt.onerror = () => { readerStop(); };
  speechSynthesis.speak(utt);
}
function readerStop() {
  speechSynthesis.cancel();
  readerSpeaking = false;
  document.querySelectorAll('.reader-verse.speaking').forEach(el => el.classList.remove('speaking'));
  const btn = document.getElementById('reader-audio-play');
  if (btn) btn.textContent = '▶ Read Aloud';
  const status = document.getElementById('reader-audio-status');
  if (status) status.textContent = 'Ready';
}
function setSpeed(btn) {
  readerRate = parseFloat(btn.dataset.rate);
  document.querySelectorAll('.speed-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  // If currently speaking, restart current verse at new speed
  if (readerSpeaking) {
    speechSynthesis.cancel();
    document.querySelectorAll('.reader-verse.speaking').forEach(el=>el.classList.remove('speaking'));
    setTimeout(readerSpeakNext, 80);
  }
}

/* ════════════════════════════════════════════════════════════
   PERSON POPUP (Family Tree)
════════════════════════════════════════════════════════════ */
async function openPersonModal(name) {
  const p = TREE_PEOPLE[name] || { desc: 'A figure in the Biblical narrative.', ref: '' };
  document.getElementById('person-modal-name').textContent = name;
  document.getElementById('person-modal-ref-label').textContent =
    p.ref ? `First reference: ${p.ref}` : '';
  document.getElementById('person-modal-desc').textContent = p.desc || '';
  document.getElementById('person-modal-verse').innerHTML =
    '<span id="person-modal-loading">Fetching scripture…</span>';
  openModal('person-modal');

  if (!p.ref) {
    document.getElementById('person-modal-verse').textContent = '—';
    return;
  }
  try {
    const apiRef = p.ref.replace(/\s+/g,'+').toLowerCase();
    const res = await fetch(`https://bible-api.com/${apiRef}?translation=kjv`);
    const data = await res.json();
    if (data.error || !data.text) throw new Error();
    document.getElementById('person-modal-verse').textContent = '"' + data.text.trim() + '"';
  } catch(e) {
    document.getElementById('person-modal-verse').textContent = 'Could not fetch verse — check connection.';
  }
}

/* ════════════════════════════════════════════════════════════
   NOTES SYSTEM
════════════════════════════════════════════════════════════ */
let notes = JSON.parse(localStorage.getItem('wow_notes') || '[]');
let editingNoteId = null; // null = new note, string = editing existing

function persistNotes() {
  localStorage.setItem('wow_notes', JSON.stringify(notes));
}

function renderNotes() {
  const list = document.getElementById('notes-list');
  if (!list) return;
  if (!notes.length) {
    list.innerHTML = '<div id="notes-empty">No notes yet — open the Bible reader, tap ✏ beside any verse, and start journaling.</div>';
    return;
  }
  list.innerHTML = '';
  // Sort newest first
  [...notes].sort((a,b) => b.ts - a.ts).forEach(note => {
    const d = new Date(note.ts);
    const dateStr = d.toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'});
    const card = document.createElement('div');
    card.className = 'note-card';
    card.innerHTML = `
      <div class="note-card-ref">${escH(note.ref)}</div>
      ${note.verseText ? `<div class="note-card-verse">"${escH(note.verseText.slice(0,120))}${note.verseText.length>120?'…':''}"</div>` : ''}
      <div class="note-card-insight">${escH(note.insight)}</div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px;">
        <span class="note-card-ts">${dateStr}</span>
        <div class="note-card-actions">
          <button class="note-edit-btn" onclick="event.stopPropagation();editNote('${note.id}')">Edit</button>
          <button class="note-del-btn" onclick="event.stopPropagation();deleteNote('${note.id}')">Delete</button>
        </div>
      </div>`;
    list.appendChild(card);
  });
}

function showNotesList() {
  document.getElementById('notes-list-view').style.display = '';
  document.getElementById('notes-edit-view').style.display = 'none';
  editingNoteId = null;
  renderNotes();
}

function openNoteEditor(ref, verseText) {
  // Can be called directly (new blank note) or from reader (pre-filled)
  editingNoteId = null;
  document.getElementById('notes-edit-mode-label').textContent = 'NEW NOTE';
  document.getElementById('notes-ref-display').textContent = ref || '';
  document.getElementById('notes-verse-display').textContent = verseText ? '"' + verseText + '"' : '';
  document.getElementById('notes-verse-display').style.display = verseText ? '' : 'none';
  document.getElementById('notes-insight-input').value = '';
  document.getElementById('notes-delete-btn').style.display = 'none';
  // Store ref/text as data attributes for saving
  document.getElementById('notes-edit-view').dataset.ref = ref || '';
  document.getElementById('notes-edit-view').dataset.verseText = verseText || '';
  document.getElementById('notes-list-view').style.display = 'none';
  document.getElementById('notes-edit-view').style.display = '';
  setTimeout(() => document.getElementById('notes-insight-input').focus(), 100);
}

function editNote(id) {
  const note = notes.find(n => n.id === id);
  if (!note) return;
  editingNoteId = id;
  document.getElementById('notes-edit-mode-label').textContent = 'EDITING NOTE';
  document.getElementById('notes-ref-display').textContent = note.ref || '';
  document.getElementById('notes-verse-display').textContent = note.verseText ? '"' + note.verseText + '"' : '';
  document.getElementById('notes-verse-display').style.display = note.verseText ? '' : 'none';
  document.getElementById('notes-insight-input').value = note.insight;
  document.getElementById('notes-delete-btn').style.display = '';
  document.getElementById('notes-edit-view').dataset.ref = note.ref || '';
  document.getElementById('notes-edit-view').dataset.verseText = note.verseText || '';
  document.getElementById('notes-list-view').style.display = 'none';
  document.getElementById('notes-edit-view').style.display = '';
  setTimeout(() => document.getElementById('notes-insight-input').focus(), 100);
}

function saveNote() {
  const insight = cleanInput(document.getElementById('notes-insight-input').value.trim());
  if (!insight) { showToast('Write your insight first'); return; }
  const ev = document.getElementById('notes-edit-view');
  const ref = ev.dataset.ref;
  const verseText = ev.dataset.verseText;
  if (editingNoteId) {
    const note = notes.find(n => n.id === editingNoteId);
    if (note) { note.insight = insight; note.ts = Date.now(); }
  } else {
    notes.unshift({ id: Date.now().toString(36), ref, verseText, insight, ts: Date.now() });
  }
  persistNotes();
  showToast('✦ Note saved');
  showNotesList();
  // Refresh reader verse row note indicator if reader is open
  if (document.getElementById('reader-modal')?.classList.contains('open')) readerRenderVerses();
}

function deleteNote(id) {
  notes = notes.filter(n => n.id !== id);
  persistNotes();
  renderNotes();
  showToast('Note deleted');
}

function deleteCurrentNote() {
  if (editingNoteId) { deleteNote(editingNoteId); showNotesList(); }
}

// Called from reader ✏ button — close reader, open notes editor
function readerOpenNote(ref, verseText) {
  closeModal('reader-modal');
  readerStop();
  openModal('notes-modal');
  // Small delay so modal opens before switching view
  setTimeout(() => openNoteEditor(ref, verseText), 80);
}

/* ════════════════════════════════════════════════════════════
   HAMBURGER MENU
════════════════════════════════════════════════════════════ */
function toggleHamburger(){ document.getElementById('nav-links').classList.toggle('open'); }
function closeHamburger(){ document.getElementById('nav-links').classList.remove('open'); }

/* ════════════════════════════════════════════════════════════
   VERSE OF THE DAY
════════════════════════════════════════════════════════════ */
const VOTD_POOL = [
  "John 3:16","Psalm 23:1","Romans 8:28","Philippians 4:13","Isaiah 40:31",
  "Proverbs 3:5","Jeremiah 29:11","Matthew 6:33","Joshua 1:9","Hebrews 11:1",
  "2 Timothy 1:7","Galatians 2:20","Ephesians 2:8","John 14:6","Luke 1:37",
  "1 Corinthians 13:4","Romans 5:8","Psalm 46:10","Micah 6:8","Matthew 11:28",
  "Revelation 21:4","Psalm 119:105","Isaiah 41:10","Deuteronomy 31:6",
  "Matthew 16:24","Romans 12:2","Colossians 3:23","1 John 4:8","Psalm 46:1",
  "Acts 1:8","Lamentations 3:22","Habakkuk 3:17","Zephaniah 3:17","Isaiah 43:2",
  "John 11:25","Matthew 5:16","Ephesians 3:20","Romans 1:16","1 Peter 5:7",
  "Hebrews 12:1","Isaiah 55:8","James 1:5","Proverbs 31:25","Romans 15:13",
  "John 15:5","Psalm 34:8","Isaiah 26:3","Philippians 4:6","1 John 5:4",
  "Matthew 28:20","Psalm 27:14","Nehemiah 8:10","Isaiah 61:1","Luke 4:18",
  "John 8:12","Romans 8:38","Ephesians 6:10","Galatians 5:22","Psalm 91:1",
  "2 Corinthians 5:17","Isaiah 40:28","Psalm 139:14","Matthew 5:14"
];
let votdRef = '';
async function loadVotd() {
  const dayIdx = Math.floor(Date.now() / 86400000) % VOTD_POOL.length;
  votdRef = VOTD_POOL[dayIdx];
  document.getElementById('votd-ref').textContent = votdRef;
  try {
    const apiRef = votdRef.replace(/\s+/g,'+').toLowerCase();
    const data = await fetch(`https://bible-api.com/${apiRef}?translation=kjv`).then(r=>r.json());
    if(data.error) throw new Error();
    document.getElementById('votd-text').textContent = '"' + sanitize(data.text.trim()) + '"';
    document.getElementById('votd-ref').textContent = '— ' + data.reference + ' (KJV)';
    votdRef = data.reference;
  } catch(e) { document.getElementById('votd-text').textContent = '"Be still, and know that I am God."'; document.getElementById('votd-ref').textContent = '— Psalm 46:10 (KJV)'; votdRef='Psalm 46:10'; }
}
function votdOpen() { searchToReader(null, votdRef); }

/* ════════════════════════════════════════════════════════════
   READING STREAK & RECENTLY VIEWED
════════════════════════════════════════════════════════════ */
let streakData = JSON.parse(localStorage.getItem('wow_streak')||'{"streak":0,"lastDate":""}');
let recentViewed = JSON.parse(localStorage.getItem('wow_recent')||'[]');

function todayStr(){ return new Date().toISOString().slice(0,10); }
function updateStreak(){
  const today = todayStr();
  const yesterday = new Date(Date.now()-86400000).toISOString().slice(0,10);
  if(streakData.lastDate===today) return;
  if(streakData.lastDate===yesterday) streakData.streak++;
  else streakData.streak = 1;
  streakData.lastDate = today;
  localStorage.setItem('wow_streak', JSON.stringify(streakData));
  renderStatusBar();
}
function addRecentView(bookIdx, chapter){
  const bookName = BIBLE_BOOKS[bookIdx].n;
  recentViewed = recentViewed.filter(r=>!(r.bookIdx===bookIdx&&r.chapter===chapter));
  recentViewed.unshift({bookIdx, chapter, bookName, ts:Date.now()});
  if(recentViewed.length>5) recentViewed.pop();
  localStorage.setItem('wow_recent', JSON.stringify(recentViewed));
  renderStatusBar();
}
function renderStatusBar(){
  const sc = document.getElementById('streak-chip');
  const rc = document.getElementById('recent-chip');
  if(streakData.streak>0){ sc.style.display=''; sc.textContent=`🔥 ${streakData.streak}-day streak`; }
  if(recentViewed.length){ rc.style.display=''; rc.textContent=`📖 Continue: ${recentViewed[0].bookName} ${recentViewed[0].chapter}`; }
}
function recentOpen(){
  if(!recentViewed.length) return;
  readerBookIdx=recentViewed[0].bookIdx; readerChapter=recentViewed[0].chapter;
  openModal('reader-modal');
}

/* ════════════════════════════════════════════════════════════
   FONT SIZE CONTROL
════════════════════════════════════════════════════════════ */
let fontSize = parseInt(localStorage.getItem('wow_fontsize')||'16');
function applyFont(){
  document.getElementById('reader-verses').style.fontSize = fontSize+'px';
  document.getElementById('font-size-display').textContent = fontSize+'px';
}
function adjustFont(d){
  fontSize = Math.max(12, Math.min(26, fontSize+d));
  localStorage.setItem('wow_fontsize', fontSize);
  applyFont();
}

/* ════════════════════════════════════════════════════════════
   HIGHLIGHTS
════════════════════════════════════════════════════════════ */
let highlights = JSON.parse(localStorage.getItem('wow_highlights')||'{}');
const HL_COLORS = {yellow:'#f5d020',blue:'#5b9cf6',green:'#4ade80',pink:'#f472b6',purple:'#c084fc'};

function getHighlightKey(bookIdx, chapter, verse){ return `${bookIdx}:${chapter}:${verse}`; }
function setHighlight(bookIdx, chapter, verse, color){
  const key = getHighlightKey(bookIdx,chapter,verse);
  if(color===null){ delete highlights[key]; } else { highlights[key]=color; }
  localStorage.setItem('wow_highlights', JSON.stringify(highlights));
  readerRenderVerses();
}
function buildHighlightPicker(bookIdx, chapter, v){
  const key = getHighlightKey(bookIdx,chapter,v.verse);
  const cur = highlights[key];
  const colors = Object.entries(HL_COLORS).map(([name,hex])=>`<span class="hc" style="background:${hex};${cur===name?'border-color:#fff;':''}}" title="${name}" onclick="event.stopPropagation();setHighlight(${bookIdx},${chapter},${v.verse},'${name}');this.closest('.highlight-picker').classList.remove('open')"></span>`).join('');
  return `<div class="rv-highlight-wrap">
    <button class="rv-highlight-btn${cur?' highlighted':''}" onclick="event.stopPropagation();this.nextSibling.classList.toggle('open')" title="Highlight">🖊</button>
    <div class="highlight-picker">${colors}<span class="hc" style="background:rgba(255,255,255,0.1);border:1px dashed rgba(255,255,255,0.3)" title="clear" onclick="event.stopPropagation();setHighlight(${bookIdx},${chapter},${v.verse},null);this.closest('.highlight-picker').classList.remove('open')">✕</span></div>
  </div>`;
}

/* ════════════════════════════════════════════════════════════
   BOOKMARKS
════════════════════════════════════════════════════════════ */
let bookmark = JSON.parse(localStorage.getItem('wow_bookmark')||'null');
function toggleBookmark(){
  const btn = document.getElementById('bookmark-btn');
  const key = `${readerBookIdx}:${readerChapter}`;
  if(bookmark && bookmark.key===key){
    bookmark=null; localStorage.removeItem('wow_bookmark');
    btn.textContent='🔖 Bookmark'; btn.classList.remove('bookmarked');
    showToast('Bookmark removed');
  } else {
    bookmark={key, bookIdx:readerBookIdx, chapter:readerChapter, bookName:BIBLE_BOOKS[readerBookIdx].n};
    localStorage.setItem('wow_bookmark', JSON.stringify(bookmark));
    btn.textContent='🔖 Bookmarked'; btn.classList.add('bookmarked');
    showToast(`Bookmarked: ${bookmark.bookName} ${bookmark.chapter}`);
  }
}
function updateBookmarkBtn(){
  const btn = document.getElementById('bookmark-btn');
  if(!btn) return;
  const key=`${readerBookIdx}:${readerChapter}`;
  if(bookmark&&bookmark.key===key){ btn.textContent='🔖 Bookmarked'; btn.classList.add('bookmarked'); }
  else { btn.textContent='🔖 Bookmark'; btn.classList.remove('bookmarked'); }
}

/* ════════════════════════════════════════════════════════════
   CROSS-REFERENCES
════════════════════════════════════════════════════════════ */
const XREFS = {
  "john 3:16":["Romans 5:8","1 John 4:9-10","Ephesians 2:8-9","Romans 6:23"],
  "psalm 23:1":["Isaiah 40:11","John 10:11","Hebrews 13:20","Ezekiel 34:15"],
  "romans 8:28":["Jeremiah 29:11","Genesis 50:20","Psalm 37:5","Proverbs 3:5-6"],
  "philippians 4:13":["2 Corinthians 12:9","Isaiah 40:31","Colossians 1:11","Ephesians 6:10"],
  "isaiah 40:31":["Psalm 27:14","Matthew 11:28-30","2 Corinthians 4:16","Philippians 4:13"],
  "proverbs 3:5-6":["Psalm 37:5","Isaiah 55:8-9","Matthew 6:33","Jeremiah 17:7"],
  "jeremiah 29:11":["Romans 8:28","Isaiah 55:8","Proverbs 16:9","Psalm 37:4"],
  "matthew 6:33":["Psalm 37:4","1 Kings 3:13","Luke 12:31","Philippians 4:19"],
  "joshua 1:9":["Deuteronomy 31:6","Psalm 27:1","Isaiah 41:10","2 Timothy 1:7"],
  "hebrews 11:1":["Romans 4:17","2 Corinthians 4:18","John 20:29","1 Peter 1:8"],
  "john 14:6":["Acts 4:12","1 Timothy 2:5","John 10:9","John 11:25"],
  "psalm 46:10":["Zephaniah 3:17","Isaiah 26:3","John 14:27","Philippians 4:7"],
  "romans 8:38-39":["John 10:28-29","Isaiah 49:16","Matthew 28:20","Psalm 139:7-10"],
  "galatians 5:22-23":["John 15:5","Colossians 3:12-14","Ephesians 5:9","2 Peter 1:5-7"],
  "matthew 5:3-12":["Luke 6:20-23","Isaiah 61:1-3","Romans 4:7-8","Revelation 22:14"],
  "1 corinthians 13:4-8":["Romans 13:8","John 13:34-35","1 John 4:7-8","Colossians 3:14"],
  "isaiah 53:5":["1 Peter 2:24","Romans 5:8","Hebrews 9:28","2 Corinthians 5:21"],
  "ephesians 2:8-9":["Romans 3:28","Galatians 2:16","Titus 3:5","Romans 11:6"],
  "2 timothy 1:7":["Romans 8:15","1 John 4:18","Psalm 34:4","Isaiah 41:10"],
  "revelation 21:4":["Isaiah 25:8","Isaiah 35:10","Romans 8:18","2 Corinthians 4:17"],
  "micah 6:8":["Deuteronomy 10:12","Matthew 23:23","Zechariah 7:9","Hosea 12:6"],
  "luke 1:37":["Genesis 18:14","Matthew 19:26","Mark 10:27","Numbers 11:23"],
  "matthew 11:28-30":["Isaiah 55:1-3","Psalm 55:22","1 Peter 5:7","Philippians 4:6-7"],
  "1 john 4:8":["1 John 4:16","John 3:16","Romans 5:8","Deuteronomy 7:9"]
};
function showXrefs(ref){
  const panel = document.getElementById('xref-panel');
  const list  = document.getElementById('xref-list');
  const key = ref.toLowerCase().trim().replace(/\s+/g,' ');
  let refs = null;
  for(const k of Object.keys(XREFS)){ if(key===k||key.startsWith(k.split(':')[0])&&key.includes(k.split(':')[1]?.split('-')[0]||'')){ refs=XREFS[k]; break; } }
  if(!refs){ panel.style.display='none'; return; }
  list.innerHTML = refs.map(r=>`<span class="xref-chip" onclick="closeModal('reader-modal');searchToReader(null,'${escH(r)}')">${escH(r)}</span>`).join('');
  panel.style.display='block';
}

/* ════════════════════════════════════════════════════════════
   COMPARE TRANSLATIONS
════════════════════════════════════════════════════════════ */
async function openCompare(){
  const book = BIBLE_BOOKS[readerBookIdx].n;
  const ref  = `${book} ${readerChapter}`;
  document.getElementById('compare-ref-label').textContent = ref;
  ['kjv','web','bbe'].forEach(t=>{ document.getElementById(`cmp-${t}`).innerHTML='<span class="compare-loading">Loading…</span>'; });
  openModal('compare-modal');
  const apiRef = ref.replace(/\s+/g,'+').toLowerCase();
  await Promise.all(['kjv','web','bbe'].map(async t=>{
    try {
      const data = await fetch(`https://bible-api.com/${apiRef}?translation=${t}`).then(r=>r.json());
      document.getElementById(`cmp-${t}`).textContent = sanitize(data.text?.trim() || 'Not available.');
    } catch(e){ document.getElementById(`cmp-${t}`).textContent='Could not load.'; }
  }));
}

/* ════════════════════════════════════════════════════════════
   WORD SEARCH
════════════════════════════════════════════════════════════ */
const BOLLS_BOOKS = ['Genesis','Exodus','Leviticus','Numbers','Deuteronomy','Joshua','Judges','Ruth','1 Samuel','2 Samuel','1 Kings','2 Kings','1 Chronicles','2 Chronicles','Ezra','Nehemiah','Esther','Job','Psalms','Proverbs','Ecclesiastes','Song of Solomon','Isaiah','Jeremiah','Lamentations','Ezekiel','Daniel','Hosea','Joel','Amos','Obadiah','Jonah','Micah','Nahum','Habakkuk','Zephaniah','Haggai','Zechariah','Malachi','Matthew','Mark','Luke','John','Acts','Romans','1 Corinthians','2 Corinthians','Galatians','Ephesians','Philippians','Colossians','1 Thessalonians','2 Thessalonians','1 Timothy','2 Timothy','Titus','Philemon','Hebrews','James','1 Peter','2 Peter','1 John','2 John','3 John','Jude','Revelation'];

async function runWordSearch(){
  const q = document.getElementById('ws-input').value.trim();
  if(!q){ showToast('Enter a word to search'); return; }
  const status = document.getElementById('ws-status');
  const results = document.getElementById('ws-results');
  const count   = document.getElementById('ws-count');
  status.textContent='Searching the KJV Bible…'; results.innerHTML=''; count.style.display='none';
  try {
    const res = await fetch(`https://bolls.life/search/KJV/${encodeURIComponent(q)}/`);
    const data = await res.json();
    if(!data||!data.length){ status.textContent='No results found. Try a different word.'; return; }
    status.textContent='';
    count.textContent=`${data.length.toLocaleString()} result${data.length===1?'':'s'} for "${q}"`;
    count.style.display='block';
    const limited = data.slice(0,200);
    results.innerHTML = limited.map(v=>{
      const bk = BOLLS_BOOKS[v.book-1]||'Unknown';
      const ref=`${bk} ${v.chapter}:${v.verse}`;
      const highlighted=v.text.replace(new RegExp(`(${escRegex(q)})`, 'gi'),'<mark>$1</mark>');
      const safeText = highlighted.replace(/<(?!mark>|\/mark>)[^>]+>/gi,''); return `<div class="ws-result" onclick="closeModal('wordsearch-modal');searchToReader(null,'${escH(ref)}')"><span class="ws-ref">${escH(ref)}</span><span class="ws-text">${safeText}</span></div>`;
    }).join('');
    if(data.length>200) results.innerHTML+=`<div style="text-align:center;padding:12px;font-family:'Cinzel',serif;font-size:0.68rem;color:rgba(201,168,76,0.4);">Showing first 200 of ${data.length.toLocaleString()} results</div>`;
  } catch(e){ status.textContent='Search unavailable — check your connection and try again.'; }
}
function escRegex(s){ return s.replace(/[-[\]{}()*+?.,\\^$|]/g,'\\$&'); }

/* ════════════════════════════════════════════════════════════
   PRAYER JOURNAL
════════════════════════════════════════════════════════════ */
let prayers = JSON.parse(localStorage.getItem('wow_prayers')||'[]');
let editingPrayerId = null;
let prayerFilter = 'all';
function persistPrayers(){ localStorage.setItem('wow_prayers',JSON.stringify(prayers)); }
function renderPrayers(){
  const list=document.getElementById('prayer-list');
  if(!list)return;
  const filtered=prayerFilter==='all'?prayers:prayers.filter(p=>p.status===prayerFilter);
  if(!filtered.length){ list.innerHTML=`<div id="prayer-empty" style="text-align:center;padding:40px;font-family:'Cinzel',serif;font-size:0.75rem;color:rgba(201,168,76,0.3);font-style:italic;">${prayerFilter==='all'?'No prayers yet.':'No '+prayerFilter+' prayers.'}</div>`; return; }
  list.innerHTML=[...filtered].sort((a,b)=>b.ts-a.ts).map(p=>{
    const d=new Date(p.ts).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'});
    return `<div class="prayer-card">
      <div class="prayer-card-header">
        <div class="prayer-card-title">${escH(p.title||'Untitled Prayer')}</div>
        <span class="prayer-status-badge ${p.status}">${p.status==='answered'?'✅ Answered':'🙏 Praying'}</span>
      </div>
      <div class="prayer-card-text">${escH(p.text.slice(0,200))}${p.text.length>200?'…':''}</div>
      <div class="prayer-card-footer">
        <span class="prayer-card-date">${d}</span>
        <div class="note-card-actions">
          <button class="note-edit-btn" onclick="event.stopPropagation();editPrayer('${p.id}')">Edit</button>
          <button class="note-del-btn" onclick="event.stopPropagation();deletePrayer('${p.id}')">Delete</button>
        </div>
      </div>
    </div>`;
  }).join('');
}
function filterPrayers(f,btn){ prayerFilter=f; document.querySelectorAll('#prayer-filter-row .speed-btn').forEach(b=>b.classList.remove('active')); btn.classList.add('active'); renderPrayers(); }
function openPrayerEditor(title,text,status){ editingPrayerId=null; document.getElementById('prayer-edit-label').textContent='NEW PRAYER'; document.getElementById('prayer-title-input').value=title||''; document.getElementById('prayer-text-input').value=text||''; document.getElementById('prayer-status-select').value=status||'praying'; document.getElementById('prayer-delete-btn').style.display='none'; document.getElementById('prayer-list-view').style.display='none'; document.getElementById('prayer-edit-view').style.display=''; setTimeout(()=>document.getElementById('prayer-title-input').focus(),100); }
function editPrayer(id){ const p=prayers.find(p=>p.id===id); if(!p)return; editingPrayerId=id; document.getElementById('prayer-edit-label').textContent='EDITING PRAYER'; document.getElementById('prayer-title-input').value=p.title; document.getElementById('prayer-text-input').value=p.text; document.getElementById('prayer-status-select').value=p.status; document.getElementById('prayer-delete-btn').style.display=''; document.getElementById('prayer-list-view').style.display='none'; document.getElementById('prayer-edit-view').style.display=''; }
function savePrayer(){ const title=document.getElementById('prayer-title-input').value.trim(); const text=document.getElementById('prayer-text-input').value.trim(); if(!text){showToast('Write your prayer first');return;} const status=document.getElementById('prayer-status-select').value; if(editingPrayerId){ const p=prayers.find(p=>p.id===editingPrayerId); if(p){p.title=title;p.text=text;p.status=status;p.ts=Date.now();} } else { prayers.unshift({id:Date.now().toString(36),title,text,status,ts:Date.now()}); } persistPrayers(); showPrayerList(); showToast('✦ Prayer saved'); }
function deletePrayer(id){ prayers=prayers.filter(p=>p.id!==id); persistPrayers(); renderPrayers(); showToast('Prayer deleted'); }
function deleteCurrentPrayer(){ if(editingPrayerId){deletePrayer(editingPrayerId);showPrayerList();} }
function showPrayerList(){ editingPrayerId=null; document.getElementById('prayer-list-view').style.display=''; document.getElementById('prayer-edit-view').style.display='none'; renderPrayers(); }

/* ════════════════════════════════════════════════════════════
   BIBLICAL HISTORY TIMELINE
════════════════════════════════════════════════════════════ */
const BIBTL_OT = [
  {date:'Before Time',event:'Creation',desc:'God creates the heavens, earth, and humanity in six days. The seventh day is sanctified as the Sabbath.',ref:'Genesis 1–2'},
  {date:'~4000 BC',event:'The Fall',desc:'Adam and Eve disobey God in the Garden. Sin, shame, and death enter creation — but the first promise of a Redeemer is given.',ref:'Genesis 3'},
  {date:'~3900 BC',event:'Cain & Abel',desc:'The first murder. Cain kills his brother Abel out of jealousy. Seth is born, and through him the covenant line continues.',ref:'Genesis 4'},
  {date:'~3000 BC',event:'Enoch Walks with God',desc:'Enoch, seventh from Adam, walks so closely with God that God takes him — he never dies. A type of resurrection.',ref:'Genesis 5:22-24'},
  {date:'~2350 BC',event:'Noah & The Flood',desc:'God judges global wickedness through a worldwide flood. Noah\'s ark preserves humanity. The rainbow covenant is established.',ref:'Genesis 6–9'},
  {date:'~2200 BC',event:'Tower of Babel',desc:'Human pride leads to Babel. God confuses languages and scatters nations across the earth.',ref:'Genesis 11'},
  {date:'~2091 BC',event:'God Calls Abraham',desc:'Abram leaves Ur for Canaan. God promises land, descendants, and blessing for all nations through his seed.',ref:'Genesis 12'},
  {date:'~2080 BC',event:'The Abrahamic Covenant',desc:'God formalizes the covenant with Abram, renamed Abraham. Circumcision is given as the covenant sign.',ref:'Genesis 15–17'},
  {date:'~2066 BC',event:'Isaac Is Born',desc:'The promised son is born to Abraham and Sarah at age 90 and 100. Nothing is impossible with God.',ref:'Genesis 21'},
  {date:'~2050 BC',event:'The Binding of Isaac',desc:'God tests Abraham by commanding him to sacrifice Isaac on Moriah. Abraham obeys; God provides a ram. The gospel is foreshadowed.',ref:'Genesis 22'},
  {date:'~2006 BC',event:'Jacob & Esau Born',desc:'Twin sons born to Isaac and Rebekah. Jacob, the younger, receives the covenant blessing and is renamed Israel.',ref:'Genesis 25–32'},
  {date:'~1898 BC',event:'Joseph Sold into Egypt',desc:'Joseph is sold by his brothers, imprisoned, and eventually rises to become second-in-command of Egypt.',ref:'Genesis 37–41'},
  {date:'~1876 BC',event:'Israel Settles in Egypt',desc:'Jacob\'s family of 70 moves to Egypt during famine. The 430-year sojourn begins.',ref:'Genesis 46–47'},
  {date:'~1526 BC',event:'Moses Is Born',desc:'Moses born during Pharaoh\'s genocide of Hebrew infants. Hidden in a basket, found by Pharaoh\'s daughter.',ref:'Exodus 2'},
  {date:'~1446 BC',event:'The Exodus',desc:'Ten plagues. The Passover. The Red Sea parts. Israel leaves Egypt after 430 years of bondage. The central event of the OT.',ref:'Exodus 7–15'},
  {date:'~1446 BC',event:'The Law at Sinai',desc:'The Ten Commandments given. The Torah revealed. The Tabernacle constructed. God dwells with His people.',ref:'Exodus 19–40'},
  {date:'~1406 BC',event:'Conquest of Canaan',desc:'Joshua leads Israel across the Jordan. Jericho falls. The promised land is divided among the twelve tribes.',ref:'Joshua 1–21'},
  {date:'~1380–1050 BC',event:'Period of the Judges',desc:'Recurring cycles of sin, oppression, repentance, and deliverance through judges: Deborah, Gideon, Samson, and others.',ref:'Judges 1–21'},
  {date:'~1100 BC',event:'Ruth & the Kinsman-Redeemer',desc:'Ruth\'s loyalty brings her into the covenant people. She marries Boaz, a type of Christ, and becomes great-grandmother of David.',ref:'Ruth 1–4'},
  {date:'~1050 BC',event:'Saul Becomes First King',desc:'Israel demands a king. Saul is anointed but disqualified through disobedience. "To obey is better than sacrifice."',ref:'1 Samuel 9–15'},
  {date:'~1010 BC',event:'David\'s Reign Begins',desc:'David unites the kingdom, brings the ark to Jerusalem, and receives the eternal covenant: his throne will endure forever.',ref:'2 Samuel 5–7'},
  {date:'~970 BC',event:'Solomon Builds the Temple',desc:'Solomon\'s temple, the dwelling place of God\'s glory, is constructed in Jerusalem. The golden age of Israel.',ref:'1 Kings 6–8'},
  {date:'~930 BC',event:'Kingdom Divided',desc:'Solomon\'s idolatry leads to the split: Israel (north, 10 tribes) and Judah (south, 2 tribes). The decline begins.',ref:'1 Kings 12'},
  {date:'~870 BC',event:'Elijah & the Prophets',desc:'Elijah stands alone against 450 prophets of Baal on Mount Carmel. God speaks in a still small voice.',ref:'1 Kings 18–19'},
  {date:'~760 BC',event:'Amos & Hosea Prophesy',desc:'Amos thunders against social injustice. Hosea pictures God\'s unfailing love through the marriage metaphor.',ref:'Amos 1, Hosea 1'},
  {date:'~740 BC',event:'Isaiah\'s Vision',desc:'"Holy, holy, holy is the LORD." Isaiah receives his commission and delivers the most messianic prophecy in the OT, including Isaiah 53.',ref:'Isaiah 6, 53'},
  {date:'~722 BC',event:'Fall of Israel (North)',desc:'Assyria conquers the northern kingdom. The ten tribes are scattered — the "lost tribes of Israel." Judah watches and does not learn.',ref:'2 Kings 17'},
  {date:'~627 BC',event:'Jeremiah Called',desc:'Jeremiah begins his 40-year ministry, weeping over Jerusalem\'s sin. He promises a new covenant written on the heart.',ref:'Jeremiah 1, 31'},
  {date:'~605–586 BC',event:'Babylon Besieges Jerusalem',desc:'Three waves of deportation. Daniel taken in 605 BC. Jerusalem falls in 586 BC. The temple is burned. The exile begins.',ref:'2 Kings 25, Daniel 1'},
  {date:'~593 BC',event:'Ezekiel\'s Visions',desc:'Ezekiel sees the chariot of God, the valley of dry bones, and the future restored temple from exile in Babylon.',ref:'Ezekiel 1, 37'},
  {date:'~538 BC',event:'Cyrus Decrees Return',desc:'Persian King Cyrus — a pagan — fulfills Isaiah\'s 150-year-old prophecy and releases the Jewish exiles.',ref:'Ezra 1, Isaiah 44:28'},
  {date:'~516 BC',event:'Second Temple Completed',desc:'Zerubbabel leads the rebuilding of the temple. Haggai and Zechariah encourage the workers. The glory returns.',ref:'Ezra 6'},
  {date:'~458 BC',event:'Ezra Returns',desc:'Ezra the priest returns to Jerusalem and leads a great spiritual reformation, restoring the reading of the Law.',ref:'Ezra 7–10'},
  {date:'~444 BC',event:'Nehemiah Rebuilds the Wall',desc:'Nehemiah rebuilds Jerusalem\'s walls in 52 days against fierce opposition. The city is restored. The Word is read publicly.',ref:'Nehemiah 1–8'},
  {date:'~432–5 BC',event:'The Silent Years (400)',desc:'No prophetic voice. Four centuries of silence between Malachi and John the Baptist. God is still working.',ref:'Malachi 4'},
];
const BIBTL_NT = [
  {date:'~5 BC',event:'Birth of Jesus',desc:'The Word becomes flesh in Bethlehem. Angels announce to shepherds. Wise men come from the east. Herod slaughters the innocents.',ref:'Luke 2, Matthew 2',nt:true},
  {date:'~AD 27',event:'John the Baptist',desc:'The voice crying in the wilderness. "Repent, for the kingdom of heaven is at hand." Jesus is baptized; the Spirit descends.',ref:'Mark 1',nt:true},
  {date:'~AD 27–30',event:'Jesus\' Ministry',desc:'Three years of teaching, healing, and signs throughout Galilee and Judea. The Sermon on the Mount. The twelve disciples called.',ref:'Matthew 5–7, John 2–11',nt:true},
  {date:'~AD 30',event:'The Last Supper',desc:'Jesus institutes the Lord\'s Supper, washes feet, and delivers the Upper Room Discourse. Gethsemane follows.',ref:'John 13–17',nt:true},
  {date:'~AD 30',event:'The Crucifixion',desc:'Jesus is crucified on Passover. "It is finished." The veil is torn. The earth shakes. The long-promised sacrifice is complete.',ref:'John 19',nt:true},
  {date:'~AD 30',event:'The Resurrection',desc:'On the third day, the tomb is empty. Jesus appears to Mary, the disciples, Thomas, and more than 500 at once.',ref:'John 20, 1 Cor 15',nt:true},
  {date:'~AD 30',event:'Pentecost',desc:'The Holy Spirit is poured out on the disciples. Three thousand are saved. The Church is born. The age of the Spirit begins.',ref:'Acts 2',nt:true},
  {date:'~AD 35',event:'Stephen Martyred',desc:'Stephen, full of the Spirit, preaches and is stoned. Saul of Tarsus watches and approves. Persecution scatters the church.',ref:'Acts 7',nt:true},
  {date:'~AD 35',event:'Paul\'s Conversion',desc:'Saul meets the risen Jesus on the Damascus road. The greatest persecutor becomes the greatest missionary.',ref:'Acts 9',nt:true},
  {date:'~AD 47–48',event:'Paul\'s First Journey',desc:'Paul and Barnabas take the Gospel to Cyprus and Asia Minor. Churches planted in Galatia.',ref:'Acts 13–14',nt:true},
  {date:'~AD 49',event:'Jerusalem Council',desc:'The foundational theological question: must Gentiles keep the Law? The answer: salvation by grace through faith alone.',ref:'Acts 15',nt:true},
  {date:'~AD 50–52',event:'Paul\'s Second Journey',desc:'Paul plants churches in Philippi, Thessalonica, and Corinth. The Gospel enters Europe. 1–2 Thessalonians written.',ref:'Acts 16–18',nt:true},
  {date:'~AD 53–57',event:'Paul\'s Third Journey',desc:'Three years in Ephesus. Galatians, 1–2 Corinthians, and Romans written — the theological core of the NT.',ref:'Acts 19–21',nt:true},
  {date:'~AD 60–62',event:'Paul\'s Roman Imprisonment',desc:'Paul appeals to Caesar, arrives in Rome. Ephesians, Philippians, Colossians, and Philemon written from prison.',ref:'Acts 27–28',nt:true},
  {date:'~AD 64',event:'Peter & Paul Martyred',desc:'Under Nero\'s persecution, Peter is crucified (upside down) and Paul is beheaded. The last eyewitnesses fall.',ref:'Church tradition',nt:true},
  {date:'~AD 66–70',event:'Fall of Jerusalem',desc:'Roman armies under Titus destroy the temple — exactly as Jesus predicted. Not one stone left on another.',ref:'Matthew 24:2, Josephus',nt:true},
  {date:'~AD 90–95',event:'John Writes Revelation',desc:'The aged apostle John receives the vision on Patmos. Seven letters to churches. The Lamb is worthy. All things new.',ref:'Revelation 1',nt:true},
  {date:'Future',event:'The Return of Christ',desc:'"Behold, he cometh with clouds; and every eye shall see him." The resurrection of the dead. The new heaven and new earth.',ref:'Revelation 19–22',nt:true},
];
let bibtlTab='ot';
function showBibtlTab(tab, btn){
  bibtlTab=tab;
  ['ot','nt','creation'].forEach(t=>{ document.getElementById('bibtl-'+t).style.display=t===tab?'':'none'; });
  document.querySelectorAll('.bibtl-tab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
}
function renderBibtl(){
  const ot=document.getElementById('bibtl-ot');
  const nt=document.getElementById('bibtl-nt');
  const cr=document.getElementById('bibtl-creation');
  if(ot&&!ot.children.length){
    ot.innerHTML=BIBTL_OT.map(e=>{ const fr=e.ref.split(',')[0].trim(); return `<div class="bibtl-item"><div><div class="bibtl-date">${escH(e.date)}</div></div><div><div class="bibtl-event">${escH(e.event)}</div><div class="bibtl-desc">${escH(e.desc)}</div><div class="bibtl-ref" onclick="searchToReader(null,this.dataset.ref)" data-ref="${escH(fr)}">${escH(e.ref)}</div></div></div>`; }).join('');
    nt.innerHTML=BIBTL_NT.map(e=>{ const fr=e.ref.split(',')[0].trim(); return `<div class="bibtl-item nt"><div><div class="bibtl-date">${escH(e.date)}</div></div><div><div class="bibtl-event">${escH(e.event)}</div><div class="bibtl-desc">${escH(e.desc)}</div><div class="bibtl-ref" onclick="searchToReader(null,this.dataset.ref)" data-ref="${escH(fr)}">${escH(e.ref)}</div></div></div>`; }).join('');
    // Render Creation days directly from CREATION_DAYS data
    if(typeof CREATION_DAYS !== 'undefined') {
      cr.innerHTML = CREATION_DAYS.map(d => {
        const tags = d.created.map(t=>`<span style="display:inline-block;background:rgba(201,168,76,0.08);border:1px solid rgba(201,168,76,0.2);border-radius:2px;padding:2px 9px;font-family:'Cinzel',serif;font-size:0.6rem;letter-spacing:0.06em;color:rgba(201,168,76,0.7);margin:2px 3px 2px 0;">${escH(t)}</span>`).join('');
        return `<div class="bibtl-item" style="border-left-color:rgba(201,168,76,0.4);">
          <div style="min-width:90px;">
            <div style="font-family:'Cinzel Decorative',serif;font-size:0.9rem;color:var(--gold-lt);">${d.icon} Day ${d.n}</div>
            <div style="font-family:'Cinzel',serif;font-size:0.6rem;letter-spacing:0.1em;color:var(--gold-dk);margin-top:2px;">${escH(d.ref)}</div>
          </div>
          <div>
            <div class="bibtl-event">${escH(d.title)}</div>
            <div class="bibtl-desc">${escH(d.verse)}</div>
            <div style="margin:8px 0;">${tags}</div>
            <div class="bibtl-desc" style="color:rgba(240,226,192,0.6);">${escH(d.desc)}</div>
          </div>
        </div>`;
      }).join('');
    }
  }
}

/* ════════════════════════════════════════════════════════════
   INIT
════════════════════════════════════════════════════════════ */
renderFavorites();
renderTicker();
setTimeout(loadVotd, 400);
renderStatusBar();
if('serviceWorker' in navigator){ navigator.serviceWorker.register('sw.js').catch(()=>{}); }

/* ── Rotating Quick Picks ─────────────────────────────────── */
(function initQuickPicks() {
  const container = document.getElementById('quick-picks');
  const COUNT = 7; // chips visible at once
  let usedIndices = [];

  function pickRandom() {
    // Shuffle a fresh set when pool is exhausted
    if (usedIndices.length >= VERSE_POOL.length - COUNT) usedIndices = [];
    const available = VERSE_POOL.map((_,i)=>i).filter(i => !usedIndices.includes(i));
    const chosen = [];
    while (chosen.length < COUNT && available.length) {
      const idx = Math.floor(Math.random() * available.length);
      chosen.push(available.splice(idx, 1)[0]);
    }
    usedIndices.push(...chosen);
    return chosen.map(i => VERSE_POOL[i]);
  }

  function render(refs) {
    container.innerHTML = refs.map(ref =>
      `<span class="quick-pick" onclick="searchToReader(null,'${escH(ref)}')">${escH(ref)}</span>`
    ).join('');
  }

  function rotate() {
    container.classList.add('fading');
    setTimeout(() => {
      render(pickRandom());
      container.classList.remove('fading');
    }, 500);
  }

  // Initial render (no fade)
  render(pickRandom());
  setInterval(rotate, 7000);
})();
