// ===========================================================
// 🌐 NOTICE TRANSLATIONS — s. 5(3)
// ===========================================================
// The notice must be available in English or any of the 22 Eighth Schedule
// languages. English is the authored source of truth; languages present here
// are fully translated. Any language NOT present falls back to English per-key,
// and `translation_status` is set to "english-fallback" so the UI can say so
// honestly rather than pretending to be a certified translation.
//
// Adding a language = add one entry to NOTICE_STRINGS (and optionally
// PURPOSE_I18N / COOKIE_I18N). Keys must mirror the English set.

// ---------------------------------------------------------------------------
// UI strings + statements. `{dpo}` etc. are substituted at build time.
// ---------------------------------------------------------------------------
export const NOTICE_STRINGS = {
  en: {
    heading: "Privacy Notice & Consent",
    languageLabel: "Language",
    noticeVersionLabel: "Notice version",
    translatedBadge: "translated",
    fallbackBadge: "english-fallback",
    fallbackNotice:
      "This notice is not yet available in your chosen language, so English is shown. We are adding translations; you can also ask us for it in any Eighth Schedule language (s. 5(3)).",

    whoWeAreTitle: "Who we are",
    dataFiduciaryText: "{name} acts as a Data Fiduciary under the Digital Personal Data Protection Act, 2023.",
    dpoLabel: "Data Protection Officer",

    collectTitle: "What we collect and why (itemised)",
    requiredLabel: "required",
    optionalLabel: "optional",
    dataLabel: "Data",
    lawfulBasisLabel: "Lawful basis",
    retentionDaysLabel: "Retention: {days} days",
    retentionActiveLabel: "Retained while your account is active",

    notCollectTitle: "What we will not collect without separate consent",

    cookiesTitle: "Cookies & trackers (itemised by purpose)",
    consentRequiredLabel: "consent required",
    alwaysOnLabel: "always on — {basis}",
    examplesLabel: "Examples",
    cookieSettingsNote:
      "Manage these any time via the “Cookie settings” button. Analytics, advertising, personalisation and social embeds are separate consents; none is pre-selected.",

    rightsTitle: "Your rights",
    manageInPrivacyCenter:
      "Manage all of these in your Privacy Center.",
    privacyCenterLink: "Privacy Center",
    cookieSettingsButton: "Cookie settings",
    boardComplaintText:
      "If we cannot resolve a grievance, you may complain to the {board}. {note}",

    dutiesTitle: "Your duties (s. 15)",

    consentTitle: "Consent & withdrawal",
    consentStatement:
      "Consent is free, specific, informed, unconditional and unambiguous. It is opt-in only (no pre-ticked boxes) and you may withdraw it at any time with ease comparable to giving it. Refusing optional processing will not block the core service.",
    withdrawalConsequences:
      "Withdrawing consent does not affect the legality of processing carried out before withdrawal. We will stop processing for that purpose and erase the related data (s. 8(7)), except where retention is required by law or is necessary to complete something already begun (s. 6(5)).",
    severabilityStatement:
      "No part of this consent asks you to waive any right under the Act. If any part of it were found to infringe the Act, the Rules or any other law, that part alone would be invalid and the rest would continue to apply (s. 6(2)).",
    accountabilityStatement:
      "{name} is the Data Fiduciary and is responsible for this processing irrespective of any agreement to the contrary or any failure by you to perform your duties under s. 15 (s. 8(1)).",

    duties: [
      "Do not impersonate another person when exercising your rights (s. 15(a)).",
      "Do not suppress material information for State identity/benefit purposes (s. 15(b)).",
      "Do not file false or frivolous complaints (s. 15(c)).",
      "Furnish only verifiably authentic information for correction/erasure (s. 15(d)).",
    ],

    rights: {
      access: "a summary of your personal data (s. 11)",
      correction: "correct or complete your data (s. 12)",
      erasure: "request erasure (s. 12)",
      withdraw: "withdraw consent with equal ease (s. 6(4))",
      grievance: "raise a grievance (s. 13)",
      nomination: "nominate someone (s. 14)",
    },

    consentLabel:
      "I have read and understood the above and I consent to the itemised collection and processing.",
    notCollectedWithoutConsent: [
      "IP address beyond the security and consent-audit purposes (we store a salted hash, not the raw address)",
      "device / OS fingerprinting for advertising",
      "precise geolocation",
      "advertising identifiers",
      "cross-site behavioural tracking",
    ],
    legacyHeading: "Updated privacy notice for your existing account",
    legacyBody:
      "You gave us your data before the DPDP Act's notice requirements took effect. This notice describes the personal data we hold, the purpose it is used for, your rights, and how to complain to the Data Protection Board. We will continue to process your data on this basis until you withdraw consent (s. 5(2)).",
  },

  hi: {
    heading: "गोपनीयता सूचना एवं सहमति",
    languageLabel: "भाषा",
    noticeVersionLabel: "सूचना संस्करण",
    translatedBadge: "अनुवादित",
    fallbackBadge: "अंग्रेज़ी-फ़ॉलबैक",
    fallbackNotice:
      "यह सूचना आपकी चुनी हुई भाषा में अभी उपलब्ध नहीं है, इसलिए अंग्रेज़ी दिखाई जा रही है। हम अनुवाद जोड़ रहे हैं; आप इसे आठवीं अनुसूची की किसी भी भाषा में भी माँग सकते हैं (धारा 5(3))।",

    whoWeAreTitle: "हम कौन हैं",
    dataFiduciaryText:
      "{name} डिजिटल व्यक्तिगत डेटा संरक्षण अधिनियम, 2023 के अंतर्गत एक डेटा नियंत्रक (Data Fiduciary) के रूप में कार्य करता है।",
    dpoLabel: "डेटा संरक्षण अधिकारी",

    collectTitle: "हम क्या एकत्र करते हैं और क्यों (मदवार)",
    requiredLabel: "आवश्यक",
    optionalLabel: "वैकल्पिक",
    dataLabel: "डेटा",
    lawfulBasisLabel: "वैध आधार",
    retentionDaysLabel: "प्रतिधारण: {days} दिन",
    retentionActiveLabel: "आपका खाता सक्रिय रहने तक प्रतिधारित",

    notCollectTitle: "अलग सहमति के बिना हम क्या एकत्र नहीं करेंगे",

    cookiesTitle: "कुकीज़ एवं ट्रैकर (उद्देश्य के अनुसार मदवार)",
    consentRequiredLabel: "सहमति आवश्यक",
    alwaysOnLabel: "सदैव सक्रिय — {basis}",
    examplesLabel: "उदाहरण",
    cookieSettingsNote:
      "इन्हें कभी भी “कुकी सेटिंग्स” बटन से प्रबंधित करें। एनालिटिक्स, विज्ञापन, वैयक्तिकरण और सोशल एम्बेड अलग-अलग सहमतियाँ हैं; इनमें से कोई भी पहले से चयनित नहीं है।",

    rightsTitle: "आपके अधिकार",
    manageInPrivacyCenter:
      "इन सभी को अपने प्राइवेसी सेंटर में प्रबंधित करें।",
    privacyCenterLink: "प्राइवेसी सेंटर",
    cookieSettingsButton: "कुकी सेटिंग्स",
    boardComplaintText:
      "यदि हम किसी शिकायत का समाधान नहीं कर पाते, तो आप {board} से शिकायत कर सकते हैं। {note}",

    dutiesTitle: "आपके कर्तव्य (धारा 15)",

    consentTitle: "सहमति एवं वापसी",
    consentStatement:
      "सहमति स्वतंत्र, विशिष्ट, सूचित, बिना शर्त और असंदिग्ध होनी चाहिए। यह केवल ऑप्ट-इन है (कोई पूर्व-चयनित बॉक्स नहीं) और आप इसे किसी भी समय उतनी ही सहजता से वापस ले सकते हैं जितनी सहजता से दी थी। वैकल्पिक प्रसंस्करण से इनकार करने पर मूल सेवा अवरुद्ध नहीं होगी।",
    withdrawalConsequences:
      "सहमति वापस लेने से वापसी से पहले किए गए प्रसंस्करण की वैधता प्रभावित नहीं होती। हम उस उद्देश्य के लिए प्रसंस्करण रोक देंगे और संबंधित डेटा मिटा देंगे (धारा 8(7)), सिवाय इसके कि कानून द्वारा प्रतिधारण आवश्यक हो या पहले से आरंभ किसी कार्य को पूरा करना आवश्यक हो (धारा 6(5))।",
    severabilityStatement:
      "इस सहमति का कोई भी भाग आपसे अधिनियम के अंतर्गत किसी अधिकार को त्यागने के लिए नहीं कहता। यदि इसका कोई भाग अधिनियम, नियमों या किसी अन्य कानून का उल्लंघन पाया जाए, तो केवल वही भाग अवैध होगा और शेष लागू रहेगा (धारा 6(2))।",
    accountabilityStatement:
      "{name} डेटा नियंत्रक है और इस प्रसंस्करण के लिए उत्तरदायी है, चाहे कोई भी विपरीत समझौता हो या आप धारा 15 के अंतर्गत अपने कर्तव्यों का पालन करने में विफल रहें (धारा 8(1))।",

    duties: [
      "अपने अधिकारों का प्रयोग करते समय किसी अन्य व्यक्ति का रूप धारण न करें (धारा 15(a))।",
      "राज्य की पहचान/लाभ प्रयोजनों के लिए आवश्यक सूचना न छिपाएँ (धारा 15(b))।",
      "झूठी या तुच्छ शिकायत दर्ज न करें (धारा 15(c))।",
      "सुधार/मिटाने के लिए केवल सत्यापन-योग्य प्रामाणिक सूचना दें (धारा 15(d))।",
    ],

    rights: {
      access: "आपके व्यक्तिगत डेटा का सारांश (धारा 11)",
      correction: "आपके डेटा को ठीक या पूर्ण करें (धारा 12)",
      erasure: "मिटाने का अनुरोध करें (धारा 12)",
      withdraw: "समान सहजता से सहमति वापस लें (धारा 6(4))",
      grievance: "शिकायत दर्ज करें (धारा 13)",
      nomination: "किसी को नामित करें (धारा 14)",
    },

    consentLabel:
      "मैंने ऊपर दी गई जानकारी पढ़ और समझ ली है और सूचीबद्ध संग्रह तथा प्रसंस्करण के लिए सहमति देता/देती हूँ।",
    notCollectedWithoutConsent: [
      "सुरक्षा एवं सहमति-ऑडिट उद्देश्यों से परे IP पता (हम कच्चा पता नहीं, एक salted hash संग्रहीत करते हैं)",
      "विज्ञापन हेतु डिवाइस / OS फ़िंगरप्रिंटिंग",
      "सटीक भू-स्थान",
      "विज्ञापन पहचानकर्ता",
      "क्रॉस-साइट व्यवहार ट्रैकिंग",
    ],
    legacyHeading: "आपके मौजूदा खाते के लिए अद्यतन गोपनीयता सूचना",
    legacyBody:
      "आपने हमें अपना डेटा DPDP अधिनियम की सूचना आवश्यकताओं के लागू होने से पहले दिया था। यह सूचना बताती है कि हम कौन-सा व्यक्तिगत डेटा रखते हैं, उसका उद्देश्य क्या है, आपके अधिकार क्या हैं, और डेटा संरक्षण बोर्ड से शिकायत कैसे करें। जब तक आप सहमति वापस नहीं लेते, हम इस आधार पर आपके डेटा का प्रसंस्करण जारी रखेंगे (धारा 5(2))।",
  },
};

// ---------------------------------------------------------------------------
// Purpose labels / descriptions (keyed by purpose_id). Missing key → English
// value from dpdp.config.js.
// ---------------------------------------------------------------------------
export const PURPOSE_I18N = {
  hi: {
    account: {
      label: "खाता एवं प्रमाणीकरण",
      description:
        "आपका खाता बनाना और सुरक्षित करना, साइन इन करना, ईमेल सत्यापित करना और अनधिकृत पहुँच से खाते की रक्षा करना।",
    },
    "strictly-functional": {
      label: "सेशन, सुरक्षा एवं लोड-बैलेंसिंग कुकीज़",
      description:
        "आपको साइन इन बनाए रखने, CSRF हमलों से बचाव, सुरक्षा लागू करने और ट्रैफ़िक संतुलित करने हेतु आवश्यक कुकीज़। DPDP अधिनियम में ‘अनिवार्य’ के लिए कोई छूट नहीं है, इसलिए हम इसे धारा 7(a) के अंतर्गत दर्ज करते हैं।",
    },
    "service-email": {
      label: "लेन-देन संबंधी ईमेल",
      description:
        "आवश्यक खाता ईमेल भेजना: ईमेल सत्यापन, पासवर्ड रीसेट, सुरक्षा अलर्ट और उल्लंघन सूचनाएँ।",
    },
    security: {
      label: "सुरक्षा, ऑडिट एवं धोखाधड़ी रोकथाम",
      description:
        "सुरक्षा और ऑडिट लॉग बनाए रखना, संदिग्ध साइन-इन का पता लगाना और दुरुपयोग रोकना (धारा 8(5), नियम 6(c))।",
    },
    consent_audit: {
      label: "सहमति प्रमाण (IP एवं संदर्भ)",
      description:
        "प्रत्येक सहमति निर्णय के साथ आपके IP का हैश, ब्राउज़र और समय दर्ज करना, ताकि हम सूचना दिए जाने और सहमति लिए जाने को सिद्ध कर सकें (धारा 6(10))। यह एक अलग समर्पित उद्देश्य है।",
    },
    twofa: {
      label: "दो-कारक प्रमाणीकरण",
      description:
        "दूसरा प्रमाणीकरण कारक नामांकित और सत्यापित करना तथा रिकवरी बैकअप कोड संग्रहीत करना।",
    },
    passkey: {
      label: "पासकी (WebAuthn)",
      description: "बिना पासवर्ड साइन इन हेतु पासकी पंजीकृत और सत्यापित करना।",
    },
    marketing: {
      label: "उत्पाद अपडेट एवं विपणन",
      description:
        "वैकल्पिक उत्पाद समाचार, सुविधा घोषणाएँ और प्रचारात्मक ईमेल भेजना।",
    },
    analytics: {
      label: "उत्पाद एनालिटिक्स",
      description:
        "उत्पाद सुधार हेतु समग्र रूप से सुविधा उपयोग मापना। विज्ञापन से अलग सहमति; कोई विज्ञापन पहचानकर्ता या क्रॉस-साइट ट्रैकिंग नहीं।",
    },
    advertising: {
      label: "विज्ञापन एवं रीटारगेटिंग",
      description:
        "लक्षित/रीटारगेट किए गए विज्ञापन देना और विज्ञापन प्रदर्शन मापना। एनालिटिक्स से अलग सहमति; बच्चों के लिए कभी नहीं।",
    },
    personalisation: {
      label: "वैयक्तिकरण",
      description:
        "आपके लिए अनुशंसाएँ और सामग्री अनुकूलित करना। अलग सहमति; बच्चों के लिए कभी नहीं।",
    },
    social_media: {
      label: "सोशल मीडिया एवं तृतीय-पक्ष एम्बेड",
      description:
        "तृतीय-पक्ष सोशल विजेट/एम्बेड और शेयर बटन लोड करना। अलग सहमति; बच्चों के लिए कभी नहीं।",
    },
    "children-service": {
      label: "बच्चों के लिए सेवा (अभिभावक-सहमति)",
      description:
        "18 वर्ष से कम आयु के उपयोगकर्ता को केवल सत्यापन-योग्य माता-पिता/अभिभावक की सहमति के बाद सेवा देना (धारा 9, नियम 10)। ट्रैकिंग, व्यवहार निगरानी और लक्षित विज्ञापन अक्षम हैं।",
    },
  },
};

// ---------------------------------------------------------------------------
// Cookie category labels / descriptions (keyed by category id).
// ---------------------------------------------------------------------------
export const COOKIE_I18N = {
  hi: {
    strictly_functional: {
      label: "अनिवार्य रूप से कार्यात्मक",
      description:
        "आपको साइन इन बनाए रखना, CSRF से बचाव, सुरक्षा लागू करना और ट्रैफ़िक संतुलित करना।",
    },
    analytics: {
      label: "एनालिटिक्स",
      description:
        "उत्पाद सुधार हेतु सुविधा उपयोग और प्रदर्शन समग्र रूप से मापना।",
    },
    advertising: {
      label: "विज्ञापन",
      description: "लक्षित/रीटारगेट विज्ञापन देना और विज्ञापन प्रदर्शन मापना।",
    },
    personalisation: {
      label: "वैयक्तिकरण",
      description: "आपके लिए अनुशंसाएँ और सामग्री अनुकूलित करना।",
    },
    social_media: {
      label: "सोशल मीडिया एवं एम्बेड",
      description: "तृतीय-पक्ष सोशल विजेट, एम्बेड और शेयर बटन लोड करना।",
    },
    consent_audit: {
      label: "सहमति प्रमाण",
      description:
        "प्रत्येक सहमति निर्णय के साथ हैश किया गया IP, यूज़र-एजेंट और समय दर्ज करना (धारा 6(10))।",
    },
  },
};

/** Interpolate {tokens} in a string. */
export const interpolate = (template, vars = {}) =>
  String(template).replace(/\{(\w+)\}/g, (_, k) =>
    vars[k] === undefined ? `{${k}}` : String(vars[k])
  );

/** Full UI + statements dictionary for a language (English fallback per key). */
export const stringsFor = (lang) => {
  const base = NOTICE_STRINGS.en;
  if (lang === "en" || !NOTICE_STRINGS[lang]) return base;
  return { ...base, ...NOTICE_STRINGS[lang] };
};

export const purposeLabel = (lang, purpose) => {
  const t = PURPOSE_I18N[lang]?.[purpose.id];
  return { label: t?.label || purpose.label, description: t?.description || purpose.description };
};

export const cookieLabel = (lang, category) => {
  const t = COOKIE_I18N[lang]?.[category.id];
  return { label: t?.label || category.label, description: t?.description || category.description };
};

/** True when a full translation exists (not just the English fallback). */
export const isTranslated = (lang) => lang === "en" || Boolean(NOTICE_STRINGS[lang]);

/**
 * Language codes that actually have a full translation. Drives the notice
 * language dropdown so users are only offered languages that render properly —
 * no dead "english-fallback" options. Adding a language to NOTICE_STRINGS
 * automatically adds it here.
 */
export const translatedLanguageCodes = () => Object.keys(NOTICE_STRINGS);

export default {
  NOTICE_STRINGS,
  PURPOSE_I18N,
  COOKIE_I18N,
  stringsFor,
  purposeLabel,
  cookieLabel,
  isTranslated,
  translatedLanguageCodes,
  interpolate,
};
