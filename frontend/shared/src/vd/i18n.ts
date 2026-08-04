import i18n from "i18next";
import { initReactI18next } from "react-i18next";

/** English-only i18n (no EN/DE toggle). The source strings ARE the keys, so with an empty
 * resource set t() returns the English text with interpolation — no rewriting needed. */
if (!i18n.isInitialized) {
  void i18n.use(initReactI18next).init({
    resources: { en: { translation: {} } },
    lng: "en",
    fallbackLng: "en",
    keySeparator: false,
    nsSeparator: false,
    interpolation: { escapeValue: false },
    returnEmptyString: false,
  });
}

export default i18n;
