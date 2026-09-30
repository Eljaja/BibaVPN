import assert from "node:assert/strict";
import test from "node:test";
import { resolveLang, setLanguageFromCfg, t } from "./i18n.js";

test("automatic language uses English for C, missing and unsupported locales", () => {
  const original = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  try {
    for (const [language, expected] of [
      ["C", "en"], ["C.UTF-8", "en"], ["", "en"],
      ["de-DE", "en"], ["en-US", "en"], ["ru-RU", "ru"], ["RU", "ru"],
    ]) {
      Object.defineProperty(globalThis, "navigator", {
        configurable: true, value: { language },
      });
      assert.equal(resolveLang({ ui_locale: "auto" }), expected, language);
      assert.equal(resolveLang({ ui_locale: "ru" }), "ru");
      assert.equal(resolveLang({ ui_locale: "en" }), "en");
      setLanguageFromCfg({ ui_locale: "auto" });
      if (expected === "en") assert.doesNotMatch(t("status_disconnected"), /[а-яё]/i);
    }
    delete globalThis.navigator;
    assert.equal(resolveLang({}), "en");
  } finally {
    if (original) Object.defineProperty(globalThis, "navigator", original);
    else delete globalThis.navigator;
    setLanguageFromCfg({});
  }
});
