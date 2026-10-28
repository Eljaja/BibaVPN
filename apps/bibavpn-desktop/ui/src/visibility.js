/** True when the WebView is backgrounded (Android/iOS may throttle or suspend timers). */
export function isDocumentHidden() {
  return typeof document !== "undefined" && document.visibilityState === "hidden";
}
