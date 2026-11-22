// Minimal service worker. Chrome on Android needs one before it offers to install the app.
// It deliberately caches nothing: this is a signed-in realtime app, and a stale cached
// page or API answer would be worse than no offline support. Every request goes to the network.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", () => {});
