// Local "enclave": IndexedDB storage for NON-extractable CryptoKeys and pinned contact keys.
// IndexedDB can hold CryptoKey objects without exposing their bytes, so the
// identity survives page navigation while staying unreadable to scripts.
window.GhostKeystore = (() => {
  "use strict";
  const DB_NAME = "ghostline";
  const DB_VERSION = 1;

  function open() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const db = req.result;
        db.createObjectStore("identity");   // the signed-in user's private keys
        db.createObjectStore("pins");       // contact keys seen before (trust on first use)
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function run(store, mode, fn) {
    const db = await open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(store, mode);
      const req = fn(tx.objectStore(store));
      tx.oncomplete = () => { db.close(); resolve(req ? req.result : undefined); };
      tx.onerror = tx.onabort = () => { db.close(); reject(tx.error); };
    });
  }

  // Pins are scoped per local account: `${ownerId}:${peerId}`.
  const pinKey = (ownerId, peerId) => `${ownerId}:${peerId}`;

  return {
    saveIdentity: (record) => run("identity", "readwrite", (s) => s.put(record, "self")),
    loadIdentity: () => run("identity", "readonly", (s) => s.get("self")),
    wipeIdentity: () => run("identity", "readwrite", (s) => s.clear()),
    getPin: (ownerId, peerId) => run("pins", "readonly", (s) => s.get(pinKey(ownerId, peerId))),
    putPin: (ownerId, peerId, pin) => run("pins", "readwrite", (s) => s.put(pin, pinKey(ownerId, peerId))),
  };
})();
