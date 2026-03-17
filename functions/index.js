const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");
const crypto = require("crypto");

initializeApp();
const db = getFirestore();

// ===== 常數設定 =====
const APP_ID = "github-memo-app-v2";
const PBKDF2_SALT_PREFIX = "twai-memo-v2-salt-2025";
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 32; // 256 bits → 32 bytes → 64 hex chars → 取前32
const RATE_LIMIT_MAP = new Map(); // 簡易記憶體限速（Cloud Functions 實例層級）

// ===== 工具函數 =====

/**
 * PBKDF2 hash（與前端 hashCredentials 完全對應）
 * 回傳 "v2:" + hex.substring(0,32)
 */
function pbkdf2Hash(accountId, password) {
  return new Promise((resolve, reject) => {
    const salt = PBKDF2_SALT_PREFIX + accountId.toLowerCase().trim();
    crypto.pbkdf2(
      password,
      salt,
      PBKDF2_ITERATIONS,
      PBKDF2_KEYLEN,
      "sha256",
      (err, derivedKey) => {
        if (err) return reject(err);
        resolve("v2:" + derivedKey.toString("hex").substring(0, 32));
      }
    );
  });
}

/**
 * 舊版 SHA-256 hash（用於向下相容）
 */
function sha256HashLegacy(accountId, password) {
  const input = accountId.trim() + ":" + password;
  return crypto.createHash("sha256").update(input).digest("hex").substring(0, 24);
}

/**
 * 依 accountId 計算 roomId（與前端邏輯相同）
 */
function computeRoomId(accountId) {
  const hash = crypto
    .createHash("sha256")
    .update("twai-room-" + accountId.toLowerCase().trim())
    .digest("hex");
  return "memos_v2_" + hash.substring(0, 24);
}

/**
 * 簡易登入頻率限制（每 IP 每分鐘最多 10 次，失敗 5 次鎖定 60 秒）
 */
function checkRateLimit(ip) {
  const now = Date.now();
  let entry = RATE_LIMIT_MAP.get(ip);
  if (!entry) {
    entry = { attempts: 0, lockedUntil: 0 };
    RATE_LIMIT_MAP.set(ip, entry);
  }
  if (entry.lockedUntil > now) {
    const secs = Math.ceil((entry.lockedUntil - now) / 1000);
    throw new HttpsError("resource-exhausted", `登入嘗試次數過多，請 ${secs} 秒後再試`);
  }
  // 超過 1 分鐘重置
  if (now - (entry.lastAttempt || 0) > 60000) {
    entry.attempts = 0;
  }
  entry.lastAttempt = now;
}

function recordFailedLogin(ip) {
  const entry = RATE_LIMIT_MAP.get(ip) || { attempts: 0, lockedUntil: 0 };
  entry.attempts = (entry.attempts || 0) + 1;
  if (entry.attempts >= 5) {
    entry.lockedUntil = Date.now() + 60000;
  }
  RATE_LIMIT_MAP.set(ip, entry);
}

function resetLoginAttempts(ip) {
  RATE_LIMIT_MAP.delete(ip);
}

// ===== Cloud Function: verifyLogin =====
/**
 * 登入驗證（前端傳帳號+密碼，後端比對 hash，不會把 pwHash 傳給前端）
 * 
 * 回傳：
 *   成功 → { success: true, roomId: string, needHashUpgrade: bool }
 *   失敗 → HttpsError
 */
exports.verifyLogin = onCall(
  { region: "asia-east1", cors: true },
  async (request) => {
    const ip = request.rawRequest?.ip || "unknown";
    const { accountId, password } = request.data || {};

    // 基本驗證
    if (!accountId || !password || accountId.length < 4 || password.length < 4) {
      throw new HttpsError("invalid-argument", "帳號和密碼長度至少 4 碼！");
    }

    // 限速檢查
    checkRateLimit(ip);

    try {
      // 1. 確認帳號是否存在
      const accountRef = db
        .collection("artifacts")
        .doc(APP_ID)
        .collection("public")
        .doc("data")
        .collection("account_registries")
        .doc(accountId);

      const accountSnap = await accountRef.get();
      if (!accountSnap.exists) {
        recordFailedLogin(ip);
        throw new HttpsError("not-found", "帳號或密碼錯誤！");
      }

      // 2. 取得 roomId
      const storedRoomId = accountSnap.data().roomId;
      const computedRoomId = computeRoomId(accountId);
      const actualRoomId = storedRoomId || computedRoomId;

      // 3. 取得 room_profile（含 pwHash）
      const profileRef = db
        .collection("artifacts")
        .doc(APP_ID)
        .collection("public")
        .doc("data")
        .collection(actualRoomId)
        .doc("room_profile");

      const profileSnap = await profileRef.get();
      if (!profileSnap.exists) {
        recordFailedLogin(ip);
        throw new HttpsError("not-found", "帳號或密碼錯誤！");
      }

      const storedHash = profileSnap.data().pwHash;
      const isLegacy = storedHash && !storedHash.startsWith("v2:");

      // 4. 計算並比對 hash（在後端執行，hash 永遠不外傳）
      let hashMatch = false;
      if (isLegacy) {
        const legacyHash = sha256HashLegacy(accountId, password);
        hashMatch = storedHash === legacyHash;
      } else {
        const newHash = await pbkdf2Hash(accountId, password);
        hashMatch = !storedHash || storedHash === newHash;
      }

      if (!hashMatch) {
        recordFailedLogin(ip);
        throw new HttpsError("unauthenticated", "帳號或密碼錯誤！");
      }

      // 5. 登入成功
      resetLoginAttempts(ip);

      // 自動升級舊版 hash
      if (isLegacy) {
        const upgradedHash = await pbkdf2Hash(accountId, password);
        await profileRef.update({ pwHash: upgradedHash });
      }

      // 補齊 roomId（若舊帳號沒有 roomId 欄位）
      if (!storedRoomId) {
        await accountRef.update({ roomId: actualRoomId });
      }

      // 回傳必要資訊（注意：絕不回傳 pwHash！）
      return {
        success: true,
        roomId: actualRoomId,
      };
    } catch (err) {
      // 已是 HttpsError 就直接往上拋
      if (err instanceof HttpsError) throw err;
      console.error("verifyLogin error:", err);
      throw new HttpsError("internal", "伺服器錯誤，請稍後再試");
    }
  }
);

// ===== Cloud Function: createAccount =====
/**
 * 建立新帳號（後端執行，密碼 hash 計算在伺服器）
 */
exports.createAccount = onCall(
  { region: "asia-east1", cors: true },
  async (request) => {
    const { accountId, password } = request.data || {};

    if (!accountId || !password || accountId.length < 4 || password.length < 4) {
      throw new HttpsError("invalid-argument", "帳號和密碼長度至少 4 碼！");
    }

    try {
      const accountRef = db
        .collection("artifacts")
        .doc(APP_ID)
        .collection("public")
        .doc("data")
        .collection("account_registries")
        .doc(accountId);

      const accountSnap = await accountRef.get();
      if (accountSnap.exists) {
        throw new HttpsError("already-exists", "帳號已被使用！");
      }

      const roomId = computeRoomId(accountId);
      const pwHash = await pbkdf2Hash(accountId, password);

      // 建立帳號登錄
      await accountRef.set({ created: Date.now(), roomId });

      // 建立房間 profile（pwHash 存在 Firestore，但前端永遠讀不到）
      const profileRef = db
        .collection("artifacts")
        .doc(APP_ID)
        .collection("public")
        .doc("data")
        .collection(roomId)
        .doc("room_profile");
      await profileRef.set({ created: Date.now(), accountId, migratedCategories: true, pwHash });

      // 建立預設分類
      const catsRef = db
        .collection("artifacts")
        .doc(APP_ID)
        .collection("public")
        .doc("data")
        .collection(roomId + "_categories");
      await catsRef.doc("cat_work").set({
        label: "工作", icon: "briefcase",
        color: "text-blue-600", bgColor: "bg-blue-50",
        activeBg: "bg-blue-100", borderColor: "border-blue-200",
        createdAt: Date.now()
      });
      await catsRef.doc("cat_personal").set({
        label: "私事", icon: "user",
        color: "text-emerald-600", bgColor: "bg-emerald-50",
        activeBg: "bg-emerald-100", borderColor: "border-emerald-200",
        createdAt: Date.now() + 1
      });

      return { success: true, roomId };
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("createAccount error:", err);
      throw new HttpsError("internal", "伺服器錯誤，請稍後再試");
    }
  }
);

// ===== Cloud Function: changePassword =====
/**
 * 修改密碼（後端驗舊密碼、計算新 hash、重新上傳）
 * 注意：備忘錄內容重加密仍由前端做（因為加密 key 來自密碼，後端不持有）
 */
exports.changePassword = onCall(
  { region: "asia-east1", cors: true },
  async (request) => {
    const { accountId, oldPassword, newPassword, roomId } = request.data || {};

    if (!accountId || !oldPassword || !newPassword || !roomId) {
      throw new HttpsError("invalid-argument", "缺少必要參數");
    }
    if (newPassword.length < 4) {
      throw new HttpsError("invalid-argument", "密碼至少 4 碼！");
    }

    try {
      const profileRef = db
        .collection("artifacts")
        .doc(APP_ID)
        .collection("public")
        .doc("data")
        .collection(roomId)
        .doc("room_profile");

      const profileSnap = await profileRef.get();
      if (!profileSnap.exists) {
        throw new HttpsError("not-found", "帳號不存在");
      }

      const storedHash = profileSnap.data().pwHash;
      const isLegacy = storedHash && !storedHash.startsWith("v2:");

      // 驗證舊密碼
      let hashMatch = false;
      if (isLegacy) {
        const legacyHash = sha256HashLegacy(accountId, oldPassword);
        hashMatch = storedHash === legacyHash;
      } else {
        const oldHash = await pbkdf2Hash(accountId, oldPassword);
        hashMatch = !storedHash || storedHash === oldHash;
      }

      if (!hashMatch) {
        throw new HttpsError("unauthenticated", "目前密碼錯誤！");
      }

      // 計算新 hash 並更新
      const newHash = await pbkdf2Hash(accountId, newPassword);
      await profileRef.update({ pwHash: newHash });

      return { success: true };
    } catch (err) {
      if (err instanceof HttpsError) throw err;
      console.error("changePassword error:", err);
      throw new HttpsError("internal", "伺服器錯誤，請稍後再試");
    }
  }
);
