// app/api/snapshot/route.ts
import { NextResponse } from "next/server";

/**
 * מקורות
 * - KEV: אנחנו משתמשים במראה GitHub הרשמית של CISA (כי cisa.gov לפעמים מחזיר 403 בסביבות ענן)
 * - EPSS: API ציבורי של FIRST
 */
const KEV_URL =
  "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json";
const EPSS_BASE = "https://api.first.org/data/v1/epss";

const NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_KEY = process.env.NVD_API_KEY; // optional
const NVD_LOOKUP_LIMIT = Number(process.env.NVD_LOOKUP_LIMIT ?? (NVD_KEY ? 30 : 10));


type KevEntry = {
  cveID?: string; // לפעמים זה ככה
  cve?: string; // ליתר ביטחון
  vendorProject?: string;
  product?: string;
  dateAdded?: string; // YYYY-MM-DD
};

type KevFeed = {
  vulnerabilities?: KevEntry[];
};

export type CveItem = {
  cve: string;
  vendor: string;
  product: string;
  kevAdded: string; // YYYY-MM-DD
  cvss: number | null;
  epss: number | null; // 0-1
  risk: number; // 0-100
};

export type VendorRow = {
  vendor: string;
  count: number;
  avgRisk: number;
  maxRisk: number;
};

export type Snapshot = {
  updatedAt: string; // מתי הנתונים נבנו (רק כשנבנה snapshot חדש)
  servedAt: string;  // מתי התשובה הוחזרה עכשיו (מתעדכן בכל רענון)
  items: CveItem[];
  vendors: VendorRow[];
  stats: {
    kevAddedToday: number;
    avgRisk: number;
  };
};




export const dynamic = "force-dynamic";


// ---------- utils ----------
function clamp(n: number, min: number, max: number) {
  return Math.max(min, Math.min(max, n));
}

function calcRisk(params: { cvss: number | null; epss: number | null; isKev: boolean }) {
  // כרגע CVSS לא מחובר -> מתבססים בעיקר על EPSS + בוסט של KEV
  const cvssPart = params.cvss == null ? 0 : params.cvss / 10;
  const epssPart = params.epss == null ? 0 : params.epss;
  const base = 0.35 * cvssPart + 0.65 * epssPart + (params.isKev ? 0.2 : 0);
  return Math.round(clamp(base, 0, 1) * 100);
}

async function fetchJsonWithTimeout<T>(url: string, ms = 12_000): Promise<T> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        // "מזדהים" כמו דפדפן רגיל כדי להימנע מ"חסימות בוטים" אצל חלק מהשירותים
        "User-Agent": "cyber-dashboard/1.0",
        Accept: "application/json",
      },
      // Next will cache per-request unless we override.
      cache: "no-store",
    });

    if (!res.ok) {
      throw new Error(`Fetch failed ${res.status} for ${url}`);
    }
    return (await res.json()) as T;
  } finally {
    clearTimeout(t);
  }
}

function chunkCvesForEpss(cves: string[]) {
  // FIRST מציינים מגבלת אורך פרמטרים (בסדר גודל ~2000 תווים כולל פסיקים)
  // אז אנחנו מחלקים ל-batches קטנים כדי להיות בטוחים. :contentReference[oaicite:2]{index=2}
  const batches: string[][] = [];
  let current: string[] = [];
  let currentLen = 0;

  for (const cve of cves) {
    const addLen = (current.length === 0 ? 0 : 1) + cve.length; // + comma
    if (currentLen + addLen > 1800) {
      if (current.length) batches.push(current);
      current = [cve];
      currentLen = cve.length;
    } else {
      current.push(cve);
      currentLen += addLen;
    }
  }
  if (current.length) batches.push(current);
  return batches;
}

async function fetchEpssMap(cves: string[]): Promise<Map<string, number>> {
  const map = new Map<string, number>();
  const batches = chunkCvesForEpss(cves);

  for (const batch of batches) {
    const url = `${EPSS_BASE}?cve=${encodeURIComponent(batch.join(","))}`;
    const data = await fetchJsonWithTimeout<{
      data?: { cve: string; epss: string | number }[];
    }>(url);

    for (const row of data.data ?? []) {
      const v = typeof row.epss === "string" ? Number(row.epss) : row.epss;
      if (Number.isFinite(v)) map.set(row.cve, v);
    }
  }

  return map;
}

type NvdResponse = {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      metrics?: any;
    };
  }>;
};

function extractCvssBaseScore(metrics: any): number | null {
  if (!metrics) return null;

  // NVD מחזיר מערכים שונים לפי גרסת CVSS
  // ננסה מהחדש לישן
  const candidates = [
    metrics.cvssMetricV40,
    metrics.cvssMetricV31,
    metrics.cvssMetricV30,
    metrics.cvssMetricV2,
  ];

  for (const arr of candidates) {
    const first = Array.isArray(arr) ? arr[0] : null;
    const score =
      first?.cvssData?.baseScore ??
      first?.cvssData?.base_score ?? // just-in-case
      null;

    if (typeof score === "number" && Number.isFinite(score)) return score;
  }
  return null;
}

// cache פר-CVE כדי לא להכות את NVD שוב ושוב
declare global {
  // eslint-disable-next-line no-var
  var __cvssCache:
    | Map<string, { at: number; cvss: number | null }>
    | undefined;
}

const CVSS_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 ימים

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchCvssForCves(cves: string[]): Promise<Map<string, number | null>> {
  const out = new Map<string, number | null>();
  if (!globalThis.__cvssCache) globalThis.__cvssCache = new Map();

  // NVD rate limiting:
  // בלי key: 5/30s, עם key: 50/30s  :contentReference[oaicite:4]{index=4}
  // נשמור מרווח בטוח בין בקשות:
  const delayMs = NVD_KEY ? 350 : 6500;

  for (const cve of cves) {
    const cached = globalThis.__cvssCache.get(cve);
    const now = Date.now();
    if (cached && now - cached.at < CVSS_TTL_MS) {
      out.set(cve, cached.cvss);
      continue;
    }

    const url = `${NVD_BASE}?cveId=${encodeURIComponent(cve)}`;
    try {
      const res = await fetch(url, {
        headers: {
          Accept: "application/json",
          ...(NVD_KEY ? { apiKey: NVD_KEY } : {}), // header apiKey ב-API 2.0 :contentReference[oaicite:5]{index=5}
        },
        cache: "no-store",
      });

      if (!res.ok) {
        // אם יש בעיה זמנית/429 - נשמור null ונמשיך
        out.set(cve, null);
        globalThis.__cvssCache.set(cve, { at: now, cvss: null });
      } else {
        const data = (await res.json()) as NvdResponse;
        const vuln = data.vulnerabilities?.[0];
        const cvss = extractCvssBaseScore(vuln?.cve?.metrics) ?? null;

        out.set(cve, cvss);
        globalThis.__cvssCache.set(cve, { at: now, cvss });
      }
    } catch {
      out.set(cve, null);
      globalThis.__cvssCache.set(cve, { at: now, cvss: null });
    }

    // מרווח בטוח כדי לא להיחסם
    await sleep(delayMs);
  }

  return out;
}


// ---------- tiny in-memory cache (MVP) ----------
declare global {
  // eslint-disable-next-line no-var
  var __snapshotCache: { at: number; value: Snapshot } | undefined;
}

const TTL_MS = 10 * 60 * 1000; // 10 דקות

export async function GET() {
  const now = Date.now();
  const cached = globalThis.__snapshotCache;
  if (cached && now - cached.at < TTL_MS) {
  return NextResponse.json(
    {
      ...cached.value,
      servedAt: new Date().toISOString(), // ✅ מתעדכן בכל רענון
    },
    {
      headers: { "Cache-Control": "no-store" }, // ✅ שלא ייתקע בקאש חיצוני
    }
  );
}


  // 1) KEV
  const kev = await fetchJsonWithTimeout<KevFeed>(KEV_URL);
  const vulns = kev.vulnerabilities ?? [];

  // 2) ניקוי + מיון לפי dateAdded (הכי חדש למעלה)
  const normalized = vulns
    .map((v) => {
      const cve = (v.cveID ?? v.cve ?? "").trim();
      const kevAdded = (v.dateAdded ?? "").trim();
      return {
        cve,
        kevAdded,
        vendor: (v.vendorProject ?? "Unknown").trim(),
        product: (v.product ?? "Unknown").trim(),
      };
    })
    .filter((v) => v.cve.startsWith("CVE-") && v.kevAdded.length >= 10)
    .sort((a, b) => b.kevAdded.localeCompare(a.kevAdded));

  // 3) בוחרים כמות הגיונית ל-MVP (אפשר להגדיל אחר כך)
  const TOP_N = 50;
  const top = normalized.slice(0, TOP_N);

  // 4) EPSS
  const cves = [...new Set(top.map((x) => x.cve))];
  const epssMap = await fetchEpssMap(cves);

  const cvesForNvd = cves.slice(0, NVD_LOOKUP_LIMIT);
const cvssMap = await fetchCvssForCves(cvesForNvd);

  const items: CveItem[] = top.map((x) => {
    const epss = epssMap.get(x.cve) ?? null;
const cvss = cvssMap.get(x.cve) ?? null;

    const risk = calcRisk({ cvss, epss, isKev: true });

    return {
      cve: x.cve,
      vendor: x.vendor,
      product: x.product,
      kevAdded: x.kevAdded,
      cvss,
      epss,
      risk,
    };
  });


  // --- Vendor summary (Heatmap data) ---
const vendorMap = new Map<string, { count: number; riskSum: number; maxRisk: number }>();

for (const i of items) {
  const key = (i.vendor || "Unknown").trim();

  // אם זה הפעם הראשונה שאנחנו רואים את ה-vendor הזה
  const current = vendorMap.get(key) ?? { count: 0, riskSum: 0, maxRisk: 0 };

  current.count += 1;           // עוד CVE לספק הזה
  current.riskSum += i.risk;    // מוסיפים את הסיכון לסכימה
  current.maxRisk = Math.max(current.maxRisk, i.risk); // שומרים מקסימום

  vendorMap.set(key, current);  // שומרים בחזרה במפה
}

// הופכים את המפה לרשימה (array) כדי לשלוח ל-Frontend
const vendors = [...vendorMap.entries()]
  .map(([vendor, v]) => ({
    vendor,
    count: v.count,
    avgRisk: Math.round(v.riskSum / v.count),
    maxRisk: v.maxRisk,
  }))
  .sort((a, b) => b.avgRisk - a.avgRisk) // הכי מסוכן למעלה
  .slice(0, 18); // רק 18 כדי שהלוח יהיה יפה


  const today = new Date().toISOString().slice(0, 10);
  const avgRisk =
    items.length === 0 ? 0 : Math.round(items.reduce((s, i) => s + i.risk, 0) / items.length);


    const nowIso = new Date().toISOString();

const snapshot: Snapshot = {
  updatedAt: nowIso, // הנתונים נבנו עכשיו
  servedAt: nowIso,  // וגם התשובה עכשיו
  items,
  vendors,
    stats: {
      kevAddedToday: items.filter((i) => i.kevAdded === today).length,
      avgRisk,
    },
  };

  globalThis.__snapshotCache = { at: now, value: snapshot };

  return NextResponse.json(snapshot, {
  headers: {
    //"Cache-Control": "public, s-maxage=5",
    "Cache-Control": "no-store",
  },
});
}
