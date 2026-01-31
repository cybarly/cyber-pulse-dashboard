"use client";

import { useEffect, useMemo, useState } from "react";
import Image from "next/image";
import { ThemeToggle } from "./ThemeToggle";

type CveItem = {
  cve: string;
  vendor: string;
  product: string;
  kevAdded: string;
  cvss: number | null;
  epss: number | null;
  risk: number;
};

type VendorRow = {
  vendor: string;
  count: number;
  avgRisk: number;
  maxRisk: number;
};

type Snapshot = {
  updatedAt: string;
  servedAt?: string;
  items: CveItem[];
  vendors: VendorRow[];
  stats: { kevAddedToday: number; avgRisk: number };
};


function pillClass(risk: number) {
  if (risk >= 80) return "bg-red-100 text-red-800";
  if (risk >= 60) return "bg-orange-100 text-orange-800";
  if (risk >= 40) return "bg-yellow-100 text-yellow-800";
  return "bg-green-100 text-green-800";
}

function vendorClass(avgRisk: number) {
  if (avgRisk >= 80) return "border-red-700";
  if (avgRisk >= 60) return "border-orange-600";
  if (avgRisk >= 40) return "border-yellow-600";
  return "border-green-600";
}

export default function DashboardClient({ data }: { data: Snapshot }) {
const [liveData, setLiveData] = useState(data);

// Auto-refresh settings
const [autoRefresh, setAutoRefresh] = useState<boolean>(false);
const [refreshSec, setRefreshSec] = useState<number>(60);


  const [q, setQ] = useState("");
  const [riskFilter, setRiskFilter] = useState<"all" | "high" | "medium" | "low">("all");
  const [mounted, setMounted] = useState(false);
useEffect(() => setMounted(true), []);


  // 3) כשדף נטען: נטען את ההגדרות השמורות מהדפדפן (אם יש)
  useEffect(() => {
    const savedOn = localStorage.getItem("autoRefreshOn");
    const savedSec = localStorage.getItem("autoRefreshSec");

    if (savedOn !== null) setAutoRefresh(savedOn === "1");

    if (savedSec !== null) {
      const n = Number(savedSec);
      // בטיחות: לא לאפשר ערכים הזויים
      if (Number.isFinite(n) && n >= 10 && n <= 600) setRefreshSec(n);
    }
  }, []);



  // 4) כל שינוי: לשמור את ההגדרות
  useEffect(() => {
    localStorage.setItem("autoRefreshOn", autoRefresh ? "1" : "0");
  }, [autoRefresh]);

  useEffect(() => {
    localStorage.setItem("autoRefreshSec", String(refreshSec));
  }, [refreshSec]);





  // 5) פעולת רענון ידנית/אוטומטית
  async function refreshNow() {
    try {
      
      const res = await fetch("/api/snapshot", { cache: "no-store" });
      if (!res.ok) return;
      const next = await res.json();
      console.log("refresh got updatedAt:", next.updatedAt);

      setLiveData(next);
    } catch {
      // לא מפילים את האתר אם יש תקלה רגעית
    }
  }

  // 6) טיימר אוטומטי: עובד רק אם autoRefresh = true
  useEffect(() => {
    if (!autoRefresh) return;

    // מרענן פעם אחת מיד כשמדליקים
    refreshNow();

    const id = window.setInterval(() => {
      refreshNow();
    }, refreshSec * 1000);

    return () => window.clearInterval(id);
  }, [autoRefresh, refreshSec]);








  function clearFilters() {
  setQ("");
  setRiskFilter("all");
}


  // מנקים את החיפוש: lowercase + trim
  const query = q.trim().toLowerCase();
const filteredItems = useMemo(() => {
  let items = liveData.items;

  // 1) סינון לפי חיפוש טקסט
  if (query) {
    items = items.filter((i) => {
      return (
        i.cve.toLowerCase().includes(query) ||
        i.vendor.toLowerCase().includes(query) ||
        i.product.toLowerCase().includes(query)
      );
    });
  }

  // 2) סינון לפי רמת סיכון
  if (riskFilter === "high") items = items.filter((i) => i.risk >= 80);
  if (riskFilter === "medium") items = items.filter((i) => i.risk >= 60 && i.risk < 80);
  if (riskFilter === "low") items = items.filter((i) => i.risk < 60);

  return items;
}, [liveData.items, query, riskFilter]);


  // מחשבים vendors מחדש מתוך items מסוננים (ככה heatmap תואם לחיפוש)
  const filteredVendors = useMemo(() => {
    const map = new Map<string, { count: number; riskSum: number; maxRisk: number }>();
    for (const i of filteredItems) {
      const key = (i.vendor || "Unknown").trim();
      const v = map.get(key) ?? { count: 0, riskSum: 0, maxRisk: 0 };
      v.count += 1;
      v.riskSum += i.risk;
      v.maxRisk = Math.max(v.maxRisk, i.risk);
      map.set(key, v);
    }
    return [...map.entries()]
      .map(([vendor, v]) => ({
        vendor,
        count: v.count,
        avgRisk: Math.round(v.riskSum / v.count),
        maxRisk: v.maxRisk,
      }))
      .sort((a, b) => b.avgRisk - a.avgRisk)
      .slice(0, 18);
  }, [filteredItems]);

  return (
    <main className="min-h-screen p-6">
      <div
  className="max-w-5xl mx-auto rounded-3xl border p-4 sm:p-6"
  style={{
    background: "var(--panel)",
    borderColor: "var(--border)",
    boxShadow: "var(--shadow)",
  }}
>


        <header className="flex flex-col gap-3 mb-6">
          <div className="flex items-center justify-between gap-3">
            <h1 className="text-2xl font-bold">Cyber Pulse Dashboard</h1>

<div className="flex flex-wrap items-center gap-2">
  <button
    onClick={() => setAutoRefresh((v) => !v)}
    className={`rounded-xl border px-3 py-2 text-sm ${
      autoRefresh ? "bg-green-600 text-white" : ""
    }`}
  >
    Auto-Refresh: {autoRefresh ? "ON" : "OFF"}
  </button>

  <select
    value={refreshSec}
    onChange={(e) => setRefreshSec(Number(e.target.value))}
    className="rounded-xl border px-3 py-2 text-sm
           bg-white text-gray-900 border-gray-200
           dark:bg-gray-900 dark:text-gray-100 dark:border-gray-800"
    disabled={!autoRefresh}
  >
    <option value={30} style={{ color: "black" }}>Every 30s</option>
    <option value={60} style={{ color: "black" }}>Every 60s</option>
    <option value={120} style={{ color: "black" }}>Every 2m</option>
    <option value={300} style={{ color: "black" }}>Every 5m</option>
  </select>

  <button
    onClick={refreshNow}
    className="rounded-xl border px-3 py-2 text-sm"
    title="Refresh now"
  >
    Refresh
  </button>
</div>

            
            <a
    href="https://buymeacoffee.com/cybar"
    target="_blank"
    rel="noopener noreferrer"
    className="opacity-80 hover:opacity-100 transition"
  >
    <Image
      src="/bmac.png"
      alt="Buy me a coffee"
      width={180}
      height={50}
    />
  </a>
            <ThemeToggle />
          </div>

          <div className="flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
            <p className="text-sm" style={{ color: "var(--muted)" }}>
  Data updated:{" "}
  {mounted ? new Date(liveData.updatedAt).toLocaleString() : "—"}
  {"  "}{"  "}<br/>
  Last refresh:{" "}
  {mounted ? new Date(liveData.servedAt).toLocaleString() : "—"}
</p>

            <div className="flex flex-col sm:flex-row gap-2 sm:items-center">

   <button
  onClick={clearFilters}
  className={`rounded-xl border px-3 py-2 text-sm dark:border-gray-800 dark:text-gray-100 ${
  riskFilter === "all" ? "bg-gray-900 text-white" : ""
}`}>
  Clear
</button>

  <input
    value={q}
    onChange={(e) => setQ(e.target.value)}
    placeholder="Search CVE / vendor / product…"
    className="w-full sm:w-80 rounded-xl border px-3 py-2 text-sm"
  />

  <div className="flex gap-2">
    <button
      onClick={() => setRiskFilter("all")}
      className={`rounded-xl border px-3 py-2 text-sm ${
        riskFilter === "all" ? "bg-gray-900 text-white" : ""
      }`}
    >
      All
    </button>

    <button
      onClick={() => setRiskFilter("high")}
      className={`rounded-xl border px-3 py-2 text-sm ${
        riskFilter === "high" ? "bg-red-600 text-white" : ""
      }`}
    >
      High
    </button>

    <button
      onClick={() => setRiskFilter("medium")}
      className={`rounded-xl border px-3 py-2 text-sm ${
        riskFilter === "medium" ? "bg-orange-500 text-white" : ""
      }`}
    >
      Medium
    </button>

    <button
      onClick={() => setRiskFilter("low")}
      className={`rounded-xl border px-3 py-2 text-sm ${
        riskFilter === "low" ? "bg-green-600 text-white" : ""
      }`}
    >
      Low
    </button>

 

  </div>
</div>

          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div
  className="rounded-2xl border p-4"
  style={{ background: "var(--panel)", borderColor: "var(--border)" }}
>
  <div className="text-sm" style={{ color: "var(--muted)" }}>KEV Added Today</div>
  <div className="text-2xl font-semibold">{liveData.stats.kevAddedToday}</div>
</div>

            <div
  className="rounded-2xl border p-4"
  style={{ background: "var(--panel)", borderColor: "var(--border)" }}
>

              <div className="text-sm" style={{ color: "var(--muted)" }}>Average risk</div>
              <div className="text-2xl font-semibold">{liveData.stats.avgRisk}/100</div>
            </div>
            <div
  className="rounded-2xl border p-4"
  style={{ background: "var(--panel)", borderColor: "var(--border)" }}
>

              <div className="text-sm" style={{ color: "var(--muted)" }}>Showing</div>
              <div className="text-2xl font-semibold">{filteredItems.length}</div>
            </div>
          </div>
        </header>

        {/* Vendor Heatmap */}
        <section className="mb-6">
          <div className="flex items-end justify-between mb-2">
            <h2 className="text-lg font-semibold">Vendor Heatmap</h2>
            <div className="text-xs text-gray-500">
              {query ? `Filtered by "${q}"` : "Top vendors (by avg risk)"}
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {filteredVendors.map((v) => (
              <div key={v.vendor} className={`rounded-2xl border p-3 ${vendorClass(v.avgRisk)}`}>
                <div className="text-sm font-semibold truncate">{v.vendor}</div>

                <div className="mt-2 flex items-center justify-between">
                  <span className="text-xs text-gray-600">Avg</span>
                  <span className="text-sm font-bold">{v.avgRisk}</span>
                </div>
                <div className="mt-1 flex items-center justify-between">
                  <span className="text-xs text-gray-600">Max</span>
                  <span className="text-sm font-bold">{v.maxRisk}</span>
                </div>
                <div className="mt-1 flex items-center justify-between">
                  <span className="text-xs text-gray-600">Items</span>
                  <span className="text-sm font-bold">{v.count}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Table */}
        <section
  className="rounded-2xl border overflow-hidden"
  style={{ background: "var(--panel)", borderColor: "var(--border)" }}
>
          <div className="p-4 border-b font-semibold">Exploited CVEs</div>

          <div className="overflow-x-auto">
            <table
  className="w-full text-sm"
  style={{ color: "var(--text)" }}
>


              <thead style={{ background: "var(--panel-2)", color: "var(--muted)" }}>


                <tr>
                  <th className="p-3">CVE</th>
                  <th className="p-3">Vendor</th>
                  <th className="p-3">Product</th>
                  <th className="p-3">KEV Added</th>
                  <th className="p-3">CVSS</th>
                  <th className="p-3">EPSS</th>
                  <th className="p-3">Risk</th>
                </tr>
              </thead>

              <tbody>
                {filteredItems.map((i) => (
                    <tr
  key={i.cve}
  className="border-t hover:opacity-90"
  style={{ borderColor: "var(--border)" }}
>

                    <td className="p-3 font-mono">{i.cve}</td>
                    <td className="p-3">{i.vendor}</td>
                    <td className="p-3">{i.product}</td>
                    <td className="p-3">{i.kevAdded}</td>
                    <td className="p-3">{i.cvss == null ? "—" : i.cvss.toFixed(1)}</td>
                    <td className="p-3">{i.epss == null ? "—" : i.epss.toFixed(2)}</td>
                    <td className="p-3">
                      <span className={`px-3 py-1 rounded-full text-xs font-bold shadow-sm ${pillClass(i.risk)}`}>
  {i.risk}
</span>

                    </td>
                  </tr>
                ))}

                {filteredItems.length === 0 && (
                  <tr>
                    <td className="p-4 text-gray-600" colSpan={7}>
                      No results.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>

        <footer className="mt-8 flex flex-col items-center gap-3 text-xs text-gray-500">
  <p>
    Note: risk score is a simple heuristic (CVSS + EPSS + KEV boost), not a prediction.
  </p>

  <a
    href="https://buymeacoffee.com/cybar"
    target="_blank"
    rel="noopener noreferrer"
    className="opacity-80 hover:opacity-100 transition"
  >
    <Image
      src="/bmac.png"
      alt="Buy me a coffee"
      width={180}
      height={50}
    />
  </a>
</footer>

      </div>
    </main>
  );
}
