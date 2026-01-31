import DashboardClient from "./DashboardClient";

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
  items: CveItem[];
  vendors: VendorRow[];
  stats: { kevAddedToday: number; avgRisk: number };
};

async function getSnapshot(): Promise<Snapshot> {
  const res = await fetch("/api/snapshot", { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to load snapshot");
  return res.json();
}

export default async function Page() {
  const data = await getSnapshot();
  return <DashboardClient data={data} />;
}
