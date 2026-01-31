import DashboardClient from "./DashboardClient";
import { headers } from "next/headers";


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
  const h = await headers();


  const host = h.get("x-forwarded-host") ?? h.get("host");
  const proto = h.get("x-forwarded-proto") ?? "https";

  if (!host) {
    throw new Error("Cannot determine host for snapshot fetch");
  }

  const baseUrl = `${proto}://${host}`;

  const res = await fetch(`${baseUrl}/api/snapshot`, {
    cache: "no-store",
  });

  if (!res.ok) {
    throw new Error("Failed to load snapshot");
  }

  return res.json();
}


export default async function Page() {
  const data = await getSnapshot();
  return <DashboardClient data={data} />;
}
