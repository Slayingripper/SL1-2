/**
 * Static topology for the Area Map view.
 *
 * The live values arrive over MQTT on pv/telemetry/<id> (published by the
 * noise/seeder containers); this module only carries the fixed metadata and
 * the position of each site inside the map's 1000x620 SVG viewBox.
 */

export type SiteType = 'house' | 'plant' | 'army';

export interface SiteMeta {
  id: string;
  name: string;
  type: SiteType;
  /** Anchor position in SVG user units (1000x620 viewBox) */
  x: number;
  y: number;
  capacityKw?: number;   // producers (inverter / substation rating)
  ratedLoadKw?: number;  // consumers
  model: string;
  serial: string;
  commissioned: string;
  feeder: string;
  description: string;
}

export const MAP_SITES: SiteMeta[] = [
  {
    id: 'house-1',
    name: 'Ktima Elia 4',
    type: 'house',
    x: 130, y: 150,
    capacityKw: 5.2,
    model: 'SolarEdge SE5000H',
    serial: 'SE5H-7F02-1194',
    commissioned: '2022-03-14',
    feeder: 'LV feeder F1 · 230 V',
    description: 'Residential rooftop array, 13 modules S-E orientation.',
  },
  {
    id: 'house-2',
    name: 'Ktima Elia 6',
    type: 'house',
    x: 330, y: 150,
    capacityKw: 3.8,
    model: 'Huawei SUN2000-3.68KTL',
    serial: 'HW36-2210-0873',
    commissioned: '2021-09-02',
    feeder: 'LV feeder F1 · 230 V',
    description: 'Residential rooftop array, 10 modules S orientation.',
  },
  {
    id: 'house-3',
    name: 'Ktima Elia 8',
    type: 'house',
    x: 530, y: 150,
    capacityKw: 6.4,
    model: 'Fronius Primo 6.0-1',
    serial: 'FR60-0341-5527',
    commissioned: '2023-05-21',
    feeder: 'LV feeder F1 · 230 V',
    description: 'Residential rooftop array, 16 modules S-W orientation.',
  },
  {
    id: 'pv-plant',
    name: 'Limassol Ridge PV Plant',
    type: 'plant',
    x: 760, y: 120,
    capacityKw: 120,
    model: 'SMA Sunny Central 150 · Substation TX-01',
    serial: 'SC150-CY-0042',
    commissioned: '2020-11-30',
    feeder: 'MV feeder F3 · 400 V · 3-phase',
    description: 'Ground-mounted plant with central inverter and 11/0.4 kV substation TX-01.',
  },
  {
    id: 'army-base',
    name: 'Camp Evagoras',
    type: 'army',
    x: 760, y: 430,
    ratedLoadKw: 30,
    model: 'Substation feed TX-01 → LV switchboard',
    serial: 'CE-SWB-0007',
    commissioned: '2019-06-11',
    feeder: 'Fed by Substation TX-01 · 400 V · 3-phase',
    description: 'Military installation drawing from the plant substation. Restricted area.',
  },
];

export const siteById = (id: string): SiteMeta | undefined =>
  MAP_SITES.find(s => s.id === id);
