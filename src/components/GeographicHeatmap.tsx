/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  Globe2,
  AlertTriangle,
  ShieldAlert,
  Crosshair,
  Filter,
  Maximize2,
  Radio,
  ExternalLink,
  Flame,
  Info,
  CheckCircle2,
  Shield,
  Layers
} from 'lucide-react';

export interface GeoAnomalyIncident {
  id: string;
  ip: string;
  domain: string;
  city: string;
  country: string;
  countryCode: string;
  lat: number;
  lng: number;
  asn: string;
  organization: string;
  subnet: string;
  vector: 'Cache Poisoning' | 'DNS Rebinding' | 'DNSSEC Strip / NS Hijack' | 'BGP / Subnet Drift' | 'NXDOMAIN Blackhole';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  anomalyScore: number;
  jaccardSimilarity: number;
  observedAt: string;
  mitigation: string;
}

export const GEO_ANOMALY_DATA: GeoAnomalyIncident[] = [
  {
    id: 'geo-1',
    ip: '185.220.101.5',
    domain: 'bankofamerica.com',
    city: 'Frankfurt',
    country: 'Germany',
    countryCode: 'DE',
    lat: 50.1109,
    lng: 8.6821,
    asn: 'AS208323',
    organization: 'Offshore Bulletproof Transit',
    subnet: '185.220.101.0/24',
    vector: 'Cache Poisoning',
    severity: 'CRITICAL',
    anomalyScore: 94,
    jaccardSimilarity: 0.0,
    observedAt: '3m ago',
    mitigation: 'Flush recursive resolver cache via `rndc flushname bankofamerica.com` and block upstream ASN 208323.'
  },
  {
    id: 'geo-2',
    ip: '103.208.220.12',
    domain: 'dns.google',
    city: 'Hong Kong',
    country: 'Hong Kong SAR',
    countryCode: 'HK',
    lat: 22.3193,
    lng: 114.1694,
    asn: 'AS133475',
    organization: 'Dragon Cloud Asia',
    subnet: '103.208.220.0/23',
    vector: 'Cache Poisoning',
    severity: 'CRITICAL',
    anomalyScore: 91,
    jaccardSimilarity: 0.0,
    observedAt: '7m ago',
    mitigation: 'Reject forged synthetic A record; verify DNSSEC cryptographic chain of trust on Root/TLD.'
  },
  {
    id: 'geo-3',
    ip: '194.26.29.11',
    domain: 'portal.financial-corp.com',
    city: 'Moscow',
    country: 'Russia',
    countryCode: 'RU',
    lat: 55.7558,
    lng: 37.6173,
    asn: 'AS48982',
    organization: 'Volga Transit Edge',
    subnet: '194.26.29.0/24',
    vector: 'DNSSEC Strip / NS Hijack',
    severity: 'CRITICAL',
    anomalyScore: 96,
    jaccardSimilarity: 0.0,
    observedAt: '11m ago',
    mitigation: 'Authoritative NS delegation mismatch detected. Audit registrar glue records immediately.'
  },
  {
    id: 'geo-4',
    ip: '198.51.100.82',
    domain: 'github.com',
    city: 'Ashburn, VA',
    country: 'United States',
    countryCode: 'US',
    lat: 39.0438,
    lng: -77.4874,
    asn: 'AS16509',
    organization: 'Amazon AWS Transit Node',
    subnet: '198.51.100.0/24',
    vector: 'BGP / Subnet Drift',
    severity: 'HIGH',
    anomalyScore: 78,
    jaccardSimilarity: 0.33,
    observedAt: '15m ago',
    mitigation: 'Verify legitimate Anycast multi-homed rollover with Fastly/GitHub edge operators.'
  },
  {
    id: 'geo-5',
    ip: '193.106.191.24',
    domain: 'quad9.net',
    city: 'Bucharest',
    country: 'Romania',
    countryCode: 'RO',
    lat: 44.4268,
    lng: 26.1025,
    asn: 'AS44034',
    organization: 'Voxility Anycast Network',
    subnet: '193.106.191.0/24',
    vector: 'NXDOMAIN Blackhole',
    severity: 'CRITICAL',
    anomalyScore: 88,
    jaccardSimilarity: 0.0,
    observedAt: '22m ago',
    mitigation: 'Forged negative answer blackholing client DNS traffic. Enforce strict RFC 4035 authenticated denial.'
  },
  {
    id: 'geo-6',
    ip: '185.191.171.12',
    domain: 'wikipedia.org',
    city: 'London',
    country: 'United Kingdom',
    countryCode: 'GB',
    lat: 51.5074,
    lng: -0.1278,
    asn: 'AS13030',
    organization: 'Init7 Cloud Infrastructure',
    subnet: '185.191.171.0/24',
    vector: 'DNSSEC Strip / NS Hijack',
    severity: 'HIGH',
    anomalyScore: 72,
    jaccardSimilarity: 0.5,
    observedAt: '29m ago',
    mitigation: 'Secondary NS record injected without verified DS record. Quarantined in resolver sandbox.'
  },
  {
    id: 'geo-7',
    ip: '177.12.189.44',
    domain: 'example.com',
    city: 'São Paulo',
    country: 'Brazil',
    countryCode: 'BR',
    lat: -23.5505,
    lng: -46.6333,
    asn: 'AS28573',
    organization: 'Claro Brasil Transit',
    subnet: '177.12.189.0/24',
    vector: 'BGP / Subnet Drift',
    severity: 'MEDIUM',
    anomalyScore: 64,
    jaccardSimilarity: 0.67,
    observedAt: '36m ago',
    mitigation: 'Anycast latency variation across Latin America gateway. Monitor baseline TTL decay.'
  },
  {
    id: 'geo-8',
    ip: '103.4.96.15',
    domain: 'one.one.one.one',
    city: 'Singapore',
    country: 'Singapore',
    countryCode: 'SG',
    lat: 1.3521,
    lng: 103.8198,
    asn: 'AS45432',
    organization: 'Equinix Asia-Pacific',
    subnet: '103.4.96.0/24',
    vector: 'Cache Poisoning',
    severity: 'HIGH',
    anomalyScore: 82,
    jaccardSimilarity: 0.2,
    observedAt: '41m ago',
    mitigation: 'Anomalous DoH upstream hop observed. Validate Cloudflare 1.1.1.1 Anycast BGP route.'
  },
  {
    id: 'geo-9',
    ip: '192.168.1.1',
    domain: 'portal.internal.corp',
    city: 'San Francisco, CA',
    country: 'United States',
    countryCode: 'US',
    lat: 37.7749,
    lng: -122.4194,
    asn: 'RFC 1918',
    organization: 'Private Intranet Subnet',
    subnet: '192.168.1.0/24',
    vector: 'DNS Rebinding',
    severity: 'CRITICAL',
    anomalyScore: 98,
    jaccardSimilarity: 0.0,
    observedAt: '48m ago',
    mitigation: 'URGENT: RFC 1918 Private IP returned for external zone. Isolate internal browser host & apply DNS rebinding protection.'
  },
  {
    id: 'geo-10',
    ip: '133.242.18.99',
    domain: 'bankofamerica.com',
    city: 'Tokyo',
    country: 'Japan',
    countryCode: 'JP',
    lat: 35.6762,
    lng: 139.6503,
    asn: 'AS9370',
    organization: 'Sakura Internet Japan',
    subnet: '133.242.0.0/16',
    vector: 'Cache Poisoning',
    severity: 'HIGH',
    anomalyScore: 76,
    jaccardSimilarity: 0.4,
    observedAt: '54m ago',
    mitigation: 'Unregistered offshore IP injected into recursive query response. Signature check failed.'
  }
];

interface GeographicHeatmapProps {
  jaccardThreshold: number;
  anomalySensitivity: number;
}

export function GeographicHeatmap({ jaccardThreshold, anomalySensitivity }: GeographicHeatmapProps) {
  const [selectedIncident, setSelectedIncident] = useState<GeoAnomalyIncident | null>(GEO_ANOMALY_DATA[0]);
  const [selectedVector, setSelectedVector] = useState<string>('ALL');
  const [viewMode, setViewMode] = useState<'heat' | 'pins'>('heat');
  const [selectedRegion, setSelectedRegion] = useState<'GLOBAL' | 'NA' | 'EU' | 'APAC'>('GLOBAL');

  // Filtered incidents
  const filteredIncidents = useMemo(() => {
    return GEO_ANOMALY_DATA.filter((item) => {
      if (selectedVector !== 'ALL' && item.vector !== selectedVector) return false;
      if (selectedRegion === 'NA' && item.countryCode !== 'US' && item.countryCode !== 'CA') return false;
      if (selectedRegion === 'EU' && !['DE', 'RU', 'RO', 'GB'].includes(item.countryCode)) return false;
      if (selectedRegion === 'APAC' && !['HK', 'SG', 'JP'].includes(item.countryCode)) return false;
      return true;
    });
  }, [selectedVector, selectedRegion]);

  // Map coordinate projection helper: Equirectangular projection
  // Coordinates in SVG viewBox: 0 0 900 450
  const projectCoords = (lat: number, lng: number) => {
    const x = ((lng + 180) / 360) * 900;
    const y = ((90 - lat) / 180) * 450;
    return { x, y };
  };

  // Check if an incident triggers alert under user configured thresholds
  const isTriggeredBySettings = (incident: GeoAnomalyIncident) => {
    return incident.jaccardSimilarity < jaccardThreshold || incident.anomalyScore >= anomalySensitivity;
  };

  const triggeredCount = useMemo(() => {
    return filteredIncidents.filter(isTriggeredBySettings).length;
  }, [filteredIncidents, jaccardThreshold, anomalySensitivity]);

  return (
    <div className="bg-white rounded-xl border border-slate-200/90 shadow-xs overflow-hidden">
      {/* Top Header of the Component */}
      <div className="p-5 border-b border-slate-200/80 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="h-8 w-8 rounded-lg bg-rose-50 text-rose-600 flex items-center justify-center border border-rose-200">
              <Flame className="h-4 w-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <span>Geographic Spoofing & Anomaly Heatmap</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800">
                  IP Origin Localization
                </span>
              </h2>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Spatial distribution of rogue resolver nodes, spoofed IP injection sources, and DNS cache poisoning origins
              </p>
            </div>
          </div>
        </div>

        {/* Controls & Filter Bar */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Mode Switch: Heatmap vs Pinpoints */}
          <div className="bg-slate-100 p-0.5 rounded-lg border border-slate-200 flex items-center text-[11px] font-semibold text-slate-600">
            <button
              onClick={() => setViewMode('heat')}
              className={`px-2.5 py-1 rounded-md transition-all flex items-center gap-1.5 ${
                viewMode === 'heat' ? 'bg-white text-slate-900 shadow-xs' : 'hover:text-slate-900'
              }`}
            >
              <Flame className="h-3 w-3 text-rose-500" />
              <span>Heatmap Gradient</span>
            </button>
            <button
              onClick={() => setViewMode('pins')}
              className={`px-2.5 py-1 rounded-md transition-all flex items-center gap-1.5 ${
                viewMode === 'pins' ? 'bg-white text-slate-900 shadow-xs' : 'hover:text-slate-900'
              }`}
            >
              <Crosshair className="h-3 w-3 text-blue-500" />
              <span>Target Pins</span>
            </button>
          </div>

          {/* Region Filter */}
          <div className="flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-[11px] font-semibold text-slate-600">
            {(['GLOBAL', 'NA', 'EU', 'APAC'] as const).map((r) => (
              <button
                key={r}
                onClick={() => setSelectedRegion(r)}
                className={`px-2 py-1 rounded-md transition-all ${
                  selectedRegion === r ? 'bg-white text-slate-900 shadow-xs' : 'hover:text-slate-900'
                }`}
              >
                {r}
              </button>
            ))}
          </div>

          {/* Vector Filter Dropdown */}
          <select
            value={selectedVector}
            onChange={(e) => setSelectedVector(e.target.value)}
            className="bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1 text-[11px] font-semibold text-slate-700 focus:outline-none focus:ring-1 focus:ring-blue-500"
          >
            <option value="ALL">All Attack Vectors ({GEO_ANOMALY_DATA.length})</option>
            <option value="Cache Poisoning">Cache Poisoning</option>
            <option value="DNS Rebinding">DNS Rebinding</option>
            <option value="DNSSEC Strip / NS Hijack">DNSSEC Strip / NS Hijack</option>
            <option value="BGP / Subnet Drift">BGP / Subnet Drift</option>
            <option value="NXDOMAIN Blackhole">NXDOMAIN Blackhole</option>
          </select>
        </div>
      </div>

      {/* Threshold Status Bar showing live reactive impact */}
      <div className="bg-slate-900 text-slate-300 px-5 py-2.5 text-xs flex flex-wrap items-center justify-between gap-3 border-b border-slate-800">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse"></span>
            <span className="font-medium text-slate-200">Active Alert Criteria:</span>
          </div>
          <span className="text-[11px] font-mono text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
            Jaccard Threshold: <strong className="text-cyan-400">{(jaccardThreshold * 100).toFixed(0)}%</strong>
          </span>
          <span className="text-[11px] font-mono text-slate-300 bg-slate-800 px-2 py-0.5 rounded border border-slate-700">
            Anomaly Sensitivity: <strong className="text-amber-400">{anomalySensitivity}</strong>
          </span>
        </div>

        <div className="flex items-center gap-3 text-[11px]">
          <span className="text-slate-400">
            Triggered Threat Hotspots: <strong className="text-rose-400 font-mono text-xs">{triggeredCount}</strong> / {filteredIncidents.length}
          </span>
          <span className="h-3 w-px bg-slate-700"></span>
          <span className="text-emerald-400 flex items-center gap-1">
            <CheckCircle2 className="h-3 w-3" />
            <span>Telemetry Synced</span>
          </span>
        </div>
      </div>

      {/* Main Map Viewport & Threat Inspector Split Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-0 border-b border-slate-200">
        {/* World Map SVG Projection Area (8 cols) */}
        <div className="lg:col-span-8 bg-[#0b101d] relative p-4 flex flex-col justify-center min-h-[420px] select-none overflow-hidden">
          {/* Subtle Coordinate Grid Labels */}
          <div className="absolute top-2 left-3 text-[9px] font-mono text-slate-500 tracking-wider">
            GRID: 15°N 45°E • ROBINSON/CYLINDRICAL PROJECTION • ORIGIN TELEMETRY
          </div>
          <div className="absolute bottom-2 left-3 text-[9px] font-mono text-slate-500">
            RESOLVERGUARD GEOLOCATION SENSOR CLUSTERS (ACTIVE)
          </div>

          <svg
            className="w-full h-full max-h-[380px]"
            viewBox="0 0 900 450"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <defs>
              {/* Radial Gradients for Heatmap Plumes */}
              <radialGradient id="heat-critical" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#ef4444" stopOpacity="0.85" />
                <stop offset="35%" stopColor="#f43f5e" stopOpacity="0.55" />
                <stop offset="70%" stopColor="#f59e0b" stopOpacity="0.25" />
                <stop offset="100%" stopColor="#ef4444" stopOpacity="0" />
              </radialGradient>
              <radialGradient id="heat-high" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.85" />
                <stop offset="45%" stopColor="#eab308" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#f59e0b" stopOpacity="0" />
              </radialGradient>
              <radialGradient id="heat-medium" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.75" />
                <stop offset="50%" stopColor="#3b82f6" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#06b6d4" stopOpacity="0" />
              </radialGradient>

              {/* Map Canvas Background Grid Pattern */}
              <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                <path d="M 30 0 L 0 0 0 30" fill="none" stroke="#17223b" strokeWidth="0.5" strokeOpacity="0.6" />
              </pattern>
            </defs>

            {/* Grid Pattern Background */}
            <rect width="900" height="450" fill="url(#grid)" />

            {/* Equator & Prime Meridian Grid Lines */}
            <line x1="0" y1="225" x2="900" y2="225" stroke="#1f2d4f" strokeWidth="0.8" strokeDasharray="3 3" />
            <line x1="450" y1="0" x2="450" y2="450" stroke="#1f2d4f" strokeWidth="0.8" strokeDasharray="3 3" />
            <line x1="0" y1="150" x2="900" y2="150" stroke="#17223b" strokeWidth="0.5" strokeDasharray="2 4" />
            <line x1="0" y1="300" x2="900" y2="300" stroke="#17223b" strokeWidth="0.5" strokeDasharray="2 4" />

            {/* World Continents Vector Outlines (Clean, Dark Tactical Style) */}
            <g fill="#162035" stroke="#253556" strokeWidth="0.8" strokeLinejoin="round" opacity="0.95">
              {/* North America */}
              <path d="M120 70 L260 70 L280 110 L250 140 L210 160 L180 190 L160 210 L140 180 L110 140 L80 110 L100 80 Z" />
              {/* Greenland */}
              <path d="M300 45 L360 45 L350 75 L310 75 Z" />
              {/* South America */}
              <path d="M220 230 L270 230 L310 270 L290 340 L260 380 L230 350 L220 280 Z" />
              {/* Europe */}
              <path d="M420 80 L510 80 L520 120 L480 150 L430 145 L410 110 Z" />
              {/* Africa */}
              <path d="M420 160 L510 160 L540 230 L520 310 L470 340 L440 280 L410 220 Z" />
              {/* Asia & Russia */}
              <path d="M510 65 L760 65 L780 120 L740 170 L680 180 L620 210 L540 160 L520 110 Z" />
              {/* India */}
              <path d="M600 180 L650 180 L630 240 L590 210 Z" />
              {/* Japan & East Asia Islands */}
              <path d="M780 130 L805 130 L795 160 L775 160 Z" />
              {/* Southeast Asia Islands */}
              <path d="M680 230 L740 230 L730 270 L670 260 Z" />
              {/* Australia */}
              <path d="M700 290 L790 290 L810 350 L740 370 L690 340 Z" />
            </g>

            {/* Subnet Route / Drift Attack Vectors (Connecting Lines from Origin to Target Domain Hub) */}
            <g stroke="#f43f5e" strokeWidth="1" strokeDasharray="3 3" opacity="0.4">
              {filteredIncidents.slice(0, 5).map((inc) => {
                const pt = projectCoords(inc.lat, inc.lng);
                return (
                  <path
                    key={`line-${inc.id}`}
                    d={`M ${pt.x} ${pt.y} Q ${(pt.x + 450) / 2} ${(pt.y + 200) / 2 - 30} 450 200`}
                    fill="none"
                  />
                );
              })}
            </g>

            {/* Central Monitored Core Hub */}
            <circle cx="450" cy="200" r="4" fill="#38bdf8" />
            <circle cx="450" cy="200" r="10" fill="none" stroke="#38bdf8" strokeWidth="0.8" opacity="0.4" />

            {/* HEATMAP LAYER (When in 'heat' mode) */}
            {viewMode === 'heat' && (
              <g className="heatmap-clouds transition-opacity duration-300">
                {filteredIncidents.map((incident) => {
                  const { x, y } = projectCoords(incident.lat, incident.lng);
                  const isTriggered = isTriggeredBySettings(incident);
                  const radius = incident.severity === 'CRITICAL' ? 38 : incident.severity === 'HIGH' ? 28 : 20;
                  const gradId = incident.severity === 'CRITICAL' ? 'heat-critical' : incident.severity === 'HIGH' ? 'heat-high' : 'heat-medium';

                  return (
                    <g key={`heat-${incident.id}`} opacity={isTriggered ? 0.9 : 0.35}>
                      <circle cx={x} cy={y} r={radius} fill={`url(#${gradId})`} />
                    </g>
                  );
                })}
              </g>
            )}

            {/* PINS & INTERACTIVE NODES */}
            <g className="nodes">
              {filteredIncidents.map((incident) => {
                const { x, y } = projectCoords(incident.lat, incident.lng);
                const isSelected = selectedIncident?.id === incident.id;
                const isTriggered = isTriggeredBySettings(incident);

                const pinColor = incident.severity === 'CRITICAL'
                  ? '#ef4444'
                  : incident.severity === 'HIGH'
                    ? '#f59e0b'
                    : '#06b6d4';

                return (
                  <g
                    key={`node-${incident.id}`}
                    className="cursor-pointer group"
                    onClick={() => setSelectedIncident(incident)}
                  >
                    {/* Pulsing Alert Ring for Triggered Threats */}
                    {isTriggered && (
                      <circle
                        cx={x}
                        cy={y}
                        r={isSelected ? 16 : 10}
                        fill="none"
                        stroke={pinColor}
                        strokeWidth="1.5"
                        opacity="0.75"
                        className="animate-ping"
                        style={{ transformOrigin: `${x}px ${y}px`, animationDuration: '2.5s' }}
                      />
                    )}

                    {/* Outer Glow Circle */}
                    <circle
                      cx={x}
                      cy={y}
                      r={isSelected ? 9 : 6}
                      fill={pinColor}
                      fillOpacity={isSelected ? 0.4 : 0.2}
                      stroke={pinColor}
                      strokeWidth={isSelected ? 2 : 1}
                    />

                    {/* Core Solid Pin */}
                    <circle
                      cx={x}
                      cy={y}
                      r={isSelected ? 4.5 : 3}
                      fill={pinColor}
                      className="transition-transform duration-200 group-hover:scale-125"
                      style={{ transformOrigin: `${x}px ${y}px` }}
                    />

                    {/* Label Badge on Hover or when Selected */}
                    {(isSelected || viewMode === 'pins') && (
                      <g>
                        <rect
                          x={x + 8}
                          y={y - 12}
                          width={incident.ip.length * 6.5 + 45}
                          height="20"
                          rx="4"
                          fill="#0f172a"
                          stroke={isSelected ? pinColor : '#334155'}
                          strokeWidth="1"
                          opacity="0.95"
                        />
                        <text
                          x={x + 13}
                          y={y + 1}
                          fill="#ffffff"
                          fontSize="9"
                          fontFamily="monospace"
                          fontWeight="bold"
                        >
                          {incident.ip}
                        </text>
                        <text
                          x={x + incident.ip.length * 6.5 + 18}
                          y={y + 1}
                          fill={pinColor}
                          fontSize="8"
                          fontWeight="bold"
                        >
                          {incident.anomalyScore}
                        </text>
                      </g>
                    )}
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Bottom Left Legend */}
          <div className="absolute bottom-3 right-3 bg-[#0d1424]/90 backdrop-blur-xs border border-slate-800 rounded-lg p-2.5 flex items-center gap-4 text-[10px] text-slate-300">
            <span className="font-semibold text-slate-400">Severity:</span>
            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-rose-500"></span>
              <span>Critical Spoof ({filteredIncidents.filter((i) => i.severity === 'CRITICAL').length})</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-amber-500"></span>
              <span>High Drift ({filteredIncidents.filter((i) => i.severity === 'HIGH').length})</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="h-2.5 w-2.5 rounded-full bg-cyan-400"></span>
              <span>Medium ({filteredIncidents.filter((i) => i.severity === 'MEDIUM').length})</span>
            </div>
          </div>
        </div>

        {/* Selected Incident Telemetry & Deep-Inspection Card (4 cols) */}
        <div className="lg:col-span-4 bg-slate-50/70 p-5 flex flex-col justify-between border-t lg:border-t-0 lg:border-l border-slate-200">
          {selectedIncident ? (
            <div className="space-y-4">
              <div className="flex items-start justify-between">
                <div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    selectedIncident.severity === 'CRITICAL'
                      ? 'bg-rose-100 text-rose-700 border border-rose-200'
                      : selectedIncident.severity === 'HIGH'
                        ? 'bg-amber-100 text-amber-700 border border-amber-200'
                        : 'bg-cyan-100 text-cyan-700 border border-cyan-200'
                  }`}>
                    {selectedIncident.severity} ALERT
                  </span>
                  <h3 className="text-base font-bold text-slate-900 font-mono mt-1.5">
                    {selectedIncident.ip}
                  </h3>
                  <p className="text-xs text-slate-500">
                    {selectedIncident.city}, {selectedIncident.country}
                  </p>
                </div>

                <div className="text-right">
                  <p className="text-[10px] uppercase font-bold text-slate-400">Anomaly Index</p>
                  <p className="text-xl font-bold font-mono text-rose-600 tabular-nums">
                    {selectedIncident.anomalyScore}
                    <span className="text-xs text-slate-400 font-normal">/100</span>
                  </p>
                </div>
              </div>

              {/* Threshold Trigger Status */}
              <div className={`p-2.5 rounded-lg text-xs flex items-center justify-between ${
                isTriggeredBySettings(selectedIncident)
                  ? 'bg-rose-50 border border-rose-200 text-rose-800'
                  : 'bg-emerald-50 border border-emerald-200 text-emerald-800'
              }`}>
                <span className="font-semibold flex items-center gap-1.5">
                  {isTriggeredBySettings(selectedIncident) ? (
                    <>
                      <ShieldAlert className="h-3.5 w-3.5 text-rose-600" />
                      <span>Alert Triggered by Sensitivity</span>
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                      <span>Suppressed by Permissive Threshold</span>
                    </>
                  )}
                </span>
                <span className="font-mono text-[11px] font-bold">
                  Jaccard: {selectedIncident.jaccardSimilarity.toFixed(2)}
                </span>
              </div>

              {/* Incident Details Grid */}
              <div className="bg-white rounded-lg border border-slate-200 p-3 space-y-2 text-xs">
                <div className="flex justify-between items-center py-0.5 border-b border-slate-100">
                  <span className="text-slate-500">Target FQDN:</span>
                  <span className="font-bold text-slate-900 font-mono">{selectedIncident.domain}</span>
                </div>
                <div className="flex justify-between items-center py-0.5 border-b border-slate-100">
                  <span className="text-slate-500">Attack Vector:</span>
                  <span className="font-semibold text-slate-800">{selectedIncident.vector}</span>
                </div>
                <div className="flex justify-between items-center py-0.5 border-b border-slate-100">
                  <span className="text-slate-500">Origin ASN:</span>
                  <span className="font-mono text-slate-700">{selectedIncident.asn} ({selectedIncident.organization})</span>
                </div>
                <div className="flex justify-between items-center py-0.5 border-b border-slate-100">
                  <span className="text-slate-500">Subnet Block:</span>
                  <span className="font-mono text-slate-700">{selectedIncident.subnet}</span>
                </div>
                <div className="flex justify-between items-center py-0.5">
                  <span className="text-slate-500">Coordinates:</span>
                  <span className="font-mono text-slate-600 tabular-nums">
                    {selectedIncident.lat.toFixed(4)}°N, {selectedIncident.lng.toFixed(4)}°E
                  </span>
                </div>
              </div>

              {/* Recommended Mitigation Playbook */}
              <div className="p-3 bg-slate-900 text-slate-200 rounded-lg space-y-1.5 text-xs">
                <div className="flex items-center gap-1.5 text-rose-400 font-bold text-[11px] uppercase tracking-wider">
                  <Shield className="h-3 w-3" />
                  <span>Recommended SecOps Playbook</span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-300 font-mono bg-slate-950/70 p-2 rounded border border-slate-800 select-all">
                  {selectedIncident.mitigation}
                </p>
              </div>
            </div>
          ) : (
            <div className="py-16 text-center text-slate-400">
              <Crosshair className="h-8 w-8 mx-auto mb-2 text-slate-300" />
              <p className="text-xs font-semibold">Click any threat node on the map</p>
              <p className="text-[11px] mt-0.5">Inspect ASN origin, subnet drift, and attack mitigation</p>
            </div>
          )}

          {/* Quick Stat Footer */}
          <div className="pt-3 border-t border-slate-200 flex items-center justify-between text-[11px] text-slate-500">
            <span>Last Scanned: Just now</span>
            <span className="font-mono font-bold text-slate-700">10 Global Nodes Monitored</span>
          </div>
        </div>
      </div>

      {/* Bottom Hub Table: Top 5 Origin Hotspots */}
      <div className="p-4 bg-slate-50/50 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-2 text-slate-600 font-medium">
          <Globe2 className="h-4 w-4 text-slate-400" />
          <span>Top Attack Origin Hubs:</span>
          <span className="text-slate-800 font-semibold">Frankfurt (DE), Moscow (RU), Hong Kong (HK), Bucharest (RO), Ashburn (US)</span>
        </div>

        <div className="flex items-center gap-3 font-mono text-[11px] text-slate-500">
          <span>Global Latency Delta: +142ms</span>
          <span>•</span>
          <span>BGP Drift Variance: 28.4%</span>
        </div>
      </div>
    </div>
  );
}
