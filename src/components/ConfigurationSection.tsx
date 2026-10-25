/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Sliders,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Check,
  RotateCcw,
  AlertTriangle,
  Zap,
  Info,
  Server,
  Lock,
  Globe2,
  Terminal,
  Layers,
  ArrowRight
} from 'lucide-react';

export interface AlertConfiguration {
  jaccardThreshold: number; // 0.10 - 1.00 (default 0.80)
  anomalySensitivity: number; // 10 - 100 (default 70)
  strictDnssec: boolean; // default true
  rfc1918ZeroTolerance: boolean; // default true
  latencyToleranceMs: number; // default 300
}

interface ConfigurationSectionProps {
  config: AlertConfiguration;
  onChangeConfig: (newConfig: AlertConfiguration) => void;
  onResetDefaults: () => void;
}

export function ConfigurationSection({
  config,
  onChangeConfig,
  onResetDefaults
}: ConfigurationSectionProps) {
  const [copiedPreset, setCopiedPreset] = useState<string | null>(null);

  // Sample interactive tester state inside settings
  const [testBaselineIps, setTestBaselineIps] = useState('171.159.228.150, 171.161.148.150');
  const [testObservedIps, setTestObservedIps] = useState('171.159.228.150, 185.220.101.5');

  // Compute live test Jaccard
  const calculateTestJaccard = () => {
    const bSet = new Set(testBaselineIps.split(',').map((s) => s.trim()).filter(Boolean));
    const oSet = new Set(testObservedIps.split(',').map((s) => s.trim()).filter(Boolean));
    const union = new Set([...bSet, ...oSet]);
    if (union.size === 0) return 1.0;
    let intersection = 0;
    for (const ip of bSet) {
      if (oSet.has(ip)) intersection++;
    }
    return Math.round((intersection / union.size) * 100) / 100;
  };

  const testJaccard = calculateTestJaccard();
  const testTriggersAlert = testJaccard < config.jaccardThreshold;

  // Preset Handlers
  const applyPreset = (presetName: string, preset: AlertConfiguration) => {
    onChangeConfig(preset);
    setCopiedPreset(presetName);
    setTimeout(() => setCopiedPreset(null), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="h-9 w-9 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center border border-blue-200">
              <Sliders className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                Detection Heuristics & Alert Configuration
              </h1>
              <p className="text-xs text-slate-500 mt-0.5">
                Tune mathematical similarity boundaries and composite anomaly sensitivity for automated threat detection
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={onResetDefaults}
            className="px-3.5 py-2 rounded-lg border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <RotateCcw className="h-3.5 w-3.5 text-slate-500" />
            <span>Reset to Standard Defaults</span>
          </button>
        </div>
      </div>

      {/* Preset Profiles Card */}
      <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <Zap className="h-3.5 w-3.5 text-amber-500" />
            <span>Security Sensitivity Presets</span>
          </h2>
          {copiedPreset && (
            <span className="text-xs font-bold text-emerald-600 flex items-center gap-1">
              <Check className="h-3.5 w-3.5" />
              <span>Applied "{copiedPreset}" preset!</span>
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Preset 1: Strict Zero-Trust */}
          <div
            onClick={() =>
              applyPreset('Strict Zero-Trust', {
                jaccardThreshold: 0.95,
                anomalySensitivity: 45,
                strictDnssec: true,
                rfc1918ZeroTolerance: true,
                latencyToleranceMs: 150
              })
            }
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              config.jaccardThreshold >= 0.9 && config.anomalySensitivity <= 50
                ? 'border-blue-600 bg-blue-50/40 ring-2 ring-blue-500/20'
                : 'border-slate-200 bg-slate-50/40 hover:border-slate-300 hover:bg-slate-50'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slate-900">Strict Zero-Trust</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-700">
                Paranoid
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mb-3">
              Ideal for high-security financial institutions, defense gateways, and cryptographic critical endpoints.
            </p>
            <div className="text-[10px] font-mono text-slate-600 space-y-1">
              <div>Jaccard Threshold: <strong className="text-slate-900">95%</strong></div>
              <div>Anomaly Sensitivity: <strong className="text-slate-900">45/100</strong></div>
              <div>DNSSEC Enforcement: <strong className="text-emerald-700">STRICT</strong></div>
            </div>
          </div>

          {/* Preset 2: Balanced Enterprise */}
          <div
            onClick={() =>
              applyPreset('Balanced Enterprise', {
                jaccardThreshold: 0.8,
                anomalySensitivity: 70,
                strictDnssec: true,
                rfc1918ZeroTolerance: true,
                latencyToleranceMs: 300
              })
            }
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              config.jaccardThreshold === 0.8 && config.anomalySensitivity === 70
                ? 'border-blue-600 bg-blue-50/40 ring-2 ring-blue-500/20'
                : 'border-slate-200 bg-slate-50/40 hover:border-slate-300 hover:bg-slate-50'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slate-900">Balanced Enterprise</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-700">
                Recommended
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mb-3">
              Standard SecOps configuration. Allows minor edge rotation while catching spoofing and cache poisoning.
            </p>
            <div className="text-[10px] font-mono text-slate-600 space-y-1">
              <div>Jaccard Threshold: <strong className="text-slate-900">80%</strong></div>
              <div>Anomaly Sensitivity: <strong className="text-slate-900">70/100</strong></div>
              <div>DNSSEC Enforcement: <strong className="text-emerald-700">STRICT</strong></div>
            </div>
          </div>

          {/* Preset 3: Permissive CDN Tolerant */}
          <div
            onClick={() =>
              applyPreset('Permissive CDN', {
                jaccardThreshold: 0.5,
                anomalySensitivity: 85,
                strictDnssec: false,
                rfc1918ZeroTolerance: true,
                latencyToleranceMs: 500
              })
            }
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              config.jaccardThreshold <= 0.6 && config.anomalySensitivity >= 80
                ? 'border-blue-600 bg-blue-50/40 ring-2 ring-blue-500/20'
                : 'border-slate-200 bg-slate-50/40 hover:border-slate-300 hover:bg-slate-50'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold text-slate-900">Permissive CDN-Tolerant</span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-200 text-slate-700">
                Multi-Cloud
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mb-3">
              Tolerates frequent Anycast IP pool rotations, Akamai/Fastly CDN drift, and global geo-DNS fluctuations.
            </p>
            <div className="text-[10px] font-mono text-slate-600 space-y-1">
              <div>Jaccard Threshold: <strong className="text-slate-900">50%</strong></div>
              <div>Anomaly Sensitivity: <strong className="text-slate-900">85/100</strong></div>
              <div>DNSSEC Enforcement: <strong className="text-slate-500">OPTIONAL</strong></div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Sliders Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* SLIDER 1: Jaccard Similarity Threshold */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <span>Jaccard Similarity Threshold (J_threshold)</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Minimum intersection-over-union coefficient required between baseline IPs and observed IPs
                </p>
              </div>
              <div className="text-right">
                <span className="text-2xl font-bold font-mono text-blue-600 tabular-nums">
                  {(config.jaccardThreshold * 100).toFixed(0)}%
                </span>
                <p className="text-[10px] text-slate-400 font-mono">
                  {config.jaccardThreshold.toFixed(2)} / 1.00
                </p>
              </div>
            </div>

            {/* Slider Track */}
            <div className="space-y-2 pt-2">
              <input
                type="range"
                min="0.10"
                max="1.00"
                step="0.05"
                value={config.jaccardThreshold}
                onChange={(e) =>
                  onChangeConfig({
                    ...config,
                    jaccardThreshold: parseFloat(e.target.value)
                  })
                }
                className="w-full h-2.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
              />
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>0.10 (Permissive)</span>
                <span>0.50</span>
                <span className="text-blue-600 font-bold">0.80 (Default)</span>
                <span>1.00 (Exact Match)</span>
              </div>
            </div>

            {/* Explanatory Rule Callout */}
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1.5">
              <p className="font-semibold text-slate-800 flex items-center gap-1.5">
                <Info className="h-3.5 w-3.5 text-blue-500" />
                <span>Detection Formula & Logic:</span>
              </p>
              <p className="font-mono text-[11px] text-slate-700 bg-white p-2 rounded border border-slate-200">
                J(A, B) = |A ∩ B| / |A ∪ B|
              </p>
              <p className="text-[11px] leading-relaxed">
                If the calculated Jaccard index between observed resolver records and the registered baseline falls below{' '}
                <strong className="text-blue-700 font-mono">{config.jaccardThreshold.toFixed(2)}</strong>, an alert
                state is immediately raised. Zero overlap (J = 0.0) is treated as a Critical Discrepancy.
              </p>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
            <span>Affects: Live Monitor, Change Detection, Audit Logs</span>
            <span className="font-semibold text-slate-700">Instant Reactive Sync</span>
          </div>
        </div>

        {/* SLIDER 2: Anomaly Score Sensitivity */}
        <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs flex flex-col justify-between">
          <div className="space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <span>Anomaly Score Alert Sensitivity</span>
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  Threshold at which multi-vector heuristic risk elevates to High/Critical incident severity
                </p>
              </div>
              <div className="text-right">
                <span className="text-2xl font-bold font-mono text-rose-600 tabular-nums">
                  {config.anomalySensitivity}
                </span>
                <p className="text-[10px] text-slate-400 font-mono">scale: 10 - 100</p>
              </div>
            </div>

            {/* Slider Track */}
            <div className="space-y-2 pt-2">
              <input
                type="range"
                min="10"
                max="95"
                step="5"
                value={config.anomalySensitivity}
                onChange={(e) =>
                  onChangeConfig({
                    ...config,
                    anomalySensitivity: parseInt(e.target.value, 10)
                  })
                }
                className="w-full h-2.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-rose-600 focus:outline-none focus:ring-2 focus:ring-rose-500/20"
              />
              <div className="flex justify-between text-[10px] font-mono text-slate-400">
                <span>10 (Aggressive Alerts)</span>
                <span>40</span>
                <span className="text-rose-600 font-bold">70 (Default)</span>
                <span>95 (Critical Only)</span>
              </div>
            </div>

            {/* Explanatory Rule Callout */}
            <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1.5">
              <p className="font-semibold text-slate-800 flex items-center gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5 text-rose-500" />
                <span>Multi-Vector Composite Weighting:</span>
              </p>
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div className="bg-white p-1.5 rounded border border-slate-200">
                  <span className="text-slate-500">Jaccard Drift:</span> <span className="font-bold">40% weight</span>
                </div>
                <div className="bg-white p-1.5 rounded border border-slate-200">
                  <span className="text-slate-500">RFC 1918 Private:</span> <span className="font-bold">30% weight</span>
                </div>
                <div className="bg-white p-1.5 rounded border border-slate-200">
                  <span className="text-slate-500">DNSSEC Absence:</span> <span className="font-bold">20% weight</span>
                </div>
                <div className="bg-white p-1.5 rounded border border-slate-200">
                  <span className="text-slate-500">Latency Deviation:</span> <span className="font-bold">10% weight</span>
                </div>
              </div>
              <p className="text-[11px] leading-relaxed">
                Incidents scoring <strong className="text-rose-700 font-mono">≥ {config.anomalySensitivity}</strong> trigger
                automated high-priority SecOps escalation and appear highlighted on the Geographic Heatmap.
              </p>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500">
            <span>Affects: Threat Badges, Heatmap Highlights, Incident Escalation</span>
            <span className="font-semibold text-slate-700">Real-Time Evaluation</span>
          </div>
        </div>
      </div>

      {/* Auxiliary Security Toggles & Rules */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700">
          Secondary Security Policies & Enforcement
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Toggle 1: RFC 1918 Private IP Zero Tolerance */}
          <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 flex flex-col justify-between">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                  <Server className="h-3.5 w-3.5 text-blue-500" />
                  <span>RFC 1918 Zero-Tolerance</span>
                </span>
                <input
                  type="checkbox"
                  checked={config.rfc1918ZeroTolerance}
                  onChange={(e) =>
                    onChangeConfig({
                      ...config,
                      rfc1918ZeroTolerance: e.target.checked
                    })
                  }
                  className="h-4 w-4 rounded text-blue-600 focus:ring-blue-500 cursor-pointer"
                />
              </div>
              <p className="text-[11px] text-slate-500">
                Instantly elevates any public domain resolving to private IP space (10.x, 172.16-31.x, 192.168.x) to
                CRITICAL DNS Rebinding alert.
              </p>
            </div>
            <span className={`text-[10px] font-bold mt-2 ${config.rfc1918ZeroTolerance ? 'text-emerald-700' : 'text-slate-400'}`}>
              {config.rfc1918ZeroTolerance ? 'ENABLED (Recommended)' : 'DISABLED'}
            </span>
          </div>

          {/* Toggle 2: Strict DNSSEC Enforcement */}
          <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 flex flex-col justify-between">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                  <Lock className="h-3.5 w-3.5 text-emerald-500" />
                  <span>Strict DNSSEC Enforcement</span>
                </span>
                <input
                  type="checkbox"
                  checked={config.strictDnssec}
                  onChange={(e) =>
                    onChangeConfig({
                      ...config,
                      strictDnssec: e.target.checked
                    })
                  }
                  className="h-4 w-4 rounded text-blue-600 focus:ring-blue-500 cursor-pointer"
                />
              </div>
              <p className="text-[11px] text-slate-500">
                Enforces presence of valid RRSIG records (Type 46) and the Authenticated Data (AD) flag for all
                signed domains.
              </p>
            </div>
            <span className={`text-[10px] font-bold mt-2 ${config.strictDnssec ? 'text-emerald-700' : 'text-slate-400'}`}>
              {config.strictDnssec ? 'ENFORCED (RFC 4035)' : 'PERMISSIVE'}
            </span>
          </div>

          {/* Setting 3: Latency Deviation Tolerance */}
          <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 flex flex-col justify-between">
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                  <Globe2 className="h-3.5 w-3.5 text-indigo-500" />
                  <span>Latency Spike Limit</span>
                </span>
                <span className="text-xs font-mono font-bold text-slate-800">
                  {config.latencyToleranceMs} ms
                </span>
              </div>
              <p className="text-[11px] text-slate-500">
                Flag routing anomalies if recursive query resolution latency exceeds baseline average by this buffer.
              </p>
            </div>
            <input
              type="range"
              min="100"
              max="1000"
              step="50"
              value={config.latencyToleranceMs}
              onChange={(e) =>
                onChangeConfig({
                  ...config,
                  latencyToleranceMs: parseInt(e.target.value, 10)
                })
              }
              className="w-full mt-2 h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-indigo-600"
            />
          </div>
        </div>
      </div>

      {/* Interactive Heuristic Simulator / Test Playground */}
      <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs space-y-4">
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <Terminal className="h-4 w-4 text-slate-600" />
            <span>Interactive Heuristics Simulator & Dry-Run</span>
          </h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Test how your adjusted Jaccard threshold and anomaly sensitivity evaluate arbitrary DNS IP record shifts
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-[11px] font-semibold text-slate-600">Sample Baseline IPs</label>
            <input
              type="text"
              value={testBaselineIps}
              onChange={(e) => setTestBaselineIps(e.target.value)}
              className="w-full mt-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-900 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="text-[11px] font-semibold text-slate-600">Sample Observed IPs</label>
            <input
              type="text"
              value={testObservedIps}
              onChange={(e) => setTestObservedIps(e.target.value)}
              className="w-full mt-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-900 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>

        {/* Live Calculation Output */}
        <div className="p-4 rounded-lg bg-slate-900 text-slate-200 flex flex-col sm:flex-row items-center justify-between gap-4 font-mono text-xs">
          <div className="flex items-center gap-6">
            <div>
              <span className="text-[10px] text-slate-400 uppercase">Calculated Jaccard:</span>
              <p className="text-lg font-bold text-cyan-400 tabular-nums">{testJaccard.toFixed(2)}</p>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 uppercase">Active Threshold:</span>
              <p className="text-lg font-bold text-slate-300 tabular-nums">{config.jaccardThreshold.toFixed(2)}</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-2 ${
              testTriggersAlert
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
            }`}>
              {testTriggersAlert ? (
                <>
                  <AlertTriangle className="h-4 w-4 text-rose-400" />
                  <span>ALERT TRIGGERED ({testJaccard.toFixed(2)} &lt; {config.jaccardThreshold.toFixed(2)})</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  <span>ALLOWED WITHIN DRIFT TOLERANCE</span>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
