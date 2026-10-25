"""
ResolverGuard: DNS Integrity Monitoring and Spoofing Detection Workbench
Enterprise DNS Operations, Integrity Audit & Spoofing Heuristics System
app.py - Main Streamlit Cybersecurity Workbench & Operational Dashboard
"""

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from detection_engine import (
    BaselineManager,
    analyze_cross_resolver_consensus,
    analyze_dns_integrity
)
from dns_monitor import (
    PUBLIC_RESOLVERS,
    classify_ip_address,
    cross_resolver_lookup,
    get_reverse_dns,
    resolve_domain,
    validate_domain_name
)
from report_generator import (
    export_alerts_to_csv,
    export_benchmark_to_csv,
    generate_cns_course_report
)
from sample_data import (
    DEMO_SCENARIOS,
    generate_evaluation_dataset,
    run_benchmark_evaluation
)

# Page configuration
st.set_page_config(
    page_title="ResolverGuard - DNS Integrity & Spoofing Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Inject custom cybersecurity dashboard styling
st.markdown("""
<style>
    /* Cybersecurity dark theme accents */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .metric-card {
        background: linear-gradient(135deg, #131b2e 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 10px;
        padding: 16px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .status-badge-match {
        background-color: rgba(16, 185, 129, 0.2);
        color: #10b981;
        border: 1px solid #10b981;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        display: inline-block;
    }
    .status-badge-drift {
        background-color: rgba(245, 158, 11, 0.2);
        color: #f59e0b;
        border: 1px solid #f59e0b;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        display: inline-block;
    }
    .status-badge-crit {
        background-color: rgba(239, 68, 68, 0.2);
        color: #ef4444;
        border: 1px solid #ef4444;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        display: inline-block;
    }
    .status-badge-info {
        background-color: rgba(59, 130, 246, 0.2);
        color: #3b82f6;
        border: 1px solid #3b82f6;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        display: inline-block;
    }
    .cyber-box {
        background: #0f172a;
        border-left: 4px solid #3b82f6;
        padding: 14px;
        border-radius: 0 8px 8px 0;
        margin-bottom: 12px;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Session State
if "baseline_mgr" not in st.session_state:
    st.session_state.baseline_mgr = BaselineManager()

if "audit_history" not in st.session_state:
    st.session_state.audit_history = []

if "benchmark_results" not in st.session_state:
    st.session_state.benchmark_results = None

if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = None

if "last_cross_resolver" not in st.session_state:
    st.session_state.last_cross_resolver = None


# Helper for logging events
def log_audit_event(analysis: Dict[str, Any]):
    st.session_state.last_analysis = analysis
    st.session_state.audit_history.insert(0, analysis)
    # Keep up to 200 items in history
    if len(st.session_state.audit_history) > 200:
        st.session_state.audit_history = st.session_state.audit_history[:200]


# Sidebar Controls
with st.sidebar:
    st.markdown("## 🛡️ **ResolverGuard**")
    st.caption("DNS Integrity & Spoofing Detection Workbench")
    st.markdown("---")

    st.markdown("### ⚙️ **Resolver Configuration**")
    resolver_choice = st.selectbox(
        "Target Recursive Resolver",
        options=list(PUBLIC_RESOLVERS.keys()) + ["Custom Resolver IP"],
        index=0
    )

    if resolver_choice == "Custom Resolver IP":
        custom_resolver = st.text_input("Enter Resolver IPv4", "1.1.1.1")
        active_resolver_ip = custom_resolver.strip()
        active_resolver_label = f"Custom ({custom_resolver})"
    else:
        active_resolver_ip = PUBLIC_RESOLVERS[resolver_choice]
        active_resolver_label = resolver_choice

    timeout_sec = st.slider("Query Timeout (Seconds)", min_value=1.0, max_value=8.0, value=3.0, step=0.5)

    st.markdown("---")
    st.markdown("### 🚀 **Rapid Lab Scenario Trigger**")
    st.info("Execute safe educational DNS scenarios with one click.")

    scenario_keys = list(DEMO_SCENARIOS.keys())
    selected_scenario_key = st.selectbox(
        "Select CNS Scenario",
        options=scenario_keys,
        format_func=lambda k: DEMO_SCENARIOS[k]["title"]
    )

    if st.button("▶ Run Selected Scenario", use_container_width=True, type="primary"):
        scen = DEMO_SCENARIOS[selected_scenario_key]
        domain = scen["domain"]
        trusted_ips = st.session_state.baseline_mgr.get_trusted_ips(domain)

        # Execute analysis against simulated data
        analysis = analyze_dns_integrity(
            domain=domain,
            observed_ips=scen["observed_ips"],
            trusted_ips=trusted_ips,
            resolution_status=scen["status"],
            resolver_name=scen["simulated_resolver"]
        )
        analysis["scenario_title"] = scen["title"]
        analysis["security_concept"] = scen["security_concept"]
        analysis["is_simulated"] = True
        log_audit_event(analysis)
        st.success(f"Executed: {scen['title']}")

    st.markdown("---")
    st.markdown("### 📊 **Course Reference**")
    st.caption("Computer & Network Security")
    st.caption("Modules: DNS Integrity, Cryptographic Baselines, Cache Poisoning Heuristics, RFC 1918 Guard")


# Main Dashboard Header
st.title("🛡️ ResolverGuard: DNS Integrity & Spoofing Workbench")
st.markdown(
    "A continuous security monitoring workbench that cross-references live recursive DNS resolution sets "
    "with verified cryptographically audited baselines, distinguishes benign CDN IP drift from active cache poisoning, "
    "and evaluates multi-resolver consensus."
)

# Top Operational Metrics Cards
baseline_records = st.session_state.baseline_mgr.list_all()
total_baselines = len(baseline_records)
total_events = len(st.session_state.audit_history)
critical_alerts = sum(1 for e in st.session_state.audit_history if e.get("severity") == "CRITICAL")
warning_alerts = sum(1 for e in st.session_state.audit_history if e.get("severity") in ("HIGH", "MEDIUM", "LOW"))
normal_matches = sum(1 for e in st.session_state.audit_history if e.get("verdict") == "MATCH")

integrity_health = 100.0 if total_events == 0 else round((normal_matches / total_events) * 100, 1)

m1, m2, m3, m4, m5 = st.columns(5)
with m1:
    st.metric("Monitored Baselines", total_baselines, delta=f"{total_baselines} active")
with m2:
    st.metric("Total Inspections", total_events, delta="Session log")
with m3:
    st.metric("Critical Alerts", critical_alerts, delta="Requires action" if critical_alerts > 0 else "Clean", delta_color="inverse")
with m4:
    st.metric("Drift / Warnings", warning_alerts, delta="CDN/Subnet variations")
with m5:
    st.metric("Integrity Health Rate", f"{integrity_health}%", delta=f"{normal_matches} verified matches")

st.markdown("---")


# Main Workbench Tabs
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🔍 Live Inspection",
    "🌐 Cross-Resolver Verification",
    "🧪 CNS Lab Scenarios",
    "📋 Baseline Management",
    "📈 Performance Evaluation",
    "📑 Audit Log & Reports"
])


# ==============================================================================
# TAB 1: Live Domain Inspection
# ==============================================================================
with tab1:
    st.subheader("Live DNS Resolution & Baseline Comparison")
    st.markdown(
        "Query any fully qualified domain name (FQDN). ResolverGuard queries the designated recursive resolver, "
        "compares the returned IP set with stored baselines, performs IP classification, and assesses tampering likelihood."
    )

    c_query, c_quick = st.columns([3, 1])
    with c_query:
        domain_input = st.text_input("Target Domain to Inspect", value="example.com", placeholder="e.g., example.com, github.com, bankofamerica.com")
    with c_quick:
        st.write("")
        st.write("")
        inspect_button = st.button("🔎 Run Integrity Check", use_container_width=True, type="primary")

    if inspect_button and domain_input:
        with st.spinner(f"Resolving '{domain_input}' via {active_resolver_label}..."):
            res_result = resolve_domain(
                domain=domain_input,
                resolver_ip=active_resolver_ip if active_resolver_ip else None,
                timeout=timeout_sec,
                record_type="A"
            )

            trusted_ips = st.session_state.baseline_mgr.get_trusted_ips(domain_input)
            analysis = analyze_dns_integrity(
                domain=domain_input,
                observed_ips=res_result["ips"],
                trusted_ips=trusted_ips,
                resolution_status=res_result["status"],
                resolver_name=active_resolver_label,
                error_message=res_result.get("error_message")
            )
            analysis["response_time_ms"] = res_result["response_time_ms"]
            analysis["canonical_name"] = res_result.get("canonical_name")
            analysis["is_simulated"] = False
            log_audit_event(analysis)

    # Display Last Analysis Result
    if st.session_state.last_analysis:
        curr = st.session_state.last_analysis
        st.markdown("### 📋 **Latest Inspection Assessment**")

        verdict = curr.get("verdict", "UNKNOWN")
        severity = curr.get("severity", "INFO")
        jaccard = curr.get("jaccard_similarity", 0.0)
        anomaly_score = curr.get("anomaly_score", 0.0)

        # Verdict Header Card
        if verdict == "MATCH":
            badge_html = f"<span class='status-badge-match'>VERIFIED INTEGRITY: {verdict}</span>"
        elif verdict in ("CDN_DRIFT", "DRIFT"):
            badge_html = f"<span class='status-badge-drift'>RECORD DRIFT: {verdict}</span>"
        elif verdict in ("SUSPICIOUS_DISCREPANCY", "CRITICAL_ANOMALY"):
            badge_html = f"<span class='status-badge-crit'>SUSPICIOUS TAMPERING: {verdict}</span>"
        else:
            badge_html = f"<span class='status-badge-info'>NOTICE: {verdict}</span>"

        st.markdown(f"#### Domain: `{curr.get('domain')}` &nbsp; | &nbsp; {badge_html}", unsafe_allow_html=True)

        col_left, col_right = st.columns([1, 1])

        with col_left:
            st.markdown("##### 🔍 Resolution Details")
            st.write(f"**Resolver Used:** `{curr.get('resolver', 'System Default')}`")
            st.write(f"**Timestamp:** `{curr.get('timestamp')}`")
            st.write(f"**Jaccard Similarity Index:** `{jaccard}` (1.0 = Exact Match, 0.0 = Complete Mismatch)")
            st.write(f"**Calculated Anomaly Score:** `{anomaly_score}` / 1.00")
            if curr.get("canonical_name"):
                st.write(f"**CNAME Canonical Name:** `{curr.get('canonical_name')}`")
            if curr.get("response_time_ms"):
                st.write(f"**Response Latency:** `{curr.get('response_time_ms')} ms`")

            # Quick action to add to baseline
            observed_ips = curr.get("observed_ips", [])
            if observed_ips and st.button("➕ Trust & Save Observed IPs to Baseline"):
                st.session_state.baseline_mgr.set_trusted_record(
                    domain=curr.get("domain"),
                    trusted_ips=observed_ips,
                    organization="Captured via Workbench",
                    notes=f"Added on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}"
                )
                st.success(f"Updated baseline for '{curr.get('domain')}'!")
                st.rerun()

        with col_right:
            st.markdown("##### 📊 Set Comparison Matrix")
            b_ips = curr.get("baseline_ips", [])
            o_ips = curr.get("observed_ips", [])

            comp_df = pd.DataFrame([
                {"Record Source": "Trusted Baseline", "IP Addresses": ", ".join(b_ips) if b_ips else "None (Unmonitored)", "Count": len(b_ips)},
                {"Record Source": "Observed Resolution", "IP Addresses": ", ".join(o_ips) if o_ips else "None (Failed/Empty)", "Count": len(o_ips)}
            ])
            st.dataframe(comp_df, use_container_width=True, hide_index=True)

            if curr.get("added_ips"):
                st.warning(f"**Newly Introduced IPs:** `{', '.join(curr.get('added_ips'))}`")
            if curr.get("removed_ips"):
                st.info(f"**Omitted Baseline IPs:** `{', '.join(curr.get('removed_ips'))}`")

        st.markdown("---")
        st.markdown("##### 🧠 Security Diagnostic Reasoning & Guidance")
        st.info(f"**Reasoning:** {curr.get('reason')}")
        st.markdown(f"**Recommended Countermeasure / Action:** {curr.get('recommended_action')}")


# ==============================================================================
# TAB 2: Multi-Resolver Cross-Verification
# ==============================================================================
with tab2:
    st.subheader("Multi-Resolver Consensus & Interception Detector")
    st.markdown(
        "A cornerstone CNS principle: An attacker on your local network or ISP path may forge answers from your "
        "local recursive resolver. Querying geographically distributed public resolvers (Cloudflare, Google, Quad9) "
        "simultaneously exposes localized DNS hijacking, captive portal interception, or censorship."
    )

    c_cross_domain, c_cross_btn = st.columns([3, 1])
    with c_cross_domain:
        cross_domain_input = st.text_input("Domain for Cross-Verification", value="bankofamerica.com")
    with c_cross_btn:
        st.write("")
        st.write("")
        run_cross_btn = st.button("🌐 Query All Resolvers", use_container_width=True, type="primary")

    if run_cross_btn and cross_domain_input:
        with st.spinner("Executing concurrent DNS resolutions across 4 global resolvers..."):
            multi_res = cross_resolver_lookup(
                domain=cross_domain_input,
                resolvers=PUBLIC_RESOLVERS,
                timeout=timeout_sec
            )
            trusted_ips = st.session_state.baseline_mgr.get_trusted_ips(cross_domain_input)
            consensus_eval = analyze_cross_resolver_consensus(
                domain=cross_domain_input,
                multi_results=multi_res,
                baseline_ips=trusted_ips
            )
            st.session_state.last_cross_resolver = {
                "domain": cross_domain_input,
                "multi_res": multi_res,
                "consensus": consensus_eval,
                "baseline_ips": trusted_ips
            }

    if st.session_state.last_cross_resolver:
        cross_data = st.session_state.last_cross_resolver
        multi_res = cross_data["multi_res"]
        consensus = cross_data["consensus"]

        if consensus["consensus"] == "CONSENSUS":
            st.success(f"✅ **Consensus Reached ({consensus['agreement_rate']*100:.0f}% Agreement)**: {consensus['details']}")
        else:
            st.error(f"⚠️ **Conflict Detected ({consensus['agreement_rate']*100:.0f}% Agreement)**: {consensus['details']}")

        # Build comparison table
        table_rows = []
        for r_name, r_val in multi_res.items():
            ips_str = ", ".join(r_val.get("ips", [])) or "None / Error"
            table_rows.append({
                "Resolver Name": r_name,
                "Status": r_val.get("status"),
                "Resolved IP(s)": ips_str,
                "Latency (ms)": r_val.get("response_time_ms", 0.0),
                "Error": r_val.get("error_message") or "None"
            })
        cross_df = pd.DataFrame(table_rows)
        st.dataframe(cross_df, use_container_width=True, hide_index=True)

        # Plot latency chart
        fig_lat = px.bar(
            cross_df,
            x="Resolver Name",
            y="Latency (ms)",
            color="Status",
            title=f"Resolution Latency Across Resolvers for '{cross_data['domain']}'",
            color_discrete_map={"SUCCESS": "#10b981", "NXDOMAIN": "#ef4444", "TIMEOUT": "#f59e0b", "ERROR": "#8b5cf6"}
        )
        fig_lat.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
        st.plotly_chart(fig_lat, use_container_width=True)


# ==============================================================================
# TAB 3: CNS Lab Scenarios (Controlled Demonstration)
# ==============================================================================
with tab3:
    st.subheader("Controlled Educational Demonstrations (CNS Lab Syllabus)")
    st.markdown(
        "These reproducible demonstrations utilize structured mock responses to safely illustrate real-world "
        "DNS threat models without launching actual network attacks or generating malicious traffic."
    )

    selected_demo = st.selectbox(
        "Choose Controlled Scenario to Inspect",
        options=list(DEMO_SCENARIOS.keys()),
        format_func=lambda k: DEMO_SCENARIOS[k]["title"]
    )

    demo_info = DEMO_SCENARIOS[selected_demo]

    col_desc, col_run = st.columns([3, 1])
    with col_desc:
        st.markdown(f"### {demo_info['title']}")
        st.markdown(f"**Target Domain:** `{demo_info['domain']}` &nbsp;|&nbsp; **Category:** `{demo_info['category']}`")
        st.markdown(f"**Threat Description:** {demo_info['description']}")
        st.markdown(f"**Educational Concept:** *{demo_info['security_concept']}*")
    with col_run:
        st.write("")
        st.write("")
        run_demo_button = st.button("🧪 Execute Demonstration", type="primary", use_container_width=True)

    if run_demo_button:
        trusted_ips = st.session_state.baseline_mgr.get_trusted_ips(demo_info["domain"])
        demo_analysis = analyze_dns_integrity(
            domain=demo_info["domain"],
            observed_ips=demo_info["observed_ips"],
            trusted_ips=trusted_ips,
            resolution_status=demo_info["status"],
            resolver_name=demo_info["simulated_resolver"]
        )
        demo_analysis["response_time_ms"] = demo_info["response_time_ms"]
        demo_analysis["scenario_title"] = demo_info["title"]
        demo_analysis["security_concept"] = demo_info["security_concept"]
        demo_analysis["is_simulated"] = True
        log_audit_event(demo_analysis)
        st.rerun()

    st.markdown("---")
    st.markdown("#### 🔬 **Attack Vector Comparison & Lifecycle Flow**")

    st.markdown("""
    | Scenario Name | Simulated Vector | Expected Verdict | Severity | Diagnostic Note |
    | :--- | :--- | :--- | :--- | :--- |
    | **1. Baseline Match** | Normal recursive query | `MATCH` | `INFO` | Observed IPs match cryptographically signed baseline. |
    | **2. Cache Poisoning** | Forged DNS answer injected | `SUSPICIOUS_DISCREPANCY` | `CRITICAL` | Disjoint IP sets; redirects users to malicious rogue host. |
    | **3. Restored Response** | Cache flushed & DNSSEC applied | `MATCH` | `INFO` | Return to verified baseline; illustrates remediation lifecycle. |
    | **4. DNS Rebinding** | Public domain -> RFC 1918 IP | `CRITICAL_ANOMALY` | `CRITICAL` | Public domain resolving to 192.168.1.1 attempts LAN pivot. |
    | **5. NXDOMAIN Hijack** | Forged negative response | `ERROR` | `HIGH` | Blackhole Denial-of-Service or rogue NXDOMAIN redirection. |
    | **6. CDN Anycast Drift** | Edge node round-robin | `CDN_DRIFT` | `LOW` | Benign partial overlap; proves IP changes != spoofing. |
    """)


# ==============================================================================
# TAB 4: Baseline Management
# ==============================================================================
with tab4:
    st.subheader("Cryptographic Baseline Management")
    st.markdown(
        "Manage the trusted repository of domain-to-IP records. Baselines represent known authentic mappings "
        "verified through authoritative nameservers, DNSSEC signatures, or enterprise registry records."
    )

    b_col1, b_col2 = st.columns([2, 1])

    with b_col1:
        st.markdown("##### ➕ Add or Update Domain Baseline Entry")
        with st.form("add_baseline_form"):
            new_domain = st.text_input("Domain Name", placeholder="e.g., portal.mybank.com")
            new_ips = st.text_input("Trusted IPv4 Addresses (Comma-separated)", placeholder="e.g., 93.184.215.14, 93.184.215.15")
            new_org = st.text_input("Organization / Cloud Provider", placeholder="e.g., Akamai Edge, AWS CloudFront")
            new_notes = st.text_area("Operational Notes", placeholder="e.g., Production banking gateway verified on 2026-10-25")
            submit_baseline = st.form_submit_button("💾 Save Baseline Entry", use_container_width=True)

            if submit_baseline:
                is_valid, err = validate_domain_name(new_domain)
                if not is_valid:
                    st.error(f"Invalid domain: {err}")
                elif not new_ips.strip():
                    st.error("Please provide at least one trusted IP address.")
                else:
                    ip_list = [ip.strip() for ip in new_ips.split(",") if ip.strip()]
                    st.session_state.baseline_mgr.set_trusted_record(
                        domain=new_domain,
                        trusted_ips=ip_list,
                        organization=new_org.strip() or "User Configured",
                        notes=new_notes.strip()
                    )
                    st.success(f"Successfully updated baseline for '{new_domain}'!")
                    st.rerun()

    with b_col2:
        st.markdown("##### 📁 Baseline Backup & Operations")
        current_baseline_json = json.dumps(st.session_state.baseline_mgr.list_all(), indent=2)
        st.download_button(
            label="📥 Export Baseline JSON",
            data=current_baseline_json,
            file_name=f"trusted_baseline_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json",
            mime="application/json",
            use_container_width=True
        )

        st.markdown("###### Reset to Default Baselines")
        if st.button("🔄 Reset Baseline to Factory Defaults", use_container_width=True):
            st.session_state.baseline_mgr = BaselineManager()
            st.success("Baselines reset to default curriculum set.")
            st.rerun()

    st.markdown("---")
    st.markdown("##### 📑 Current Monitored Baselines Table")
    all_b = st.session_state.baseline_mgr.list_all()

    if all_b:
        baseline_rows = []
        for d_name, d_val in all_b.items():
            baseline_rows.append({
                "Domain": d_name,
                "Trusted IPs": ", ".join(d_val.get("trusted_ips", [])),
                "IP Count": len(d_val.get("trusted_ips", [])),
                "Organization": d_val.get("organization", "N/A"),
                "Notes": d_val.get("notes", ""),
                "Updated At": d_val.get("updated_at", "N/A")
            })
        base_df = pd.DataFrame(baseline_rows)
        st.dataframe(base_df, use_container_width=True, hide_index=True)

        # Remove domain section
        del_col1, del_col2 = st.columns([3, 1])
        with del_col1:
            del_domain = st.selectbox("Select Domain to Remove from Baseline", options=list(all_b.keys()))
        with del_col2:
            st.write("")
            st.write("")
            if st.button("🗑️ Delete Baseline", use_container_width=True):
                st.session_state.baseline_mgr.remove_record(del_domain)
                st.warning(f"Removed '{del_domain}' from baseline.")
                st.rerun()
    else:
        st.info("No baseline records currently configured.")


# ==============================================================================
# TAB 5: Performance Evaluation Suite
# ==============================================================================
with tab5:
    st.subheader("Performance Evaluation & Detection Heuristics Benchmark")
    st.markdown(
        "In accordance with Seventh Semester CNS evaluation standards, the detection engine is tested against a "
        "labeled ground-truth benchmark dataset comprising Normal traffic, Cache Poisoning, DNS Rebinding, Benign CDN Drift, "
        "and NXDOMAIN blackholing. Processing latencies, Confusion Matrix, Accuracy, Precision, Recall, and F1-Score are computed."
    )

    c_bench_btn, c_bench_seed = st.columns([2, 1])
    with c_bench_seed:
        sample_size = st.slider("Benchmark Sample Size", min_value=20, max_value=100, value=60, step=10)
    with c_bench_btn:
        st.write("")
        st.write("")
        run_benchmark_btn = st.button("🚀 Run Live Benchmark Evaluation", type="primary", use_container_width=True)

    if run_benchmark_btn or st.session_state.benchmark_results is None:
        with st.spinner("Generating reproducible dataset and measuring detection operations..."):
            custom_dataset = generate_evaluation_dataset(n_samples=sample_size, seed=42)
            st.session_state.benchmark_results = run_benchmark_evaluation(custom_dataset)

    bench = st.session_state.benchmark_results
    summ = bench["summary"]

    st.markdown("#### 📊 **Benchmark Results Summary**")
    b1, b2, b3, b4, b5 = st.columns(5)
    with b1:
        st.metric("Accuracy", f"{summ['accuracy'] * 100:.2f}%", delta="Overall correctness")
    with b2:
        st.metric("Precision", f"{summ['precision'] * 100:.2f}%", delta="TP / (TP + FP)")
    with b3:
        st.metric("Recall (Sensitivity)", f"{summ['recall'] * 100:.2f}%", delta="TP / (TP + FN)")
    with b4:
        st.metric("F1-Score", f"{summ['f1_score']:.4f}", delta="Harmonic mean")
    with b5:
        st.metric("Avg Latency", f"{summ['avg_latency_ms']} ms", delta=f"Min: {summ['min_latency_ms']}ms / Max: {summ['max_latency_ms']}ms")

    col_cm, col_bar = st.columns([1, 1])

    with col_cm:
        st.markdown("##### 🧮 Confusion Matrix")
        cm_z = [
            [summ["true_negatives"], summ["false_positives"]],
            [summ["false_negatives"], summ["true_positives"]]
        ]
        cm_text = [
            [f"TN: {summ['true_negatives']}", f"FP: {summ['false_positives']}"],
            [f"FN: {summ['false_negatives']}", f"TP: {summ['true_positives']}"]
        ]
        fig_cm = ff_cm = go.Figure(data=go.Heatmap(
            z=cm_z,
            x=["Predicted: Safe / Drift", "Predicted: Threat / Anomaly"],
            y=["Actual: Safe / Drift", "Actual: Threat / Anomaly"],
            text=cm_text,
            texttemplate="%{text}",
            colorscale="Viridis",
            showscale=False
        ))
        fig_cm.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            margin=dict(l=20, r=20, t=30, b=20)
        )
        st.plotly_chart(fig_cm, use_container_width=True)

    with col_bar:
        st.markdown("##### 📈 Performance Metrics Distribution")
        metrics_df = pd.DataFrame([
            {"Metric": "Accuracy", "Score": summ["accuracy"]},
            {"Metric": "Precision", "Score": summ["precision"]},
            {"Metric": "Recall", "Score": summ["recall"]},
            {"Metric": "F1-Score", "Score": summ["f1_score"]}
        ])
        fig_bar = px.bar(
            metrics_df,
            x="Metric",
            y="Score",
            range_y=[0.0, 1.05],
            color="Metric",
            color_discrete_sequence=["#3b82f6", "#10b981", "#f59e0b", "#8b5cf6"]
        )
        fig_bar.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
        st.plotly_chart(fig_bar, use_container_width=True)

    st.markdown("##### 📋 Labeled Benchmark Evaluation Rows")
    bench_df = pd.DataFrame(bench["rows"])
    st.dataframe(bench_df, use_container_width=True, hide_index=True)

    # Export benchmark CSV
    bench_csv, _ = export_benchmark_to_csv(bench)
    st.download_button(
        label="📥 Export Benchmark Metrics to CSV",
        data=bench_csv,
        file_name=f"resolverguard_benchmark_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        use_container_width=True
    )


# ==============================================================================
# TAB 6: Audit Log & Report Generator
# ==============================================================================
with tab6:
    st.subheader("Security Event Audit Log & Academic Report Generator")
    st.markdown(
        "Review historical inspection events recorded during this session. Generate complete CSV audit logs "
        "and structured CNS Course Project Investigation Reports."
    )

    c_rep1, c_rep2 = st.columns([1, 1])

    with c_rep1:
        st.markdown("##### 📥 Export Event Audit Trail (CSV)")
        audit_csv, _ = export_alerts_to_csv(st.session_state.audit_history)
        st.download_button(
            label="📥 Download Audit Log (CSV)",
            data=audit_csv,
            file_name=f"resolverguard_audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    with c_rep2:
        st.markdown("##### 📄 Generate Formal CNS Course Project Report")
        course_rep = generate_cns_course_report(
            alerts=st.session_state.audit_history,
            benchmark_summary=st.session_state.benchmark_results["summary"] if st.session_state.benchmark_results else None,
            active_resolver=active_resolver_label,
            total_baseline_domains=len(st.session_state.baseline_mgr.list_all())
        )
        st.download_button(
            label="📄 Download Course Audit Report (TXT/MD)",
            data=course_rep,
            file_name=f"CNS_Course_Report_ResolverGuard_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True
        )

    st.markdown("---")
    st.markdown("##### 🔍 Inspection Event Log Table")

    if st.session_state.audit_history:
        # Filter controls
        f_col1, f_col2 = st.columns([2, 1])
        with f_col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            )
        with f_col2:
            verdict_search = st.text_input("Filter by Domain / Keyword", placeholder="e.g. bank, example")

        filtered_history = [
            h for h in st.session_state.audit_history
            if h.get("severity") in severity_filter
            and (not verdict_search or verdict_search.lower() in h.get("domain", "").lower())
        ]

        if filtered_history:
            history_rows = []
            for h in filtered_history:
                history_rows.append({
                    "Timestamp": h.get("timestamp"),
                    "Domain": h.get("domain"),
                    "Verdict": h.get("verdict"),
                    "Severity": h.get("severity"),
                    "Jaccard": h.get("jaccard_similarity"),
                    "Baseline IPs": ", ".join(h.get("baseline_ips", [])),
                    "Observed IPs": ", ".join(h.get("observed_ips", [])),
                    "Anomaly Score": h.get("anomaly_score"),
                    "Reason": h.get("reason", "")
                })
            st.dataframe(pd.DataFrame(history_rows), use_container_width=True, hide_index=True)
        else:
            st.info("No events match the selected filters.")
    else:
        st.info("No inspection events recorded yet. Run a domain check or execute a lab scenario above.")

    # Display preview of Formal Report
    with st.expander("👁️ Preview Formal Security Operations Report"):
        st.code(course_rep, language="text")

# Footer
st.markdown("---")
st.markdown(
    "<center><small style='color: #64748b;'>"
    "ResolverGuard: DNS Integrity Monitoring & Spoofing Detection Workbench | "
    "Enterprise DNS Operations Center | "
    "Strict Anti-Poisoning & RFC 1918 Guard Engine"
    "</small></center>",
    unsafe_allow_html=True
)
