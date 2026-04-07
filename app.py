#!/usr/bin/env python3
"""
Domain File Scanner — Web UI
Real-time SSE progress · grouped secret categories · JSON / CSV / PDF export
"""

from flask import Flask, Response, render_template_string, request, stream_with_context
import subprocess, json, re, tempfile, os, csv, io
from datetime import datetime

app = Flask(__name__)

# ── Risk classification ────────────────────────────────────────────────────────
HIGH_RISK = {
    "aws_access_key_id", "google_api_key", "stripe_secret_key",
    "api_key_assignment", "generic_secret_key_assignment",
    "bearer_or_jwt_token_assignment", "authorization_bearer_header",
    "jwt_token_value", "jws_token_assignment", "artifact_token_assignment",
    "github_token", "slack_token", "slack_webhook_url", "twilio_sid_token",
    "sendgrid_api_key", "client_secret_custom",
    "firebase_api_key_in_config", "firebase_database_url_assignment",
    "access_token_value", "refresh_token_value", "id_token_value",
    "oauth_token_querystring", "azure_storage_connection_string",
    "azure_sas_token", "redis_password_assignment",
    "database_url_with_password", "jdbc_url_with_password",
}
MEDIUM_RISK = {
    "password_assignment", "default_credentials_pair",
    "default_admin_credentials", "database_url",
    "database_connection_assignment", "storage_bucket_url",
    "aws_s3_bucket_name", "gcs_bucket_name", "bucket_assignment",
    "aws_s3_bucket_url_path", "bucket_assignment_extended",
    "firebase_url", "firebase_storage_bucket",
}
LOW_RISK = {
    "username_assignment", "admin_email",
    "internal_endpoint_path", "feature_flag_or_bypass_logic",
}

# ── Human-readable labels ──────────────────────────────────────────────────────
LABEL_MAP = {
    "aws_access_key_id":                "AWS Access Key ID",
    "google_api_key":                   "Google API Key",
    "stripe_secret_key":                "Stripe Secret Key",
    "api_key_assignment":               "API Key Assignment",
    "generic_secret_key_assignment":    "Generic Secret / JWT / Private Key",
    "bearer_or_jwt_token_assignment":   "Bearer / JWT Token Assignment",
    "authorization_bearer_header":      "Authorization Bearer Header",
    "jwt_token_value":                  "JWT Token Value",
    "jws_token_assignment":             "JWS Token Assignment",
    "artifact_token_assignment":        "Artifact Token",
    "github_token":                     "GitHub Token",
    "slack_token":                      "Slack Bot Token",
    "slack_webhook_url":                "Slack Webhook URL",
    "twilio_sid_token":                 "Twilio SID / Token",
    "sendgrid_api_key":                 "SendGrid API Key",
    "client_secret_custom":             "Client / Checkout / Merchant Secret",
    "firebase_api_key_in_config":       "Firebase API Key (config)",
    "firebase_database_url_assignment": "Firebase Database URL",
    "access_token_value":               "Access Token",
    "refresh_token_value":              "Refresh Token",
    "id_token_value":                   "ID Token",
    "oauth_token_querystring":          "OAuth Token (querystring)",
    "azure_storage_connection_string":  "Azure Storage Connection String",
    "azure_sas_token":                  "Azure SAS Token",
    "redis_password_assignment":        "Redis Password",
    "database_url_with_password":       "Database URL (with credentials)",
    "jdbc_url_with_password":           "JDBC URL (with credentials)",
    "password_assignment":              "Password Assignment",
    "default_credentials_pair":         "Default Credentials Pair",
    "default_admin_credentials":        "Default Admin Credentials",
    "database_url":                     "Database URL",
    "database_connection_assignment":   "Database Connection String",
    "storage_bucket_url":               "Storage Bucket URL",
    "aws_s3_bucket_name":               "AWS S3 Bucket Name",
    "aws_s3_bucket_url_path":           "AWS S3 Bucket URL Path",
    "gcs_bucket_name":                  "GCS Bucket Name",
    "bucket_assignment":                "Bucket Assignment",
    "bucket_assignment_extended":       "Extended Bucket Assignment",
    "firebase_url":                     "Firebase URL",
    "firebase_storage_bucket":          "Firebase Storage Bucket",
    "username_assignment":              "Username Assignment",
    "admin_email":                      "Admin / Security Email",
    "internal_endpoint_path":           "Internal / Admin Endpoint",
    "feature_flag_or_bypass_logic":     "Feature Flag / Auth Bypass",
}

# ── Category grouping ──────────────────────────────────────────────────────────
CATEGORIES = {
    "Cloud Provider Keys": [
        "aws_access_key_id", "google_api_key", "stripe_secret_key",
        "sendgrid_api_key", "twilio_sid_token",
        "firebase_api_key_in_config", "firebase_database_url_assignment",
    ],
    "API & Auth Tokens": [
        "api_key_assignment", "generic_secret_key_assignment",
        "bearer_or_jwt_token_assignment", "authorization_bearer_header",
        "jwt_token_value", "jws_token_assignment", "artifact_token_assignment",
        "access_token_value", "refresh_token_value", "id_token_value",
        "oauth_token_querystring", "client_secret_custom",
    ],
    "VCS & Chat Service Tokens": [
        "github_token", "slack_token", "slack_webhook_url",
    ],
    "Azure Secrets": [
        "azure_storage_connection_string", "azure_sas_token",
    ],
    "Database & Storage": [
        "database_url", "database_url_with_password",
        "database_connection_assignment", "jdbc_url_with_password",
        "redis_password_assignment",
        "storage_bucket_url", "aws_s3_bucket_name", "aws_s3_bucket_url_path",
        "gcs_bucket_name", "bucket_assignment", "bucket_assignment_extended",
        "firebase_url", "firebase_storage_bucket",
    ],
    "Credentials & Accounts": [
        "password_assignment", "username_assignment",
        "default_credentials_pair", "default_admin_credentials",
        "admin_email",
    ],
    "Recon / Low-Risk": [
        "internal_endpoint_path", "feature_flag_or_bypass_logic",
    ],
}

def risk_level(t):
    if t in HIGH_RISK:   return "HIGH"
    if t in MEDIUM_RISK: return "MEDIUM"
    return "LOW"

def human_label(t):
    return LABEL_MAP.get(t, t.replace("_", " ").title())

# ── HTML template ──────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DomainScanner</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;700&family=Space+Grotesk:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#07090f;--s1:#0c1018;--s2:#121824;--s3:#1a2233;
  --bd:#1e2a3d;--bd2:#253048;
  --ac:#00e5ff;--ac2:#7c3aed;
  --red:#f43f5e;--ylw:#fb923c;--grn:#10b981;--blu:#38bdf8;
  --txt:#e2e8f2;--muted:#64748b;--muted2:#8899aa;
  --mono:'IBM Plex Mono',monospace;
  --sans:'Space Grotesk',sans-serif;
}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--txt);font-family:var(--mono);min-height:100vh;overflow-x:hidden}
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,229,255,.012) 2px,rgba(0,229,255,.012) 4px);pointer-events:none;z-index:9999}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,229,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.04) 1px,transparent 1px);background-size:48px 48px;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1;max-width:1160px;margin:0 auto;padding:36px 20px 100px}
header{display:flex;align-items:center;gap:18px;margin-bottom:44px;padding-bottom:28px;border-bottom:1px solid var(--bd)}
.logo{width:52px;height:52px;background:linear-gradient(135deg,var(--ac),var(--ac2));border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0;box-shadow:0 0 32px rgba(0,229,255,.25)}
h1{font-family:var(--sans);font-size:26px;font-weight:800;letter-spacing:-.5px}
h1 em{font-style:normal;color:var(--ac)}
.sub{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:2px;margin-top:3px}
.card{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:26px;margin-bottom:28px}
.form-row{display:grid;grid-template-columns:1fr 160px 160px auto;gap:14px;align-items:end}
.field{display:flex;flex-direction:column;gap:7px}
.field label{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted)}
.field input{background:var(--s2);border:1px solid var(--bd2);color:var(--txt);padding:11px 14px;border-radius:8px;font-family:var(--mono);font-size:13px;outline:none;transition:.2s}
.field input:focus{border-color:var(--ac);box-shadow:0 0 0 3px rgba(0,229,255,.12)}
.field input::placeholder{color:var(--muted)}
.btn-primary{background:var(--ac);color:#000;border:none;padding:12px 26px;border-radius:8px;font-family:var(--mono);font-size:12px;font-weight:700;cursor:pointer;text-transform:uppercase;letter-spacing:1.5px;white-space:nowrap;transition:.2s;align-self:end}
.btn-primary:hover{box-shadow:0 0 24px rgba(0,229,255,.4);background:#00f5ff}
.btn-primary:disabled{background:var(--s3);color:var(--muted);cursor:not-allowed;box-shadow:none}
#prog-wrap{display:none}
.prog-card{background:var(--s1);border:1px solid var(--bd);border-radius:14px;padding:26px;margin-bottom:20px}
.prog-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px}
.prog-title{font-family:var(--sans);font-size:15px;font-weight:700;color:var(--ac);text-transform:uppercase;letter-spacing:1px}
.live-dot{width:9px;height:9px;background:var(--ac);border-radius:50%;animation:blink 1.1s infinite}
@keyframes blink{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(0,229,255,.5)}50%{opacity:.5;box-shadow:0 0 0 7px rgba(0,229,255,0)}}
.phases{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:22px}
.phase{background:var(--s2);border:1px solid var(--bd);border-radius:10px;padding:16px;transition:.3s}
.phase.active{border-color:var(--ac);background:rgba(0,229,255,.05)}
.phase.done{border-color:var(--grn);background:rgba(16,185,129,.04)}
.phase-icon{font-size:22px;margin-bottom:8px;display:block}
.phase.active .phase-icon{animation:spin .9s linear infinite;display:inline-block}
@keyframes spin{to{transform:rotate(360deg)}}
.phase-name{font-family:var(--sans);font-size:12px;font-weight:700;margin-bottom:3px}
.phase-desc{font-size:10px;color:var(--muted);line-height:1.5}
.phase-stat{font-size:11px;color:var(--ac);font-weight:700;margin-top:6px}
.pbar-wrap{background:var(--s3);border-radius:4px;height:5px;overflow:hidden;margin-bottom:10px}
.pbar{height:100%;background:linear-gradient(90deg,var(--ac),var(--ac2));border-radius:4px;transition:width .6s ease;width:0;box-shadow:0 0 12px rgba(0,229,255,.5)}
.pbar-label{font-size:11px;color:var(--muted);margin-bottom:16px}
.log{background:#040608;border:1px solid var(--bd);border-radius:8px;padding:14px;height:170px;overflow-y:auto;font-size:11px;line-height:1.7}
.ll{display:flex;gap:10px}
.ll .ts{color:#2a3550;flex-shrink:0}
.ll.ok .msg{color:var(--muted2)}
.ll.found .msg{color:var(--ac)}
.ll.warn .msg{color:var(--ylw)}
.ll.err .msg{color:var(--red)}
.ll.done .msg{color:var(--grn);font-weight:700}
#results{display:none}
.results-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:22px;flex-wrap:wrap;gap:12px}
.results-title{font-family:var(--sans);font-size:22px;font-weight:800}
.export-row{display:flex;gap:8px;flex-wrap:wrap}
.btn-exp{background:var(--s2);border:1px solid var(--bd2);color:var(--muted2);padding:8px 16px;border-radius:7px;font-family:var(--mono);font-size:11px;cursor:pointer;text-transform:uppercase;letter-spacing:1px;display:inline-flex;align-items:center;gap:6px;transition:.2s}
.btn-exp:hover{border-color:var(--ac);color:var(--ac)}
.btn-exp.csv:hover{border-color:var(--grn);color:var(--grn)}
.btn-exp.pdf:hover{border-color:var(--red);color:var(--red)}
.stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:26px}
.stat{background:var(--s1);border:1px solid var(--bd);border-radius:12px;padding:18px;text-align:center}
.stat-n{font-family:var(--sans);font-size:36px;font-weight:800;line-height:1;margin-bottom:5px;color:var(--ac)}
.stat-n.ylw{color:var(--ylw)}.stat-n.red{color:var(--red)}.stat-n.grn{color:var(--grn)}
.stat-l{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted)}
.panel{background:var(--s1);border:1px solid var(--bd);border-radius:12px;margin-bottom:16px;overflow:hidden}
.phdr{padding:14px 18px;background:var(--s2);display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none;border-bottom:1px solid var(--bd)}
.phdr:hover{background:var(--s3)}
.ptitle{font-family:var(--sans);font-size:13px;font-weight:700;display:flex;align-items:center;gap:8px}
.pico{font-size:16px}
.pbody{padding:18px}
.chevron{color:var(--muted);font-size:11px;transition:.2s}
.panel.closed .chevron{transform:rotate(-90deg)}
.panel.closed .pbody{display:none}
.cnt{font-size:11px;padding:3px 10px;border-radius:20px;border:1px solid;background:rgba(0,0,0,.3)}
.cnt-red{color:var(--red);border-color:rgba(244,63,94,.3)}
.cnt-ylw{color:var(--ylw);border-color:rgba(251,146,60,.3)}
.cnt-def{color:var(--muted);border-color:var(--bd)}
.js-list{max-height:240px;overflow-y:auto;display:flex;flex-direction:column;gap:4px}
.js-item{font-size:11px;color:var(--blu);padding:6px 10px;background:var(--s2);border-radius:6px;word-break:break-all;border:1px solid transparent}
.js-item:hover{border-color:var(--bd2)}
.cat-group{margin-bottom:24px}
.cat-heading{font-family:var(--sans);font-size:13px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:1.5px;padding:0 0 8px;margin-bottom:12px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px}
.cat-ico{font-size:15px}
.cat-cnt{font-size:10px;background:var(--s3);border:1px solid var(--bd2);border-radius:12px;padding:2px 8px;color:var(--muted);margin-left:auto}
.finding{border:1px solid var(--bd);border-radius:10px;margin-bottom:10px;overflow:hidden}
.ftype-bar{padding:10px 14px;background:var(--s3);display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--bd)}
.ftype-name{font-family:var(--sans);font-weight:700;font-size:12px;color:var(--txt)}
.furl-bar{padding:8px 14px;background:var(--s2);font-size:11px;color:var(--blu);word-break:break-all;display:flex;align-items:center;justify-content:space-between;gap:10px;border-bottom:1px solid var(--bd)}
.furl{flex:1}
.fhits{flex-shrink:0;font-weight:700;color:var(--ylw);font-size:11px}
.matches{padding:10px 14px;display:flex;flex-direction:column;gap:8px}
.mrow{padding:8px 10px;background:var(--s3);border-radius:7px;border:1px solid var(--bd)}
.mrow.high{border-color:rgba(244,63,94,.25);background:rgba(244,63,94,.04)}
.mrow.medium{border-color:rgba(251,146,60,.2);background:rgba(251,146,60,.03)}
.mrow.low{border-color:rgba(16,185,129,.2);background:rgba(16,185,129,.03)}
.badge{display:inline-flex;align-items:center;padding:2px 7px;border-radius:4px;font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap;border:1px solid}
.b-high{background:rgba(244,63,94,.15);color:var(--red);border-color:rgba(244,63,94,.4)}
.b-medium{background:rgba(251,146,60,.15);color:var(--ylw);border-color:rgba(251,146,60,.4)}
.b-low{background:rgba(16,185,129,.12);color:var(--grn);border-color:rgba(16,185,129,.35)}
.mval{font-size:11px;background:#030508;padding:4px 8px;border-radius:4px;word-break:break-all;margin-bottom:4px;border:1px solid var(--bd);color:#c8d4e8;font-family:var(--mono)}
.mctx{font-size:10px;color:var(--muted);word-break:break-all;line-height:1.5}
.ptbl{width:100%;border-collapse:collapse;font-size:12px}
.ptbl th{text-align:left;padding:8px 12px;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);border-bottom:1px solid var(--bd)}
.ptbl td{padding:8px 12px;border-bottom:1px solid rgba(30,42,61,.5);word-break:break-all}
.ptbl tr:last-child td{border-bottom:none}
.ptbl tr:hover td{background:var(--s2)}
.sc{font-weight:700}
.sc-2xx{color:var(--grn)}.sc-3xx{color:var(--blu)}.sc-401,.sc-403{color:var(--ylw)}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--s3);border-radius:3px}
@media(max-width:760px){.form-row{grid-template-columns:1fr}.phases{grid-template-columns:1fr}.stat-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="logo">&#128269;</div>
  <div>
    <h1>Domain<em>Scanner</em></h1>
    <div class="sub">JS Secrets &middot; Sensitive Paths &middot; Security Audit</div>
  </div>
</header>
<div class="card">
  <div class="form-row">
    <div class="field"><label>Target URL</label><input id="inp-target" type="text" placeholder="https://example.com" autocomplete="off"></div>
    <div class="field"><label>Max Pages</label><input id="inp-pages" type="number" value="80" min="1" max="500"></div>
    <div class="field"><label>Timeout (sec)</label><input id="inp-timeout" type="number" value="8" min="1" max="60"></div>
    <button class="btn-primary" id="scanBtn" onclick="startScan()">&#9654; Scan</button>
  </div>
</div>
<div id="prog-wrap">
  <div class="prog-card">
    <div class="prog-hdr">
      <span class="prog-title">Live Scan Progress</span>
      <div class="live-dot"></div>
    </div>
    <div class="phases">
      <div class="phase" id="ph1"><span class="phase-icon">&#9675;</span><div class="phase-name">Phase 1 &mdash; Crawl</div><div class="phase-desc">Spider pages, collect JS URLs</div><div class="phase-stat" id="ph1-stat"></div></div>
      <div class="phase" id="ph2"><span class="phase-icon">&#9675;</span><div class="phase-name">Phase 2 &mdash; Secrets</div><div class="phase-desc">Scan JS for hardcoded credentials</div><div class="phase-stat" id="ph2-stat"></div></div>
      <div class="phase" id="ph3"><span class="phase-icon">&#9675;</span><div class="phase-name">Phase 3 &mdash; Paths</div><div class="phase-desc">Probe sensitive file endpoints</div><div class="phase-stat" id="ph3-stat"></div></div>
    </div>
    <div class="pbar-wrap"><div class="pbar" id="pbar"></div></div>
    <div class="pbar-label" id="pbar-lbl">Waiting to start&hellip;</div>
    <div class="log" id="log"></div>
  </div>
</div>
<div id="results">
  <div class="results-hdr">
    <div class="results-title">Scan Results</div>
    <div class="export-row">
      <button class="btn-exp" onclick="dlJSON()">&#11015; JSON</button>
      <button class="btn-exp csv" onclick="dlCSV()">&#11015; CSV</button>
      <button class="btn-exp pdf" onclick="dlPDF()">&#11015; PDF Report</button>
    </div>
  </div>
  <div class="stat-grid">
    <div class="stat"><div class="stat-n grn" id="s-pages">&mdash;</div><div class="stat-l">Pages Crawled</div></div>
    <div class="stat"><div class="stat-n" id="s-js">&mdash;</div><div class="stat-l">JS Files</div></div>
    <div class="stat"><div class="stat-n ylw" id="s-matches">&mdash;</div><div class="stat-l">Secret Matches</div></div>
    <div class="stat"><div class="stat-n red" id="s-paths">&mdash;</div><div class="stat-l">Sensitive Hits</div></div>
  </div>
  <div class="panel" id="pnl-js">
    <div class="phdr" onclick="toggle('pnl-js')"><span class="ptitle"><span class="pico">&#128220;</span> Discovered JavaScript Files</span><div style="display:flex;gap:8px;align-items:center"><span class="cnt cnt-def" id="c-js">0</span><span class="chevron">&#9662;</span></div></div>
    <div class="pbody"><div class="js-list" id="js-list"></div></div>
  </div>
  <div class="panel" id="pnl-sec">
    <div class="phdr" onclick="toggle('pnl-sec')"><span class="ptitle"><span class="pico">&#128272;</span> Hardcoded Secrets &mdash; By Category</span><div style="display:flex;gap:8px;align-items:center"><span class="cnt cnt-red" id="c-sec">0</span><span class="chevron">&#9662;</span></div></div>
    <div class="pbody" id="sec-body"></div>
  </div>
  <div class="panel" id="pnl-paths">
    <div class="phdr" onclick="toggle('pnl-paths')"><span class="ptitle"><span class="pico">&#9888;&#65039;</span> Sensitive Path Hits</span><div style="display:flex;gap:8px;align-items:center"><span class="cnt cnt-ylw" id="c-paths">0</span><span class="chevron">&#9662;</span></div></div>
    <div class="pbody"><table class="ptbl"><thead><tr><th>Status</th><th>Path</th><th>Content-Type</th><th>Size</th></tr></thead><tbody id="paths-tbody"></tbody></table></div>
  </div>
</div>
</div>
<script>
const CAT_DEF=CATEGORIES_JSON;
const HIGH=new Set(HIGH_RISK_JSON);
const MED=new Set(MEDIUM_RISK_JSON);
const LABELS=LABELS_JSON;
const CAT_ICONS={"Cloud Provider Keys":"☁️","API & Auth Tokens":"🔑","VCS & Chat Service Tokens":"💬","Azure Secrets":"🔷","Database & Storage":"🗄️","Credentials & Accounts":"👤","Recon / Low-Risk":"🔎"};
let REPORT=null;
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function risk(t){return HIGH.has(t)?'high':MED.has(t)?'medium':'low'}
function badgeCls(t){return{high:'b-high',medium:'b-medium',low:'b-low'}[risk(t)]}
function rlabel(t){return risk(t).toUpperCase()}
function hlabel(t){return LABELS[t]||t.replace(/_/g,' ').replace(/\\b\\w/g,c=>c.toUpperCase())}
function toggle(id){document.getElementById(id).classList.toggle('closed')}
function log(msg,cls='ok'){
  const el=document.getElementById('log');
  const now=new Date().toLocaleTimeString('en-US',{hour12:false});
  const d=document.createElement('div');d.className='ll '+cls;
  d.innerHTML='<span class="ts">'+now+'</span><span class="msg">'+esc(msg)+'</span>';
  el.appendChild(d);el.scrollTop=el.scrollHeight;
}
function setBar(pct,lbl){document.getElementById('pbar').style.width=pct+'%';document.getElementById('pbar-lbl').textContent=lbl}
function setPhase(n,state){
  const el=document.getElementById('ph'+n);
  el.classList.remove('active','done');
  if(state)el.classList.add(state);
  const ico=el.querySelector('.phase-icon');
  ico.textContent=state==='done'?'✓':state==='active'?'◷':'○';
}
function startScan(){
  const target=document.getElementById('inp-target').value.trim();
  if(!target){alert('Enter a target URL');return}
  const pages=document.getElementById('inp-pages').value;
  const timeout=document.getElementById('inp-timeout').value;
  document.getElementById('scanBtn').disabled=true;
  document.getElementById('prog-wrap').style.display='block';
  document.getElementById('results').style.display='none';
  document.getElementById('log').innerHTML='';
  [1,2,3].forEach(n=>{setPhase(n,'');document.getElementById('ph'+n+'-stat').textContent=''});
  setBar(0,'Initializing…');
  const src=new EventSource('/scan?target='+encodeURIComponent(target)+'&max_pages='+pages+'&timeout='+timeout);
  src.onmessage=e=>{
    const m=JSON.parse(e.data);
    if(m.type==='phase'){
      const p=m.phase;
      if(p===1){setPhase(1,'active');setBar(5,'Crawling pages…')}
      if(p===2){setPhase(1,'done');setPhase(2,'active');setBar(38,'Scanning JS files for secrets…')}
      if(p===3){setPhase(2,'done');setPhase(3,'active');setBar(72,'Probing sensitive paths…')}
      log(m.msg,'ok');
    } else if(m.type==='progress'){
      log(m.msg,m.cls||'ok');
      if(m.pct)setBar(m.pct,m.msg.substring(0,80));
      if(m.phase===1&&m.pages!==undefined)document.getElementById('ph1-stat').textContent=m.pages+' pages';
      if(m.phase===2&&m.js!==undefined)document.getElementById('ph2-stat').textContent=m.js+' JS files';
      if(m.phase===3&&m.paths!==undefined)document.getElementById('ph3-stat').textContent=m.paths+' paths';
    } else if(m.type==='done'){
      setPhase(3,'done');setBar(100,'✓ Scan complete');
      log('Scan finished successfully.','done');src.close();
      renderResults(m.report);document.getElementById('scanBtn').disabled=false;
    } else if(m.type==='error'){
      log('ERROR: '+m.msg,'err');setBar(0,'Scan failed.');src.close();document.getElementById('scanBtn').disabled=false;
    }
  };
  src.onerror=()=>{log('Connection lost.','err');src.close();document.getElementById('scanBtn').disabled=false};
}
function renderResults(r){
  REPORT=r;
  const interesting=(r.sensitive_results||[]).filter(x=>[200,206,301,302,307,308,401,403].includes(x.status));
  const totalMatch=(r.js_secret_findings||[]).reduce((a,f)=>a+(f.matches_count||0),0);
  document.getElementById('s-pages').textContent=r.visited_pages_count||0;
  document.getElementById('s-js').textContent=(r.js_files||[]).length;
  document.getElementById('s-matches').textContent=totalMatch;
  document.getElementById('s-paths').textContent=interesting.length;
  const jsList=document.getElementById('js-list');jsList.innerHTML='';
  (r.js_files||[]).forEach(u=>{const d=document.createElement('div');d.className='js-item';d.textContent=u;jsList.appendChild(d)});
  document.getElementById('c-js').textContent=(r.js_files||[]).length;
  renderSecrets(r.js_secret_findings||[]);
  const tbody=document.getElementById('paths-tbody');tbody.innerHTML='';
  document.getElementById('c-paths').textContent=interesting.length;
  if(!interesting.length){tbody.innerHTML='<tr><td colspan="4" style="color:var(--muted)">No interesting responses from sensitive paths.</td></tr>';}
  else{interesting.forEach(p=>{const sc=p.status;const cls=sc>=200&&sc<300?'sc-2xx':sc>=300&&sc<400?'sc-3xx':'sc-'+sc;tbody.insertAdjacentHTML('beforeend','<tr><td><span class="sc '+cls+'">'+sc+'</span></td><td style="font-family:var(--mono);font-size:11px">'+esc(p.path)+'</td><td style="font-size:11px">'+esc((p.content_type||'').substring(0,55))+'</td><td style="font-size:11px">'+p.content_length+' B</td></tr>')})}
  document.getElementById('results').style.display='block';
  document.getElementById('results').scrollIntoView({behavior:'smooth'});
}
function renderSecrets(findings){
  const body=document.getElementById('sec-body');body.innerHTML='';
  const byType={};
  findings.forEach(f=>{(f.matches||[]).forEach(m=>{if(!byType[m.type])byType[m.type]=[];byType[m.type].push({jsUrl:f.js_url,match:m.match,snippet:m.snippet})})});
  const totalFiles=findings.length;
  const totalMatches=Object.values(byType).reduce((a,v)=>a+v.length,0);
  document.getElementById('c-sec').textContent=totalFiles+' files \u00b7 '+totalMatches+' matches';
  if(!totalMatches){body.innerHTML='<div style="color:var(--muted);font-size:12px">No hardcoded secrets detected.</div>';return}
  Object.entries(CAT_DEF).forEach(([cat,types])=>{
    const hitsInCat=types.filter(t=>byType[t]&&byType[t].length>0);
    if(!hitsInCat.length)return;
    const total=hitsInCat.reduce((a,t)=>a+byType[t].length,0);
    const ico=CAT_ICONS[cat]||'\u25b8';
    const grp=document.createElement('div');grp.className='cat-group';
    grp.innerHTML='<div class="cat-heading"><span class="cat-ico">'+ico+'</span>'+esc(cat)+'<span class="cat-cnt">'+total+' match'+(total!==1?'es':'')+'</span></div>';
    hitsInCat.forEach(t=>{
      const items=byType[t];const lvl=risk(t);
      const byUrl={};items.forEach(i=>{(byUrl[i.jsUrl]=byUrl[i.jsUrl]||[]).push(i)});
      const card=document.createElement('div');card.className='finding';
      card.innerHTML='<div class="ftype-bar"><span class="ftype-name">'+esc(hlabel(t))+'</span><span class="badge '+badgeCls(t)+'">'+rlabel(t)+'</span></div>';
      Object.entries(byUrl).forEach(([url,ms])=>{
        const ub=document.createElement('div');ub.className='furl-bar';
        ub.innerHTML='<span class="furl">'+esc(url)+'</span><span class="fhits">'+ms.length+' hit'+(ms.length!==1?'s':'')+'</span>';
        card.appendChild(ub);
        const md=document.createElement('div');md.className='matches';
        ms.forEach(m=>{md.insertAdjacentHTML('beforeend','<div class="mrow '+lvl+'"><div class="mval">'+esc(m.match)+'</div><div class="mctx">Context: '+esc(m.snippet)+'</div></div>')});
        card.appendChild(md);
      });
      grp.appendChild(card);
    });
    body.appendChild(grp);
  });
  const allCatTypes=Object.values(CAT_DEF).flat();
  const uncatTypes=Object.keys(byType).filter(t=>!allCatTypes.includes(t));
  if(uncatTypes.length){
    const grp=document.createElement('div');grp.className='cat-group';
    grp.innerHTML='<div class="cat-heading">&#10067; Other</div>';
    uncatTypes.forEach(t=>{byType[t].forEach(i=>{grp.insertAdjacentHTML('beforeend','<div class="mrow '+risk(t)+'"><span class="badge '+badgeCls(t)+'">'+rlabel(t)+'</span><div style="margin-top:6px"><div class="mval">'+esc(i.match)+'</div><div class="mctx">'+esc(i.snippet)+'</div></div></div>')})});
    body.appendChild(grp);
  }
}
function dlJSON(){if(!REPORT)return;const b=new Blob([JSON.stringify(REPORT,null,2)],{type:'application/json'});dl(b,'scan_report.json')}
function dlCSV(){if(!REPORT)return;fetch('/export/csv',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(REPORT)}).then(r=>r.blob()).then(b=>dl(b,'scan_report.csv'))}
function dlPDF(){if(!REPORT)return;fetch('/export/pdf',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(REPORT)}).then(r=>r.blob()).then(b=>dl(b,'scan_report.html'))}
function dl(blob,name){const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();URL.revokeObjectURL(a.href)}
</script>
</body>
</html>
"""

def build_html():
    h = HTML
    h = h.replace('CATEGORIES_JSON', json.dumps(CATEGORIES))
    h = h.replace('HIGH_RISK_JSON',  json.dumps(list(HIGH_RISK)))
    h = h.replace('MEDIUM_RISK_JSON',json.dumps(list(MEDIUM_RISK)))
    h = h.replace('LABELS_JSON',     json.dumps(LABEL_MAP))
    return h

RENDERED_HTML = build_html()

# ──────────────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return RENDERED_HTML

@app.route('/scan')
def scan():
    target    = request.args.get('target', '')
    max_pages = request.args.get('max_pages', '80')
    timeout   = request.args.get('timeout', '8')

    def generate():
        def sse(data):
            return f"data: {json.dumps(data)}\n\n"

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp:
            output_file = tmp.name

        try:
            yield sse({"type": "phase", "phase": 1, "msg": f"Starting crawl on {target}"})

            cmd = [
                'python', '/app/scanner.py',
                target,
                '--max-pages', max_pages,
                '--timeout',   timeout,
                '--output',    output_file,
                '--no-color',
            ]

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )

            phase = 1
            page_count = 0
            js_count   = 0
            path_count = 0

            for raw in proc.stdout:
                line = raw.rstrip()
                if not line:
                    continue

                if '[1/3]' in line or ('Crawling' in line and 'pages' in line):
                    phase = 1
                    yield sse({"type": "phase", "phase": 1, "msg": line})
                    continue
                if '[2/3]' in line or ('Scanning' in line and 'JS files' in line):
                    phase = 2
                    m = re.search(r'(\d+)\s+discovered JS', line)
                    if m: js_count = int(m.group(1))
                    yield sse({"type": "phase", "phase": 2, "msg": line})
                    continue
                if '[3/3]' in line or ('Probing' in line and 'sensitive' in line):
                    phase = 3
                    m = re.search(r'(\d+)\s+sensitive', line)
                    if m: path_count = int(m.group(1))
                    yield sse({"type": "phase", "phase": 3, "msg": line})
                    continue

                mp = re.search(r'(\d+)\s+pages?', line, re.I)
                if mp and phase == 1: page_count = int(mp.group(1))
                mj = re.search(r'(\d+)\s+JS', line, re.I)
                if mj and phase == 2: js_count = int(mj.group(1))

                cls = 'ok'
                if '.js' in line.lower(): cls = 'found'
                elif re.search(r'\b(error|fail|exception)\b', line, re.I): cls = 'err'
                elif re.search(r'\b(401|403|200)\b', line): cls = 'warn'

                yield sse({
                    "type":  "progress",
                    "phase": phase,
                    "msg":   line,
                    "cls":   cls,
                    "pages": page_count,
                    "js":    js_count,
                    "paths": path_count,
                    "pct":   12 if phase == 1 else (55 if phase == 2 else 85),
                })

            proc.wait()

            if not os.path.exists(output_file):
                yield sse({"type": "error", "msg": "Scanner produced no output file."})
                return

            with open(output_file, 'r') as f:
                report = json.load(f)

            app.config['LAST_REPORT'] = report
            yield sse({"type": "done", "report": report})

        except Exception as e:
            yield sse({"type": "error", "msg": str(e)})
        finally:
            try:
                os.unlink(output_file)
            except Exception:
                pass

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'}
    )


@app.route('/export/csv', methods=['POST'])
def export_csv():
    r = request.get_json()
    out = io.StringIO()
    w = csv.writer(out)

    w.writerow(['DOMAIN SCANNER REPORT'])
    w.writerow(['Target', r.get('target',''), 'Generated', datetime.now().strftime('%Y-%m-%d %H:%M')])
    w.writerow([])

    w.writerow(['== HARDCODED SECRETS =='])
    w.writerow(['Category', 'Type', 'Human Label', 'Risk', 'JS File', 'Value', 'Context'])
    all_cat_types = {t: cat for cat, types in CATEGORIES.items() for t in types}
    for f in r.get('js_secret_findings', []):
        for m in f.get('matches', []):
            t = m['type']
            cat = all_cat_types.get(t, 'Other')
            w.writerow([cat, t, human_label(t), risk_level(t), f['js_url'], m['match'], m['snippet']])

    w.writerow([])
    w.writerow(['== SENSITIVE PATHS =='])
    w.writerow(['Status', 'Path', 'Content-Type', 'Size (bytes)'])
    interesting = [x for x in r.get('sensitive_results', []) if x['status'] in (200,206,301,302,307,308,401,403)]
    for x in interesting:
        w.writerow([x['status'], x['path'], x.get('content_type',''), x.get('content_length',0)])

    w.writerow([])
    w.writerow(['== JS FILES =='])
    w.writerow(['URL'])
    for u in r.get('js_files', []): w.writerow([u])

    return Response(
        out.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=scan_report.csv'}
    )


@app.route('/export/pdf', methods=['POST'])
def export_pdf():
    r   = request.get_json()
    ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    interesting   = [x for x in r.get('sensitive_results', []) if x['status'] in (200,206,301,302,307,308,401,403)]
    total_matches = sum(f.get('matches_count', 0) for f in r.get('js_secret_findings', []))

    by_type: dict = {}
    for f in r.get('js_secret_findings', []):
        for m in f.get('matches', []):
            by_type.setdefault(m['type'], []).append({'url': f['js_url'], **m})

    def badge_html(t):
        lvl = risk_level(t)
        colors = {'HIGH':('#fef2f2','#dc2626'),'MEDIUM':('#fffbeb','#d97706'),'LOW':('#f0fdf4','#16a34a')}
        bg, fg = colors[lvl]
        return f'<span style="background:{bg};color:{fg};padding:1px 7px;border-radius:3px;font-size:9px;font-weight:700">{lvl}</span>'

    cat_icons = {'Cloud Provider Keys':'☁️','API & Auth Tokens':'🔑','VCS & Chat Service Tokens':'💬',
                 'Azure Secrets':'🔷','Database & Storage':'🗄️','Credentials & Accounts':'👤','Recon / Low-Risk':'🔎'}

    secs_html = ''
    for cat, types in CATEGORIES.items():
        hits = [(t, by_type[t]) for t in types if t in by_type]
        if not hits: continue
        total = sum(len(v) for _, v in hits)
        ico   = cat_icons.get(cat, '▸')
        secs_html += f'<div style="margin-bottom:22px"><h3 style="font-size:12px;color:#475569;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #e2e8f0;padding-bottom:6px;margin-bottom:12px">{ico} {cat} <span style="font-weight:400;color:#94a3b8">({total} matches)</span></h3>'
        for t, items in hits:
            by_url: dict = {}
            for i in items: by_url.setdefault(i['url'], []).append(i)
            secs_html += f'<div style="margin-bottom:10px;border:1px solid #e2e8f0;border-radius:8px;overflow:hidden"><div style="background:#f8fafc;padding:8px 12px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #e2e8f0"><span style="font-weight:700;font-size:12px">{human_label(t)}</span>{badge_html(t)}</div>'
            for url, ms in by_url.items():
                secs_html += f'<div style="padding:6px 12px;font-size:10px;color:#0369a1;border-bottom:1px solid #f1f5f9;word-break:break-all">{url} <span style="color:#94a3b8">({len(ms)} hit{"s" if len(ms)!=1 else ""})</span></div>'
                for m in ms:
                    secs_html += f'<div style="padding:6px 12px;border-bottom:1px solid #f8fafc"><code style="font-size:10px;background:#f8fafc;padding:2px 6px;border-radius:3px;word-break:break-all;display:block;margin-bottom:3px">{m["match"]}</code><span style="font-size:10px;color:#64748b">{m.get("snippet","")}</span></div>'
            secs_html += '</div>'
        secs_html += '</div>'

    paths_rows = ''
    for x in interesting:
        sc    = x['status']
        color = '#16a34a' if 200<=sc<300 else '#2563eb' if 300<=sc<400 else '#d97706'
        paths_rows += f'<tr><td style="color:{color};font-weight:700">{sc}</td><td style="font-family:monospace;font-size:11px;word-break:break-all">{x["path"]}</td><td style="font-size:11px">{(x.get("content_type") or "")[:50]}</td><td>{x.get("content_length",0)} B</td></tr>'

    js_items = ''.join(f'<li style="font-size:11px;font-family:monospace;color:#0369a1;word-break:break-all;margin-bottom:3px">{u}</li>' for u in r.get('js_files', []))

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body{{font-family:'Segoe UI',sans-serif;margin:0;color:#1e293b;font-size:13px}}
  .cover{{background:linear-gradient(135deg,#0f172a,#1e3a5f);color:#fff;padding:50px 40px}}
  .cover h1{{font-size:32px;margin:8px 0 0;letter-spacing:-1px}}
  .cover .sub{{font-size:12px;opacity:.6;text-transform:uppercase;letter-spacing:2px}}
  .cover .meta{{margin-top:24px;font-size:12px;opacity:.8;line-height:1.8}}
  .body{{padding:36px 40px}}
  .stats{{display:flex;gap:16px;margin-bottom:28px}}
  .sbox{{flex:1;background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;text-align:center}}
  .sn{{font-size:28px;font-weight:800;line-height:1}}
  .sl{{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:#64748b;margin-top:4px}}
  h2{{font-size:17px;color:#0f172a;margin:26px 0 12px;padding-bottom:8px;border-bottom:2px solid #e2e8f0}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:#f1f5f9;padding:8px 10px;text-align:left;font-size:11px;text-transform:uppercase;color:#64748b;letter-spacing:.5px}}
  td{{padding:7px 10px;border-bottom:1px solid #f1f5f9}}
  footer{{margin-top:40px;font-size:10px;color:#94a3b8;border-top:1px solid #e2e8f0;padding-top:12px}}
</style>
</head><body>
<div class="cover">
  <div class="sub">Security Audit Report</div>
  <h1>Domain Scanner</h1>
  <div class="meta"><div><b>Target:</b> {r.get("target","")}</div><div><b>Generated:</b> {ts}</div></div>
</div>
<div class="body">
  <h2>Executive Summary</h2>
  <div class="stats">
    <div class="sbox"><div class="sn">{r.get("visited_pages_count",0)}</div><div class="sl">Pages</div></div>
    <div class="sbox"><div class="sn">{len(r.get("js_files",[]))}</div><div class="sl">JS Files</div></div>
    <div class="sbox"><div class="sn" style="color:#dc2626">{total_matches}</div><div class="sl">Secrets</div></div>
    <div class="sbox"><div class="sn" style="color:#d97706">{len(interesting)}</div><div class="sl">Sensitive Hits</div></div>
  </div>
  <h2>🔐 Hardcoded Secrets by Category</h2>
  {secs_html if secs_html else '<p style="color:#94a3b8">No secrets detected.</p>'}
  <h2>⚠️ Sensitive Path Hits</h2>
  {f'<table><thead><tr><th>Status</th><th>Path</th><th>Content-Type</th><th>Size</th></tr></thead><tbody>{paths_rows}</tbody></table>' if paths_rows else '<p style="color:#94a3b8">No interesting responses.</p>'}
  <h2>📜 JavaScript Files ({len(r.get("js_files",[]))})</h2>
  <ul style="padding-left:16px">{js_items}</ul>
  <div class="footer">Generated by DomainScanner &middot; {ts}</div>
</div>
</body></html>"""

    return Response(
        html, mimetype='text/html',
        headers={'Content-Disposition': 'attachment; filename=scan_report.html'}
    )


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False, threaded=True)