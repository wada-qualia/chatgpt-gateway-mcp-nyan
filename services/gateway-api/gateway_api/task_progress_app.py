from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from .config import Settings
from .mcp_federation_compat import MCP_APPS_EXTENSION_ID, ModernRequestAdmission
from .mcp_presentation import PresentationContext
from .task_progress import (
    TASK_PROGRESS_CAPABILITY_ID,
    TASK_PROGRESS_RESOURCE_MIME,
    TASK_PROGRESS_RESOURCE_URI,
    TASK_PROGRESS_RESOURCE_V1_URI,
    TASK_PROGRESS_RESOURCE_V2_URI,
    TASK_PROGRESS_RESOURCE_V3_URI,
    TASK_PROGRESS_RESOURCE_V4_URI,
    TASK_PROGRESS_RESOURCE_V5_URI,
    TASK_PROGRESS_RESOURCE_V6_URI,
    TASK_PROGRESS_RESOURCE_V7_URI,
    TASK_PROGRESS_RESOURCE_V8_URI,
    TASK_PROGRESS_RESOURCE_V9_URI,
    TaskProgressSnapshotV1,
    task_progress_model_payload,
    task_progress_text,
)

TASK_PROGRESS_APPS_PROTOCOL_VERSION = "2026-01-26"
TASK_PROGRESS_RENDER_TOOL = "render_task_progress"
TASK_PROGRESS_GET_TOOL = "task_progress_get"
TASK_PROGRESS_CANCEL_TOOL = "task_progress_cancel"
TASK_PROGRESS_TOOL_NAMES = frozenset(
    {
        TASK_PROGRESS_RENDER_TOOL,
        TASK_PROGRESS_GET_TOOL,
        TASK_PROGRESS_CANCEL_TOOL,
    }
)

TASK_PROGRESS_APP_V1_HTML = '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1">\n<title>ATLAS Task Progress</title>\n<style>\n:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--bg:Canvas;--fg:CanvasText;--muted:color-mix(in srgb,CanvasText 58%,transparent);--line:color-mix(in srgb,CanvasText 16%,transparent);--surface:color-mix(in srgb,Canvas 92%,CanvasText 8%);--accent:LinkText;--danger:#b42318;--ok:#067647;--warn:#b54708}\n*{box-sizing:border-box}\nbody{margin:0;background:transparent;color:var(--fg)}\nmain{max-width:980px;margin:0 auto;padding:12px}\n.card{border:1px solid var(--line);border-radius:16px;background:var(--bg);overflow:hidden;box-shadow:0 1px 2px color-mix(in srgb,CanvasText 8%,transparent)}\n.header{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:14px 14px 10px}\n.title{min-width:0}\nh1{font-size:15px;line-height:1.35;margin:0;font-weight:650;overflow-wrap:anywhere}\n.subtitle{display:flex;align-items:center;gap:8px;margin-top:5px;font-size:12px;color:var(--muted);flex-wrap:wrap}\n.status{font-weight:650;color:var(--fg)}\n.fresh{display:inline-flex;align-items:center;gap:5px}\n.dot{width:7px;height:7px;border-radius:999px;background:var(--ok)}\n[data-stale="true"] .dot{background:var(--warn)}\n.actions{display:flex;align-items:center;gap:7px;flex-wrap:wrap;justify-content:flex-end}\nbutton{font:inherit;border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--fg);padding:7px 10px;cursor:pointer}\nbutton:hover{filter:brightness(.97)}\nbutton:disabled{opacity:.45;cursor:not-allowed}\nbutton.primary{background:var(--fg);color:var(--bg);border-color:var(--fg)}\nbutton.danger{color:var(--danger)}\nbutton.compact{padding:7px 8px}\n.summary{padding:0 14px 14px}\n.progress-row{display:flex;align-items:center;justify-content:space-between;gap:12px;font-size:12px}\n.track{height:7px;border-radius:999px;background:var(--surface);overflow:hidden;margin-top:8px}\n.bar{height:100%;background:var(--accent);width:0;transition:width .2s ease}\n.track.indeterminate .bar{width:35%;animation:slide 1.35s ease-in-out infinite}\n@keyframes slide{0%{transform:translateX(-120%)}50%{transform:translateX(180%)}100%{transform:translateX(330%)}}\n.blocker{margin-top:12px;padding:9px 10px;border-radius:10px;background:color-mix(in srgb,var(--warn) 11%,transparent);font-size:12px;line-height:1.4}\n.stages{border-top:1px solid var(--line);padding:10px 14px 12px;display:grid;gap:7px}\n.stage{display:grid;grid-template-columns:10px minmax(0,1fr) auto;gap:8px;align-items:center;font-size:12px}\n.stage-dot{width:8px;height:8px;border:1px solid var(--line);border-radius:50%;background:var(--surface)}\n.stage[data-status="succeeded"] .stage-dot{background:var(--ok);border-color:var(--ok)}\n.stage[data-status="running"] .stage-dot{background:var(--accent);border-color:var(--accent)}\n.stage[data-status="failed"] .stage-dot,.stage[data-status="blocked"] .stage-dot{background:var(--danger);border-color:var(--danger)}\n.stage-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}\n.stage-state{color:var(--muted)}\n.details{display:none;border-top:1px solid var(--line);padding:14px}\n[data-mode="fullscreen"] .details{display:grid;gap:16px}\n.section h2{font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}\n.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px}\n.tile{border:1px solid var(--line);border-radius:10px;padding:9px;font-size:12px;min-width:0}\n.tile strong{display:block;margin-bottom:4px;overflow-wrap:anywhere}\n.tile span{color:var(--muted);overflow-wrap:anywhere}\n.empty{color:var(--muted);font-size:12px}\n[data-mode="pip"] main{padding:8px}\n[data-mode="pip"] .stages{display:none}\n[data-mode="pip"] .header{padding:10px 10px 8px}\n[data-mode="pip"] .summary{padding:0 10px 10px}\n@media(max-width:520px){main{padding:8px}.header{flex-direction:column}.actions{width:100%;justify-content:flex-start}.stage-state{display:none}}\n</style>\n</head>\n<body>\n<main>\n<section class="card" id="card" data-mode="inline" data-stale="false" aria-live="polite">\n<div class="header">\n<div class="title">\n<h1 id="title">Task progress</h1>\n<div class="subtitle"><span class="status" id="status">Loading</span><span class="fresh"><span class="dot"></span><span id="freshness">Connecting</span></span></div>\n</div>\n<div class="actions">\n<button class="compact" id="pip" type="button" hidden aria-label="Keep task progress visible">Pin</button>\n<button class="primary" id="details" type="button" hidden>Details</button>\n<button class="danger" id="cancel" type="button" hidden>Cancel</button>\n</div>\n</div>\n<div class="summary">\n<div class="progress-row"><span id="current">Waiting for task state</span><span id="count"></span></div>\n<div class="track indeterminate" id="track" role="progressbar" aria-label="Task progress"><div class="bar" id="bar"></div></div>\n<div class="blocker" id="blocker" hidden></div>\n</div>\n<div class="stages" id="stages"></div>\n<div class="details" id="detailPane">\n<div class="section"><h2>Acceptance</h2><div class="grid" id="checks"></div></div>\n<div class="section"><h2>Evidence</h2><div class="grid" id="evidence"></div></div>\n<div class="section"><h2>Delivery</h2><div class="grid" id="delivery"></div></div>\n<div class="section"><h2>Changes</h2><div class="grid" id="changes"></div></div>\n</div>\n</section>\n</main>\n<script>\n(() => {\nconst APP_VERSION="1";\nconst UI_PROTOCOL="2026-01-26";\nconst terminal=new Set(["succeeded","failed","cancelled","rolled_back"]);\nlet seq=0;\nlet pending=new Map();\nlet nextId=1;\nlet snapshot=null;\nlet runId=null;\nlet chatContext=null;\nlet hostContext={};\nlet refreshTimer=null;\nlet reconnecting=false;\nconst el=id=>document.getElementById(id);\nconst card=el("card");\nfunction send(message){window.parent.postMessage(message,"*")}\nfunction request(method,params){const id=nextId++;send({jsonrpc:"2.0",id,method,params});return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});setTimeout(()=>{const item=pending.get(id);if(item){pending.delete(id);reject(new Error("timeout"))}},15000)})}\nfunction notify(method,params={}){send({jsonrpc:"2.0",method,params})}\nfunction text(node,value){node.textContent=value==null?"":String(value)}\nfunction modeAvailable(mode){const modes=hostContext&&hostContext.availableDisplayModes;return Array.isArray(modes)&&modes.includes(mode)}\nfunction applyContext(ctx){hostContext=ctx&&typeof ctx==="object"?ctx:{};const mode=typeof hostContext.displayMode==="string"?hostContext.displayMode:"inline";card.dataset.mode=mode;document.documentElement.dataset.theme=hostContext.theme||"";el("pip").hidden=!modeAvailable("pip");el("details").hidden=!modeAvailable("fullscreen")}\nfunction snapshotFromResult(result){const meta=result&&result._meta&&result._meta["atlas.task_progress_ui"];return meta&&meta.snapshot&&typeof meta.snapshot==="object"?meta.snapshot:null}\nfunction acceptSnapshot(next){if(!next||typeof next.sequence!=="number")return;if(next.sequence<seq)return;seq=next.sequence;snapshot=next;runId=next.run_id||runId;reconnecting=false;render();scheduleRefresh()}\nfunction useResult(result){const next=snapshotFromResult(result);if(next){acceptSnapshot(next);return}const structured=result&&result.structuredContent;if(structured&&structured.run_id){runId=structured.run_id;renderStructured(structured)}}\nfunction renderStructured(data){text(el("title"),"Task progress");text(el("status"),data.status||"unknown");text(el("freshness"),"Limited fallback");card.dataset.stale="false"}\nfunction stageLabel(stage){return String(stage.status||"unknown").replaceAll("_"," ")}\nfunction render(){\nif(!snapshot)return;\ncard.dataset.stale=reconnecting?"true":"false";\ntext(el("title"),snapshot.title||"Task progress");\ntext(el("status"),String(snapshot.status||"unknown").replaceAll("_"," "));\ntext(el("freshness"),reconnecting?"Reconnecting":"Up to date");\nconst stages=Array.isArray(snapshot.stages)?snapshot.stages:[];\nconst current=stages.find(item=>item.id===snapshot.current_stage_id);\ntext(el("current"),current?current.title:"No active stage");\nconst progress=snapshot.progress||{};\nconst track=el("track");\nconst bar=el("bar");\nif(progress.mode==="determinate"&&Number.isFinite(progress.total)&&progress.total>0){\nconst completed=Math.max(0,Math.min(Number(progress.completed)||0,Number(progress.total)));\nconst total=Number(progress.total);\ntrack.classList.remove("indeterminate");\ntrack.setAttribute("aria-valuemin","0");\ntrack.setAttribute("aria-valuemax",String(total));\ntrack.setAttribute("aria-valuenow",String(completed));\nbar.style.width=`${(completed/total)*100}%`;\ntext(el("count"),`${completed} / ${total}`);\n}else{\ntrack.classList.add("indeterminate");\ntrack.removeAttribute("aria-valuemin");\ntrack.removeAttribute("aria-valuemax");\ntrack.removeAttribute("aria-valuenow");\nbar.style.width="";\ntext(el("count"),"In progress");\n}\nconst blockers=Array.isArray(snapshot.blockers)?snapshot.blockers:[];\nconst blocker=el("blocker");\nif(blockers.length){blocker.hidden=false;text(blocker,blockers[0].message||blockers[0].status||"Blocked")}else{blocker.hidden=true;text(blocker,"")}\nconst stageRoot=el("stages");stageRoot.replaceChildren();\nfor(const stage of stages.slice(0,12)){\nconst row=document.createElement("div");row.className="stage";row.dataset.status=stage.status||"unknown";\nconst dot=document.createElement("span");dot.className="stage-dot";\nconst name=document.createElement("span");name.className="stage-name";text(name,stage.title||stage.id);\nconst state=document.createElement("span");state.className="stage-state";text(state,stageLabel(stage));\nrow.append(dot,name,state);stageRoot.append(row)\n}\nrenderTiles(el("checks"),snapshot.checks,"label","status");\nrenderTiles(el("evidence"),snapshot.artifacts,"label","status");\nconst delivery=Object.entries(snapshot.delivery||{}).map(([key,value])=>({label:key,status:value&&typeof value==="object"?(value.status||value.result||value.revision||"recorded"):"recorded"}));\nrenderTiles(el("delivery"),delivery,"label","status");\nconst changes=snapshot.changes||{};\nconst changeItems=[{label:"Files",status:String(changes.visible_count??changes.count??0)},{label:"Lines added",status:String(changes.added_lines??0)},{label:"Lines removed",status:String(changes.removed_lines??0)}];\nrenderTiles(el("changes"),changeItems,"label","status");\nel("cancel").hidden=!snapshot.cancel_supported||terminal.has(snapshot.status);\nqueueMicrotask(resize)\n}\nfunction renderTiles(root,items,labelKey,statusKey){\nroot.replaceChildren();\nconst list=Array.isArray(items)?items:[];\nif(!list.length){const empty=document.createElement("span");empty.className="empty";text(empty,"No records");root.append(empty);return}\nfor(const item of list.slice(0,24)){const tile=document.createElement("div");tile.className="tile";const strong=document.createElement("strong");text(strong,item[labelKey]||item.id||"Record");const span=document.createElement("span");text(span,item[statusKey]||"recorded");tile.append(strong,span);root.append(tile)}\n}\nfunction args(lastSequence=true){const out={run_id:runId};if(lastSequence&&seq>0)out.last_sequence=seq;if(chatContext)out.chat_context=chatContext;return out}\nasync function refresh(){\nif(!runId||reconnecting)return;\ntry{const result=await request("tools/call",{name:"task_progress_get",arguments:args(true)});useResult(result)}\ncatch(_){reconnecting=true;render()}\n}\nfunction scheduleRefresh(){\nif(refreshTimer){clearTimeout(refreshTimer);refreshTimer=null}\nif(!snapshot||terminal.has(snapshot.status))return;\nrefreshTimer=setTimeout(refresh,4000)\n}\nasync function setDisplay(mode){if(!modeAvailable(mode))return;try{const result=await request("ui/request-display-mode",{mode});applyContext({...hostContext,displayMode:result&&result.mode?result.mode:mode});render()}catch(_){}}\nasync function cancel(){\nif(!snapshot||!snapshot.cancel_supported)return;\nel("cancel").disabled=true;\ntry{const result=await request("tools/call",{name:"task_progress_cancel",arguments:args(false)});useResult(result)}finally{el("cancel").disabled=false}\n}\nfunction resize(){const rect=document.documentElement.getBoundingClientRect();notify("ui/notifications/size-changed",{width:Math.ceil(rect.width),height:Math.ceil(rect.height)})}\nwindow.addEventListener("message",event=>{\nif(event.source!==window.parent)return;\nconst message=event.data;\nif(!message||message.jsonrpc!=="2.0")return;\nif(Object.prototype.hasOwnProperty.call(message,"id")&&!message.method){\nconst item=pending.get(message.id);if(!item)return;pending.delete(message.id);if(message.error)item.reject(new Error(message.error.message||"request failed"));else item.resolve(message.result);return\n}\nif(message.method==="ui/notifications/tool-input"){\nconst input=message.params&&message.params.arguments||{};runId=typeof input.run_id==="string"?input.run_id:runId;chatContext=typeof input.chat_context==="string"?input.chat_context:chatContext;if(runId)refresh()\n}else if(message.method==="ui/notifications/tool-result"){useResult(message.params)}\nelse if(message.method==="ui/notifications/host-context-changed"){applyContext(message.params||{});render()}\nelse if(message.method==="ui/resource-teardown"){if(refreshTimer)clearTimeout(refreshTimer);if(Object.prototype.hasOwnProperty.call(message,"id"))send({jsonrpc:"2.0",id:message.id,result:{}})}\nelse if(message.method==="ui/notifications/request-teardown"){if(refreshTimer)clearTimeout(refreshTimer)}\n});\nel("pip").addEventListener("click",()=>setDisplay("pip"));\nel("details").addEventListener("click",()=>setDisplay("fullscreen"));\nel("cancel").addEventListener("click",cancel);\nrequest("ui/initialize",{appInfo:{name:"ATLAS Task Progress",version:APP_VERSION},appCapabilities:{availableDisplayModes:["inline","pip","fullscreen"]},protocolVersion:UI_PROTOCOL})\n.then(result=>{applyContext(result&&result.hostContext||{});notify("ui/notifications/initialized");resize();if(runId)refresh()})\n.catch(()=>{reconnecting=true;renderStructured({status:"unavailable"})});\n})();\n</script>\n</body>\n</html>'
TASK_PROGRESS_APP_V1_SHA256 = hashlib.sha256(TASK_PROGRESS_APP_V1_HTML.encode("utf-8")).hexdigest()
assert TASK_PROGRESS_APP_V1_SHA256 == "1de3c8f2940a00202faef802519094a94040c911545fce8107f8bb2478d20c6d"


TASK_PROGRESS_APP_V2_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ATLAS Task Progress</title>
<style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--bg:Canvas;--fg:CanvasText;--muted:color-mix(in srgb,CanvasText 58%,transparent);--line:color-mix(in srgb,CanvasText 16%,transparent);--surface:color-mix(in srgb,Canvas 92%,CanvasText 8%);--accent:LinkText;--danger:#b42318;--ok:#067647;--warn:#b54708}
*{box-sizing:border-box}
body{margin:0;background:transparent;color:var(--fg)}
main{max-width:980px;margin:0 auto;padding:12px}
.card{border:1px solid var(--line);border-radius:16px;background:var(--bg);overflow:hidden;box-shadow:0 1px 2px color-mix(in srgb,CanvasText 8%,transparent)}
.header{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:14px 14px 10px}
.title{min-width:0}
h1{font-size:15px;line-height:1.35;margin:0;font-weight:650;overflow-wrap:anywhere}
.subtitle{display:flex;align-items:center;gap:8px;margin-top:5px;font-size:12px;color:var(--muted);flex-wrap:wrap}
.status{font-weight:650;color:var(--fg)}
.fresh{display:inline-flex;align-items:center;gap:5px}
.dot{width:7px;height:7px;border-radius:999px;background:var(--ok)}
[data-stale="true"] .dot{background:var(--warn)}
.actions{display:flex;align-items:center;gap:7px;flex-wrap:wrap;justify-content:flex-end}
button{font:inherit;border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--fg);padding:7px 10px;cursor:pointer}
button:hover{filter:brightness(.97)}
button:disabled{opacity:.45;cursor:not-allowed}
button.primary{background:var(--fg);color:var(--bg);border-color:var(--fg)}
button.danger{color:var(--danger)}
button.compact{padding:7px 8px}
.summary{padding:0 14px 14px}
.progress-row{display:flex;align-items:center;justify-content:space-between;gap:12px;font-size:12px}
.track{height:7px;border-radius:999px;background:var(--surface);overflow:hidden;margin-top:8px}
.bar{height:100%;background:var(--accent);width:0;transition:width .2s ease}
.track.indeterminate .bar{width:35%;animation:slide 1.35s ease-in-out infinite}
@keyframes slide{0%{transform:translateX(-120%)}50%{transform:translateX(180%)}100%{transform:translateX(330%)}}
.blocker{margin-top:12px;padding:9px 10px;border-radius:10px;background:color-mix(in srgb,var(--warn) 11%,transparent);font-size:12px;line-height:1.4}
.stages{border-top:1px solid var(--line);padding:10px 14px 12px;display:grid;gap:7px}
.stage{display:grid;grid-template-columns:10px minmax(0,1fr) auto;gap:8px;align-items:center;font-size:12px}
.stage-dot{width:8px;height:8px;border:1px solid var(--line);border-radius:50%;background:var(--surface)}
.stage[data-status="succeeded"] .stage-dot{background:var(--ok);border-color:var(--ok)}
.stage[data-status="running"] .stage-dot{background:var(--accent);border-color:var(--accent)}
.stage[data-status="failed"] .stage-dot,.stage[data-status="blocked"] .stage-dot{background:var(--danger);border-color:var(--danger)}
.stage-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.stage-state{color:var(--muted)}
.details{display:none;border-top:1px solid var(--line);padding:14px}
[data-mode="fullscreen"] .details{display:grid;gap:16px}
.section h2{font-size:12px;margin:0 0 8px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px}
.tile{border:1px solid var(--line);border-radius:10px;padding:9px;font-size:12px;min-width:0}
.tile strong{display:block;margin-bottom:4px;overflow-wrap:anywhere}
.tile span{color:var(--muted);overflow-wrap:anywhere}
.empty{color:var(--muted);font-size:12px}
[data-mode="pip"] main{padding:8px}
[data-mode="pip"] .stages{display:none}
[data-mode="pip"] .header{padding:10px 10px 8px}
[data-mode="pip"] .summary{padding:0 10px 10px}
@media(max-width:520px){main{padding:8px}.header{flex-direction:column}.actions{width:100%;justify-content:flex-start}.stage-state{display:none}}
</style>
</head>
<body>
<main>
<section class="card" id="card" data-mode="inline" data-stale="false" aria-live="polite">
<div class="header">
<div class="title">
<h1 id="title">Task progress</h1>
<div class="subtitle"><span class="status" id="status">Loading</span><span class="fresh"><span class="dot"></span><span id="freshness">Connecting</span></span></div>
</div>
<div class="actions">
<button class="compact" id="pip" type="button" hidden aria-label="Keep task progress visible">Pin</button>
<button class="primary" id="details" type="button" hidden>Details</button>
<button class="danger" id="cancel" type="button" hidden>Cancel</button>
</div>
</div>
<div class="summary">
<div class="progress-row"><span id="current">Waiting for task state</span><span id="count"></span></div>
<div class="track indeterminate" id="track" role="progressbar" aria-label="Task progress"><div class="bar" id="bar"></div></div>
<div class="blocker" id="blocker" hidden></div>
</div>
<div class="stages" id="stages"></div>
<div class="details" id="detailPane">
<div class="section"><h2>Acceptance</h2><div class="grid" id="checks"></div></div>
<div class="section"><h2>Evidence</h2><div class="grid" id="evidence"></div></div>
<div class="section"><h2>Delivery</h2><div class="grid" id="delivery"></div></div>
<div class="section"><h2>Changes</h2><div class="grid" id="changes"></div></div>
</div>
</section>
</main>
<script>
(() => {
const APP_VERSION="1";
const UI_PROTOCOL="2026-01-26";
const terminal=new Set(["succeeded","failed","cancelled","rolled_back"]);
let seq=0;
let pending=new Map();
let nextId=1;
let snapshot=null;
let runId=null;
let chatContext=null;
let hostContext={};
let refreshTimer=null;
let reconnecting=false;
let standardBridgeState="pending";
let resolveStandardBridge;
const standardBridgeReady=new Promise(resolve=>{resolveStandardBridge=resolve});
let refreshInFlight=false;
const el=id=>document.getElementById(id);
const card=el("card");
function openAIHost(){return window.openai&&typeof window.openai==="object"?window.openai:null}
function openAIValue(globals,key){if(globals&&typeof globals==="object"&&Object.prototype.hasOwnProperty.call(globals,key))return globals[key];const host=openAIHost();return host?host[key]:undefined}
function send(message){window.parent.postMessage(message,"*")}
function request(method,params){const id=nextId++;send({jsonrpc:"2.0",id,method,params});return new Promise((resolve,reject)=>{pending.set(id,{resolve,reject});setTimeout(()=>{const item=pending.get(id);if(item){pending.delete(id);reject(new Error("timeout"))}},15000)})}
function notify(method,params={}){send({jsonrpc:"2.0",method,params})}
function text(node,value){node.textContent=value==null?"":String(value)}
function modeAvailable(mode){const host=openAIHost();if(host&&typeof host.requestDisplayMode==="function"&&(mode==="pip"||mode==="fullscreen"))return true;const modes=hostContext&&hostContext.availableDisplayModes;return Array.isArray(modes)&&modes.includes(mode)}
function applyContext(ctx){const next=ctx&&typeof ctx==="object"?ctx:{};hostContext={...hostContext,...next};const mode=typeof hostContext.displayMode==="string"?hostContext.displayMode:"inline";card.dataset.mode=mode;document.documentElement.dataset.theme=hostContext.theme||"";el("pip").hidden=!modeAvailable("pip");el("details").hidden=!modeAvailable("fullscreen")}
function snapshotFromResult(result){const meta=result&&result._meta&&result._meta["atlas.task_progress_ui"];return meta&&meta.snapshot&&typeof meta.snapshot==="object"?meta.snapshot:null}
function acceptSnapshot(next){if(!next||typeof next.sequence!=="number")return;if(next.sequence<seq)return;seq=next.sequence;snapshot=next;runId=next.run_id||runId;reconnecting=false;render();scheduleRefresh()}
function useResult(result){const next=snapshotFromResult(result);if(next){acceptSnapshot(next);return}const structured=result&&result.structuredContent;if(structured&&structured.run_id){runId=structured.run_id;renderStructured(structured)}}
function openAIResult(globals){const structured=openAIValue(globals,"toolOutput");const meta=openAIValue(globals,"toolResponseMetadata");if((!structured||typeof structured!=="object")&&(!meta||typeof meta!=="object"))return null;return {structuredContent:structured&&typeof structured==="object"?structured:{},_meta:meta&&typeof meta==="object"?meta:{}}}
function hydrateOpenAI(globals){const host=openAIHost();if(!host&&(!globals||typeof globals!=="object"))return false;const input=openAIValue(globals,"toolInput");if(input&&typeof input==="object"){runId=typeof input.run_id==="string"?input.run_id:runId;chatContext=typeof input.chat_context==="string"?input.chat_context:chatContext}const ctx={};const theme=openAIValue(globals,"theme");const displayMode=openAIValue(globals,"displayMode");if(typeof theme==="string")ctx.theme=theme;if(typeof displayMode==="string")ctx.displayMode=displayMode;if(host&&typeof host.requestDisplayMode==="function")ctx.availableDisplayModes=["inline","pip","fullscreen"];applyContext(ctx);const result=openAIResult(globals);if(result)useResult(result);return true}
function settleStandardBridge(state){if(standardBridgeState!=="pending")return;standardBridgeState=state;resolveStandardBridge(state)}
function standardCallTool(name,toolArgs){return request("tools/call",{name,arguments:toolArgs})}
async function callTool(name,toolArgs){
if(standardBridgeState==="pending")await standardBridgeReady;
if(standardBridgeState==="ready")return standardCallTool(name,toolArgs);
const host=openAIHost();
if(host&&typeof host.callTool==="function")return host.callTool(name,toolArgs);
throw new Error("tool bridge unavailable")
}
function renderStructured(data){text(el("title"),"Task progress");text(el("status"),data.status||"unknown");text(el("freshness"),"Limited fallback");card.dataset.stale="false"}
function stageLabel(stage){return String(stage.status||"unknown").replaceAll("_"," ")}
function render(){
if(!snapshot)return;
card.dataset.stale=reconnecting?"true":"false";
text(el("title"),snapshot.title||"Task progress");
text(el("status"),String(snapshot.status||"unknown").replaceAll("_"," "));
text(el("freshness"),reconnecting?"Reconnecting":"Up to date");
const stages=Array.isArray(snapshot.stages)?snapshot.stages:[];
const current=stages.find(item=>item.id===snapshot.current_stage_id);
text(el("current"),current?current.title:"No active stage");
const progress=snapshot.progress||{};
const track=el("track");
const bar=el("bar");
if(progress.mode==="determinate"&&Number.isFinite(progress.total)&&progress.total>0){
const completed=Math.max(0,Math.min(Number(progress.completed)||0,Number(progress.total)));
const total=Number(progress.total);
track.classList.remove("indeterminate");
track.setAttribute("aria-valuemin","0");
track.setAttribute("aria-valuemax",String(total));
track.setAttribute("aria-valuenow",String(completed));
bar.style.width=`${(completed/total)*100}%`;
text(el("count"),`${completed} / ${total}`);
}else{
track.classList.add("indeterminate");
track.removeAttribute("aria-valuemin");
track.removeAttribute("aria-valuemax");
track.removeAttribute("aria-valuenow");
bar.style.width="";
text(el("count"),"In progress");
}
const blockers=Array.isArray(snapshot.blockers)?snapshot.blockers:[];
const blocker=el("blocker");
if(blockers.length){blocker.hidden=false;text(blocker,blockers[0].message||blockers[0].status||"Blocked")}else{blocker.hidden=true;text(blocker,"")}
const stageRoot=el("stages");stageRoot.replaceChildren();
for(const stage of stages.slice(0,12)){
const row=document.createElement("div");row.className="stage";row.dataset.status=stage.status||"unknown";
const dot=document.createElement("span");dot.className="stage-dot";
const name=document.createElement("span");name.className="stage-name";text(name,stage.title||stage.id);
const state=document.createElement("span");state.className="stage-state";text(state,stageLabel(stage));
row.append(dot,name,state);stageRoot.append(row)
}
renderTiles(el("checks"),snapshot.checks,"label","status");
renderTiles(el("evidence"),snapshot.artifacts,"label","status");
const delivery=Object.entries(snapshot.delivery||{}).map(([key,value])=>({label:key,status:value&&typeof value==="object"?(value.status||value.result||value.revision||"recorded"):"recorded"}));
renderTiles(el("delivery"),delivery,"label","status");
const changes=snapshot.changes||{};
const changeItems=[{label:"Files",status:String(changes.visible_count??changes.count??0)},{label:"Lines added",status:String(changes.added_lines??0)},{label:"Lines removed",status:String(changes.removed_lines??0)}];
renderTiles(el("changes"),changeItems,"label","status");
el("cancel").hidden=!snapshot.cancel_supported||terminal.has(snapshot.status);
queueMicrotask(resize)
}
function renderTiles(root,items,labelKey,statusKey){
root.replaceChildren();
const list=Array.isArray(items)?items:[];
if(!list.length){const empty=document.createElement("span");empty.className="empty";text(empty,"No records");root.append(empty);return}
for(const item of list.slice(0,24)){const tile=document.createElement("div");tile.className="tile";const strong=document.createElement("strong");text(strong,item[labelKey]||item.id||"Record");const span=document.createElement("span");text(span,item[statusKey]||"recorded");tile.append(strong,span);root.append(tile)}
}
function args(lastSequence=true){const out={run_id:runId};if(lastSequence&&seq>0)out.last_sequence=seq;if(chatContext)out.chat_context=chatContext;return out}
async function refresh(){
if(!runId||reconnecting||refreshInFlight)return;
refreshInFlight=true;
try{const result=await callTool("task_progress_get",args(true));useResult(result)}
catch(_){reconnecting=true;render();scheduleRefresh()}
finally{refreshInFlight=false}
}
function scheduleRefresh(){
if(refreshTimer){clearTimeout(refreshTimer);refreshTimer=null}
if(!runId||(snapshot&&terminal.has(snapshot.status)))return;
refreshTimer=setTimeout(()=>{refreshTimer=null;reconnecting=false;refresh()},4000)
}
async function setDisplay(mode){if(!modeAvailable(mode))return;try{const host=openAIHost();const result=host&&typeof host.requestDisplayMode==="function"?await host.requestDisplayMode({mode}):await request("ui/request-display-mode",{mode});applyContext({...hostContext,displayMode:result&&result.mode?result.mode:mode});render()}catch(_){}}
async function cancel(){
if(!snapshot||!snapshot.cancel_supported)return;
el("cancel").disabled=true;
try{const result=await callTool("task_progress_cancel",args(false));useResult(result)}finally{el("cancel").disabled=false}
}
function resize(){const rect=document.documentElement.getBoundingClientRect();const width=Math.ceil(rect.width);const height=Math.ceil(rect.height);const host=openAIHost();if(host&&typeof host.notifyIntrinsicHeight==="function"){try{host.notifyIntrinsicHeight(height)}catch(_){}}notify("ui/notifications/size-changed",{width,height})}
window.addEventListener("message",event=>{
if(event.source!==window.parent)return;
const message=event.data;
if(!message||message.jsonrpc!=="2.0")return;
if(Object.prototype.hasOwnProperty.call(message,"id")&&!message.method){
const item=pending.get(message.id);if(!item)return;pending.delete(message.id);if(message.error)item.reject(new Error(message.error.message||"request failed"));else item.resolve(message.result);return
}
if(message.method==="ui/notifications/tool-input"){
const input=message.params&&message.params.arguments||{};runId=typeof input.run_id==="string"?input.run_id:runId;chatContext=typeof input.chat_context==="string"?input.chat_context:chatContext;if(runId)refresh()
}else if(message.method==="ui/notifications/tool-result"){useResult(message.params)}
else if(message.method==="ui/notifications/host-context-changed"){applyContext(message.params||{});render()}
else if(message.method==="ui/resource-teardown"){if(refreshTimer)clearTimeout(refreshTimer);if(Object.prototype.hasOwnProperty.call(message,"id"))send({jsonrpc:"2.0",id:message.id,result:{}})}
else if(message.method==="ui/notifications/request-teardown"){if(refreshTimer)clearTimeout(refreshTimer)}
});
window.addEventListener("openai:set_globals",event=>{const globals=event&&event.detail&&event.detail.globals;const previousRunId=runId;hydrateOpenAI(globals);resize();if(runId&&runId!==previousRunId)refresh()});
el("pip").addEventListener("click",()=>setDisplay("pip"));
el("details").addEventListener("click",()=>setDisplay("fullscreen"));
el("cancel").addEventListener("click",cancel);
const openAIBootstrapped=hydrateOpenAI();
if(openAIBootstrapped){resize();if(runId)refresh()}
request("ui/initialize",{appInfo:{name:"ATLAS Task Progress",version:APP_VERSION},appCapabilities:{availableDisplayModes:["inline","pip","fullscreen"]},protocolVersion:UI_PROTOCOL})
.then(result=>{settleStandardBridge("ready");applyContext(result&&result.hostContext||{});notify("ui/notifications/initialized");resize();if(runId)refresh()})
.catch(()=>{settleStandardBridge("unavailable");if(!openAIHost()){reconnecting=true;renderStructured({status:"unavailable"})}});
})();
</script>
</body>
</html>"""

TASK_PROGRESS_APP_V2_SHA256 = hashlib.sha256(
    TASK_PROGRESS_APP_V2_HTML.encode("utf-8")
).hexdigest()
assert TASK_PROGRESS_APP_V2_SHA256 == "4730fb0fe981206079cc50d1155d14e80103d616e5852d1630d2b3d2f6ed5b2f"


def _task_progress_app_v3_html() -> str:
    html = TASK_PROGRESS_APP_V2_HTML
    replacements = (
        (
            '''function standardCallTool(name,toolArgs){return request("tools/call",{name,arguments:toolArgs})}
async function callTool(name,toolArgs){
if(standardBridgeState==="pending")await standardBridgeReady;
if(standardBridgeState==="ready")return standardCallTool(name,toolArgs);
const host=openAIHost();
if(host&&typeof host.callTool==="function")return host.callTool(name,toolArgs);
throw new Error("tool bridge unavailable")
}''',
            '''function standardCallTool(name,toolArgs){return request("tools/call",{name,arguments:toolArgs})}
function isDefiniteStandardBridgeUnavailable(error){return error&&error.code===-32601}
function legacyCallTool(name,toolArgs){
const host=openAIHost();
if(host&&typeof host.callTool==="function")return host.callTool(name,toolArgs);
throw new Error("tool bridge unavailable")
}
async function callTool(name,toolArgs,{allowLegacyFallback=false}={}){
if(standardBridgeState==="pending")await standardBridgeReady;
if(standardBridgeState==="ready"){
try{return await standardCallTool(name,toolArgs)}
catch(error){
if(!allowLegacyFallback||!isDefiniteStandardBridgeUnavailable(error))throw error;
standardBridgeState="unavailable"
}
}
return legacyCallTool(name,toolArgs)
}''',
        ),
        (
            'try{const result=await callTool("task_progress_get",args(true));useResult(result)}',
            'try{const result=await callTool("task_progress_get",args(true),{allowLegacyFallback:true});useResult(result)}',
        ),
        (
            '''async function cancel(){
if(!snapshot||!snapshot.cancel_supported)return;
el("cancel").disabled=true;
try{const result=await callTool("task_progress_cancel",args(false));useResult(result)}finally{el("cancel").disabled=false}
}''',
            '''async function cancel(){
if(!snapshot||!snapshot.cancel_supported)return;
el("cancel").disabled=true;
try{const result=await callTool("task_progress_cancel",args(false));useResult(result)}
catch(_){reconnecting=true;render();scheduleRefresh()}
finally{el("cancel").disabled=false}
}''',
        ),
        (
            'const item=pending.get(message.id);if(!item)return;pending.delete(message.id);if(message.error)item.reject(new Error(message.error.message||"request failed"));else item.resolve(message.result);return',
            'const item=pending.get(message.id);if(!item)return;pending.delete(message.id);if(message.error){const error=new Error(message.error.message||"request failed");if(Number.isInteger(message.error.code))error.code=message.error.code;item.reject(error)}else item.resolve(message.result);return',
        ),
    )
    for old, new in replacements:
        if html.count(old) != 1:
            raise RuntimeError("Task Progress v3 source replacement drift")
        html = html.replace(old, new, 1)
    return html


TASK_PROGRESS_APP_V3_HTML = _task_progress_app_v3_html()
TASK_PROGRESS_APP_V3_SHA256 = hashlib.sha256(
    TASK_PROGRESS_APP_V3_HTML.encode("utf-8")
).hexdigest()
assert TASK_PROGRESS_APP_V3_SHA256 == "89c7a07f72b28d38c232925c323879e42acdff239f7ac376b344c64e53600cae"


def _task_progress_app_v4_html() -> str:
    html = TASK_PROGRESS_APP_V3_HTML
    old_call_tool = '''function standardCallTool(name,toolArgs){return request("tools/call",{name,arguments:toolArgs})}
function isDefiniteStandardBridgeUnavailable(error){return error&&error.code===-32601}
function legacyCallTool(name,toolArgs){
const host=openAIHost();
if(host&&typeof host.callTool==="function")return host.callTool(name,toolArgs);
throw new Error("tool bridge unavailable")
}
async function callTool(name,toolArgs,{allowLegacyFallback=false}={}){
if(standardBridgeState==="pending")await standardBridgeReady;
if(standardBridgeState==="ready"){
try{return await standardCallTool(name,toolArgs)}
catch(error){
if(!allowLegacyFallback||!isDefiniteStandardBridgeUnavailable(error))throw error;
standardBridgeState="unavailable"
}
}
return legacyCallTool(name,toolArgs)
}'''
    new_call_tool = '''function standardCallTool(name,toolArgs){return request("tools/call",{name,arguments:toolArgs})}
async function callTool(name,toolArgs){
const host=openAIHost();
if(host&&typeof host.callTool==="function")return host.callTool(name,toolArgs);
if(standardBridgeState==="pending")await standardBridgeReady;
if(standardBridgeState==="ready")return standardCallTool(name,toolArgs);
throw new Error("tool bridge unavailable")
}'''
    if html.count(old_call_tool) != 1:
        raise RuntimeError("Task Progress v4 tool bridge source replacement drift")
    html = html.replace(old_call_tool, new_call_tool, 1)
    old_get = 'try{const result=await callTool("task_progress_get",args(true),{allowLegacyFallback:true});useResult(result)}'
    new_get = 'try{const result=await callTool("task_progress_get",args(true));useResult(result)}'
    if html.count(old_get) != 1:
        raise RuntimeError("Task Progress v4 GET source replacement drift")
    html = html.replace(old_get, new_get, 1)
    old_initialize_refresh = '.then(result=>{settleStandardBridge("ready");applyContext(result&&result.hostContext||{});notify("ui/notifications/initialized");resize();if(runId)refresh()})'
    new_initialize_refresh = '.then(result=>{settleStandardBridge("ready");applyContext(result&&result.hostContext||{});notify("ui/notifications/initialized");resize();if(runId&&!openAIBootstrapped)refresh()})'
    if html.count(old_initialize_refresh) != 1:
        raise RuntimeError("Task Progress v4 initialize refresh source replacement drift")
    return html.replace(old_initialize_refresh, new_initialize_refresh, 1)


TASK_PROGRESS_APP_V4_HTML = _task_progress_app_v4_html()
TASK_PROGRESS_APP_V4_SHA256 = hashlib.sha256(
    TASK_PROGRESS_APP_V4_HTML.encode("utf-8")
).hexdigest()
assert TASK_PROGRESS_APP_V4_SHA256 == "2e2f901bdba42d47e28cf0655ccdf15acab323f13d89a8e3eb45c4f48e834de7"


def _task_progress_app_v5_html() -> str:
    html = TASK_PROGRESS_APP_V4_HTML
    old_tool_input = 'const input=message.params&&message.params.arguments||{};runId=typeof input.run_id==="string"?input.run_id:runId;chatContext=typeof input.chat_context==="string"?input.chat_context:chatContext;if(runId)refresh()'
    new_tool_input = 'const params=message.params&&typeof message.params==="object"?message.params:{};const input=params.arguments&&typeof params.arguments==="object"?params.arguments:params;runId=typeof input.run_id==="string"?input.run_id:runId;chatContext=typeof input.chat_context==="string"?input.chat_context:chatContext;if(runId)refresh()'
    if html.count(old_tool_input) != 1:
        raise RuntimeError("Task Progress v5 tool-input envelope source replacement drift")
    return html.replace(old_tool_input, new_tool_input, 1)


TASK_PROGRESS_APP_V5_HTML = _task_progress_app_v5_html()
TASK_PROGRESS_APP_V5_SHA256 = hashlib.sha256(
    TASK_PROGRESS_APP_V5_HTML.encode("utf-8")
).hexdigest()
assert TASK_PROGRESS_APP_V5_SHA256 == "e7f7422c07605fcee0d72364cea8bf342455746e6807351b5f7e7dfb4f44b31b"


def _task_progress_app_v6_html() -> str:
    html = TASK_PROGRESS_APP_V5_HTML
    old_call_tool = '''function standardCallTool(name,toolArgs){return request("tools/call",{name,arguments:toolArgs})}
async function callTool(name,toolArgs){
const host=openAIHost();
if(host&&typeof host.callTool==="function")return host.callTool(name,toolArgs);
if(standardBridgeState==="pending")await standardBridgeReady;
if(standardBridgeState==="ready")return standardCallTool(name,toolArgs);
throw new Error("tool bridge unavailable")
}'''
    new_call_tool = '''function standardCallTool(name,toolArgs){return request("tools/call",{name,arguments:toolArgs})}
function isDefiniteStandardBridgeUnavailable(error){return error&&error.code===-32601}
function compatibilityCallTool(name,toolArgs){
const host=openAIHost();
if(host&&typeof host.callTool==="function")return host.callTool(name,toolArgs);
throw new Error("tool bridge unavailable")
}
async function callTool(name,toolArgs,{allowCompatibilityFallback=false}={}){
if(standardBridgeState==="pending")await standardBridgeReady;
if(standardBridgeState==="ready"){
try{return await standardCallTool(name,toolArgs)}
catch(error){
if(!allowCompatibilityFallback||!isDefiniteStandardBridgeUnavailable(error))throw error;
standardBridgeState="unavailable"
}
}
return compatibilityCallTool(name,toolArgs)
}'''
    if html.count(old_call_tool) != 1:
        raise RuntimeError("Task Progress v6 tool bridge source replacement drift")
    html = html.replace(old_call_tool, new_call_tool, 1)
    old_get = 'try{const result=await callTool("task_progress_get",args(true));useResult(result)}'
    new_get = 'try{const result=await callTool("task_progress_get",args(true),{allowCompatibilityFallback:true});useResult(result)}'
    if html.count(old_get) != 1:
        raise RuntimeError("Task Progress v6 GET source replacement drift")
    return html.replace(old_get, new_get, 1)


TASK_PROGRESS_APP_V6_HTML = _task_progress_app_v6_html()
TASK_PROGRESS_APP_V6_SHA256 = hashlib.sha256(
    TASK_PROGRESS_APP_V6_HTML.encode("utf-8")
).hexdigest()
assert TASK_PROGRESS_APP_V6_SHA256 == "21fe88c2351fb7a896e1b5c690b3914fae8d4b3e286238677b4e4d8698fc1729"


def _task_progress_app_v7_html() -> str:
    html = TASK_PROGRESS_APP_V6_HTML
    old_initialize = '.then(result=>{settleStandardBridge("ready");applyContext(result&&result.hostContext||{});notify("ui/notifications/initialized");resize();if(runId&&!openAIBootstrapped)refresh()})'
    new_initialize = '.then(result=>{const capabilities=result&&result.hostCapabilities;settleStandardBridge(capabilities&&capabilities.serverTools?"ready":"unavailable");applyContext(result&&result.hostContext||{});notify("ui/notifications/initialized");resize();if(runId&&!openAIBootstrapped)refresh()})'
    if html.count(old_initialize) != 1:
        raise RuntimeError("Task Progress v7 serverTools capability source replacement drift")
    return html.replace(old_initialize, new_initialize, 1)


TASK_PROGRESS_APP_V7_HTML = _task_progress_app_v7_html()
TASK_PROGRESS_APP_V7_SHA256 = hashlib.sha256(
    TASK_PROGRESS_APP_V7_HTML.encode("utf-8")
).hexdigest()
assert TASK_PROGRESS_APP_V7_SHA256 == "e5ec527a24436146616d4ba4595aa274157dbb9dae6917d9e7e65fc1ff35e364"


def _task_progress_app_v8_html() -> str:
    html = TASK_PROGRESS_APP_V7_HTML
    old_result = 'function openAIResult(globals){const structured=openAIValue(globals,"toolOutput");const meta=openAIValue(globals,"toolResponseMetadata");if((!structured||typeof structured!=="object")&&(!meta||typeof meta!=="object"))return null;return {structuredContent:structured&&typeof structured==="object"?structured:{},_meta:meta&&typeof meta==="object"?meta:{}}}'
    new_result = 'function openAIResult(globals){const structured=openAIValue(globals,"toolOutput");const meta=openAIValue(globals,"toolResponseMetadata");const full=meta&&typeof meta==="object"&&meta.mcp_tool_result&&typeof meta.mcp_tool_result==="object"?meta.mcp_tool_result:meta&&typeof meta==="object"&&meta.call_tool_result&&typeof meta.call_tool_result==="object"?meta.call_tool_result:null;if(full)return full;if((!structured||typeof structured!=="object")&&(!meta||typeof meta!=="object"))return null;return {structuredContent:structured&&typeof structured==="object"?structured:{},_meta:meta&&typeof meta==="object"?meta:{}}}'
    if html.count(old_result) != 1:
        raise RuntimeError("Task Progress v8 ChatGPT metadata envelope source replacement drift")
    return html.replace(old_result, new_result, 1)


TASK_PROGRESS_APP_V8_HTML = _task_progress_app_v8_html()
TASK_PROGRESS_APP_V8_SHA256 = hashlib.sha256(
    TASK_PROGRESS_APP_V8_HTML.encode("utf-8")
).hexdigest()
assert TASK_PROGRESS_APP_V8_SHA256 == "fdb4732537feeedca875a56b8c9b2b0b2becfd6cfcf7ac229c8ebf800da3276a"


def _task_progress_app_v9_html() -> str:
    html = TASK_PROGRESS_APP_V8_HTML
    old_initialize = '''request("ui/initialize",{appInfo:{name:"ATLAS Task Progress",version:APP_VERSION},appCapabilities:{availableDisplayModes:["inline","pip","fullscreen"]},protocolVersion:UI_PROTOCOL})
.then(result=>{const capabilities=result&&result.hostCapabilities;settleStandardBridge(capabilities&&capabilities.serverTools?"ready":"unavailable");applyContext(result&&result.hostContext||{});notify("ui/notifications/initialized");resize();if(runId&&!openAIBootstrapped)refresh()})
.catch(()=>{settleStandardBridge("unavailable");if(!openAIHost()){reconnecting=true;renderStructured({status:"unavailable"})}});'''
    new_initialize = '''function initializeHostBridge(){return request("ui/initialize",{appInfo:{name:"ATLAS Task Progress",version:APP_VERSION},appCapabilities:{availableDisplayModes:["inline","pip","fullscreen"]},protocolVersion:UI_PROTOCOL})
.then(result=>{const capabilities=result&&result.hostCapabilities;settleStandardBridge(capabilities&&capabilities.serverTools?"ready":"unavailable");applyContext(result&&result.hostContext||{});notify("ui/notifications/initialized");resize();if(runId&&!openAIBootstrapped)refresh()})
.catch(()=>{settleStandardBridge("unavailable");if(!openAIHost()){reconnecting=true;renderStructured({status:"unavailable"})}})}
function deferInitializeHostBridge(){setTimeout(()=>{initializeHostBridge()},0)}
if(document.readyState==="complete")deferInitializeHostBridge();else window.addEventListener("load",deferInitializeHostBridge,{once:true});'''
    if html.count(old_initialize) != 1:
        raise RuntimeError("Task Progress v9 deferred initialization source replacement drift")
    return html.replace(old_initialize, new_initialize, 1)


TASK_PROGRESS_APP_V9_HTML = _task_progress_app_v9_html()
TASK_PROGRESS_APP_V9_SHA256 = hashlib.sha256(
    TASK_PROGRESS_APP_V9_HTML.encode("utf-8")
).hexdigest()
assert TASK_PROGRESS_APP_V9_SHA256 == "5be04c885ca05b86f193e2148c03218626ddbb73d5147658406e2c62d881eae6"


def _task_progress_app_v10_html() -> str:
    html = TASK_PROGRESS_APP_V9_HTML
    old_call_tool = '''async function callTool(name,toolArgs,{allowCompatibilityFallback=false}={}){
if(standardBridgeState==="pending")await standardBridgeReady;
if(standardBridgeState==="ready"){
try{return await standardCallTool(name,toolArgs)}
catch(error){
if(!allowCompatibilityFallback||!isDefiniteStandardBridgeUnavailable(error))throw error;
standardBridgeState="unavailable"
}
}
return compatibilityCallTool(name,toolArgs)
}'''
    new_call_tool = '''async function callTool(name,toolArgs,{allowCompatibilityFallback=false}={}){
if(standardBridgeState==="pending"){
const host=openAIHost();
if(allowCompatibilityFallback&&host&&typeof host.callTool==="function"){
const state=await Promise.race([standardBridgeReady,new Promise(resolve=>setTimeout(()=>resolve("compatibility-timeout"),500))]);
if(state==="compatibility-timeout"&&standardBridgeState==="pending")return compatibilityCallTool(name,toolArgs)
}else await standardBridgeReady
}
if(standardBridgeState==="ready"){
try{return await standardCallTool(name,toolArgs)}
catch(error){
if(!allowCompatibilityFallback||!isDefiniteStandardBridgeUnavailable(error))throw error;
standardBridgeState="unavailable"
}
}
return compatibilityCallTool(name,toolArgs)
}'''
    if html.count(old_call_tool) != 1:
        raise RuntimeError("Task Progress v10 pending compatibility fallback source replacement drift")
    return html.replace(old_call_tool, new_call_tool, 1)


TASK_PROGRESS_APP_HTML = _task_progress_app_v10_html()
TASK_PROGRESS_APP_SHA256 = hashlib.sha256(
    TASK_PROGRESS_APP_HTML.encode("utf-8")
).hexdigest()
assert TASK_PROGRESS_APP_SHA256 == "18e1083af7218f7f4d64918bad29b018348db2317b9c5d06a4a94ea7f3ff8a7c"


def task_progress_apps_negotiated(
    settings: Settings,
    admission: ModernRequestAdmission | None,
    presentation: PresentationContext,
) -> bool:
    if not settings.gateway_task_progress_ui_enabled or admission is None:
        return False
    if (
        presentation.allowed_tool_names is not None
        and not TASK_PROGRESS_TOOL_NAMES.issubset(presentation.allowed_tool_names)
    ):
        return False
    extensions = admission.client_capabilities.get("extensions")
    if not isinstance(extensions, Mapping):
        return False
    app_settings = extensions.get(MCP_APPS_EXTENSION_ID)
    if not isinstance(app_settings, Mapping):
        return False
    mime_types = app_settings.get("mimeTypes")
    return isinstance(mime_types, list | tuple) and TASK_PROGRESS_RESOURCE_MIME in mime_types


def task_progress_server_extensions(apps_negotiated: bool) -> dict[str, Any]:
    if not apps_negotiated:
        return {}
    return {MCP_APPS_EXTENSION_ID: {}}


def task_progress_resource_meta() -> dict[str, Any]:
    return {
        "ui": {
            "csp": {
                "connectDomains": [],
                "resourceDomains": [],
                "frameDomains": [],
                "baseUriDomains": [],
            },
            "permissions": {},
            "prefersBorder": True,
        }
    }


def task_progress_resource_list_result() -> dict[str, Any]:
    def item(uri: str, *, legacy_version: str | None) -> dict[str, Any]:
        suffix = f" (legacy {legacy_version})" if legacy_version else ""
        return {
            "uri": uri,
            "name": f"ATLAS Task Progress{suffix}",
            "title": f"ATLAS Task Progress{suffix}",
            "description": (
                "Frozen compatibility Task Progress App resource."
                if legacy_version
                else "Interactive evidence-backed task progress for the authenticated Gateway run."
            ),
            "mimeType": TASK_PROGRESS_RESOURCE_MIME,
            "_meta": task_progress_resource_meta(),
        }

    return {
        "resources": [
            item(TASK_PROGRESS_RESOURCE_URI, legacy_version=None),
            item(TASK_PROGRESS_RESOURCE_V9_URI, legacy_version="v9"),
            item(TASK_PROGRESS_RESOURCE_V8_URI, legacy_version="v8"),
            item(TASK_PROGRESS_RESOURCE_V7_URI, legacy_version="v7"),
            item(TASK_PROGRESS_RESOURCE_V6_URI, legacy_version="v6"),
            item(TASK_PROGRESS_RESOURCE_V5_URI, legacy_version="v5"),
            item(TASK_PROGRESS_RESOURCE_V4_URI, legacy_version="v4"),
            item(TASK_PROGRESS_RESOURCE_V3_URI, legacy_version="v3"),
            item(TASK_PROGRESS_RESOURCE_V2_URI, legacy_version="v2"),
            item(TASK_PROGRESS_RESOURCE_V1_URI, legacy_version="v1"),
        ]
    }


def task_progress_resource_read_result(uri: str) -> dict[str, Any]:
    if uri == TASK_PROGRESS_RESOURCE_URI:
        text = TASK_PROGRESS_APP_HTML
    elif uri == TASK_PROGRESS_RESOURCE_V9_URI:
        text = TASK_PROGRESS_APP_V9_HTML
    elif uri == TASK_PROGRESS_RESOURCE_V8_URI:
        text = TASK_PROGRESS_APP_V8_HTML
    elif uri == TASK_PROGRESS_RESOURCE_V7_URI:
        text = TASK_PROGRESS_APP_V7_HTML
    elif uri == TASK_PROGRESS_RESOURCE_V6_URI:
        text = TASK_PROGRESS_APP_V6_HTML
    elif uri == TASK_PROGRESS_RESOURCE_V5_URI:
        text = TASK_PROGRESS_APP_V5_HTML
    elif uri == TASK_PROGRESS_RESOURCE_V4_URI:
        text = TASK_PROGRESS_APP_V4_HTML
    elif uri == TASK_PROGRESS_RESOURCE_V3_URI:
        text = TASK_PROGRESS_APP_V3_HTML
    elif uri == TASK_PROGRESS_RESOURCE_V2_URI:
        text = TASK_PROGRESS_APP_V2_HTML
    elif uri == TASK_PROGRESS_RESOURCE_V1_URI:
        text = TASK_PROGRESS_APP_V1_HTML
    else:
        raise ValueError("Unknown Task Progress UI resource")
    return {
        "contents": [
            {
                "uri": uri,
                "mimeType": TASK_PROGRESS_RESOURCE_MIME,
                "text": text,
                "_meta": task_progress_resource_meta(),
            }
        ]
    }


def _object_schema(
    properties: dict[str, Any] | None = None,
    required: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": properties or {},
        "required": required or [],
        "additionalProperties": False,
    }


def _input_schema(*, include_sequence: bool) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "run_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 160,
            "description": "Opaque authorized Task Progress run identifier.",
        }
    }
    if include_sequence:
        properties["last_sequence"] = {
            "type": "integer",
            "minimum": 0,
            "description": "Last Task Progress sequence already observed by the caller.",
        }
    return _object_schema(properties, ["run_id"])


def _output_schema() -> dict[str, Any]:
    properties = {
        "ok": {"type": "boolean"},
        "error": {"type": ["string", "null"]},
        "schema_version": {"type": "string", "const": "1"},
        "capability": {"type": "string", "const": TASK_PROGRESS_CAPABILITY_ID},
        "run_id": {"type": "string"},
        "status": {"type": "string"},
        "current_stage": {"type": ["object", "null"]},
        "progress": {"type": "object"},
        "blocker": {"type": ["object", "null"]},
        "sequence": {"type": "integer", "minimum": 0},
        "updated_at": {"type": "string"},
    }
    return _object_schema(properties, list(properties))


def _annotations(
    title: str,
    *,
    read_only: bool,
    destructive: bool = False,
) -> dict[str, Any]:
    return {
        "title": title,
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": read_only,
        "openWorldHint": False,
    }


def _task_progress_security_schemes() -> list[dict[str, Any]]:
    # /mcp is bearer-authenticated, but Task Progress adds no narrower per-tool scope.
    # Publish that boundary explicitly so ChatGPT can authorize app-initiated calls.
    return [{"type": "oauth2", "scopes": []}]


def task_progress_tool_definitions() -> list[dict[str, Any]]:
    render_meta: dict[str, Any] = {
        "ui": {
            "resourceUri": TASK_PROGRESS_RESOURCE_URI,
            "visibility": ["model", "app"],
        },
        "ui/resourceUri": TASK_PROGRESS_RESOURCE_URI,
        "openai/outputTemplate": TASK_PROGRESS_RESOURCE_URI,
        "openai/widgetAccessible": True,
    }
    get_meta: dict[str, Any] = {
        "ui": {"visibility": ["model", "app"]},
        "openai/widgetAccessible": True,
    }
    cancel_meta: dict[str, Any] = {
        "ui": {"visibility": ["model", "app"]},
        "openai/widgetAccessible": True,
    }
    tools = [
        {
            "name": TASK_PROGRESS_RENDER_TOOL,
            "description": "Open the authenticated ATLAS Task Progress view for an existing run. Never pass access tokens, API keys, passwords, private keys, or other secrets in tool arguments.",
            "inputSchema": _input_schema(include_sequence=False),
            "outputSchema": _output_schema(),
            "annotations": _annotations("Open task progress", read_only=True),
        },
        {
            "name": TASK_PROGRESS_GET_TOOL,
            "description": "Read the current evidence-backed Task Progress snapshot for an authorized run without remounting the UI. Never pass access tokens, API keys, passwords, private keys, or other secrets in tool arguments.",
            "inputSchema": _input_schema(include_sequence=True),
            "outputSchema": _output_schema(),
            "annotations": _annotations("Refresh task progress", read_only=True),
        },
        {
            "name": TASK_PROGRESS_CANCEL_TOOL,
            "description": "Request cancellation only for running command sessions already correlated to an authorized Task Progress run. Never pass access tokens, API keys, passwords, private keys, or other secrets in tool arguments.",
            "inputSchema": _input_schema(include_sequence=False),
            "outputSchema": _output_schema(),
            "annotations": _annotations(
                "Cancel task execution",
                read_only=False,
                destructive=True,
            ),
        },
    ]
    for tool, meta in zip(tools, (render_meta, get_meta, cancel_meta), strict=True):
        tool["securitySchemes"] = _task_progress_security_schemes()
        meta["securitySchemes"] = _task_progress_security_schemes()
        tool["_meta"] = meta
    return tools


def task_progress_tool_result(
    snapshot: TaskProgressSnapshotV1,
    *,
    apps_negotiated: bool,
    last_sequence: int | None = None,
) -> dict[str, Any]:
    structured = {
        "ok": True,
        "error": None,
        **task_progress_model_payload(snapshot),
    }
    result: dict[str, Any] = {
        "content": [{"type": "text", "text": task_progress_text(snapshot)}],
        "structuredContent": structured,
        "isError": False,
    }
    if apps_negotiated:
        result["_meta"] = {
            "atlas.task_progress_ui": {
                "capability": TASK_PROGRESS_CAPABILITY_ID,
                "resourceUri": TASK_PROGRESS_RESOURCE_URI,
                "resourceVersion": "1",
                "resourceSha256": TASK_PROGRESS_APP_SHA256,
                "sequence": snapshot.sequence,
                "unchanged": (
                    last_sequence is not None and last_sequence == snapshot.sequence
                ),
                "snapshot": snapshot.model_dump(mode="json"),
            }
        }
    return result
