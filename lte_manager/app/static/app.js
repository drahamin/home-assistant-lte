const $=(s,r=document)=>r.querySelector(s);
const $$=(s,r=document)=>[...r.querySelectorAll(s)];
const api=p=>new URL(p.replace(/^\//,''),document.baseURI).toString();
const baseZones=['North Vineyard','South Vineyard','Cellar','Winery','Estate Gate','Guest House','Unassigned'];
const deviceTypes=['Camera','Environmental sensor','Irrigation controller','Gateway / router','Security device','Vehicle / equipment','Other IoT'];
const securityFields=[['imsi','IMSI','001010000000001'],['k','K · 32 HEX',''],['opc','OPc · 32 HEX',''],['amf','AMF · 4 HEX','8000'],['apn','APN',window.LTE_CONFIG.apn],['msisdn','MSISDN · OPTIONAL','']];
let subscribers=[];
let activeZone='All zones';
let activeType='All roles';
let deviceSearch='';

function secureFieldsMarkup(compact=false){return securityFields.filter(([name])=>!compact||name!=='msisdn').map(([name,label,placeholder])=>`<div class="field"><label>${label}</label><input name="${name}" placeholder="${placeholder}" value="${['amf','apn'].includes(name)?placeholder:''}" ${['k','opc'].includes(name)?'type="password" autocomplete="off"':''}></div>`).join('')}
function fieldMarkup(compact=false){
  if(compact)return `<div class="field"><label>DEVICE NAME</label><input name="name" placeholder="North gate camera"></div>${secureFieldsMarkup(true)}`;
  return `<div class="field"><label>DEVICE NAME</label><input name="name" placeholder="North gate camera"></div>
    <div class="field"><label>DEVICE ROLE</label><select name="device_type">${deviceTypes.map(type=>`<option ${type==='Other IoT'?'selected':''}>${type}</option>`).join('')}</select></div>
    <div class="field"><label>VINEYARD ZONE</label><input name="zone" placeholder="North Vineyard" list="estate-zones"></div>
    <label class="field critical-field"><span>CRITICAL ASSET</span><input type="checkbox" name="critical"><i></i><small>Highlight this device for daily operations</small></label>
    <div class="field wide"><label>OPERATIONS NOTES</label><textarea name="notes" maxlength="160" placeholder="Location, purpose, expected reporting interval, or recorder"></textarea></div>
    ${secureFieldsMarkup()}`;
}
$('#ue-form').innerHTML=fieldMarkup();
$('#sim-form').innerHTML=fieldMarkup(true);

function badge(el,online){el.textContent=online?'Online':'Offline';el.className=`badge ${online?'online':'offline'}`}
function statusLight(name,state,label){const light=$(`#light-${name}`),text=$(`#light-${name}-label`);light.className=state;text.textContent=label}
function toast(msg){const el=$('#toast');el.textContent=msg;el.classList.add('show');setTimeout(()=>el.classList.remove('show'),2600)}
function escapeHtml(s){const d=document.createElement('div');d.textContent=s??'';return d.innerHTML}
async function jsonFetch(path,opt){const r=await fetch(api(path),opt);const j=await r.json();if(!r.ok)throw new Error(j.error||'Request failed');return j}

async function refresh(){
  const button=$('#refresh');button.classList.add('loading');button.disabled=true;
  try{
    const d=await jsonFetch('api/overview');
    badge($('#epc-badge'),d.epc.online);badge($('#bts-badge'),d.bts.online);
    statusLight('epc',d.epc.online?'online':'offline',d.epc.online?'Online':'Offline');
    statusLight('s1',d.epc.s1.online?'online':'offline',d.epc.s1.online?'Connected':'Closed');
    statusLight('radio',d.bts.online?'online':'offline',d.bts.online?'Online':'Offline');
    if(d.routing.verified===true)statusLight('internet','online','UE verified');else if(d.routing.verified===false)statusLight('internet','offline','Test failed');else if(d.routing.configured===false)statusLight('internet','offline','Needs setup');else statusLight('internet','unknown',d.routing.configured?'Test needed':'Not verified');
    $('#s1-status').textContent=d.epc.s1.online?`${d.epc.s1.latency_ms} ms`:'Closed';
    $('#db-status').textContent=d.epc.database.online?'Reachable':'Unavailable';
    $('#ue-count').textContent=d.subscriber_count;
    $('#camera-count').textContent=d.inventory?.cameras??0;
    $('#iot-count').textContent=d.inventory?.iot??0;
    $('#critical-count').textContent=d.inventory?.critical??0;
    const healthy=d.epc.online&&d.bts.online,partial=d.epc.online||d.bts.online;
    $('#estate-status').textContent=healthy?'Ready':partial?'Needs attention':'Action needed';
    $('#estate-status').className=healthy?'good':partial?'warn':'bad';
    $('#estate-health').textContent=healthy?'Estate network ready for operations':partial?'Part of the estate network needs attention':'Core and radio are currently unreachable';
    $('#hero-pulse').classList.toggle('alert',!healthy);
    $('#last-checked').textContent=`Checked ${new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}`;
    $('#events').innerHTML=d.events.length?d.events.map(e=>`<div class="event">${escapeHtml(e.message)}<small>${new Date(e.created_at*1000).toLocaleString()}</small></div>`).join(''):'<div class="empty">No events yet</div>';
    await Promise.all([loadUEs(),loadHistory(currentHistoryHours()),loadAlertSettings()]);
  }catch(e){
    $('#estate-status').textContent='Check failed';$('#estate-status').className='bad';
    $('#estate-health').textContent='Unable to read the estate network';toast(e.message);
  }finally{button.classList.remove('loading');button.disabled=false}
}

function zoneOptions(current){return [...new Set([current,...baseZones,...subscribers.map(row=>row.zone)])].filter(Boolean).map(zone=>`<option ${zone===current?'selected':''}>${escapeHtml(zone)}</option>`).join('')}
function roleOptions(current){return deviceTypes.map(type=>`<option ${type===current?'selected':''}>${type}</option>`).join('')}
function renderSubscribers(){
  const query=deviceSearch.trim().toLowerCase();
  const visible=subscribers.filter(row=>(activeZone==='All zones'||row.zone===activeZone)&&(activeType==='All roles'||row.device_type===activeType)&&(!query||[row.name,row.imsi,row.zone,row.device_type,row.notes].some(value=>String(value||'').toLowerCase().includes(query))));
  const counts=subscribers.reduce((map,row)=>(map[row.zone]=(map[row.zone]||0)+1,map),{});
  $('#zone-summary').innerHTML=[['All zones',subscribers.length],...Object.entries(counts).sort()].map(([zone,count])=>`<button class="zone-chip ${zone===activeZone?'active':''}" data-zone-filter="${escapeHtml(zone)}"><svg><use href="#i-zone"></use></svg><span>${escapeHtml(zone)}</span><b>${count}</b></button>`).join('');
  $('#ue-rows').innerHTML=visible.map(row=>`<tr><td><b>${escapeHtml(row.name)}</b>${row.notes?`<small class="device-note">${escapeHtml(row.notes)}</small>`:''}</td><td><select class="role-select" data-profile-imsi="${row.imsi}">${roleOptions(row.device_type)}</select></td><td><select class="zone-select" data-zone-imsi="${row.imsi}">${zoneOptions(row.zone)}</select></td><td><label class="critical-toggle" title="Mark as operationally critical"><input type="checkbox" data-critical-imsi="${row.imsi}" ${row.critical?'checked':''}><i></i><span>${row.critical?'Critical':'Standard'}</span></label></td><td>${row.imsi}</td><td>${escapeHtml(row.apn)}</td><td><button data-delete="${row.imsi}" title="Remove">Remove</button></td></tr>`).join('');
  $('#ue-empty').style.display=visible.length?'none':'block';
  $('#ue-empty').textContent=subscribers.length?'No devices match these filters.':'No estate devices provisioned yet.';
  $$('[data-zone-filter]').forEach(button=>button.onclick=()=>{activeZone=button.dataset.zoneFilter;renderSubscribers()});
  $$('[data-zone-imsi]').forEach(select=>select.onchange=async()=>{try{await jsonFetch(`api/subscribers/${select.dataset.zoneImsi}/zone`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({zone:select.value})});toast('Vineyard zone updated');await loadUEs()}catch(e){toast(e.message)}});
  $$('[data-profile-imsi]').forEach(select=>select.onchange=async()=>{try{await updateProfile(select.dataset.profileImsi,{device_type:select.value});toast('Device role updated');await loadUEs()}catch(e){toast(e.message)}});
  $$('[data-critical-imsi]').forEach(input=>input.onchange=async()=>{try{await updateProfile(input.dataset.criticalImsi,{critical:input.checked});toast(input.checked?'Critical device highlighted':'Critical flag removed');await loadUEs()}catch(e){toast(e.message)}});
  $$('[data-delete]').forEach(button=>button.onclick=async()=>{if(!confirm(`Remove UE ${button.dataset.delete} from the EPC?`))return;try{await jsonFetch(`api/subscribers/${button.dataset.delete}`,{method:'DELETE'});toast('UE removed');refresh()}catch(e){toast(e.message)}});
}
function updateProfile(imsi,body){return jsonFetch(`api/subscribers/${imsi}/profile`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})}
async function loadUEs(){subscribers=await jsonFetch('api/subscribers');renderSubscribers()}

$('#device-search').oninput=event=>{deviceSearch=event.target.value;renderSubscribers()};
$('#device-type-filter').onchange=event=>{activeType=event.target.value;renderSubscribers()};

function currentHistoryHours(){return Number($('.range-picker .active')?.dataset.hours||24)}
function historyPath(points,key,onlineY,offlineY,width){
  if(!points.length)return '';
  const first=points[0].sampled_at,last=points[points.length-1].sampled_at,span=Math.max(last-first,1);
  let path='';
  points.forEach((point,index)=>{const x=16+(point.sampled_at-first)/span*(width-32),y=point[key]?onlineY:offlineY;if(index===0)path=`M ${x} ${y}`;else path+=` H ${x} V ${y}`});
  return path;
}
async function loadHistory(hours=24){
  try{
    const data=await jsonFetch(`api/history?hours=${hours}`),width=720;
    $('#epc-uptime').textContent=data.uptime.epc===null?'No data':`${data.uptime.epc}%`;
    $('#radio-uptime').textContent=data.uptime.radio===null?'No data':`${data.uptime.radio}%`;
    $('#history-samples').textContent=data.points.length?`${data.points.length} checks recorded`:'History begins after the first check';
    if(!data.points.length){$('#history-chart').innerHTML='<div class="empty chart-empty">Monitoring is starting. Availability will appear here automatically.</div>';return}
    const epc=historyPath(data.points,'epc_online',38,62,width),radio=historyPath(data.points,'bts_online',98,122,width);
    $('#history-chart').innerHTML=`<svg viewBox="0 0 ${width} 150" role="img" aria-label="Connection history"><line x1="16" y1="75" x2="704" y2="75" class="chart-divider"/><text x="16" y="20">EPC</text><text x="16" y="88">RADIO</text><path d="${epc}" class="chart-line epc-line"/><path d="${radio}" class="chart-line radio-line"/><text x="16" y="146">${hours===168?'7 days ago':hours+' hours ago'}</text><text x="704" y="146" text-anchor="end">Now</text></svg>`;
  }catch(e){$('#history-chart').innerHTML='<div class="empty chart-empty">History is temporarily unavailable.</div>'}
}
$$('.range-picker button').forEach(button=>button.onclick=()=>{$$('.range-picker button').forEach(b=>b.classList.toggle('active',b===button));loadHistory(Number(button.dataset.hours))});

async function loadAlertSettings(){
  try{
    const data=await jsonFetch('api/alerts/settings'),form=$('#alert-form'),prefs=data.settings;
    form.elements.epc_enabled.checked=prefs.epc_enabled;form.elements.radio_enabled.checked=prefs.radio_enabled;
    form.elements.failure_threshold.value=String(prefs.failure_threshold);form.elements.cooldown_minutes.value=String(prefs.cooldown_minutes);
    const active=Object.entries(data.states).filter(([,state])=>state.active).map(([name])=>name.toUpperCase());
    $('#alert-readiness').className=`alert-readiness ${data.home_assistant_ready?'ready':'warning'}`;
    $('#alert-readiness').textContent=active.length?`Active alert: ${active.join(' + ')}`:data.home_assistant_ready?'Home Assistant notifications ready':'Notifications become active when installed in Home Assistant';
  }catch(e){$('#alert-readiness').textContent='Alert settings unavailable'}
}
$('#alert-form').onsubmit=async event=>{event.preventDefault();const form=event.currentTarget,body={epc_enabled:form.elements.epc_enabled.checked,radio_enabled:form.elements.radio_enabled.checked,failure_threshold:Number(form.elements.failure_threshold.value),cooldown_minutes:Number(form.elements.cooldown_minutes.value)};try{await jsonFetch('api/alerts/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});toast('Alert rules saved');loadAlertSettings()}catch(e){toast(e.message)}};

$$('.nav').forEach(button=>button.onclick=()=>showPage(button.dataset.page));$$('[data-go]').forEach(button=>button.onclick=()=>showPage(button.dataset.go));
function showPage(id,updateHash=true){if(!document.getElementById(id))id='overview';$$('.nav').forEach(n=>n.classList.toggle('active',n.dataset.page===id));$$('.page').forEach(p=>p.classList.toggle('active',p.id===id));$('#page-title').textContent={overview:'Vineyard network',ues:'Estate devices',bts:'Estate radio',sim:'SIM workbench',diagnostics:'Network care'}[id];if(updateHash&&location.hash!==`#${id}`)history.replaceState(null,'',`#${id}`);if(id==='sim')readerStatus();if(id==='diagnostics'){loadLogs();loadInternetPlan();loadRoutingAssistant()}window.scrollTo({top:0,behavior:'smooth'})}
$('#refresh').onclick=refresh;$('#add-ue').onclick=()=>{$('#form-error').textContent='';$('#ue-dialog').showModal()};
$$('[data-action]').forEach(button=>button.onclick=()=>{const action=button.dataset.action;if(action==='add-ue'){showPage('ues');$('#add-ue').click()}else if(action==='diagnostics'){showPage('diagnostics');$('#run-diagnostics').click()}else showPage(action)});
$('#save-ue').onclick=async()=>{const body=Object.fromEntries(new FormData($('#ue-dialog form')));try{await jsonFetch('api/subscribers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});$('#ue-dialog').close();$('#ue-dialog form').reset();toast('Estate device provisioned');refresh()}catch(e){$('#form-error').textContent=e.message}};
$('#commission-form').onsubmit=async event=>{event.preventDefault();try{const response=await fetch(api('api/commissioning'),{method:'POST',body:new FormData(event.target)}),data=await response.json();if(!response.ok)throw new Error(data.error);$('#commission-result').className='warning';$('#commission-result').textContent=`Stored ${data.name} (${data.size.toLocaleString()} bytes). Apply it in licensed Nokia BTS Site Manager.`;toast('Commissioning file stored privately')}catch(e){toast(e.message)}};
async function readerStatus(){try{const data=await jsonFetch('api/sim/readers');badge($('#sim-ready'),data.ready);$('#sim-ready').textContent=data.ready?'Ready':'Setup needed';const rows=[['Physical writes enabled',data.enabled],['pySim tools installed',data.pysim],['USB bus visible',data.usb_visible],['CCID / PC-SC reader',data.readers.length>0]];$('#reader-details').innerHTML=rows.map(([name,ready])=>`<div class="ready-row"><span>${name}</span><b style="color:${ready?'var(--green)':'var(--amber)'}">${ready?'Yes':'No'}</b></div>`).join('')+(data.readers.length?`<div class="warning">Detected: ${escapeHtml(data.readers.join(', '))}</div>`:'')}catch(e){toast(e.message)}}
$('#generate-script').onclick=async()=>{const body=Object.fromEntries(new FormData($('#sim-form')));try{const response=await fetch(api('api/sim/script'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!response.ok){const data=await response.json();throw new Error(data.error)}const blob=await response.blob(),url=URL.createObjectURL(blob),link=document.createElement('a');link.href=url;link.download=`pysim-${body.imsi}.txt`;link.click();URL.revokeObjectURL(url);toast('Worksheet generated')}catch(e){toast(e.message)}};
function showOpc(data,includeOp=false){$('#opc-result').innerHTML=`<div>${includeOp?`<small>Generated OP · ${escapeHtml(data.op)}</small><br>`:''}<code>${escapeHtml(data.opc)}</code></div><div class="opc-buttons"><button class="secondary small" id="copy-opc">Copy OPc</button><button class="secondary small" id="use-opc">Use in profile</button></div>`;$('#copy-opc').onclick=async()=>{await navigator.clipboard.writeText(data.opc);toast('OPc copied')};$('#use-opc').onclick=()=>{$('#sim-form [name="k"]').value=$('#opc-k').value;$('#sim-form [name="opc"]').value=data.opc;toast('K and OPc added to the profile worksheet')}}
$('#calculate-opc').onclick=async()=>{try{const data=await routingPost('api/sim/opc',{k:$('#opc-k').value,op:$('#opc-op').value});showOpc(data);toast('OPc calculated without storing secrets')}catch(e){toast(e.message)}};
$('#generate-test-values').onclick=async()=>{if(!confirm('Generate new K and OP values for a programmable test SIM? Existing unsaved values will be replaced.'))return;try{const data=await routingPost('api/sim/test-values');$('#opc-k').value=data.k;$('#opc-op').value=data.op;showOpc(data,true);toast('Secure test values generated')}catch(e){toast(e.message)}};
async function loadLogs(){try{const rows=await jsonFetch('api/logs?limit=300');$('#live-log').innerHTML=rows.length?rows.map(row=>`<div class="log-line"><time>${new Date(row.created_at*1000).toLocaleTimeString()}</time><span class="log-kind ${row.kind}">${escapeHtml(row.kind.toUpperCase())}</span><span>${escapeHtml(row.message)}</span></div>`).join(''):'<div class="log-line muted-line">No activity logged yet.</div>';if($('#follow-logs').checked)$('#live-log').scrollTop=$('#live-log').scrollHeight}catch(e){toast(e.message)}}
async function loadInternetPlan(){try{const data=await jsonFetch('api/internet-plan');$('#internet-plan').innerHTML=data.steps.map((step,index)=>`<div class="breakout-step"><b>${index+1}</b>${escapeHtml(step)}</div>`).join('')+`<div class="breakout-note">${escapeHtml(data.note)}</div>`}catch(e){$('#internet-plan').innerHTML=`<div class="warning">${escapeHtml(e.message)}</div>`}}
function routingPost(path,body={}){return jsonFetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})}
async function loadRoutingAssistant(){
  try{
    const data=await jsonFetch('api/epc-routing/status'),cfg=data.config;
    $$('#routing-assistant button, #routing-assistant input').forEach(control=>control.disabled=!cfg.enabled);
    if(!cfg.enabled){$('#routing-access').className='routing-access';$('#routing-access').innerHTML='<b>Opt-in required.</b> In Home Assistant app Configuration, enable <code>epc_routing_management_enabled</code>, confirm the SSH user and uplink interface, then restart the app.';$('#routing-summary').textContent='Disabled in configuration';return}
    const secure=data.key_present&&data.host_trusted;
    $$('[data-console-action]').forEach(control=>control.disabled=!secure);
    $('#epc-console-state').textContent=secure?'Ready':'Access setup required';
    $('#routing-access').className=`routing-access ${secure?'ready':''}`;
    $('#routing-access').innerHTML=`<b>${escapeHtml(cfg.user)}@${escapeHtml(cfg.host)}:${cfg.port}</b> · SSH key ${data.key_present?'stored':'needed'} · host fingerprint ${data.host_trusted?'trusted':'not trusted'} · ${escapeHtml(cfg.subnet)} via ${escapeHtml(cfg.interface)}`;
    $('#routing-summary').textContent=secure?'Secure access ready':'Setup required';
    if(data.key_present){const keyData=await jsonFetch('api/epc-routing/key/generate');showEpcPublicKey(keyData.public_key)}
    const preview=await jsonFetch('api/epc-routing/preview');
    $('#routing-preview').innerHTML=preview.changes.map((change,index)=>`<div><b>${index+1}</b><span>${escapeHtml(change)}</span></div>`).join('')+`<small class="muted">${escapeHtml(preview.rollback)}</small>`;
  }catch(e){$('#routing-access').className='routing-access';$('#routing-access').textContent=e.message}
}
$('#routing-assistant').ontoggle=()=>{if($('#routing-assistant').open)loadRoutingAssistant()};
function setEpcKeyResult(message,state='') {const result=$('#epc-key-result');result.textContent=message;result.className=`key-result ${state}`.trim()}
$('#epc-key-form').onsubmit=async event=>{event.preventDefault();setEpcKeyResult('Checking and storing the private key…');try{const response=await fetch(api('api/epc-routing/key'),{method:'POST',body:new FormData(event.currentTarget)}),data=await response.json();if(!response.ok)throw new Error(data.error);setEpcKeyResult('Private key stored securely in Home Assistant.','success');toast('EPC SSH key stored privately');event.currentTarget.reset();loadRoutingAssistant()}catch(e){setEpcKeyResult(e.message,'error');toast(e.message)}};
function showEpcPublicKey(key){$('#epc-public-key').innerHTML=`<div class="public-key-box"><small>Install this public key in the EPC user’s authorized_keys file:</small><code>${escapeHtml(key)}</code><button class="secondary small" id="copy-epc-public-key">Copy public key</button></div>`;$('#copy-epc-public-key').onclick=async()=>{await navigator.clipboard.writeText(key);toast('EPC public key copied')}}
$('#generate-epc-key').onclick=async()=>{let confirmValue='';if($('#routing-access').textContent.includes('key stored')){confirmValue=prompt('A key already exists. Type REPLACE KEY to replace it. The old public key will stop working.');if(!confirmValue)return}setEpcKeyResult('Generating a dedicated key…');try{const data=await routingPost('api/epc-routing/key/generate',{confirm:confirmValue});showEpcPublicKey(data.public_key);setEpcKeyResult('Dedicated private key stored securely. Only the public key is shown above.','success');toast('Dedicated EPC key generated');loadRoutingAssistant()}catch(e){setEpcKeyResult(e.message,'error');toast(e.message)}};
$('#scan-epc-key').onclick=async()=>{try{const data=await routingPost('api/epc-routing/scan');$('#epc-fingerprints').innerHTML=`<div class="warning">Verify this fingerprint through a trusted source before accepting it.</div>`+data.fingerprints.map(item=>`<div class="fingerprint"><small>${escapeHtml(item.type)}</small><code>${escapeHtml(item.fingerprint)}</code><button class="secondary" data-trust-fingerprint="${escapeHtml(item.fingerprint)}">Trust this fingerprint</button></div>`).join('');$$('[data-trust-fingerprint]').forEach(button=>button.onclick=async()=>{try{await routingPost('api/epc-routing/trust',{fingerprint:button.dataset.trustFingerprint});toast('EPC host fingerprint trusted');$('#epc-fingerprints').innerHTML='';loadRoutingAssistant()}catch(e){toast(e.message)}})}catch(e){$('#epc-fingerprints').innerHTML=`<div class="connection-result error"><b>No fingerprint available</b><span>${escapeHtml(e.message)}</span></div>`;toast(e.message)}};
function renderEpcConnectivity(data){const state=data.ssh?'success':data.reachable?'warning':'error',banner=data.banner?`<code>${escapeHtml(data.banner)}</code>`:'';$('#epc-connectivity-result').className=`connection-result ${state}`;$('#epc-connectivity-result').innerHTML=`<b>${data.ssh?'SSH is reachable':'EPC access needs attention'}</b><span>${escapeHtml(data.detail)}</span>${banner}`;$('#epc-console-state').textContent=data.ssh?'SSH reachable':'Connection failed'}
$('#test-epc-access').onclick=async()=>{const button=$('#test-epc-access');button.disabled=true;button.textContent='Testing…';try{const data=await routingPost('api/epc-routing/connectivity');renderEpcConnectivity(data);toast(data.ssh?'EPC SSH is reachable':'EPC access needs attention')}catch(e){$('#epc-connectivity-result').className='connection-result error';$('#epc-connectivity-result').innerHTML=`<b>Connection test failed</b><span>${escapeHtml(e.message)}</span>`;toast(e.message)}finally{button.disabled=false;button.textContent='Test EPC access'}};
$$('[data-console-action]').forEach(button=>button.onclick=async()=>{const output=$('#epc-console-output');output.textContent=`Running ${button.textContent}…`;$$('[data-console-action]').forEach(control=>control.disabled=true);try{const data=await routingPost('api/epc-console/run',{action:button.dataset.consoleAction});output.textContent=`${data.label} · ${data.host}\n${new Date(data.checked_at*1000).toLocaleString()}\n\n${data.output}`;$('#epc-console-state').textContent='Connected';toast(`${data.label} complete`)}catch(e){output.textContent=`Unable to open EPC console\n\n${e.message}`;$('#epc-console-state').textContent='Connection failed';toast(e.message)}finally{loadRoutingAssistant()}});
function renderRoutingStatus(data){const names={forwarding:'IPv4 forwarding',interface:'Uplink interface',route:'EPC public route',nat:'NAT masquerade',outbound:'Subscriber outbound rule',return:'Established return rule',service:'Persistent routing service'};$('#routing-result').innerHTML=Object.entries(names).map(([key,name])=>`<div class="routing-check"><span>${name}</span><b class="${data.checks[key]?'pass':'fail'}">${data.checks[key]?'Ready':'Needs setup'}</b></div>`).join('')+`<div class="routing-check"><span>Observed packets</span><b>${data.counters.outbound} out · ${data.counters.return} back</b></div>`;$('#routing-summary').textContent=data.ready?'Routing ready':'Routing needs attention'}
$('#check-epc-routing').onclick=async()=>{try{const data=await routingPost('api/epc-routing/check');renderRoutingStatus(data);toast(data.ready?'EPC routing is ready':'Routing needs attention')}catch(e){toast(e.message)}};
$('#apply-epc-routing').onclick=async()=>{const host=window.LTE_CONFIG.epc_host,confirmation=prompt(`This changes forwarding and firewall rules on ${host}. Type APPLY ${host} to continue.`);if(!confirmation)return;try{const data=await routingPost('api/epc-routing/apply',{confirm:confirmation});renderRoutingStatus(data.status);toast('Subscriber Internet routing applied')}catch(e){toast(e.message)}};
$('#rollback-epc-routing').onclick=async()=>{const host=window.LTE_CONFIG.epc_host,confirmation=prompt(`Remove only Baiamonte-managed routing from ${host}. Type ROLLBACK ${host} to continue.`);if(!confirmation)return;try{await routingPost('api/epc-routing/rollback',{confirm:confirmation});toast('Baiamonte routing rolled back');$('#check-epc-routing').click()}catch(e){toast(e.message)}};
$('#start-ue-test').onclick=async()=>{try{const data=await routingPost('api/epc-routing/verify/start');$('#routing-result').innerHTML=`<div class="traffic-result pass"><b>Test recording started.</b><br>${escapeHtml(data.instruction)}</div>`;$('#finish-ue-test').hidden=false;$('#start-ue-test').hidden=true}catch(e){toast(e.message)}};
$('#finish-ue-test').onclick=async()=>{try{const data=await routingPost('api/epc-routing/verify/finish');$('#routing-result').innerHTML=`<div class="traffic-result ${data.verified?'pass':'fail'}"><b>${data.verified?'UE Internet path verified':'Traffic test needs attention'}</b><br>${escapeHtml(data.message)}<br><small>New packets: ${data.delta.outbound} out · ${data.delta.return} back</small></div>`;$('#finish-ue-test').hidden=true;$('#start-ue-test').hidden=false;$('#routing-summary').textContent=data.verified?'UE Internet verified':'Verification needed'}catch(e){toast(e.message)}};
$('#run-diagnostics').onclick=async()=>{const button=$('#run-diagnostics');button.disabled=true;button.textContent='Running…';try{const data=await jsonFetch('api/diagnostics/run',{method:'POST'}),ok=!data.failures;badge($('#diagnostic-summary'),ok);$('#diagnostic-summary').textContent=ok?'All checks passed':`${data.failures} need attention`;$('#diagnostic-results').innerHTML=data.checks.map(check=>`<div class="check ${check.ok?'pass':'fail'}"><span>${check.ok?'✓':'!'}</span><div><b>${escapeHtml(check.name)}</b><small>${escapeHtml(check.detail)}</small>${!check.ok&&check.suggestion?`<em>${escapeHtml(check.suggestion)}</em>`:''}</div></div>`).join('');loadLogs()}catch(e){toast(e.message)}finally{button.disabled=false;button.textContent='Run diagnostics'}};
$('#log-analyze-form').onsubmit=async event=>{event.preventDefault();try{const response=await fetch(api('api/logs/analyze'),{method:'POST',body:new FormData(event.target)}),data=await response.json();if(!response.ok)throw new Error(data.error);$('#log-findings').innerHTML=data.findings.length?`<p class="muted">${data.lines} lines analyzed</p>`+data.findings.map(f=>`<div class="finding"><b>${escapeHtml(f.title)} · ${f.count}</b><span>${escapeHtml(f.action)}</span></div>`).join(''):`<div class="warning success">No known error patterns found in ${data.lines} lines.</div>`;loadLogs()}catch(e){toast(e.message)}};
$('#clear-log-view').onclick=()=>{$('#live-log').innerHTML='<div class="log-line muted-line">View cleared. New activity will appear here.</div>'};
setInterval(()=>{if($('#diagnostics').classList.contains('active')&&$('#follow-logs').checked)loadLogs()},4000);
$$('.checklist input[type="checkbox"]').forEach((input,index)=>{const key=`baiamonte-bts-check-${index}`;input.checked=localStorage.getItem(key)==='true';input.onchange=()=>localStorage.setItem(key,String(input.checked))});
window.addEventListener('hashchange',()=>showPage(location.hash.slice(1)||'overview',false));
showPage(location.hash.slice(1)||'overview',false);refresh();
