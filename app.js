(() => {
  const $ = (id) => document.getElementById(id);
  const REMINDER_KEY = 'daymark.reminder.v1';
  const TOUR_KEY_PREFIX = 'daymark.onboarding.v1.';
  const DAY_LABELS = ['Su','Mo','Tu','We','Th','Fr','Sa'];
  const today = new Date();
  const iso = (date) => `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')}`;
  const safeLoad = (key, fallback) => { try { const value = JSON.parse(localStorage.getItem(key)); return value ?? fallback; } catch { return fallback; } };
  let entries = [];
  let drafts = [];
  let reminder = safeLoad(REMINDER_KEY, {enabled:false, frequency:'daily', time:'17:00', days:[1,2,3,4,5]});
  let currentUser = null;
  let showAllEntries = false;
  let highlightOnly = false;
  let tourStep = 0;
  let toastTimer;

  const esc = (s='') => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const prettyDate = (value, options={month:'short',day:'numeric',year:'numeric'}) => { const [y,m,d]=value.split('-').map(Number); return new Date(y,m-1,d).toLocaleDateString(undefined,options); };
  const sortedEntries = (items=entries) => [...items].sort((a,b)=>b.date.localeCompare(a.date));
  const TOUR_STEPS = [
    {title:'Welcome to Daymark',copy:'Keep a private record of your work, then turn those notes into a clear appraisal narrative. This quick tour shows you the basics.',view:'home'},
    {title:'Capture your work',copy:'Use Add entry to record what you did, when you did it, the project, and its impact. You can add past work on its original date.',view:'home'},
    {title:'Flag the standouts',copy:'Mark achievements, certifications, or awards as highlights in the entry form. They’ll be easy to find when it’s time to prepare for a review.',view:'home'},
    {title:'Choose a review period',copy:'Open Appraisal summary and select a quarter, year, or custom date range. Daymark drafts a narrative from entries in that period.',view:'summaries'},
    {title:'Review and keep your draft',copy:'Check the supporting entries beside the narrative, edit the wording, then save or export your draft for your performance review.',view:'summaries'}
  ];
  function renderTourStep(){const step=TOUR_STEPS[tourStep];showView(step.view);$('tourCount').textContent=`${tourStep+1} of ${TOUR_STEPS.length}`;$('tourTitle').textContent=step.title;$('tourCopy').textContent=step.copy;$('tourProgress').style.width=`${((tourStep+1)/TOUR_STEPS.length)*100}%`;$('tourBack').classList.toggle('hidden',tourStep===0);$('tourNext').textContent=tourStep===TOUR_STEPS.length-1?'Finish tour':'Next';}
  function finishTour(){try{if(currentUser)localStorage.setItem(`${TOUR_KEY_PREFIX}${currentUser.id}`,'done');}catch{}$('onboardingTour').classList.add('hidden');showView('home');}
  function maybeStartTour(){if(!currentUser)return;try{if(localStorage.getItem(`${TOUR_KEY_PREFIX}${currentUser.id}`)==='done')return;}catch{}tourStep=0;$('onboardingTour').classList.remove('hidden');renderTourStep();$('tourNext').focus();}
  async function api(path, options={}){
    const headers={...(options.body?{'Content-Type':'application/json'}:{}),...(options.headers||{})};
    let response;
    try{response=await fetch(path,{...options,headers,credentials:'same-origin'});}catch{throw new Error('Could not reach Daymark. Start the local API server and reload this page.');}
    if(response.status===204)return null;
    const payload=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(payload.detail||'Something went wrong. Please try again.');
    return payload;
  }
  function showAuth(message=''){$('appShell').classList.add('hidden');$('authGate').classList.remove('hidden');$('authError').textContent=message;}
  async function loadOAuthProviders(){try{const providers=await api('/api/auth/providers');document.querySelectorAll('[data-oauth]').forEach(button=>{const enabled=!!providers[button.dataset.oauth];button.disabled=!enabled;button.title=enabled?'Continue securely with Google':'Google sign-in credentials are not configured yet';});$('oauthFootnote').textContent=providers.google?'Sign in securely with your Google account.':'Google sign-in becomes available after credentials are configured.';}catch{}}
  const passkeysSupported=()=>window.isSecureContext&&'credentials'in navigator&&'PublicKeyCredential'in window;
  function b64urlToBytes(value){const base64=value.replace(/-/g,'+').replace(/_/g,'/');const binary=atob(base64+'='.repeat((4-base64.length%4)%4));return Uint8Array.from(binary,c=>c.charCodeAt(0));}
  function bytesToB64url(value){const bytes=new Uint8Array(value);let binary='';for(const byte of bytes)binary+=String.fromCharCode(byte);return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
  function serializePasskey(credential){const response=credential.response;const packed={clientDataJSON:bytesToB64url(response.clientDataJSON)};if(response.attestationObject)packed.attestationObject=bytesToB64url(response.attestationObject);if(response.authenticatorData)packed.authenticatorData=bytesToB64url(response.authenticatorData);if(response.signature)packed.signature=bytesToB64url(response.signature);if(response.userHandle)packed.userHandle=bytesToB64url(response.userHandle);if(response.getTransports)packed.transports=response.getTransports();return{id:credential.id,rawId:bytesToB64url(credential.rawId),type:credential.type,authenticatorAttachment:credential.authenticatorAttachment,response:packed,clientExtensionResults:credential.getClientExtensionResults()};}
  async function loadPasskeys(){if(!currentUser)return;try{const list=await api('/api/auth/passkeys');$('passkeyList').innerHTML=list.length?list.map((key,index)=>`<div class="passkey-item"><span><strong>Passkey ${index+1}</strong><small>Added ${new Date(key.createdAt).toLocaleDateString()}${key.backedUp?' · synced credential':''}</small></span><button class="quiet-button" data-delete-passkey="${esc(key.id)}">Remove</button></div>`).join(''):'<p class="passkey-empty">No passkeys set up for this account yet.</p>';}catch(error){$('passkeyList').innerHTML=`<p class="passkey-empty">${esc(error.message)}</p>`;}}
  async function addPasskey(){if(!passkeysSupported()){ $('passkeyFeedback').textContent='Passkeys need a supported browser and a secure HTTPS connection.';return;}const button=$('addPasskey');button.disabled=true;$('passkeyFeedback').textContent='Waiting for your device…';try{const options=await api('/api/auth/passkeys/register/options',{method:'POST',body:JSON.stringify({})});const challenge=options.challenge;options.challenge=b64urlToBytes(options.challenge);options.user.id=b64urlToBytes(options.user.id);if(options.excludeCredentials)options.excludeCredentials=options.excludeCredentials.map(item=>({...item,id:b64urlToBytes(item.id)}));const credential=await navigator.credentials.create({publicKey:options});if(!credential)throw new Error('Your device did not create a passkey.');await api('/api/auth/passkeys/register/verify',{method:'POST',body:JSON.stringify({challenge,credential:serializePasskey(credential)})});$('passkeyFeedback').textContent='Passkey set up. Your device will verify it when you sign in.';await loadPasskeys();}catch(error){$('passkeyFeedback').textContent=error.name==='NotAllowedError'?'Passkey setup was cancelled.':error.message;}finally{button.disabled=false;}}
  async function signInWithPasskey(){if(!passkeysSupported()){showAuth('Passkeys require a supported browser and a secure HTTPS connection.');return;}const button=$('passkeyLogin');button.disabled=true;$('authError').textContent='';button.textContent='Waiting for your device…';try{const options=await api('/api/auth/passkeys/login/options',{method:'POST',body:JSON.stringify({})});const challenge=options.challenge;options.challenge=b64urlToBytes(options.challenge);if(options.allowCredentials)options.allowCredentials=options.allowCredentials.map(item=>({...item,id:b64urlToBytes(item.id)}));const credential=await navigator.credentials.get({publicKey:options});if(!credential)throw new Error('No passkey was selected.');const user=await api('/api/auth/passkeys/login/verify',{method:'POST',body:JSON.stringify({challenge,credential:serializePasskey(credential)})});await enterApp(user);}catch(error){$('authError').textContent=error.name==='NotAllowedError'?'Passkey sign-in was cancelled or no passkey was found.':error.message;}finally{button.disabled=false;button.innerHTML='<span aria-hidden="true">⌑</span> Continue with passkey';}}
  async function enterApp(user){
    currentUser=user; $('userEmail').textContent=user.email; $('authGate').classList.add('hidden'); $('appShell').classList.remove('hidden');
    try{
      [entries,drafts,reminder]=await Promise.all([api('/api/entries'),api('/api/drafts'),api('/api/reminders')]);
      reminder.backgroundPush=(await api('/api/push/status')).subscribed;
      const oldEntries=safeLoad('daymark.entries.v1',[]), oldDrafts=safeLoad('daymark.drafts.v1',[]);
      if(entries.length===0&&(oldEntries.length||oldDrafts.length)&&confirm(`Move ${oldEntries.length} old entries and ${oldDrafts.length} saved drafts from this browser into your signed-in account?`)){
        for(const item of oldEntries)await api('/api/entries',{method:'POST',body:JSON.stringify({date:item.date,type:item.type,description:item.description,project:item.project||'',impact:item.impact||'',highlight:!!item.highlight})});
        for(const draft of oldDrafts)await api('/api/drafts',{method:'POST',body:JSON.stringify({start:draft.start,end:draft.end,text:draft.text})});
        localStorage.removeItem('daymark.entries.v1');localStorage.removeItem('daymark.drafts.v1');[entries,drafts]=await Promise.all([api('/api/entries'),api('/api/drafts')]);
      }
      renderHome();renderSavedDrafts();renderReminderForm();await loadPasskeys();maybeStartTour();
    }
    catch(error){showAuth(error.message);}
  }
  async function initializeAuth(){
    try{const user=await api('/api/auth/me');await enterApp(user);}
    catch(error){const params=new URLSearchParams(location.search);showAuth(params.get('auth_error')|| (error.message.includes('Could not reach')?error.message:''));if(params.has('auth_error'))history.replaceState(null,'',location.pathname);}
  }
  const toast = (message) => { const el=$('toast'); el.textContent=message; el.classList.add('show'); clearTimeout(toastTimer); toastTimer=setTimeout(()=>el.classList.remove('show'),2400); };
  const typeClass = (type) => type==='Certification'?'cert':type.startsWith('Award')?'award':'';
  const renderEntryRow = (e) => `<article class="entry-row"><div class="entry-date"><strong>${prettyDate(e.date,{day:'numeric'})}</strong><small>${prettyDate(e.date,{month:'short'})}</small></div><div class="entry-copy"><div class="entry-title" title="${esc(e.description)}">${esc(e.description)}</div><div class="entry-meta"><span class="entry-tag ${typeClass(e.type)}">${esc(e.type)}</span>${e.project?`<span>·</span><span>${esc(e.project)}</span>`:''}${e.highlight?'<span class="highlight-mark" title="Highlight">✦</span>':''}</div></div><button class="entry-edit" data-edit="${esc(e.id)}" aria-label="Edit entry">···</button></article>`;
  function renderHome(){
    const items=sortedEntries(highlightOnly?entries.filter(e=>e.highlight):entries);
    const visible=showAllEntries?items:items.slice(0,5);
    $('entriesList').innerHTML=visible.map(renderEntryRow).join('');
    $('entriesList').classList.toggle('hidden',items.length===0);
    $('emptyEntries').classList.toggle('hidden',items.length>0);
    $('allEntries').textContent=highlightOnly?'Show all entries →':showAllEntries?'Show recent':'View all →';
    $('todayLabel').textContent=`YOUR WORK JOURNAL · ${today.toLocaleDateString(undefined,{weekday:'long',month:'long',day:'numeric'})}`;
  }
  function openEntry(entry){
    $('entryForm').reset(); $('entryId').value=entry?.id||''; $('entryDate').value=entry?.date||iso(today); $('entryType').value=entry?.type||'Work'; $('entryDescription').value=entry?.description||''; $('entryProject').value=entry?.project||''; $('entryImpact').value=entry?.impact||''; $('entryHighlight').checked=!!entry?.highlight;
    $('modalTitle').textContent=entry?'Edit a moment':'Capture a moment'; $('saveEntry').textContent=entry?'Save changes':'Save entry'; $('deleteEntry').classList.toggle('hidden',!entry); $('entryModal').classList.remove('hidden'); setTimeout(()=>$('entryDescription').focus(),50);
  }
  function closeEntry(){ $('entryModal').classList.add('hidden'); }
  function showView(name){
    $('homeView').classList.toggle('hidden',name!=='home'); $('summaryView').classList.toggle('hidden',name!=='summaries'); $('settingsView').classList.toggle('hidden',name!=='settings');
    document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.view===name));
    $('crumb').textContent=name==='home'?'Journal':name==='settings'?'Settings':'Appraisal summary'; $('sidebar').classList.remove('open'); window.scrollTo({top:0,behavior:'smooth'});
  }
  function setRange(period){
    document.querySelectorAll('.period-button').forEach(b=>b.classList.toggle('active',b.dataset.period===period));
    const start=new Date(today.getFullYear(), today.getMonth(), 1), end=new Date(today.getFullYear(),today.getMonth()+1,0);
    if(period==='year'){$('startDate').value=`${today.getFullYear()}-01-01`; $('endDate').value=`${today.getFullYear()}-12-31`;}
    else if(period==='quarter'){const q=Math.floor(today.getMonth()/3); $('startDate').value=iso(new Date(today.getFullYear(),q*3,1)); $('endDate').value=iso(new Date(today.getFullYear(),q*3+3,0));}
    else if(period==='custom'&&!$('startDate').value){$('startDate').value=iso(start); $('endDate').value=iso(end);}
  }
  function renderEvidence(items){
    $('evidenceCount').textContent=items.length;
    $('evidenceList').innerHTML=items.length?items.map(e=>`<article class="evidence-item"><div class="evidence-item-head"><span>${prettyDate(e.date)} · ${esc(e.type)}</span>${e.highlight?'<span class="highlight-mark">✦</span>':''}</div><strong>${esc(e.description)}</strong>${e.project?`<p>Project: ${esc(e.project)}</p>`:''}${e.impact?`<p>Outcome: ${esc(e.impact)}</p>`:''}</article>`).join(''):'<div class="evidence-placeholder">No entries were recorded in this period. Try a wider date range or add a past entry.</div>';
  }
  function updateWordCount(){const count=$('summaryText').value.trim().split(/\s+/).filter(Boolean).length; $('wordCount').textContent=`${count} ${count===1?'word':'words'}`;}
  function renderSavedDrafts(){
    const host=$('savedDrafts');
    if(!drafts.length){host.innerHTML='<div class="saved-empty">No saved drafts yet.</div>';return;}
    host.innerHTML=drafts.map(d=>`<div class="saved-draft"><div><strong>${prettyDate(d.start)} — ${prettyDate(d.end)}</strong><small>Saved ${new Date(d.savedAt).toLocaleDateString()} · ${d.text.trim().split(/\s+/).filter(Boolean).length} words</small></div><button class="quiet-button" data-load-draft="${esc(d.id)}">Open draft →</button></div>`).join('');
  }
  async function generate(){
    const start=$('startDate').value,end=$('endDate').value;
    if(!start||!end||start>end){toast('Choose a valid start and end date.');return;}
    const button=$('generateSummary'),hadDraft=!$('draftResult').classList.contains('hidden');button.disabled=true;button.textContent='Generating…';$('draftEmpty').classList.add('hidden');$('draftResult').classList.remove('hidden');$('summaryLoading').classList.remove('hidden');$('summaryEditor').classList.add('is-generating');$('summaryText').disabled=true;$('draftStatus').textContent='GENERATING SUMMARY';
    try{
      const result=await api('/api/summaries/generate',{method:'POST',body:JSON.stringify({start,end})});
      const evidence=result.entries||[]; $('summaryText').value=(result.paragraphs||[]).join('\n\n'); $('rangeCaption').textContent=`${prettyDate(start)} — ${prettyDate(end)} · ${evidence.length} supporting ${evidence.length===1?'entry':'entries'}`;
      $('draftEmpty').classList.add('hidden'); $('draftResult').classList.remove('hidden'); $('draftActions').classList.remove('hidden'); $('draftStatus').textContent=result.mode==='mock'&&evidence.length?'LOCAL MOCK · EDITABLE DRAFT':result.mode==='gemini'&&evidence.length?'GEMINI · EDITABLE DRAFT':evidence.length?'EDITABLE DRAFT':'NO ENTRIES FOUND'; renderEvidence(evidence); updateWordCount(); $('summaryText').focus();
    }catch(error){toast(error.message);if(!hadDraft){$('draftResult').classList.add('hidden');$('draftEmpty').classList.remove('hidden');$('draftStatus').textContent='READY TO GENERATE';}}
    finally{$('summaryLoading').classList.add('hidden');$('summaryEditor').classList.remove('is-generating');$('summaryText').disabled=false;button.disabled=false;button.innerHTML='✳ Generate summary';}
  }
  async function saveDraft(){
    try{await api('/api/drafts',{method:'POST',body:JSON.stringify({start:$('startDate').value,end:$('endDate').value,text:$('summaryText').value})});drafts=await api('/api/drafts');renderSavedDrafts();toast('Draft saved to your account.');}
    catch(error){toast(error.message);}
  }
  function downloadWord(){
    const title=`Appraisal summary — ${$('rangeCaption').textContent}`;
    const toRtf=s=>s.replace(/[\\{}]/g,'\\$&').replace(/\n/g,'\\par\n').replace(/[^\x00-\x7F]/g,c=>`\\u${c.charCodeAt(0)}?`);
    const content=`{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Georgia;}}\\f0\\fs30 ${toRtf(title)}\\par\\par\\fs24 ${toRtf($('summaryText').value)}}`;
    const blob=new Blob([content],{type:'application/rtf'}), url=URL.createObjectURL(blob), a=document.createElement('a'); a.href=url; a.download='daymark-appraisal-summary.doc'; a.click(); URL.revokeObjectURL(url); $('exportMenu').classList.add('hidden'); toast('Word document downloaded.');
  }
  function setupReminder(){
    if(!currentUser||reminder.backgroundPush)return;
    const bits=reminder.time.split(':').map(Number), now=new Date();
    if(!reminder.enabled||now.getHours()!==bits[0]||now.getMinutes()!==bits[1])return;
    if(reminder.frequency==='weekdays'&&(now.getDay()===0||now.getDay()===6))return;
    if(reminder.frequency==='custom'&&!reminder.days.includes(now.getDay()))return;
    const sentKey=`daymark.reminder.sent.${iso(now)}`; if(localStorage.getItem(sentKey))return;
    const title='Log today’s work in Daymark'; const body='Capture an achievement, project update, or impact while the details are fresh.';
    if('Notification'in window&&Notification.permission==='granted'){new Notification(title,{body,icon:'./icon.svg'});localStorage.setItem(sentKey,'1');}
  }
  function renderReminderForm(){
    $('reminderEnabled').checked=!!reminder.enabled; $('reminderFrequency').value=reminder.frequency||'daily'; $('reminderTime').value=reminder.time||'17:00'; $('customDays').classList.toggle('hidden',reminder.frequency!=='custom');
    $('dayPicker').innerHTML=DAY_LABELS.map((d,i)=>`<button type="button" class="day-chip ${(reminder.days||[]).includes(i)?'selected':''}" data-day="${i}">${d}</button>`).join('');
    $('notificationHelp').textContent=reminder.backgroundPush?'Background push is enabled on this device.':('Notification'in window)?`Browser permission: ${Notification.permission}. Background push needs VAPID keys configured on the server.`:'This browser does not support notifications. You can still save your reminder preference.';
  }
  function decodeVapidKey(value){const padded=value+'='.repeat((4-value.length%4)%4);const raw=atob(padded.replace(/-/g,'+').replace(/_/g,'/'));return Uint8Array.from(raw,c=>c.charCodeAt(0));}
  async function subscribeForPush(){
    if(!('serviceWorker'in navigator)||!('PushManager'in window)||!('Notification'in window))return false;
    const {publicKey}=await api('/api/push/public-key');if(!publicKey)return false;
    if(Notification.permission!=='granted'){const permission=await Notification.requestPermission();if(permission!=='granted')return false;}
    const registration=await navigator.serviceWorker.ready;
    let subscription=await registration.pushManager.getSubscription();
    if(!subscription)subscription=await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:decodeVapidKey(publicKey)});
    await api('/api/push/subscriptions',{method:'POST',body:JSON.stringify(subscription.toJSON())});return true;
  }

  document.querySelectorAll('[data-oauth]').forEach(button=>button.addEventListener('click',()=>{if(!button.disabled)location.href=`/api/auth/${button.dataset.oauth}`;}));
  if(passkeysSupported())$('passkeyLogin').classList.remove('hidden');
  $('passkeyLogin').addEventListener('click',signInWithPasskey);
  $('addPasskey').addEventListener('click',addPasskey);
  $('tourNext').addEventListener('click',()=>{if(tourStep>=TOUR_STEPS.length-1){finishTour();return;}tourStep+=1;renderTourStep();});
  $('tourBack').addEventListener('click',()=>{if(tourStep>0){tourStep-=1;renderTourStep();}});
  $('tourSkip').addEventListener('click',finishTour);
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!$('onboardingTour').classList.contains('hidden'))finishTour();});
  $('passkeyList').addEventListener('click',async event=>{const button=event.target.closest('[data-delete-passkey]');if(!button)return;button.disabled=true;try{await api(`/api/auth/passkeys/${encodeURIComponent(button.dataset.deletePasskey)}`,{method:'DELETE'});$('passkeyFeedback').textContent='Passkey removed.';await loadPasskeys();}catch(error){$('passkeyFeedback').textContent=error.message;button.disabled=false;}});
  $('logoutButton').addEventListener('click',async()=>{try{await api('/api/auth/logout',{method:'POST'});}catch{}currentUser=null;entries=[];drafts=[];showAuth();});

  $('addEntryTop').addEventListener('click',()=>openEntry()); $('emptyAdd').addEventListener('click',()=>openEntry()); $('closeModal').addEventListener('click',closeEntry); $('cancelEntry').addEventListener('click',closeEntry);
  $('entryModal').addEventListener('click',e=>{if(e.target===$('entryModal'))closeEntry();});
  $('entryForm').addEventListener('submit',async e=>{e.preventDefault();const id=$('entryId').value;const item={date:$('entryDate').value,type:$('entryType').value,description:$('entryDescription').value.trim(),project:$('entryProject').value.trim(),impact:$('entryImpact').value.trim(),highlight:$('entryHighlight').checked};const button=$('saveEntry');button.disabled=true;try{const saved=await api(id?`/api/entries/${encodeURIComponent(id)}`:'/api/entries',{method:id?'PUT':'POST',body:JSON.stringify(item)});entries=id?entries.map(old=>old.id===id?saved:old):[saved,...entries];renderHome();closeEntry();toast(id?'Entry updated.':'Entry saved to your account.');}catch(error){toast(error.message);}finally{button.disabled=false;}});
  $('entriesList').addEventListener('click',e=>{const button=e.target.closest('[data-edit]');if(!button)return;const item=entries.find(x=>x.id===button.dataset.edit);if(item)openEntry(item);});
  $('deleteEntry').addEventListener('click',async()=>{const id=$('entryId').value;if(!id||!confirm('Delete this entry?'))return;try{await api(`/api/entries/${encodeURIComponent(id)}`,{method:'DELETE'});entries=entries.filter(e=>e.id!==id);renderHome();closeEntry();toast('Entry deleted.');}catch(error){toast(error.message);}});
  $('allEntries').addEventListener('click',()=>{if(highlightOnly){highlightOnly=false;showAllEntries=true;}else showAllEntries=!showAllEntries;renderHome();});
  document.querySelectorAll('.nav-item').forEach(b=>b.addEventListener('click',()=>showView(b.dataset.view)));
  $('createSummary').addEventListener('click',()=>{showView('summaries');setRange('year');}); $('backHome').addEventListener('click',()=>showView('home'));
  document.querySelectorAll('.period-button').forEach(b=>b.addEventListener('click',()=>setRange(b.dataset.period)));
  $('generateSummary').addEventListener('click',generate); $('regenerate').addEventListener('click',generate); $('summaryText').addEventListener('input',updateWordCount); $('saveDraft').addEventListener('click',saveDraft);
  $('exportButton').addEventListener('click',()=>$('exportMenu').classList.toggle('hidden')); $('exportWord').addEventListener('click',downloadWord); $('exportPdf').addEventListener('click',()=>{ $('exportMenu').classList.add('hidden'); window.print(); }); document.addEventListener('click',e=>{if(!e.target.closest('.export-wrap'))$('exportMenu').classList.add('hidden');});
  $('reminderTop').addEventListener('click',()=>{renderReminderForm();loadPasskeys();showView('settings');}); $('backFromSettings').addEventListener('click',()=>showView('home'));
  $('reminderFrequency').addEventListener('change',()=>{$('customDays').classList.toggle('hidden',$('reminderFrequency').value!=='custom');});
  $('dayPicker').addEventListener('click',e=>{const b=e.target.closest('[data-day]');if(b)b.classList.toggle('selected');});
  $('saveReminder').addEventListener('click',async()=>{const enabled=$('reminderEnabled').checked;const days=[...document.querySelectorAll('.day-chip.selected')].map(b=>Number(b.dataset.day));const nextReminder={enabled,frequency:$('reminderFrequency').value,time:$('reminderTime').value||'17:00',days,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC'};try{reminder=await api('/api/reminders',{method:'PUT',body:JSON.stringify(nextReminder)});if(enabled){try{reminder.backgroundPush=await subscribeForPush();}catch{reminder.backgroundPush=false;}if(!reminder.backgroundPush&&'Notification'in window&&Notification.permission==='default'){try{await Notification.requestPermission();}catch{}}}renderReminderForm();$('settingsFeedback').textContent='Saved';setTimeout(()=>$('settingsFeedback').textContent='',2400);if(enabled&&!reminder.backgroundPush)toast('Preference saved. Background push needs VAPID setup; this device can remind while Daymark is open.');else toast(enabled?'Push reminder saved.':'Reminder turned off.');}catch(error){toast(error.message);}});
  $('savedDrafts').addEventListener('click',e=>{const button=e.target.closest('[data-load-draft]');if(!button)return;const draft=drafts.find(d=>d.id===button.dataset.loadDraft);if(!draft)return;$('startDate').value=draft.start;$('endDate').value=draft.end;$('rangeCaption').textContent=`${prettyDate(draft.start)} — ${prettyDate(draft.end)} · Saved draft`;$('summaryText').value=draft.text;$('draftEmpty').classList.add('hidden');$('draftResult').classList.remove('hidden');$('draftActions').classList.remove('hidden');$('draftStatus').textContent='SAVED DRAFT';renderEvidence(sortedEntries(entries.filter(e=>e.date>=draft.start&&e.date<=draft.end)));updateWordCount();window.scrollTo({top:0,behavior:'smooth'});});
  $('menuButton').addEventListener('click',()=>$('sidebar').classList.toggle('open'));

  $('startDate').value=`${today.getFullYear()}-01-01`; $('endDate').value=`${today.getFullYear()}-12-31`; renderHome(); renderReminderForm(); renderSavedDrafts();
  initializeAuth();
  loadOAuthProviders();
  window.setInterval(setupReminder,60000); setupReminder();
  if('serviceWorker'in navigator&&location.protocol!=='file:')navigator.serviceWorker.register('./sw.js').catch(()=>{});
})();
