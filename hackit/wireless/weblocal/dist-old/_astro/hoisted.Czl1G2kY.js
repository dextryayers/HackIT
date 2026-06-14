import"./Navbar.astro_astro_type_script_index_0_lang.Ct-hBWHq.js";import"https://cdn.jsdelivr.net/npm/sweetalert2@11";import"./TerminalOutput.astro_astro_type_script_index_0_lang.CP9MqDl5.js";async function d(){const t=document.getElementById("workspace-grid");try{const r=(await(await fetch("/api/workspaces")).json()).workspaces||[];r.length===0?t.innerHTML=`<div class="col-span-full flex flex-col items-center py-16">
        <div class="w-16 h-16 rounded-2xl bg-muted/50 flex items-center justify-center mb-5 border border-border">
          <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" class="text-muted-foreground"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
        </div>
        <p class="text-sm text-muted-foreground font-medium">No workspaces</p>
        <p class="text-xs text-muted-foreground/60 mt-1 mb-5">Create a workspace to organize your sessions</p>
        <button onclick="createWorkspace()" class="px-5 py-2.5 rounded-xl bg-gradient-to-r from-primary to-cyber-green text-white text-sm font-semibold transition-all duration-300 shadow-lg shadow-primary/20 hover:shadow-[0_0_30px_rgba(0,212,255,0.4)] flex items-center gap-2">
          <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          Create Workspace
        </button>
      </div>`:t.innerHTML=`<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">${r.map(e=>{const o=typeof e=="string"?e:e.name||e.id||"Unnamed",s=e.created_at||e.created||"",a=e.attack_count??e.session_count??0,i=(e.status||"active")==="active"?'<span class="px-2 py-0.5 rounded-full bg-cyber-green/10 text-cyber-green text-[10px] font-semibold border border-cyber-green/20">Active</span>':'<span class="px-2 py-0.5 rounded-full bg-muted/50 text-muted-foreground text-[10px] font-semibold border border-border">Inactive</span>',n=s?new Date(s).toLocaleDateString("en-US",{month:"short",day:"numeric",year:"numeric"}):"";return`<div onclick="selectWorkspace('${o}')" class="group relative overflow-hidden rounded-xl bg-card border border-border hover:border-primary/30 hover:shadow-[0_0_25px_rgba(0,212,255,0.12)] transition-all duration-300 cursor-pointer hover:-translate-y-0.5">
          <div class="absolute inset-0 bg-gradient-to-br from-primary/[0.03] via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
          <div class="absolute top-0 left-0 w-full h-0.5 bg-gradient-to-r from-primary via-cyber-green to-cyber-purple scale-x-0 group-hover:scale-x-100 transition-transform duration-500 origin-left"></div>
          <div class="relative z-10 p-4">
            <div class="flex items-start justify-between mb-3">
              <div class="w-9 h-9 rounded-lg bg-gradient-to-br from-primary/20 to-cyber-green/20 flex items-center justify-center">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-primary"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
              </div>
              <button onclick="event.stopPropagation(); deleteWorkspace('${o}')" class="opacity-0 group-hover:opacity-100 transition-opacity duration-200 p-1 rounded-md hover:bg-cyber-red/10 text-muted-foreground hover:text-cyber-red" title="Delete workspace">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              </button>
            </div>
            <h3 class="text-sm font-semibold text-foreground group-hover:text-primary transition-colors">${o}</h3>
            <div class="flex items-center gap-3 mt-2 text-[11px] text-muted-foreground">
              ${n?`<span>${n}</span>`:""}
              <span>${a} attack${a!==1?"s":""}</span>
            </div>
            <div class="mt-3">${i}</div>
          </div>
        </div>`}).join("")}</div>`,window.appendTerminalById?.("sessions-terminal",`<span class="text-cyber-green">Loaded ${r.length} workspaces</span>`)}catch{t.innerHTML='<div class="col-span-full flex flex-col items-center py-16"><div class="w-14 h-14 rounded-2xl bg-cyber-red/10 flex items-center justify-center mb-4 border border-cyber-red/20"><svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="text-cyber-red"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg></div><p class="text-sm text-cyber-red font-medium">Failed to load workspaces</p><p class="text-xs text-muted-foreground/60 mt-1">Check backend connection</p></div>'}}d();
