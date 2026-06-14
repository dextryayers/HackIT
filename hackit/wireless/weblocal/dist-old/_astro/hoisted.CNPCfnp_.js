import"./Navbar.astro_astro_type_script_index_0_lang.Ct-hBWHq.js";import"https://cdn.jsdelivr.net/npm/sweetalert2@11";import"./TerminalOutput.astro_astro_type_script_index_0_lang.CP9MqDl5.js";let n=[],o=[],d="lua";async function l(){try{const e=await(await fetch("/api/plugins")).json();n=e.lua||[],o=e.ruby||[],document.getElementById("lua-count-badge").textContent=n.length,document.getElementById("ruby-count-badge").textContent=o.length,document.getElementById("total-count-badge").textContent=`${n.length+o.length} plugins loaded`,s();const r=document.getElementById("plugin-script");r.innerHTML=[...n.map(t=>`<option value="${t}" data-engine="lua">${t}</option>`),...o.map(t=>`<option value="${t}" data-engine="ruby">${t}</option>`)].join(""),document.getElementById("tab-lua").classList.add("active-tab","bg-primary/10","text-primary")}catch{}}function s(a){const e=document.getElementById("plugin-grid"),r=n,t=d;if(r.length===0){e.innerHTML=`<div class="col-span-full flex flex-col items-center py-10">
      <div class="w-14 h-14 rounded-2xl bg-muted/50 flex items-center justify-center mb-3 border border-border">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" class="text-muted-foreground"><line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
      </div>
      <p class="text-sm text-muted-foreground font-medium">No Lua plugins found</p>
      <p class="text-xs text-muted-foreground/60 mt-1">Add scripts to the plugin directory</p>
    </div>`;return}e.innerHTML=r.map(i=>`<div class="group relative overflow-hidden rounded-xl bg-card border border-border hover:border-primary/30 hover:shadow-[0_0_20px_rgba(0,212,255,0.15)] hover:-translate-y-0.5 transition-all duration-300 p-4 cursor-pointer" onclick="selectPlugin('${i}', '${t}')">
      <div class="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
      <div class="relative z-10 flex items-center justify-between gap-3">
        <div class="flex items-center gap-3 min-w-0">
          <span class="w-8 h-8 rounded-lg bg-gradient-to-br from-primary to-cyan-600 flex items-center justify-center text-white text-[10px] font-bold shrink-0 shadow-lg">L</span>
          <div class="min-w-0">
            <p class="text-sm font-medium text-foreground truncate">${i}</p>
            <p class="text-[11px] text-muted-foreground/60 truncate">${t}/${i}</p>
          </div>
        </div>
        <span class="w-7 h-7 rounded-lg bg-muted/50 flex items-center justify-center text-muted-foreground group-hover:text-primary group-hover:bg-primary/10 transition-all duration-200 shrink-0">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        </span>
      </div>
    </div>`).join("")}l();
