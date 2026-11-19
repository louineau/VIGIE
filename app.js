/* =========================================================================
 *  VIGIE — application (vanilla JS, aucune dépendance)
 *  Données : window.VIGIE_DATA (data/veille.js) et window.VIGIE_FICHES (data/fiches.js)
 * ====================================================================== */
(function () {
  "use strict";

  const D = window.VIGIE_DATA || { items: [], themes: [], sources: [], weeks: [], agenda: [], site: {} };
  const F = window.VIGIE_FICHES || [];
  const app = document.getElementById("app");
  const TH = Object.fromEntries((D.themes || []).map(t => [t.id, t]));
  const BY_ID = Object.fromEntries((D.items || []).map(i => [i.id, i]));
  const SEV = { crit: { label: "Critique", rank: 3 }, high: { label: "Élevée", rank: 2 }, med: { label: "Moyenne", rank: 1 }, low: { label: "Faible", rank: 0 } };
  const KIND = { alerte: "Alertes", avis: "Avis", actu: "Actualités", cti: "Menaces", recherche: "Recherche", version: "Versions", media: "Médias", kev: "Exploitées (KEV)", cve: "CVE" };
  const STATUS = { passe: "Passé", en_vigueur: "En vigueur", en_cours: "En cours", a_venir: "À venir" };
  const NOW = Date.now();
  const DAY = 864e5;

  /* ---------- utilitaires ---------- */
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const safeUrl = u => /^https?:\/\//i.test(u || "") ? u : "#";
  const ts = d => (d ? Date.parse(d) : 0) || 0;
  const fmtDate = (d, opt) => d ? new Date(d).toLocaleDateString("fr-FR", opt || { day: "numeric", month: "short", year: "numeric" }) : "";
  function ago(d) {
    const s = (NOW - ts(d)) / 1000;
    if (s < 3600) return "il y a " + Math.max(1, Math.round(s / 60)) + " min";
    if (s < 86400) return "il y a " + Math.round(s / 3600) + " h";
    if (s < 7 * 86400) return "il y a " + Math.round(s / 86400) + " j";
    return fmtDate(d);
  }
  const within = (it, days) => NOW - ts(it.date) <= days * DAY;
  const themeStyle = id => TH[id] ? `style="--tc:${esc(TH[id].color)}"` : "";

  function sevBadge(it) {
    if (!it.sev) return "";
    const t = SEV[it.sev].label + (it.cvss != null ? " · " + it.cvss.toFixed(1) : "");
    return `<span class="sev ${it.sev}" title="Criticité ${it.cvss != null ? "(CVSS)" : "(estimée)"}">${esc(t)}</span>`;
  }

  function itemHtml(it) {
    const tags = (it.themes || []).filter(t => TH[t]).map(t =>
      `<button class="tag" type="button" data-theme="${esc(t)}" ${themeStyle(t)}>${esc(TH[t].label)}</button>`).join("");
    const extra = it.extra && it.extra.due ? `<span>échéance CISA ${esc(fmtDate(it.extra.due))}</span>` : "";
    return `<article class="item" data-sev="${esc(it.sev || "")}">
      <span class="item-bar"></span>
      <div class="item-body">
        <div class="item-meta">${sevBadge(it)}<span class="item-src">${esc(it.source)}</span><span class="cote" title="Fiabilité de la source">${esc(it.cote)}</span><time datetime="${esc(it.date)}">${esc(ago(it.date))}</time>${extra}</div>
        <a class="item-title" href="${esc(safeUrl(it.link))}" target="_blank" rel="noopener noreferrer">${esc(it.title)}</a>
        ${it.summary ? `<p class="item-sum">${esc(it.summary)}</p>` : ""}
        ${tags ? `<div class="tags">${tags}</div>` : ""}
      </div></article>`;
  }

  function bindTags(root) {
    root.querySelectorAll(".tag[data-theme]").forEach(b => b.addEventListener("click", () => {
      location.hash = "#/flux?theme=" + encodeURIComponent(b.dataset.theme);
    }));
  }

  function ficheCard(f) {
    const tags = (f.themes || []).filter(t => TH[t]).map(t => `<span class="tag" ${themeStyle(t)}>${esc(TH[t].label)}</span>`).join("");
    return `<a class="card" href="#/fiche/${encodeURIComponent(f.slug)}">
      <div class="item-meta"><time>${esc(fmtDate(f.date))}</time>${f.cote ? `<span class="cote">${esc(f.cote)}</span>` : ""}${f.draft ? '<span class="draft">brouillon</span>' : ""}</div>
      <h3>${esc(f.title)}</h3>${f.summary ? `<p>${esc(f.summary)}</p>` : ""}
      ${tags ? `<div class="tags">${tags}</div>` : ""}</a>`;
  }

  /* ---------- vues ---------- */
  function viewDashboard() {
    const items = D.items || [];
    const d1 = items.filter(i => within(i, 1)).length;
    const severe7 = items.filter(i => within(i, 7) && (i.sev === "crit" || i.sev === "high")).length;
    const kev = items.filter(i => i.kind === "kev").length;
    const top = items.filter(i => within(i, 7) && (i.sev === "crit" || (i.themes || []).includes("exploit")))
      .sort((a, b) => (SEV[b.sev]?.rank ?? -1) - (SEV[a.sev]?.rank ?? -1) || ts(b.date) - ts(a.date)).slice(0, 8);
    const next = (D.agenda || []).filter(e => ts(e.date) >= NOW - DAY).sort((a, b) => ts(a.date) - ts(b.date))[0];

    const tiles = (D.themes || []).map(t => {
      const n7 = items.filter(i => within(i, 7) && (i.themes || []).includes(t.id)).length;
      const n30 = items.filter(i => (i.themes || []).includes(t.id)).length;
      const days = Array.from({ length: 14 }, (_, k) => items.filter(i => (i.themes || []).includes(t.id) && Math.floor((NOW - ts(i.date)) / DAY) === 13 - k).length);
      const mx = Math.max(1, ...days);
      return `<a class="theme-tile" href="#/flux?theme=${esc(t.id)}" ${themeStyle(t.id)}>
        <span class="theme-ico" aria-hidden="true">${esc(t.icon)}</span>
        <span><span class="theme-name">${esc(t.label)}</span><br><span class="theme-count">${n7} cette semaine · ${n30} sur 30 j</span></span>
        <span class="spark" aria-hidden="true">${days.map(v => `<i style="height:${Math.round(v / mx * 100)}%"></i>`).join("")}</span></a>`;
    }).join("");

    app.innerHTML = `
      <div class="page-head">
        <p class="eyebrow">Tableau de bord</p>
        <h1>${esc(D.site.tagline || "Veille cybersécurité")}</h1>
        <p class="lede">${esc(D.site.description || "")}</p>
      </div>
      <div class="kpis">
        <a class="kpi" href="#/flux?days=1"><div class="kpi-num">${d1}</div><div class="kpi-label">entrées sur 24 h</div></a>
        <a class="kpi ${severe7 ? "alert" : ""}" href="#/flux?sev=high&days=7"><div class="kpi-num">${severe7}</div><div class="kpi-label">critiques ou élevées sur 7 j</div></a>
        <a class="kpi" href="#/flux?kind=kev"><div class="kpi-num">${kev}</div><div class="kpi-label">vulnérabilités exploitées ajoutées (CISA KEV, 30 j)</div></a>
        <a class="kpi" href="#/fiches"><div class="kpi-num">${F.length}</div><div class="kpi-label">fiches d'analyse</div></a>
      </div>

      <section class="section">
        <div class="section-head"><h2>À la une — 7 derniers jours</h2><a class="more" href="#/flux?sev=crit&days=7">Tout voir →</a></div>
        ${top.length ? `<div class="items">${top.map(itemHtml).join("")}</div>` : '<div class="empty">Rien de critique ni d\'exploité cette semaine.</div>'}
      </section>

      <section class="section">
        <div class="section-head"><h2>Thèmes</h2><span class="muted" style="font-size:13px">14 derniers jours</span></div>
        <div class="themes">${tiles}</div>
      </section>

      <div class="two section">
        <section>
          <div class="section-head"><h2>Dernières fiches</h2><a class="more" href="#/fiches">Toutes →</a></div>
          ${F.length ? `<div class="grid">${F.slice(0, 3).map(ficheCard).join("")}</div>` : '<div class="empty">Aucune fiche publiée pour l\'instant.</div>'}
        </section>
        <section>
          <div class="section-head"><h2>Prochaine échéance</h2><a class="more" href="#/agenda">Agenda →</a></div>
          ${next ? `<div class="card"><div class="tl-date">${esc(fmtDate(next.date, { day: "numeric", month: "long", year: "numeric" }))}</div><h3>${esc(next.title)}</h3><p>${esc(next.detail)}</p></div>` : '<div class="empty">Aucune échéance à venir.</div>'}
          <div class="section-head" style="margin-top:22px"><h2>Sources</h2><a class="more" href="#/methode">Détail →</a></div>
          <p class="muted" style="margin:0">${(D.sources || []).filter(s => s.ok).length} sources sur ${(D.sources || []).length} ont répondu à la dernière collecte · ${D.stats ? D.stats.archive : 0} entrées en archive.</p>
        </section>
      </div>`;
    bindTags(app);
  }

  /* état des filtres du flux */
  const flux = { q: "", theme: new Set(), sev: null, kind: null, cote: null, days: null, sort: "date", shown: 40 };

  function viewFlux(params) {
    flux.theme = new Set(params.get("theme") ? params.get("theme").split(",") : []);
    flux.sev = params.get("sev"); flux.kind = params.get("kind"); flux.cote = params.get("cote");
    flux.days = params.get("days") ? +params.get("days") : null;
    flux.q = params.get("q") || ""; flux.shown = 40;

    app.innerHTML = `
      <div class="page-head"><p class="eyebrow">Flux</p><h1>Toutes les entrées</h1>
      <p class="lede">${(D.items || []).length} entrées sur ${esc(String(D.site.recent_days || 30))} jours, issues de ${(D.sources || []).length} sources. Cliquez sur un thème pour filtrer.</p></div>
      <div class="filters">
        <input class="search" id="q" type="search" placeholder="Rechercher (titre, résumé, source, CVE…)" value="${esc(flux.q)}" autocomplete="off" aria-label="Rechercher">
        <div class="chips" id="chThemes"></div>
        <div class="chips" id="chOther"></div>
      </div>
      <div class="result-count" id="count"></div>
      <div id="list"></div>`;
    const q = document.getElementById("q");
    q.addEventListener("input", () => { flux.q = q.value; flux.shown = 40; renderList(); });
    renderChips(); renderList();
  }

  function chip(label, on, onClick, color) {
    const b = document.createElement("button");
    b.type = "button"; b.className = "chip" + (on ? " on" : ""); b.textContent = label;
    if (color) b.style.setProperty("--tc", color);
    b.addEventListener("click", onClick);
    return b;
  }

  function renderChips() {
    const a = document.getElementById("chThemes"), b = document.getElementById("chOther");
    a.innerHTML = '<span class="chip-label">thème</span>'; b.innerHTML = "";
    (D.themes || []).forEach(t => a.appendChild(chip(t.icon + " " + t.label, flux.theme.has(t.id), () => {
      flux.theme.has(t.id) ? flux.theme.delete(t.id) : flux.theme.add(t.id); refresh();
    }, t.color)));
    const lab = s => { const l = document.createElement("span"); l.className = "chip-label"; l.textContent = s; return l; };
    b.appendChild(lab("criticité"));
    [["crit", "Critique"], ["high", "≥ Élevée"], ["med", "≥ Moyenne"]].forEach(([k, l]) =>
      b.appendChild(chip(l, flux.sev === k, () => { flux.sev = flux.sev === k ? null : k; refresh(); })));
    b.appendChild(lab("période"));
    [[1, "24 h"], [7, "7 j"], [30, "30 j"]].forEach(([k, l]) =>
      b.appendChild(chip(l, flux.days === k, () => { flux.days = flux.days === k ? null : k; refresh(); })));
    b.appendChild(lab("type"));
    const kinds = [...new Set((D.items || []).map(i => i.kind))];
    kinds.forEach(k => b.appendChild(chip(KIND[k] || k, flux.kind === k, () => { flux.kind = flux.kind === k ? null : k; refresh(); })));
    b.appendChild(lab("fiabilité"));
    ["A", "B", "C"].forEach(k => b.appendChild(chip(k, flux.cote === k, () => { flux.cote = flux.cote === k ? null : k; refresh(); })));
    b.appendChild(lab("tri"));
    b.appendChild(chip(flux.sort === "date" ? "Plus récent" : "Plus critique", true, () => { flux.sort = flux.sort === "date" ? "sev" : "date"; refresh(); }));
  }

  function refresh() {
    const p = new URLSearchParams();
    if (flux.theme.size) p.set("theme", [...flux.theme].join(","));
    ["sev", "kind", "cote", "days"].forEach(k => { if (flux[k]) p.set(k, flux[k]); });
    if (flux.q) p.set("q", flux.q);
    history.replaceState(null, "", "#/flux" + (p.toString() ? "?" + p : ""));
    flux.shown = 40; renderChips(); renderList();
  }

  function filtered() {
    const minRank = flux.sev ? SEV[flux.sev].rank : -1;
    const words = flux.q.toLowerCase().split(/\s+/).filter(Boolean);
    let out = (D.items || []).filter(i => {
      if (flux.theme.size && ![...flux.theme].every(t => (i.themes || []).includes(t))) return false;
      if (minRank > -1 && (SEV[i.sev]?.rank ?? -1) < minRank) return false;
      if (flux.kind && i.kind !== flux.kind) return false;
      if (flux.cote && i.cote !== flux.cote) return false;
      if (flux.days && !within(i, flux.days)) return false;
      if (words.length) {
        const hay = (i.title + " " + i.summary + " " + i.source + " " + (i.themes || []).map(t => TH[t]?.label || "").join(" ")).toLowerCase();
        if (!words.every(w => hay.includes(w))) return false;
      }
      return true;
    });
    out.sort(flux.sort === "sev"
      ? (a, b) => (SEV[b.sev]?.rank ?? -1) - (SEV[a.sev]?.rank ?? -1) || (b.cvss || 0) - (a.cvss || 0) || ts(b.date) - ts(a.date)
      : (a, b) => ts(b.date) - ts(a.date));
    return out;
  }

  function renderList() {
    const list = document.getElementById("list"), count = document.getElementById("count");
    const all = filtered();
    count.textContent = all.length + (all.length > 1 ? " entrées" : " entrée");
    if (!all.length) { list.innerHTML = '<div class="empty">Aucune entrée ne correspond à ces filtres.</div>'; return; }
    list.innerHTML = `<div class="items">${all.slice(0, flux.shown).map(itemHtml).join("")}</div>` +
      (all.length > flux.shown ? `<button class="load-more" id="more" type="button">Afficher plus (${all.length - flux.shown} restantes)</button>` : "");
    bindTags(list);
    const m = document.getElementById("more");
    if (m) m.addEventListener("click", () => { flux.shown += 40; renderList(); });
  }

  function viewFiches() {
    app.innerHTML = `<div class="page-head"><p class="eyebrow">Fiches</p><h1>Fiches d'analyse</h1>
      <p class="lede">Une information de veille, vérifiée à la source, analysée et accompagnée de recommandations.</p></div>
      ${F.length ? `<div class="cards">${F.map(ficheCard).join("")}</div>` : '<div class="empty">Aucune fiche publiée pour l\'instant. Ajoutez un fichier Markdown dans <code>fiches/</code>.</div>'}`;
  }

  function viewFiche(slug) {
    const f = F.find(x => x.slug === slug);
    if (!f) { app.innerHTML = '<div class="empty">Fiche introuvable. <a href="#/fiches">Retour aux fiches</a></div>'; return; }
    const tags = (f.themes || []).filter(t => TH[t]).map(t => `<a class="tag" href="#/flux?theme=${esc(t)}" ${themeStyle(t)}>${esc(TH[t].label)}</a>`).join("");
    app.innerHTML = `<article class="article">
      <a class="back" href="#/fiches">← Fiches</a>
      <p class="eyebrow">Fiche de veille</p>
      <h1>${esc(f.title)}</h1>
      ${f.summary ? `<p class="lede">${esc(f.summary)}</p>` : ""}
      <div class="article-meta"><time>${esc(fmtDate(f.date, { day: "numeric", month: "long", year: "numeric" }))}</time>
        ${f.cote ? `<span>Fiabilité <span class="cote">${esc(f.cote)}</span></span>` : ""}
        ${f.criticite ? `<span>Criticité : ${esc(f.criticite)}</span>` : ""}
        ${f.draft ? '<span class="draft">brouillon</span>' : ""}</div>
      ${tags ? `<div class="tags">${tags}</div>` : ""}
      <div class="prose">${f.html}</div></article>`;
  }

  function viewHebdo() {
    const weeks = D.weeks || [];
    app.innerHTML = `<div class="page-head"><p class="eyebrow">Hebdo</p><h1>Synthèses hebdomadaires</h1>
      <p class="lede">Générées automatiquement à partir de l'archive : volume par thème et entrées les plus sévères de chaque semaine.</p></div>
      ${weeks.length ? weeks.map(w => {
        const tot = Object.values(w.themes).reduce((a, b) => a + b, 0) || 1;
        const ordered = Object.entries(w.themes).sort((a, b) => b[1] - a[1]);
        const tops = w.top.map(id => BY_ID[id]).filter(Boolean);
        return `<section class="week">
          <div class="week-head"><h3>Semaine du ${esc(fmtDate(w.start, { day: "numeric", month: "long" }))} au ${esc(fmtDate(w.end, { day: "numeric", month: "long", year: "numeric" }))}</h3>
            <span class="muted">${w.total} entrées · ${w.severe} critiques ou élevées</span></div>
          <div class="stack" aria-hidden="true">${ordered.map(([t, n]) => `<i style="--tc:${esc(TH[t]?.color || "#888")};width:${(n / tot * 100).toFixed(1)}%"></i>`).join("")}</div>
          <div class="legend">${ordered.map(([t, n]) => `<span style="--tc:${esc(TH[t]?.color || "#888")}">${esc(TH[t]?.label || t)} ${n}</span>`).join("")}</div>
          ${tops.length ? `<ol>${tops.map(i => `<li>${sevBadge(i)} <a href="${esc(safeUrl(i.link))}" target="_blank" rel="noopener noreferrer">${esc(i.title)}</a> <span class="muted">— ${esc(i.source)}</span></li>`).join("")}</ol>` : ""}
        </section>`;
      }).join("") : '<div class="empty">Pas encore assez d\'historique.</div>'}`;
  }

  function viewAgenda() {
    const ev = (D.agenda || []).slice().sort((a, b) => ts(a.date) - ts(b.date));
    let marked = false;
    const rows = ev.map(e => {
      let m = "";
      if (!marked && ts(e.date) > NOW) { marked = true; m = `<li class="now-marker">— aujourd'hui, ${esc(fmtDate(new Date().toISOString(), { day: "numeric", month: "long", year: "numeric" }))} —</li>`; }
      return m + `<li class="tl" data-status="${esc(e.status)}">
        <div class="tl-date">${esc(fmtDate(e.date, { day: "numeric", month: "long", year: "numeric" }))}</div>
        <div class="tl-title">${esc(e.title)}<span class="status">${esc(STATUS[e.status] || e.status)}</span></div>
        <p class="tl-detail">${esc(e.detail)} ${e.source ? `<a href="${esc(safeUrl(e.source))}" target="_blank" rel="noopener noreferrer">Source</a>` : ""}${e.checked ? ` <span class="muted">· vérifié le ${esc(fmtDate(e.checked))}</span>` : ""}</p></li>`;
    }).join("");
    app.innerHTML = `<div class="page-head"><p class="eyebrow">Agenda</p><h1>Échéances réglementaires</h1>
      <p class="lede">AI Act, NIS 2 et textes associés. Chaque date renvoie à sa source ; à revérifier dans le texte officiel avant citation.</p></div>
      ${ev.length ? `<ol class="timeline">${rows}</ol>` : '<div class="empty">Aucune échéance.</div>'}`;
  }

  function viewMethode() {
    const src = (D.sources || []).slice().sort((a, b) => (a.group || "").localeCompare(b.group || "") || a.name.localeCompare(b.name));
    app.innerHTML = `<div class="page-head"><p class="eyebrow">Méthode</p><h1>Méthode et sources</h1>
      <p class="lede">Comment cette veille est collectée, triée et analysée.</p></div>
      <section class="section" style="margin-top:0"><h2>Cycle de veille</h2>
        <div class="cycle">
          <div class="step"><strong>Orientation</strong>Axes suivis et publics visés.</div>
          <div class="step"><strong>Collecte</strong>Flux RSS/Atom, CISA KEV et NVD, toutes les 6 h.</div>
          <div class="step"><strong>Tri</strong>Thèmes et criticité attribués automatiquement.</div>
          <div class="step"><strong>Analyse</strong>Vérification à la source et fiche rédigée à la main.</div>
          <div class="step"><strong>Diffusion</strong>Site, synthèse hebdo, flux RSS.</div>
          <div class="step"><strong>Ajustement</strong>Revue trimestrielle des sources et des règles.</div>
        </div></section>
      <div class="two section">
        <section><h2>Fiabilité des sources</h2>
          <table class="tbl"><thead><tr><th>Cote</th><th>Signification</th></tr></thead><tbody>
            <tr><td><span class="cote">A</span></td><td>Source officielle ou primaire (CERT, autorité, éditeur du produit)</td></tr>
            <tr><td><span class="cote">B</span></td><td>Chercheur ou éditeur reconnu</td></tr>
            <tr><td><span class="cote">C</span></td><td>Média spécialisé : à recouper avec une source A ou B</td></tr>
            <tr><td><span class="cote">D</span></td><td>Blog ou réseau social : jamais utilisé seul</td></tr></tbody></table></section>
        <section><h2>Criticité</h2>
          <table class="tbl"><thead><tr><th>Niveau</th><th>Règle</th></tr></thead><tbody>
            <tr><td><span class="sev crit">Critique</span></td><td>CVSS ≥ 9, ou exploitation active / zero-day</td></tr>
            <tr><td><span class="sev high">Élevée</span></td><td>CVSS ≥ 7, alerte CERT, KEV, exécution de code à distance</td></tr>
            <tr><td><span class="sev med">Moyenne</span></td><td>CVSS ≥ 4</td></tr>
            <tr><td class="muted">—</td><td>Non évaluée automatiquement (actualité, recherche)</td></tr></tbody></table></section>
      </div>
      <section class="section"><h2>Sources suivies</h2>
        <table class="tbl"><thead><tr><th>Source</th><th>Groupe</th><th>Type</th><th>Cote</th><th>Dernière collecte</th></tr></thead><tbody>
        ${src.map(s => `<tr><td>${s.url && s.url.startsWith("http") ? `<a href="${esc(safeUrl(s.url))}" target="_blank" rel="noopener noreferrer">${esc(s.name)}</a>` : esc(s.name)}</td>
          <td>${esc(s.group)}</td><td>${esc(KIND[s.kind] || s.kind)}</td><td><span class="cote">${esc(s.cote)}</span></td>
          <td>${s.ok === true ? `<span class="ok">● ${s.count} entrées</span>` : s.ok === false ? `<span class="ko" title="${esc(s.error || "")}">● en échec</span>` : '<span class="muted">—</span>'}</td></tr>`).join("")}
        </tbody></table></section>`;
  }

  /* ---------- routeur ---------- */
  function route() {
    const h = location.hash.replace(/^#\/?/, "");
    const [path, query] = h.split("?");
    const params = new URLSearchParams(query || "");
    const seg = path.split("/");
    document.querySelectorAll("#nav a").forEach(a => a.classList.toggle("active",
      a.dataset.route === seg[0] || (seg[0] === "fiche" && a.dataset.route === "fiches")));
    if (seg[0] === "flux") viewFlux(params);
    else if (seg[0] === "fiches") viewFiches();
    else if (seg[0] === "fiche") viewFiche(decodeURIComponent(seg[1] || ""));
    else if (seg[0] === "hebdo") viewHebdo();
    else if (seg[0] === "agenda") viewAgenda();
    else if (seg[0] === "methode") viewMethode();
    else viewDashboard();
    const titles = { flux: "Flux", fiches: "Fiches", fiche: "Fiche", hebdo: "Hebdo", agenda: "Agenda", methode: "Méthode" };
    document.title = (D.site.name || "VIGIE") + (titles[seg[0]] ? " — " + titles[seg[0]] : " — Veille cybersécurité");
    window.scrollTo(0, 0);
  }

  /* ---------- en-tête, pied, thème ---------- */
  const name = D.site.name || "VIGIE";
  document.getElementById("brandName").textContent = name;
  document.getElementById("footName").textContent = name;
  document.getElementById("footTag").textContent = D.site.tagline || "";
  if (D.updated) document.getElementById("updated").textContent = "maj " + ago(D.updated);
  if (D.site.repo) document.getElementById("repoWrap").innerHTML = ` · <a href="${esc(safeUrl(D.site.repo))}" target="_blank" rel="noopener">Dépôt</a>`;
  document.getElementById("themeBtn").addEventListener("click", () => {
    const cur = document.documentElement.dataset.theme ||
      (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const nxt = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = nxt;
    try { localStorage.setItem("vigie-theme", nxt); } catch (e) { /* stockage indisponible */ }
  });
  window.addEventListener("hashchange", route);
  route();
})();
