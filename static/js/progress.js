async function pollStatus(scanId){
  const r = await fetch(`/scan-status/${scanId}`);
  const s = await r.json();
  const bar = document.getElementById('scanProgressBar');
  const urlSpan = document.getElementById('currentUrl');
  const pageSpan = document.getElementById('currentPage');
  const totalSpan = document.getElementById('totalPages');
  const stageSpan = document.getElementById('stage');
  const modeBanner = document.getElementById('scanModeBanner');
  if(urlSpan) urlSpan.textContent = s.current_url || '';
  if(pageSpan) pageSpan.textContent = s.done;
  if(totalSpan) totalSpan.textContent = s.total;
  if(bar && s.total){ bar.style.width = ((s.done/s.total)||0)*100 + '%'; }
  if(stageSpan) stageSpan.textContent = s.phase;
  if (modeBanner && typeof s.render_js !== 'undefined') {
    modeBanner.style.display = 'block';
    if (s.render_js) {
      modeBanner.className = 'alert alert-warning mb-2';
      modeBanner.innerHTML = '<strong>ACTIVE ANALYSIS:</strong> Headless browser executes JavaScript during this scan.';
    } else {
      modeBanner.className = 'alert alert-success mb-2';
      modeBanner.innerHTML = '<strong>SAFE MODE:</strong> Static fetch only (no JavaScript execution).';
    }
  }
  if (s.status === 'completed' || s.status === 'cancelled' || s.status === 'error' || s.status === 'partial') {
    if (s.domain) {
      const mode = s.render_js ? 'active' : 'safe';
      window.location.href = `/site/${s.domain}?scan_id=${encodeURIComponent(scanId)}&mode=${mode}`;
    }
  } else {
    setTimeout(()=>pollStatus(scanId), 1000);
  }
}

document.getElementById('btn-cancel')?.addEventListener('click', async ()=>{
  if (window.SCAN_ID){
    await fetch(`/scan-cancel/${window.SCAN_ID}`, {method:'POST'});
  }
});
