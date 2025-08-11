async function pollStatus(scanId){
  const r = await fetch(`/scan-status/${scanId}`);
  const s = await r.json();
  const bar = document.getElementById('scanProgressBar');
  const urlSpan = document.getElementById('currentUrl');
  const pageSpan = document.getElementById('currentPage');
  const totalSpan = document.getElementById('totalPages');
  const stageSpan = document.getElementById('stage');
  if(urlSpan) urlSpan.textContent = s.current_url || '';
  if(pageSpan) pageSpan.textContent = s.done;
  if(totalSpan) totalSpan.textContent = s.total;
  if(bar && s.total){ bar.style.width = ((s.done/s.total)||0)*100 + '%'; }
  if(stageSpan) stageSpan.textContent = s.phase;
  if (s.status === 'completed' || s.status === 'cancelled' || s.status === 'error' || s.status === 'partial') {
    if (s.domain) {
      window.location.href = `/site/${s.domain}`;
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
