function openShot(url){
  document.getElementById('shot-img').src = url;
  document.getElementById('open-original').href = url;
  document.getElementById('shot-modal').classList.remove('hidden');
}
function closeShot(){ document.getElementById('shot-modal').classList.add('hidden'); }
