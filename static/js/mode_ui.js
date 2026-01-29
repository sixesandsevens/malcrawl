(() => {
  function setHTML(el, html) {
    if (el) {
      el.innerHTML = html;
    }
  }

  function updateCapabilities(active) {
    const js = document.getElementById('cap_js_exec');
    const dom = document.getElementById('cap_render_dom');
    const shot = document.getElementById('cap_screenshot');
    const net = document.getElementById('cap_net_capture');
    const note = document.getElementById('modeNote');

    if (!js || !dom || !shot || !net) return;

    if (active) {
      js.textContent = '✅ JavaScript execution (headless browser)';
      dom.textContent = '✅ Rendered DOM after JS';
      shot.textContent = '✅ Screenshot capture (if enabled)';
      net.textContent = '✅ Browser network request list (observed)';
      setHTML(
        note,
        '<span class="text-warning fw-semibold">ACTIVE mode enabled.</span> Consider VM/sandbox usage.'
      );
    } else {
      js.textContent = '❌ JavaScript execution (headless browser)';
      dom.textContent = '❌ Rendered DOM after JS';
      shot.textContent = '❌ Screenshot capture';
      net.textContent = '❌ Browser network request list';
      setHTML(
        note,
        'Default is <span class="fw-semibold">SAFE</span> mode. Toggle Active analysis only when you understand the risk.'
      );
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('render_js');
    if (!toggle) return;

    const modalEl = document.getElementById('activeModeModal');
    const cancelBtn = document.getElementById('activeModeCancel');
    const confirmBtn = document.getElementById('activeModeConfirm');

    let confirmed = false;
    let bsModal = null;
    if (modalEl && window.bootstrap?.Modal) {
      bsModal = new window.bootstrap.Modal(modalEl, {
        backdrop: 'static',
        keyboard: false,
      });
    }

    updateCapabilities(toggle.checked);

    toggle.addEventListener('change', () => {
      if (toggle.checked) {
        if (bsModal) {
          confirmed = false;
          bsModal.show();
        } else {
          updateCapabilities(true);
        }
      } else {
        updateCapabilities(false);
      }
    });

    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => {
        toggle.checked = false;
        updateCapabilities(false);
      });
    }

    if (confirmBtn) {
      confirmBtn.addEventListener('click', () => {
        confirmed = true;
        toggle.checked = true;
        updateCapabilities(true);
        if (bsModal) bsModal.hide();
      });
    }

    if (modalEl) {
      modalEl.addEventListener('hidden.bs.modal', () => {
        if (toggle.checked && !confirmed) {
          toggle.checked = false;
          updateCapabilities(false);
        }
        if (confirmed) {
          confirmed = false;
        }
      });
    }
  });
})();
