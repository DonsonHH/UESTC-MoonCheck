(() => {
  let mode = 'system';
  try {
    const saved = localStorage.getItem('moon-color-mode');
    if (['system', 'light', 'dark'].includes(saved)) mode = saved;
  } catch {}
  document.documentElement.dataset.theme = mode;
})();
