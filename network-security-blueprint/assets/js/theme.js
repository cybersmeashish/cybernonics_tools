/* Apply saved / preferred theme before first paint */
(function(){var t='light';try{t=localStorage.getItem('nsbp_theme')||((window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light');}catch(e){}document.documentElement.setAttribute('data-theme',t);})();
