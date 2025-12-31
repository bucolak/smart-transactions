// Apply a loading spinner and disable submit buttons on form submission
(function () {
  const attachSpinners = () => {
    document.querySelectorAll('form').forEach((form) => {
      form.addEventListener('submit', (event) => {
        const submitter = event.submitter || form.querySelector('button[type="submit"]');
        if (!submitter || submitter.type !== 'submit' || submitter.dataset.loading === 'true') return;

        submitter.dataset.loading = 'true';
        submitter.dataset.original = submitter.innerHTML;
        const currentWidth = submitter.getBoundingClientRect().width;
        if (currentWidth) {
          submitter.style.minWidth = `${currentWidth}px`;
        }
        submitter.classList.add('btn-loading');

        const label = submitter.dataset.loadingText || submitter.textContent.trim() || 'Working...';
        submitter.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span><span>${label}</span>`;
        submitter.setAttribute('disabled', 'true');
      });
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attachSpinners);
  } else {
    attachSpinners();
  }
})();
