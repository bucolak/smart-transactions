// Smooth scroll for in-page anchors
const navLinks = document.querySelectorAll('a[href^="#"]');
navLinks.forEach((link) => {
  link.addEventListener('click', (event) => {
    const targetId = link.getAttribute('href') || '';
    if (targetId.startsWith('#') && targetId.length > 1) {
      const target = document.querySelector(targetId);
      if (target) {
        event.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }
  });
});

// Live brand color preview for onboarding forms
const brandInputs = document.querySelectorAll('#brand_color');
brandInputs.forEach((input) => {
  const updateColor = () => {
    const val = input.value;
    if (/^#([0-9a-fA-F]{6})$/.test(val)) {
      document.documentElement.style.setProperty('--brand-color', val);
    }
  };
  input.addEventListener('input', updateColor);
  updateColor();
});

// Lightweight loading indicator for AI forms
document.querySelectorAll('.ai-action-form').forEach((form) => {
  form.addEventListener('submit', () => {
    const button = form.querySelector('button[type="submit"]');
    if (!button || button.dataset.loading === 'true') return;
    button.dataset.loading = 'true';
    const original = button.innerHTML;
    button.dataset.original = original;
    button.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Working';
    button.setAttribute('disabled', 'true');
  });
});

// OTP input sanitation
document.querySelectorAll('.otp-control').forEach((input) => {
  input.addEventListener('input', () => {
    input.value = (input.value || '').replace(/[^0-9]/g, '').slice(0, 6);
  });
  input.addEventListener('focus', () => input.select());
});
