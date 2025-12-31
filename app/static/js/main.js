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
