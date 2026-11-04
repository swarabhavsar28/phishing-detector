"use strict";

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-value]").forEach((element) => {
    const raw = Number.parseFloat(element.dataset.value || "0");
    const value = Number.isFinite(raw) ? Math.min(100, Math.max(0, raw)) : 0;
    element.style.setProperty("--value", `${value}%`);
  });

  document.querySelectorAll("[data-fill-url]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = document.querySelector("#url-input");
      if (!input) return;
      input.value = button.dataset.fillUrl || "";
      input.focus();
    });
  });

  document.querySelectorAll("[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const message = form.dataset.confirm || "Continue?";
      if (!window.confirm(message)) event.preventDefault();
    });
  });

  document.querySelectorAll("[data-loading-form]").forEach((form) => {
    form.addEventListener("submit", () => {
      const button = form.querySelector("button[type='submit']");
      if (!button) return;
      button.classList.add("is-loading");
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
    });
  });

  const messageField = document.querySelector("#message-input");
  const count = document.querySelector("[data-char-count]");
  if (messageField && count) {
    const updateCount = () => { count.textContent = `${messageField.value.length.toLocaleString()} / 12,000`; };
    messageField.addEventListener("input", updateCount);
    updateCount();
  }
});
