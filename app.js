(() => {
  "use strict";

  const root = document.documentElement;
  const body = document.body;
  const main = document.querySelector(".main");
  const mobileBar = document.querySelector(".mobile-bar");
  const sidebar = document.querySelector("#sidebar");
  const menuButton = document.querySelector(".menu-button");
  const collapseButton = document.querySelector(".collapse-button");
  const scrim = document.querySelector(".scrim");
  const settingsTrigger = document.querySelector(".settings-trigger");
  const appearancePanel = document.querySelector("#appearance-panel");
  const modelButton = document.querySelector(".model-button");
  const modelMenu = document.querySelector(".model-menu");
  const composer = document.querySelector(".composer");
  const prompt = document.querySelector("#prompt");
  const expandButton = document.querySelector(".expand-button");
  const feedback = document.querySelector(".attachment-feedback");
  const voiceButton = document.querySelector(".voice-button");
  const toast = document.querySelector(".toast");
  let lastSidebarFocus = null;
  let recordingTimer = null;
  let seconds = 0;
  let toastTimer = null;

  const showToast = (message) => {
    window.clearTimeout(toastTimer);
    toast.textContent = message;
    toast.hidden = false;
    toastTimer = window.setTimeout(() => { toast.hidden = true; }, 2200);
  };

  const setSidebar = (open) => {
    body.classList.toggle("sidebar-open", open);
    menuButton.setAttribute("aria-expanded", String(open));
    menuButton.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    // Inert keeps virtual cursor and keyboard users inside the modal mobile drawer.
    main.inert = open;
    mobileBar.inert = open;
    if (open) {
      lastSidebarFocus = document.activeElement;
      sidebar.querySelector("a[href], button:not([disabled])").focus();
    } else if (lastSidebarFocus instanceof HTMLElement) {
      lastSidebarFocus.focus();
    }
  };

  menuButton.addEventListener("click", () => setSidebar(!body.classList.contains("sidebar-open")));
  collapseButton.addEventListener("click", () => setSidebar(false));
  scrim.addEventListener("click", () => setSidebar(false));

  settingsTrigger.addEventListener("click", () => {
    const open = appearancePanel.hidden;
    appearancePanel.hidden = !open;
    settingsTrigger.setAttribute("aria-expanded", String(open));
  });

  // Radio-like buttons retain native button ergonomics while making the entire visual card clickable.
  document.querySelectorAll(".theme-swatch").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".theme-swatch").forEach((item) => {
        item.classList.toggle("selected", item === button);
        item.setAttribute("aria-checked", String(item === button));
      });
      root.dataset.theme = button.dataset.theme;
      showToast(`${button.textContent.trim()} theme selected`);
    });
  });

  document.querySelectorAll(".stance-button").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".stance-button").forEach((item) => {
        item.classList.toggle("selected", item === button);
        item.setAttribute("aria-checked", String(item === button));
      });
      root.dataset.stance = button.dataset.stance;
      showToast(`${button.querySelector("strong").textContent} stance selected`);
    });
  });

  const setModelMenu = (open) => {
    modelMenu.hidden = !open;
    modelButton.setAttribute("aria-expanded", String(open));
    if (open) modelMenu.querySelector('[aria-checked="true"]').focus();
  };
  modelButton.addEventListener("click", () => setModelMenu(modelMenu.hidden));
  modelMenu.querySelectorAll("[role='menuitemradio']").forEach((item) => {
    item.addEventListener("click", () => {
      modelMenu.querySelectorAll("[role='menuitemradio']").forEach((option) => option.setAttribute("aria-checked", String(option === item)));
      modelButton.querySelector("strong").textContent = item.dataset.model;
      modelButton.querySelector("small").textContent = item.dataset.mode;
      setModelMenu(false);
      modelButton.focus();
      showToast(`${item.dataset.model} selected`);
    });
  });

  expandButton.addEventListener("click", () => {
    const expanded = composer.classList.toggle("expanded");
    expandButton.setAttribute("aria-expanded", String(expanded));
    expandButton.setAttribute("aria-label", expanded ? "Collapse composer" : "Expand composer");
    prompt.focus();
  });

  document.querySelector(".attach-button").addEventListener("click", () => {
    feedback.hidden = false;
    showToast("Mock brief attached");
  });
  feedback.querySelector("button").addEventListener("click", () => {
    feedback.hidden = true;
    showToast("Attachment removed");
  });

  voiceButton.addEventListener("click", () => {
    const recording = voiceButton.getAttribute("aria-pressed") === "false";
    voiceButton.setAttribute("aria-pressed", String(recording));
    voiceButton.setAttribute("aria-label", recording ? "Stop voice note recording" : "Record a voice note");
    voiceButton.classList.toggle("recording", recording);
    voiceButton.querySelector(".record-time").hidden = !recording;
    if (recording) {
      seconds = 0;
      recordingTimer = window.setInterval(() => {
        seconds += 1;
        voiceButton.querySelector(".record-time").textContent = `0:${String(seconds).padStart(2, "0")}`;
      }, 1000);
      showToast("Voice note recording started");
    } else {
      window.clearInterval(recordingTimer);
      showToast("Mock voice note ready");
    }
  });

  // This prototype never transmits text; submit feedback exists only to demonstrate interaction state.
  composer.addEventListener("submit", (event) => {
    event.preventDefault();
    const sendButton = composer.querySelector(".send-button");
    sendButton.disabled = true;
    showToast(prompt.value.trim() ? "Mock message sent" : "Write a message first");
    window.setTimeout(() => { sendButton.disabled = false; }, 550);
    if (prompt.value.trim()) prompt.value = "";
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Tab" && body.classList.contains("sidebar-open")) {
      const focusable = [...sidebar.querySelectorAll('a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])')]
        .filter((item) => !item.closest("[hidden]"));
      const first = focusable[0];
      const last = focusable.at(-1);
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
    if (event.key !== "Escape") return;
    if (!modelMenu.hidden) { setModelMenu(false); modelButton.focus(); }
    else if (!appearancePanel.hidden) { appearancePanel.hidden = true; settingsTrigger.setAttribute("aria-expanded", "false"); settingsTrigger.focus(); }
    else if (body.classList.contains("sidebar-open")) setSidebar(false);
  });

  document.addEventListener("click", (event) => {
    if (!modelMenu.hidden && !event.target.closest(".model-picker")) setModelMenu(false);
    if (!appearancePanel.hidden && !event.target.closest(".settings-panel") && !event.target.closest(".appearance-panel")) {
      appearancePanel.hidden = true;
      settingsTrigger.setAttribute("aria-expanded", "false");
    }
  });
})();
