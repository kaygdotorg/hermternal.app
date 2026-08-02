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
  const transcript = document.querySelector(".transcript");
  const toast = document.querySelector(".toast");
  const narrowScreen = window.matchMedia("(max-width: 850px)");
  const pointerFine = window.matchMedia("(hover: hover) and (pointer: fine)");
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  let lastSidebarFocus = null;
  let recordingTimer = null;
  let streamTimer = null;
  let seconds = 0;
  let toastTimer = null;

  const showToast = (message) => {
    window.clearTimeout(toastTimer);
    toast.textContent = message;
    toast.hidden = false;
    toastTimer = window.setTimeout(() => { toast.hidden = true; }, 2200);
  };

  const setSidebar = (open) => {
    if (!narrowScreen.matches) open = false;
    body.classList.toggle("sidebar-open", open);
    menuButton.setAttribute("aria-expanded", String(open));
    menuButton.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    // The drawer is modal only on narrow screens; inert prevents focus and virtual-cursor escape.
    main.inert = open;
    mobileBar.inert = open;
    if (open) {
      lastSidebarFocus = document.activeElement;
      sidebar.querySelector("a[href], button:not([disabled])")?.focus();
    } else if (lastSidebarFocus instanceof HTMLElement && narrowScreen.matches) {
      lastSidebarFocus.focus();
    }
  };

  menuButton.addEventListener("click", () => setSidebar(!body.classList.contains("sidebar-open")));
  collapseButton.addEventListener("click", () => setSidebar(false));
  scrim.addEventListener("click", () => setSidebar(false));
  narrowScreen.addEventListener("change", () => setSidebar(false));

  const setAppearancePanel = (open, restoreFocus = false) => {
    appearancePanel.hidden = !open;
    settingsTrigger.setAttribute("aria-expanded", String(open));
    if (open) appearancePanel.querySelector('[aria-checked="true"]')?.focus();
    else if (restoreFocus) settingsTrigger.focus();
  };

  settingsTrigger.addEventListener("click", () => setAppearancePanel(appearancePanel.hidden));

  // Radio-like buttons preserve large native button targets while exposing selection semantics.
  document.querySelectorAll(".theme-swatch").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".theme-swatch").forEach((item) => {
        item.classList.toggle("selected", item === button);
        item.setAttribute("aria-checked", String(item === button));
      });
      root.dataset.theme = button.dataset.theme;
      showToast(`${button.querySelector("strong").textContent} environment selected`);
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

  const setModelMenu = (open, restoreFocus = false) => {
    modelMenu.hidden = !open;
    modelButton.setAttribute("aria-expanded", String(open));
    if (open) modelMenu.querySelector('[aria-checked="true"]')?.focus();
    else if (restoreFocus) modelButton.focus();
  };

  modelButton.addEventListener("click", () => setModelMenu(modelMenu.hidden));
  modelMenu.querySelectorAll("[role='menuitemradio']").forEach((item) => {
    item.addEventListener("click", () => {
      modelMenu.querySelectorAll("[role='menuitemradio']").forEach((option) => option.setAttribute("aria-checked", String(option === item)));
      modelButton.querySelector("strong").textContent = item.dataset.model;
      modelButton.querySelector("small").textContent = item.dataset.mode;
      setModelMenu(false, true);
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
    showToast("Mock brief attached locally");
  });
  document.querySelector(".context-button").addEventListener("click", () => showToast("Mock context chooser opened"));
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
    window.clearInterval(recordingTimer);
    if (recording) {
      seconds = 0;
      recordingTimer = window.setInterval(() => {
        seconds += 1;
        voiceButton.querySelector(".record-time").textContent = `0:${String(seconds).padStart(2, "0")}`;
      }, 1000);
      showToast("Voice note recording started");
    } else {
      showToast("Mock voice note ready");
    }
  });

  document.querySelectorAll(".approval-actions button").forEach((button) => {
    button.addEventListener("click", () => showToast(button.classList.contains("approve") ? "Mock access allowed once" : "Mock access declined"));
  });
  document.querySelector(".tool-content button").addEventListener("click", () => showToast("Mock tool trace inspected"));
  document.querySelector(".new-thread").addEventListener("click", () => { prompt.value = ""; prompt.focus(); showToast("New local thought ready"); });

  const addMockExchange = (message) => {
    const entry = document.createElement("article");
    entry.className = "trace-entry user-entry mock-exchange";
    const node = document.createElement("div");
    node.className = "trace-node";
    node.setAttribute("aria-hidden", "true");
    node.textContent = "⌁";
    const content = document.createElement("div");
    content.className = "entry-content";
    const header = document.createElement("header");
    const author = document.createElement("strong");
    author.textContent = "You";
    const time = document.createElement("time");
    time.textContent = "Now";
    const copy = document.createElement("div");
    copy.className = "user-copy";
    const paragraph = document.createElement("p");
    paragraph.textContent = message;
    header.append(author, time);
    copy.append(paragraph);
    content.append(header, copy);
    entry.append(node, content);
    transcript.append(entry);

    const status = document.createElement("div");
    status.className = "trace-entry tool-entry mock-stream";
    status.setAttribute("role", "status");
    status.innerHTML = '<div class="trace-node tool-node" aria-hidden="true"><span>···</span></div><div class="entry-content tool-content"><header><strong>Preparing a mock response</strong><span class="live-indicator"><i></i><i></i><i></i><span class="sr-only">In progress</span></span></header><p>No text leaves this browser.</p></div>';
    transcript.append(status);
    status.scrollIntoView({ behavior: reducedMotion.matches ? "auto" : "smooth", block: "nearest" });
    window.clearTimeout(streamTimer);
    streamTimer = window.setTimeout(() => {
      status.querySelector("strong").textContent = "Mock response ready";
      status.querySelector(".live-indicator").remove();
      status.querySelector("p").textContent = "Streaming state completed locally; no response was generated.";
    }, 1100);
  };

  // Submitting demonstrates local command → stream feedback only; no transport exists in this prototype.
  composer.addEventListener("submit", (event) => {
    event.preventDefault();
    const message = prompt.value.trim();
    if (!message) { showToast("Write a direction first"); prompt.focus(); return; }
    const sendButton = composer.querySelector(".send-button");
    sendButton.disabled = true;
    addMockExchange(message);
    prompt.value = "";
    showToast("Mock command added locally");
    window.setTimeout(() => { sendButton.disabled = false; }, 550);
  });

  prompt.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key === "Enter") {
      event.preventDefault();
      composer.requestSubmit();
    }
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
    if (!modelMenu.hidden) setModelMenu(false, true);
    else if (!appearancePanel.hidden) setAppearancePanel(false, true);
    else if (composer.classList.contains("expanded")) expandButton.click();
    else if (body.classList.contains("sidebar-open")) setSidebar(false);
  });

  document.addEventListener("click", (event) => {
    if (!modelMenu.hidden && !event.target.closest(".model-picker")) setModelMenu(false);
    if (!appearancePanel.hidden && !event.target.closest(".sidebar-footer") && !event.target.closest(".appearance-panel")) setAppearancePanel(false);
  });

  // Cursor displacement is restrained to ±3px and resets through the same interruptible transform.
  if (pointerFine.matches && !reducedMotion.matches) {
    document.querySelectorAll(".magnetic").forEach((element) => {
      element.addEventListener("pointermove", (event) => {
        const bounds = element.getBoundingClientRect();
        const x = ((event.clientX - bounds.left) / bounds.width - .5) * 6;
        const y = ((event.clientY - bounds.top) / bounds.height - .5) * 6;
        element.style.setProperty("--mag-x", `${x.toFixed(2)}px`);
        element.style.setProperty("--mag-y", `${y.toFixed(2)}px`);
      });
      element.addEventListener("pointerleave", () => {
        element.style.setProperty("--mag-x", "0px");
        element.style.setProperty("--mag-y", "0px");
      });
    });
  }
})();
