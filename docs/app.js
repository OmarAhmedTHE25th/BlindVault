(() => {
  "use strict";

  // 1. Mobile Navigation Drawer & Header Product Switcher
  const menuBtn = document.getElementById("mobile-menu-btn");
  const drawer = document.getElementById("mobile-drawer");
  if (menuBtn && drawer) {
    menuBtn.addEventListener("click", () => {
      const open = menuBtn.getAttribute("aria-expanded") === "true";
      menuBtn.setAttribute("aria-expanded", String(!open));
      drawer.hidden = open;
    });
    drawer.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        menuBtn.setAttribute("aria-expanded", "false");
        drawer.hidden = true;
      });
    });
  }

  const switchPills = document.querySelectorAll(".switch-pill");
  const controlCard = document.querySelector("#control-plane .control-card");
  switchPills.forEach((pill) => {
    pill.addEventListener("click", () => {
      const product = pill.dataset.product;
      switchPills.forEach((btn) => {
        const active = btn === pill;
        btn.classList.toggle("is-active", active);
        btn.setAttribute("aria-selected", String(active));
      });
      if (product === "control") {
        document.getElementById("control-plane")?.scrollIntoView({ behavior: "smooth", block: "center" });
        if (controlCard) {
          controlCard.classList.add("is-highlighted");
          window.setTimeout(() => controlCard.classList.remove("is-highlighted"), 1800);
        }
      } else {
        document.getElementById("top")?.scrollIntoView({ behavior: "smooth" });
      }
    });
  });

  // 2. Hero 3-Stage Egress Transformation Card
  const stagePills = Array.from(document.querySelectorAll(".stage-pill"));
  const stagePanels = Array.from(document.querySelectorAll(".stage-panel"));
  const cycleStatus = document.getElementById("hero-cycle-status");
  let currentStage = 0;
  let cycleTimer = null;

  function setHeroStage(index) {
    currentStage = index;
    stagePills.forEach((pill, i) => {
      const active = i === index;
      pill.classList.toggle("is-active", active);
      pill.setAttribute("aria-selected", String(active));
    });
    stagePanels.forEach((panel, i) => {
      const active = i === index;
      panel.hidden = !active;
      panel.classList.toggle("is-active", active);
    });
  }

  function startAutoCycle() {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (cycleTimer) window.clearInterval(cycleTimer);
    cycleTimer = window.setInterval(() => {
      setHeroStage((currentStage + 1) % stagePills.length);
    }, 3600);
  }

  stagePills.forEach((pill, idx) => {
    pill.addEventListener("click", () => {
      if (cycleTimer) {
        window.clearInterval(cycleTimer);
        cycleTimer = null;
      }
      if (cycleStatus) cycleStatus.textContent = "Interactive";
      setHeroStage(idx);
    });
  });
  startAutoCycle();

  // 3. Interactive "Bank vs. Cloud" X-Ray Toggle + 2-of-3 Shard Recovery + Quorum Simulation
  const xrayBtns = document.querySelectorAll(".xray-btn");
  const cloudPane = document.getElementById("xray-cloud-pane");
  const bankPane = document.getElementById("xray-bank-pane");

  xrayBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const mode = btn.dataset.xrayMode;
      xrayBtns.forEach((b) => {
        const active = b === btn;
        b.classList.toggle("is-active", active);
        b.setAttribute("aria-selected", String(active));
      });
      if (cloudPane && bankPane) {
        const showCloud = mode === "cloud";
        cloudPane.hidden = !showCloud;
        cloudPane.classList.toggle("is-active", showCloud);
        bankPane.hidden = showCloud;
        bankPane.classList.toggle("is-active", !showCloud);
      }
    });
  });

  // Cloud Node Failure / 2-of-3 Shard Recovery Demo
  const lossBtn = document.getElementById("simulate-loss-btn");
  const lossLabel = document.getElementById("simulate-loss-label");
  const shard0 = document.getElementById("shard-0");
  const shard0State = document.getElementById("shard-0-state");
  const recoveryBanner = document.getElementById("recovery-banner");
  let simulatedOutage = false;

  if (lossBtn && shard0 && shard0State && recoveryBanner && lossLabel) {
    lossBtn.addEventListener("click", () => {
      simulatedOutage = !simulatedOutage;
      lossBtn.classList.toggle("is-tripped", simulatedOutage);
      shard0.classList.toggle("is-offline", simulatedOutage);
      shard0State.classList.toggle("badge-emerald", !simulatedOutage);
      shard0State.classList.toggle("badge-red", simulatedOutage);
      recoveryBanner.classList.toggle("is-recovered", simulatedOutage);

      if (simulatedOutage) {
        lossLabel.textContent = "Restore Cloud Node";
        shard0State.textContent = "Offline (404)";
        recoveryBanner.innerHTML =
          "<strong>SHARD_RECOVERY Triggered:</strong> Shard 0 unreachable — rebuilt exact ciphertext from Shards 1 &amp; 2 via 2-of-3 XOR parity and logged to <code class='mono-inline'>regtech_audit.log</code>.";
      } else {
        lossLabel.textContent = "Simulate Cloud Node Failure";
        shard0State.textContent = "Online";
        recoveryBanner.innerHTML =
          "<strong>Normal Mirroring Active:</strong> Primary `.enc` blob verified intact alongside 3 healthy shards.";
      }
    });
  }

  // Interactive 2-of-3 Ed25519 Quorum Officer Toggle
  const officerChips = Array.from(document.querySelectorAll(".officer-chip"));
  const quorumBadge = document.getElementById("quorum-status-badge");
  const quorumText = document.getElementById("quorum-status-text");
  const denialBanner = document.getElementById("quorum-denial-banner");
  const tableWrap = document.getElementById("rehydrated-table-wrap");

  function updateQuorumState() {
    const signedCount = officerChips.filter((c) => c.classList.contains("is-signed")).length;
    const authorized = signedCount >= 2;
    if (quorumBadge && quorumText && denialBanner && tableWrap) {
      quorumBadge.classList.toggle("is-denied", !authorized);
      quorumText.textContent = authorized
        ? `Ed25519 Quorum Verified (${signedCount}-of-3)`
        : `Quorum Denied (${signedCount}-of-3 Signed — Need ≥ 2)`;
      denialBanner.hidden = authorized;
      tableWrap.classList.toggle("is-locked", !authorized);
    }
  }

  officerChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      const signed = chip.classList.toggle("is-signed");
      chip.setAttribute("aria-pressed", String(signed));
      const check = chip.querySelector(".officer-check");
      if (check) check.textContent = signed ? "✓" : "+";
      updateQuorumState();
    });
  });

  // 4. Collapsible Raw Benchmark Drawer
  const drawerBtn = document.getElementById("bench-drawer-toggle");
  const benchDrawer = document.getElementById("bench-drawer");
  if (drawerBtn && benchDrawer) {
    drawerBtn.addEventListener("click", () => {
      const expanded = drawerBtn.getAttribute("aria-expanded") === "true";
      drawerBtn.setAttribute("aria-expanded", String(!expanded));
      benchDrawer.hidden = expanded;
    });
  }

  // 5. Tabbed Quickstart CLI & One-Click Copy
  const codeTabs = document.querySelectorAll(".code-tab");
  const codeBlocks = document.querySelectorAll(".code-block");
  const copyBtn = document.getElementById("copy-code-btn");
  const copyLabel = document.getElementById("copy-code-label");

  codeTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const key = tab.dataset.codeTab;
      codeTabs.forEach((t) => {
        const active = t === tab;
        t.classList.toggle("is-active", active);
        t.setAttribute("aria-selected", String(active));
      });
      codeBlocks.forEach((block) => {
        const active = block.dataset.codePanel === key;
        block.hidden = !active;
        block.classList.toggle("is-active", active);
      });
    });
  });

  if (copyBtn && copyLabel) {
    copyBtn.addEventListener("click", async () => {
      const activeCode = document.querySelector(".code-block.is-active code")?.textContent || "";
      try {
        await navigator.clipboard.writeText(activeCode);
      } catch {
        const ta = document.createElement("textarea");
        ta.value = activeCode;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      copyBtn.classList.add("is-copied");
      copyLabel.textContent = "Copied ✓";
      window.setTimeout(() => {
        copyBtn.classList.remove("is-copied");
        copyLabel.textContent = "Copy";
      }, 1800);
    });
  }

  // 6. Smooth Scroll Reveal via IntersectionObserver
  const reveals = document.querySelectorAll(".reveal-on-scroll");
  if ("IntersectionObserver" in window) {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.12 }
    );
    reveals.forEach((el) => observer.observe(el));
  } else {
    reveals.forEach((el) => el.classList.add("is-visible"));
  }
})();
