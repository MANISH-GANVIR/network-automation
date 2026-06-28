const API = "http://127.0.0.1:8000";
let historyStack = [];
let updatePeerGlobal = "";  // 🔥 ADDED

function $(id) { return document.getElementById(id); }

/* ================= NAVIGATION HELPERS ================= */
function hideAll() {
  document.querySelectorAll(".page-center")
    .forEach(v => v.style.display = "none");
}

function show(viewId) {
  hideAll();
  $(viewId).style.display = "flex";
}

function push(viewId) {
  historyStack.push(viewId);
  show(viewId);
}

function goBack() {
  historyStack.pop();
  const prev = historyStack.pop();
  if (prev) push(prev);
  else show("loginView");
}

function exitApp() {
  historyStack = [];
  show("loginView");
}

/* ================= LOGIN ================= */
function login() {
  const msg = $("msg");
  msg.innerText = "";

  fetch(API + "/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: $("username").value,
      password: $("password").value
    })
  })
  .then(r => r.json())
  .then(d => {
    if (d.success === true) {
      historyStack = [];
      show("projectView");
    } else {
      msg.innerText = "Invalid login";
    }
  })
  .catch(() => {
    msg.innerText = "Backend not reachable";
  });
}

/* ================= PROJECT / FIREWALL ================= */
function selectProject(p) {
  if (p === "vpn_automation") push("firewallView");
}

function selectFirewall(fw) {
  if (fw === "ASA") push("asaView");
}

/* ================= ASA RUNNER ================= */
function runASA(task) {
  const out = $("asaOutput");
  out.style.display = "block";

  let taskName = task;
  let peerIpDisplay = "";

  if (task === "discovery") taskName = "tunnel discovery";
  else if (task === "reset") taskName = "tunnel reset";
  else if (task === "update") taskName = "tunnel update";
  else if (task === "build") taskName = "tunnel build";
  else if (task === "troubleshoot") taskName = "tunnel troubleshoot";

  let payload = {};

  if (task === "reset") {
    const peerIp = prompt("Enter Peer IP of VPN tunnel to reset (example: 4.227.229.249):");
    if (!peerIp) return;
    peerIpDisplay = ` for ${peerIp}`;
    payload = { peer_ip: peerIp.trim() };
  }

  if (task === "update") {
    const peerIp = prompt("Enter Peer IP of VPN you want to update:");
    if (!peerIp) return;
    peerIpDisplay = ` for ${peerIp}`;

    out.innerHTML = `<span class="status-spinner"></span> Fetching configuration for ${peerIp}<span class="animated-dots">.</span>`;

    let dotCount = 0;
    let dotInterval = setInterval(() => {
      dotCount = (dotCount + 1) % 4;
      const dots = ".".repeat(dotCount);
      out.innerHTML = `<span class="status-spinner"></span> Fetching configuration for ${peerIp}<span class="animated-dots">${dots}</span>`;
    }, 500);

    fetch(API + "/asa/update", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        peer_ip: peerIp,
        preview_only: true
      })
    })
    .then(res => res.json())
    .then(data => {
      clearInterval(dotInterval);
      out.innerHTML = `<span class="status-success">✓</span> Configuration loaded for ${peerIp}!\n\n`;

      if (data.stdout) {
        out.innerHTML += data.stdout;
        document.getElementById("modalCurrentConfig").textContent = data.stdout;
      }

      if (data.error) {
        out.innerHTML = `<span class="status-error">✗</span> Error!\n\n${data.error}`;
        return;
      }

      updatePeerGlobal = peerIp;
      document.getElementById("updateModal").style.display = "flex";
      renderUpdateFields();
    })
    .catch(() => {
      clearInterval(dotInterval);
      out.innerHTML = `<span class="status-error">✗</span> Failed to fetch configuration.`;
    });

    return;
  }

  out.innerHTML = `<span class="status-spinner"></span> Running ASA ${taskName}${peerIpDisplay}<span class="animated-dots">.</span>`;

  let dotCount = 0;
  let dotInterval = setInterval(() => {
    dotCount = (dotCount + 1) % 4;
    const dots = ".".repeat(dotCount);
    out.innerHTML = `<span class="status-spinner"></span> Running ASA ${taskName}${peerIpDisplay}<span class="animated-dots">${dots}</span>`;
  }, 500);

  fetch(API + "/asa/" + task, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  })
  .then(async r => {
    clearInterval(dotInterval);
    const text = await r.text();

    try {
      const obj = JSON.parse(text);

      if (obj.stdout) {
        out.innerHTML = `<span class="status-success">✓</span> ${taskName} completed${peerIpDisplay}!\n\n${obj.stdout}`;
      } else if (obj.error) {
        out.innerHTML = `<span class="status-error">✗</span> Error!\n\nERROR:\n${obj.error}`;
      } else {
        out.innerHTML = `<span class="status-success">✓</span> Done!\n\n${text}`;
      }
    } catch {
      out.innerHTML = `<span class="status-success">✓</span> Done!\n\n${text}`;
    }
  })
  .catch(() => {
    clearInterval(dotInterval);
    out.innerHTML = `<span class="status-error">✗</span> Failed to execute task`;
  });
}

/* ================= WINDOW CONTROLS ================= */
function winMin() { $("winRoot").classList.add("minimized"); }
function winMax() {
  $("winRoot").classList.remove("minimized");
  $("winRoot").classList.remove("closed");
}
function winClose() { $("winRoot").classList.add("closed"); }

/* ===== ASA TERMINAL CONTROLS ===== */
function termMin() {
  const t = document.getElementById("asaTerminal");
  t.classList.remove("maximized");
  t.classList.add("minimized");
}
function termMax() {
  const t = document.getElementById("asaTerminal");
  t.classList.remove("minimized");
  t.classList.toggle("maximized");
}
function termClose() {
  const t = document.getElementById("asaTerminal");
  t.classList.add("closed");
}

function submitUpdate() {
  const choice = (document.getElementById("updateChoice").value || "").trim();
  if (!choice) {
    alert("Select option first");
    return;
  }

  let payload = {
    peer_ip: updatePeerGlobal,
    choice: choice
  };

  if (choice === "1") {
    payload.new_peer_ip = document.getElementById("new_peer_ip")?.value.trim();
  }

  if (choice === "2") {
    payload.local_action = document.getElementById("local_action")?.value;
    if (payload.local_action === "delete") {
      payload.delete_local_ip = document.getElementById("delete_local_ip")?.value.trim();
      payload.delete_local_mask = document.getElementById("delete_local_mask")?.value.trim();
    } else if (payload.local_action === "add") {
      payload.new_local_ip = document.getElementById("new_local_ip")?.value.trim();
      payload.new_local_mask = document.getElementById("new_local_mask")?.value.trim();
    } else if (payload.local_action === "replace") {
      payload.old_local_ip = document.getElementById("old_local_ip")?.value.trim();
      payload.old_local_mask = document.getElementById("old_local_mask")?.value.trim();
      payload.new_local_ip = document.getElementById("new_local_ip")?.value.trim();
      payload.new_local_mask = document.getElementById("new_local_mask")?.value.trim();
    }
  }

  if (choice === "3") {
    payload.remote_action = document.getElementById("remote_action")?.value;
    if (payload.remote_action === "delete") {
      payload.delete_remote_ip = document.getElementById("delete_remote_ip")?.value.trim();
      payload.delete_remote_mask = document.getElementById("delete_remote_mask")?.value.trim();
    } else if (payload.remote_action === "add") {
      payload.new_remote_ip = document.getElementById("new_remote_ip")?.value.trim();
      payload.new_remote_mask = document.getElementById("new_remote_mask")?.value.trim();
    } else if (payload.remote_action === "replace") {
      payload.old_remote_ip = document.getElementById("old_remote_ip")?.value.trim();
      payload.old_remote_mask = document.getElementById("old_remote_mask")?.value.trim();
      payload.new_remote_ip = document.getElementById("new_remote_ip")?.value.trim();
      payload.new_remote_mask = document.getElementById("new_remote_mask")?.value.trim();
    }
  }

  if (choice === "4") payload.new_transform_set = document.getElementById("new_transform_set")?.value.trim();
  if (choice === "5") payload.new_psk = document.getElementById("new_psk")?.value.trim();

  const out = document.getElementById("asaOutput");

  if (choice === "3" && payload.remote_action === "replace") {
    const ok = confirm("🚨 WARNING: Replacing an active VPN remote subnet may impact traffic. Use change window and update remote side.\n\nProceed?");
    if (!ok) return alert("Cancelled");
    payload.user_confirmed = true;
  }

  if (choice === "3" && payload.remote_action === "add") {
    const ok = confirm("⚠️ WARNING: Adding a remote subnet may impact production VPN traffic. Use change window and update remote side.\n\nProceed?");
    if (!ok) return alert("Cancelled");
    payload.user_confirmed_add = true;
  }

  if (choice === "2" && payload.local_action !== "delete") {
    const action = payload.local_action || "add";
    const ok = confirm(`⚠️ WARNING: VPN traffic may be impacted if remote side is not updated. Do you want to proceed?\n\nAction: ${action.toUpperCase()} Local Subnet`);
    if (!ok) return alert("Cancelled");
    payload.user_confirmed_local = true;
  }

  if (choice === "3" && payload.remote_action === "delete") {
    const ok = confirm("🚨 WARNING: Deleting a remote subnet will remove ALL related ACL entries. This may impact VPN traffic. Use change window and update remote side.\n\nProceed?");
    if (!ok) return alert("Cancelled");
    payload.user_confirmed_delete = true;
  }

  payload.local_action = document.getElementById("local_action")?.value?.trim();

  if (choice === "2" && payload.local_action === "delete") {
    const ok = confirm("🚨 WARNING: Deleting a local subnet will remove ALL related ACL entries. This may impact VPN traffic.\n\nProceed?");
    if (!ok) return alert("Cancelled");
    payload.user_confirmed_delete = true;
  }

  if (window.processingModal && typeof window.processingModal.show === "function") {
    window.processingModal.show("Processing your update...");
  }

  fetch(API + "/asa/update", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  })
  .then(res => {
    if (window.processingModal && typeof window.processingModal.hide === "function") {
      window.processingModal.hide();
    }
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  })
  .then(result => {
    const output = result.stdout || result.error || "Done";

    if (output.includes("[WARNING]") && output.includes("already configured")) {
      const userChoice = confirm("⚠️ Already Exists!\n\nDo you want to continue?\n\nOK = Yes (Override)\nCancel = No (Abort)");

      if (userChoice) {
        out.textContent += "\n\n🔄 Overriding...\n";

        if (window.processingModal && typeof window.processingModal.show === "function") {
          window.processingModal.show("Please Wait...!");
        }

        fetch(API + "/asa/update", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        })
        .then(res => {
          if (window.processingModal && typeof window.processingModal.hide === "function") {
            window.processingModal.hide();
          }
          return res.json();
        })
        .then(finalResult => {
          out.textContent += "\n" + (finalResult.stdout || finalResult.error || "Done");
          alert("✅ Done! Check operation logs in CLI Output");
          closeModal();
        });
      } else {
        out.textContent += "\n\n❌ Cancelled by user";
        closeModal();
      }
    } else {
      out.textContent += "\n" + output;
      alert("✅ Update Complete! Check operation logs in CLI output");
      closeModal();
    }
  })
  .catch(err => {
    if (window.processingModal && typeof window.processingModal.hide === "function") {
      window.processingModal.hide();
    }
    console.error(err);
    out.textContent += "\nERROR: " + err.message;
    alert("Error: " + err.message);
  });
}

/* ================= BIG MODAL VIEW ================= */
function showBigModal(text) {
  let modal = document.getElementById("bigModal");

  if (!modal) {
    modal = document.createElement("div");
    modal.id = "bigModal";
    modal.style.position = "fixed";
    modal.style.top = "5%";
    modal.style.left = "10%";
    modal.style.width = "80%";
    modal.style.height = "80%";
    modal.style.background = "#0c1f33";
    modal.style.color = "#00ffcc";
    modal.style.padding = "20px";
    modal.style.overflowY = "auto";
    modal.style.zIndex = "9999";
    modal.style.borderRadius = "10px";
    modal.style.fontFamily = "monospace";
    modal.style.whiteSpace = "pre-wrap";

    const closeBtn = document.createElement("button");
    closeBtn.innerText = "Close";
    closeBtn.style.position = "absolute";
    closeBtn.style.top = "10px";
    closeBtn.style.right = "10px";
    closeBtn.onclick = () => modal.remove();

    modal.appendChild(closeBtn);

    const content = document.createElement("div");
    content.id = "bigModalContent";
    modal.appendChild(content);

    document.body.appendChild(modal);
  }

  document.getElementById("bigModalContent").innerText = text;
}

function renderUpdateFields() {
  const choice = document.getElementById("updateChoice").value;
  const container = document.getElementById("updateDynamicFields");
  container.innerHTML = "";

  if (choice === "2") {
    container.innerHTML = `
      <label style="margin-top:10px; display:block;">Local Subnet Action</label>
      <select id="local_action" style="width:100%; padding:12px; font-size:16px;">
        <option value="add">Add New Local Subnet</option>
        <option value="replace">Replace Existing Local Subnet</option>
        <option value="delete">Delete Local Subnet</option>
      </select>

      <div id="localReplaceBlock" style="margin-top:12px; display:none;">
        <input id="old_local_ip" placeholder="Enter OLD Local Subnet IP (to replace)">
        <input id="old_local_mask" placeholder="Enter OLD Local Subnet Mask (to replace)">
      </div>

      <div id="localDeleteBlock" style="margin-top:12px; display:none;">
        <input id="delete_local_ip" placeholder="Enter Local Subnet IP (to delete)">
        <input id="delete_local_mask" placeholder="Enter Local Subnet Mask (to delete)">
      </div>

      <div id="newLocalInputs" style="margin-top:12px;">
        <input id="new_local_ip" placeholder="Enter NEW Local Subnet IP">
        <input id="new_local_mask" placeholder="Enter NEW Local Subnet Mask">
      </div>
    `;

    const sel = document.getElementById("local_action");
    const replaceBlock = document.getElementById("localReplaceBlock");
    const deleteBlock = document.getElementById("localDeleteBlock");
    const newInputs = document.getElementById("newLocalInputs");

    sel.onchange = () => {
      replaceBlock.style.display = (sel.value === "replace") ? "block" : "none";
      deleteBlock.style.display = (sel.value === "delete") ? "block" : "none";
      newInputs.style.display = (sel.value === "delete") ? "none" : "block";
    };
    sel.onchange();
    return;
  }

  if (choice === "3") {
    container.innerHTML = `
      <label style="margin-top:10px; display:block;">Remote Subnet Action</label>
      <select id="remote_action" style="width:100%; padding:12px; font-size:16px;">
        <option value="add">Add New Remote Subnet</option>
        <option value="replace">Replace Existing Remote Subnet</option>
        <option value="delete">Delete Remote Subnet</option>
      </select>

      <div id="replaceBlock" style="margin-top:12px; display:none;">
        <input id="old_remote_ip" placeholder="Enter OLD Remote Subnet IP (to replace)">
        <input id="old_remote_mask" placeholder="Enter OLD Remote Subnet Mask (to replace)">
      </div>

      <div id="deleteBlock" style="margin-top:12px; display:none;">
        <input id="delete_remote_ip" placeholder="Enter Remote Subnet IP (to delete)">
        <input id="delete_remote_mask" placeholder="Enter Remote Subnet Mask (to delete)">
      </div>

      <div id="newRemoteInputs" style="margin-top:12px;">
        <input id="new_remote_ip" placeholder="Enter NEW Remote Subnet IP">
        <input id="new_remote_mask" placeholder="Enter NEW Remote Subnet Mask">
      </div>
    `;

    const sel = document.getElementById("remote_action");
    const replaceBlock = document.getElementById("replaceBlock");
    const deleteBlock = document.getElementById("deleteBlock");
    const newInputs = document.getElementById("newRemoteInputs");

    sel.onchange = () => {
      replaceBlock.style.display = (sel.value === "replace") ? "block" : "none";
      deleteBlock.style.display = (sel.value === "delete") ? "block" : "none";
      newInputs.style.display = (sel.value === "delete") ? "none" : "block";
    };
    sel.onchange();
    return;
  }

  if (choice === "1") {
    container.innerHTML = `<input id="new_peer_ip" placeholder="Enter new Peer IP">`;
    return;
  }

  if (choice === "4") {
    container.innerHTML = `<input id="new_transform_set" placeholder="Enter new Transform Set">`;
    return;
  }

  if (choice === "5") {
    container.innerHTML = `<input id="new_psk" placeholder="Enter new Pre-Shared Key">`;
    return;
  }
}

/* ================= INIT ================= */
hideAll();
show("loginView");

// ===== MODAL WINDOW CONTROLS =====
function modalMin() {
  const modal = document.getElementById("updateModal");
  if (modal) modal.style.display = "none";
}

function modalMax() {
  const modal = document.getElementById("updateModal");
  if (modal) {
    const box = modal.querySelector(".modal-box");
    if (box) {
      if (box.style.width === "95vw") {
        box.style.width = "1200px";
        box.style.height = "auto";
      } else {
        box.style.width = "95vw";
        box.style.height = "90vh";
      }
    }
  }
}

// ===== MAKE MODAL DRAGGABLE =====
document.addEventListener("DOMContentLoaded", function() {
  const modal = document.getElementById("updateModal");
  if (!modal) return;

  const modalBox = modal.querySelector(".modal-box");
  const titleBar = modal.querySelector(".modal-bar");

  if (!modalBox || !titleBar) return;

  let isDragging = false;
  let startX, startY, initialLeft, initialTop;

  titleBar.addEventListener("mousedown", function(e) {
    if (e.target.classList.contains("mbtn")) return;

    isDragging = true;
    startX = e.clientX;
    startY = e.clientY;

    const rect = modalBox.getBoundingClientRect();
    initialLeft = rect.left;
    initialTop = rect.top;

    modalBox.style.transform = "none";
    modalBox.style.left = initialLeft + "px";
    modalBox.style.top = initialTop + "px";
  });

  document.addEventListener("mousemove", function(e) {
    if (!isDragging) return;

    const dx = e.clientX - startX;
    const dy = e.clientY - startY;

    modalBox.style.left = (initialLeft + dx) + "px";
    modalBox.style.top = (initialTop + dy) + "px";
  });

  document.addEventListener("mouseup", function() {
    isDragging = false;
  });
});

// ===== CONFIG BOX RESIZER =====
document.addEventListener("DOMContentLoaded", function() {
  const resizer = document.getElementById("configResizer");
  const configBox = document.getElementById("modalCurrentConfig");

  if (!resizer || !configBox) return;

  let isResizing = false;
  let startY = 0;
  let startHeight = 0;

  resizer.addEventListener("mousedown", function(e) {
    isResizing = true;
    startY = e.clientY;
    startHeight = configBox.offsetHeight;
    document.body.style.cursor = "ns-resize";
    e.preventDefault();
  });

  document.addEventListener("mousemove", function(e) {
    if (!isResizing) return;

    const delta = e.clientY - startY;
    const newHeight = startHeight + delta;

    if (newHeight >= 150 && newHeight <= 600) {
      configBox.style.height = newHeight + "px";
    }
  });

  document.addEventListener("mouseup", function() {
    if (isResizing) {
      isResizing = false;
      document.body.style.cursor = "default";
    }
  });
});

function closeModal() {
  const modal = document.getElementById("updateModal");
  if (modal) modal.style.display = "none";

  const choice = document.getElementById("updateChoice");
  const fields = document.getElementById("updateDynamicFields");

  if (choice) choice.value = "";
  if (fields) fields.innerHTML = "";
}

function openAIAssistant() {
  document.getElementById("aiPanel").style.display = "block";
  loadChatHistory();
}

function closeAI() {
  document.getElementById("aiPanel").style.display = "none";
}

let aiMaximized = false;

function aiMax() {
  const panel = document.getElementById("aiPanel");

  if (!aiMaximized) {
    panel.style.width = "90%";
    panel.style.height = "85vh";
    panel.style.right = "5%";
    panel.style.bottom = "5%";
    aiMaximized = true;
  } else {
    panel.style.width = "500px";
    panel.style.height = "600px";
    panel.style.right = "20px";
    panel.style.bottom = "20px";
    aiMaximized = false;
  }
}

let aiMinimized = false;

function aiMin() {
  const input = document.getElementById("aiInput");
  const output = document.getElementById("chatMessages");
  const loading = document.getElementById("aiLoading");
  const analyzeBtn = document.querySelector("#aiPanel button");
  const panel = document.getElementById("aiPanel");

  if (!aiMinimized) {
    panel.style.height = "60px";
    panel.style.overflow = "hidden";

    input.style.display = "none";
    output.style.display = "none";
    loading.style.display = "none";

    if (analyzeBtn) analyzeBtn.style.display = "none";
    aiMinimized = true;
  } else {
    panel.style.height = "85vh";
    panel.style.overflow = "visible";

    input.style.display = "block";
    output.style.display = "block";

    if (analyzeBtn) analyzeBtn.style.display = "block";
    aiMinimized = false;
  }
}

/* ================= AI CHAT HELPERS (THEME SAFE) ================= */
function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderMsg(role, text) {
  const cls = role === "user" ? "user-msg" : "ai-msg";
  const icon = role === "user" ? "👤" : "🤖";
  return `<div class="${cls}">${icon} ${escapeHtml(text).replace(/\n/g, "<br>")}</div>`;
}

function saveChatHistory() {
  const box = document.getElementById("chatMessages");
  if (!box) return;
  sessionStorage.setItem("ai_chat_html", box.innerHTML);
}

function loadChatHistory() {
  const box = document.getElementById("chatMessages");
  if (!box) return;
  const saved = sessionStorage.getItem("ai_chat_html");
  if (saved) box.innerHTML = saved;
  box.scrollTop = box.scrollHeight;
}

function collectAttachedFilesPayload() {
  const input = document.getElementById("aiFileInput");
  if (!input || !input.files || input.files.length === 0) return Promise.resolve([]);

  const readers = Array.from(input.files).map(file => {
    return new Promise((resolve) => {
      const fr = new FileReader();
      fr.onload = () => resolve({
        name: file.name,
        size: file.size,
        type: file.type || "text/plain",
        content: String(fr.result || "")
      });
      fr.onerror = () => resolve({
        name: file.name,
        size: file.size,
        type: file.type || "text/plain",
        content: ""
      });
      fr.readAsText(file);
    });
  });

  return Promise.all(readers);
}

async function analyzeAI() {
  const inputEl = document.getElementById("aiInput");
  const chat = document.getElementById("chatMessages");
  const loading = document.getElementById("aiLoading");
  const loadingText = document.getElementById("loadingText");

  const message = (inputEl?.value || "").trim();
  if (!message) return;

  try {
    // user msg
    chat.innerHTML += renderMsg("user", message);
    inputEl.value = "";
    chat.scrollTop = chat.scrollHeight;
    saveChatHistory();

    if (loadingText) loadingText.innerText = "🤖 Thinking...";
    if (loading) loading.style.display = "flex";

    const filesPayload = await collectAttachedFilesPayload();
    if (filesPayload.length > 0) {
      chat.innerHTML += renderMsg("user", `[Attached: ${filesPayload.map(f => f.name).join(", ")}]`);
      chat.scrollTop = chat.scrollHeight;
      saveChatHistory();
    }

    // ✅ NO fallback. hit only backend API
    const resp = await fetch("http://127.0.0.1:8000/ai/chat", {
      method: "POST",
      mode: "cors",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: message,
        files: filesPayload
      })
    });

    const raw = await resp.text();

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status} - ${raw}`);
    }

    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      throw new Error(`Invalid JSON response: ${raw}`);
    }

    chat.innerHTML += renderMsg("ai", data.response || "No response.");
    chat.scrollTop = chat.scrollHeight;
    saveChatHistory();

    const aiFileInput = document.getElementById("aiFileInput");
    const selectedFilesText = document.getElementById("selectedFilesText");
    if (aiFileInput) aiFileInput.value = "";
    if (selectedFilesText) selectedFilesText.innerText = "No files selected";

    inputEl.focus();
  } catch (err) {
    chat.innerHTML += renderMsg("ai", `❌ Error: ${err.message}`);
    chat.scrollTop = chat.scrollHeight;
    saveChatHistory();
    console.error("AI fetch error:", err);
  } finally {
    if (loading) loading.style.display = "none";
  }
}
// =============================
// DRAG AI WINDOW (FIXED)
// =============================
document.addEventListener("DOMContentLoaded", function () {
  loadChatHistory();

  const continueBtn = document.getElementById("modalContinue");
  if (continueBtn) {
    continueBtn.onclick = function(e) {
      e.preventDefault();
      e.stopPropagation();
      submitUpdate();
    };
  }

  const cancelBtn = document.getElementById("modalCancel");
  if (cancelBtn) {
    cancelBtn.onclick = function(e) {
      e.preventDefault();
      e.stopPropagation();
      closeModal();
    };
  }

  const dropdown = document.getElementById("updateChoice");
  if (dropdown) {
    dropdown.addEventListener("change", renderUpdateFields);
  }

  const aiFileInput = document.getElementById("aiFileInput");
  if (aiFileInput) {
    aiFileInput.addEventListener("change", function() {
      const text = document.getElementById("selectedFilesText");
      const files = Array.from(aiFileInput.files || []);
      if (text) {
        text.textContent = files.length ? files.map(f => f.name).join(", ") : "No files selected";
      }
    });
  }

  setTimeout(function() {
    const aiPanel = document.getElementById("aiPanel");
    const aiHeader = document.getElementById("aiHeader");

    if (!aiPanel || !aiHeader) {
      console.warn("AI Panel or Header not found");
      return;
    }

    aiHeader.style.cursor = "move";

    let isDragging = false;
    let offsetX = 0;
    let offsetY = 0;

    aiHeader.addEventListener("mousedown", function (e) {
      isDragging = true;

      const rect = aiPanel.getBoundingClientRect();
      offsetX = e.clientX - rect.left;
      offsetY = e.clientY - rect.top;

      aiPanel.style.right = "auto";
      aiPanel.style.bottom = "auto";

      aiPanel.style.left = rect.left + "px";
      aiPanel.style.top = rect.top + "px";

      e.preventDefault();
    });

    document.addEventListener("mousemove", function (e) {
      if (!isDragging) return;

      let newLeft = e.clientX - offsetX;
      let newTop = e.clientY - offsetY;

      const panelWidth = aiPanel.offsetWidth;
      const panelHeight = aiPanel.offsetHeight;
      const screenWidth = window.innerWidth;
      const screenHeight = window.innerHeight;

      if (newLeft < 0) newLeft = 0;
      if (newTop < 0) newTop = 0;
      if (newLeft > screenWidth - panelWidth) newLeft = screenWidth - panelWidth;
      if (newTop > screenHeight - panelHeight) newTop = screenHeight - panelHeight;

      aiPanel.style.left = newLeft + "px";
      aiPanel.style.top = newTop + "px";
    });

    document.addEventListener("mouseup", function () {
      isDragging = false;
    });
  }, 100);
});

function clearAIChat() {
  const chat = document.getElementById("chatMessages");

  chat.innerHTML = `
    <div class="ai-msg">
      🤖 Hello! How can I assist you today?
      If you have any questions about network security,
      feel free to ask.
    </div>
  `;

  document.getElementById("aiInput").value = "";
  document.getElementById("aiLoading").style.display = "none";

  const aiFileInput = document.getElementById("aiFileInput");
  const selectedFilesText = document.getElementById("selectedFilesText");
  if (aiFileInput) aiFileInput.value = "";
  if (selectedFilesText) selectedFilesText.innerText = "No files selected";

  saveChatHistory();
}

