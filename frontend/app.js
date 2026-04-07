const API = `${window.location.protocol}//${window.location.hostname}:8000`;

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
  let peerIpDisplay = "";  // 🔥 PEER IP STORE KARO

  if (task === "discovery") {
    taskName = "tunnel discovery";
  } else if (task === "reset") {
    taskName = "tunnel reset";
  } else if (task === "update") {
    taskName = "tunnel update";
  } else if (task === "build") {
    taskName = "tunnel build";
  } else if (task === "troubleshoot") {
    taskName = "tunnel troubleshoot";
  }

  let payload = {};

  if (task === "reset") {
    const peerIp = prompt("Enter Peer IP of VPN tunnel to reset (example: 4.227.229.249):");
    if (!peerIp) {
      return;
    }
    peerIpDisplay = ` for ${peerIp}`;  // 🔥 PEER IP ADD KAR
    payload = { peer_ip: peerIp.trim() };
  }

  if (task === "update") {
    const peerIp = prompt("Enter Peer IP of VPN you want to update:");
    if (!peerIp) {
      return;
    }
    peerIpDisplay = ` for ${peerIp}`;  // 🔥 PEER IP ADD KAR

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

  // 🔥 SPINNER + PEER IP DIKHAO
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
      }
      else if (obj.error) {
        out.innerHTML = `<span class="status-error">✗</span> Error!\n\nERROR:\n${obj.error}`;
      }
      else {
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
function winMin() {
  $("winRoot").classList.add("minimized");
}

function winMax() {
  $("winRoot").classList.remove("minimized");
  $("winRoot").classList.remove("closed");
}

function winClose() {
  $("winRoot").classList.add("closed");
}

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

// ===== UPDATE MODAL FUNCTIONS =====
// ===== UPDATE MODAL FUNCTIONS =====
//function submitUpdate() {
//   const choice = (document.getElementById("updateChoice").value || "").trim();
//
//    if (!choice) {
//        alert("Select option first");
//        return;
//    }
//
//    let payload = {
//        peer_ip: updatePeerGlobal,
//        choice: choice
//    };
//
//    if (choice === "1") {
//        payload.new_peer_ip = document.getElementById("new_peer_ip")?.value.trim();
//    }
//
//    if (choice === "2") {
//    payload.local_action = document.getElementById("local_action")?.value;
//    if (payload.local_action === "delete") {
//        payload.delete_local_ip = document.getElementById("delete_local_ip")?.value.trim();
//        payload.delete_local_mask = document.getElementById("delete_local_mask")?.value.trim();
//    } else if (payload.local_action === "add") {
//        payload.new_local_ip = document.getElementById("new_local_ip")?.value.trim();
//        payload.new_local_mask = document.getElementById("new_local_mask")?.value.trim();
//    } else if (payload.local_action === "replace") {
//        payload.old_local_ip = document.getElementById("old_local_ip")?.value.trim();
//        payload.old_local_mask = document.getElementById("old_local_mask")?.value.trim();
//        payload.new_local_ip = document.getElementById("new_local_ip")?.value.trim();
//        payload.new_local_mask = document.getElementById("new_local_mask")?.value.trim();
//    }
//}
//    if (choice === "3") {
//    payload.remote_action = document.getElementById("remote_action")?.value;
//
//    if (payload.remote_action === "delete") {
//        payload.delete_remote_ip = document.getElementById("delete_remote_ip")?.value.trim();
//        payload.delete_remote_mask = document.getElementById("delete_remote_mask")?.value.trim();
//    } else if (payload.remote_action === "add") {
//        payload.new_remote_ip = document.getElementById("new_remote_ip")?.value.trim();
//        payload.new_remote_mask = document.getElementById("new_remote_mask")?.value.trim();
//    } else if (payload.remote_action === "replace") {
//        payload.old_remote_ip = document.getElementById("old_remote_ip")?.value.trim();
//        payload.old_remote_mask = document.getElementById("old_remote_mask")?.value.trim();
//        payload.new_remote_ip = document.getElementById("new_remote_ip")?.value.trim();
//        payload.new_remote_mask = document.getElementById("new_remote_mask")?.value.trim();
//    }
//}
//    if (choice === "4") {
//        payload.new_transform_set = document.getElementById("new_transform_set")?.value.trim();
//    }
//
//    if (choice === "5") {
//        payload.new_psk = document.getElementById("new_psk")?.value.trim();
//    }
//
//    const out = document.getElementById("asaOutput");
//
//    console.log("Payload:", payload);
//    console.log("DEBUG choice:", choice, "local_action:", payload.local_action, "remote_action:", payload.remote_action);
//
//
//
//// ✅ GUI confirmation only for Remote Subnet REPLACE
//if (choice === "3" && payload.remote_action === "replace") {
//    const ok = confirm(
//        "🚨 WARNING: Replacing an active VPN remote subnet may impact traffic. Use change window and update remote side.\n\nProceed?"
//    );
//
//    if (!ok) {
//        alert("Cancelled");
//        return;
//    }
//
//    payload.user_confirmed = true;
//}
//
//// ✅ GUI confirmation for Remote Subnet ADD
//if (choice === "3" && payload.remote_action === "add") {
//    const ok = confirm(
//        "⚠️ WARNING: Adding a remote subnet may impact production VPN traffic. Use change window and update remote side.\n\nProceed?"
//    );
//    if (!ok) {
//        alert("Cancelled");
//        return;
//    }
//    payload.user_confirmed_add = true;
//}
//
//// ✅ LOCAL SUBNET - ADD/REPLACE only
//if (choice === "2" && payload.local_action !== "delete") {
//    const action = payload.local_action || "add";
//    const ok = confirm(
//        `⚠️ WARNING: VPN traffic may be impacted if remote side is not updated. Do you want to proceed?\n\nAction: ${action.toUpperCase()} Local Subnet`
//    );
//    if (!ok) {
//        alert("Cancelled");
//        return;
//    }
//    payload.user_confirmed_local = true;
//}
//
//
//
//// ✅ REMOTE DELETE
//if (choice === "3" && payload.remote_action === "delete") {
//    const ok = confirm(
//        "🚨 WARNING: Deleting a remote subnet will remove ALL related ACL entries. This may impact VPN traffic. Use change window and update remote side.\n\nProceed?"
//    );
//    if (!ok) {
//        alert("Cancelled");
//        return;
//    }
//    payload.user_confirmed_delete = true;
//}
//
//
//payload.local_action = document.getElementById("local_action")?.value?.trim();
//
//// ✅ LOCAL DELETE WARNING
//if (choice === "2" && payload.local_action === "delete") {
//    const ok = confirm(
//        "🚨 WARNING: Deleting a local subnet will remove ALL related ACL entries. This may impact VPN traffic.\n\nProceed?"
//    );
//    if (!ok) {
//        alert("Cancelled");
//        return;
//    }
//    payload.user_confirmed_delete = true;
//}
//
//
//
//
//// 🔥 START SPINNER (CORRECT)
//out.innerHTML += "\n<span class='status-spinner'></span> Processing Update<span class='animated-dots'>.</span>";
//
//let spinnerCount = 0;
//let spinnerInterval = setInterval(() => {
//    spinnerCount = (spinnerCount + 1) % 4;
//    const dots = ".".repeat(spinnerCount);
//
//    // Replace sirf last line mein dots
//    out.innerHTML = out.innerHTML.replace(
//        /Processing Update<span class='animated-dots'>.*?<\/span>/,
//        `Processing Update<span class='animated-dots'>${dots}</span>`
//    );
//}, 500);
//
//    fetch(API + "/asa/update", {
//        method: "POST",
//        headers: { "Content-Type": "application/json" },
//        body: JSON.stringify(payload)
//    })
//    .then(res => {
//        clearInterval(spinnerInterval);
//        if (!res.ok) throw new Error("HTTP " + res.status);
//        return res.json();
//    })
//    .then(result => {
//        const output = result.stdout || result.error || "Done";
//        out.textContent += "\n" + output;
//
//        if (output.includes("[WARNING]") && output.includes("already configured")) {
//            const userChoice = confirm("⚠️ Already Exists!\n\nDo you want to continue?\n\nOK = Yes (Override)\nCancel = No (Abort)");
//
//            if (userChoice) {
//                out.textContent += "\n\n🔄 Overriding...\n";
//
//                fetch(API + "/asa/update", {
//                    method: "POST",
//                    headers: { "Content-Type": "application/json" },
//                    body: JSON.stringify(payload)
//                })
//                .then(res => res.json())
//                .then(finalResult => {
//                    out.textContent += "\n" + (finalResult.stdout || finalResult.error || "Done");
//                    alert("✅ Done! Check operation logs in CLI Output");
//                    closeModal();
//                });
//            } else {
//                out.textContent += "\n\n❌ Cancelled by user";
//                closeModal();
//            }
//        } else {
//            alert("✅ Update Complete! Check operation logs in CLI output");
//            closeModal();
//        }
//    })
//    .catch(err => {
//        clearInterval(spinnerInterval);
//        console.error(err);
//        out.textContent += "\nERROR: " + err.message;
//        alert("Error: " + err.message);
//    });
//}
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
    if (choice === "4") {
        payload.new_transform_set = document.getElementById("new_transform_set")?.value.trim();
    }

    if (choice === "5") {
        payload.new_psk = document.getElementById("new_psk")?.value.trim();
    }

    const out = document.getElementById("asaOutput");

    console.log("Payload:", payload);
    console.log("DEBUG choice:", choice, "local_action:", payload.local_action, "remote_action:", payload.remote_action);

// ✅ GUI confirmation only for Remote Subnet REPLACE
if (choice === "3" && payload.remote_action === "replace") {
    const ok = confirm(
        "🚨 WARNING: Replacing an active VPN remote subnet may impact traffic. Use change window and update remote side.\n\nProceed?"
    );

    if (!ok) {
        alert("Cancelled");
        return;
    }

    payload.user_confirmed = true;
}

// ✅ GUI confirmation for Remote Subnet ADD
if (choice === "3" && payload.remote_action === "add") {
    const ok = confirm(
        "⚠️ WARNING: Adding a remote subnet may impact production VPN traffic. Use change window and update remote side.\n\nProceed?"
    );
    if (!ok) {
        alert("Cancelled");
        return;
    }
    payload.user_confirmed_add = true;
}

// ✅ LOCAL SUBNET - ADD/REPLACE only
if (choice === "2" && payload.local_action !== "delete") {
    const action = payload.local_action || "add";
    const ok = confirm(
        `⚠️ WARNING: VPN traffic may be impacted if remote side is not updated. Do you want to proceed?\n\nAction: ${action.toUpperCase()} Local Subnet`
    );
    if (!ok) {
        alert("Cancelled");
        return;
    }
    payload.user_confirmed_local = true;
}

// ✅ REMOTE DELETE
if (choice === "3" && payload.remote_action === "delete") {
    const ok = confirm(
        "🚨 WARNING: Deleting a remote subnet will remove ALL related ACL entries. This may impact VPN traffic. Use change window and update remote side.\n\nProceed?"
    );
    if (!ok) {
        alert("Cancelled");
        return;
    }
    payload.user_confirmed_delete = true;
}

payload.local_action = document.getElementById("local_action")?.value?.trim();

// ✅ LOCAL DELETE WARNING
if (choice === "2" && payload.local_action === "delete") {
    const ok = confirm(
        "🚨 WARNING: Deleting a local subnet will remove ALL related ACL entries. This may impact VPN traffic.\n\nProceed?"
    );
    if (!ok) {
        alert("Cancelled");
        return;
    }
    payload.user_confirmed_delete = true;
}

// 🔥 SHOW SPINNER BEFORE API CALL
processingModal.show("Processing your update...");

fetch(API + "/asa/update", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
})
.then(res => {
    // 🔥 HIDE SPINNER AFTER RESPONSE
    processingModal.hide();

    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
})
.then(result => {
    const output = result.stdout || result.error || "Done";
    out.textContent += "\n" + output;

    if (output.includes("[WARNING]") && output.includes("already configured")) {
        const userChoice = confirm("⚠️ Already Exists!\n\nDo you want to continue?\n\nOK = Yes (Override)\nCancel = No (Abort)");

        if (userChoice) {
            out.textContent += "\n\n🔄 Overriding...\n";


            // 🔥 SHOW SPINNER AGAIN (SAME MESSAGE)
processingModal.show("Please Wait...!");

            fetch(API + "/asa/update", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            })
            .then(res => {
                // 🔥 HIDE SPINNER
                processingModal.hide();
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
        alert("✅ Update Complete! Check operation logs in CLI output");
        closeModal();
    }
})
.catch(err => {
    // 🔥 HIDE SPINNER ON ERROR
    processingModal.hide();

    console.error(err);
    out.textContent += "\nERROR: " + err.message;
    alert("Error: " + err.message);
});
}


// ================= BIG MODAL VIEW =================
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
        container.innerHTML = `
            <input id="new_peer_ip" placeholder="Enter new Peer IP">
        `;
        return;
    }

    if (choice === "4") {
        container.innerHTML = `
            <input id="new_transform_set" placeholder="Enter new Transform Set">
        `;
        return;
    }

    if (choice === "5") {
        container.innerHTML = `
            <input id="new_psk" placeholder="Enter new Pre-Shared Key">
        `;
        return;
    }
}
// 🔥 ADDED EVENT LISTENERS
document.addEventListener("DOMContentLoaded", function() {
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
});

/* ================= INIT ================= */
hideAll();
show("loginView");

// ===== MODAL WINDOW CONTROLS =====
function modalMin() {
    const modal = document.getElementById("updateModal");
    if (modal) {
        modal.style.display = "none";
    }
}

function modalMax() {
    const modal = document.getElementById("updateModal");
    if (modal) {
        const box = modal.querySelector(".modal-box");
        if (box) {
            // Toggle between normal and maximized
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
        // Don't drag if clicking buttons
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