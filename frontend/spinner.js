// spinner.js

export function startSpinner(elementId, message) {
    const el = document.getElementById(elementId);

    const frames = ["◰", "◳", "◲", "◱"];
    let i = 0;

    el.innerHTML = `${message} <span id="${elementId}-spin">◰</span><br><br>`;

    const interval = setInterval(() => {
        const spinEl = document.getElementById(`${elementId}-spin`);
        if (spinEl) {
            spinEl.textContent = frames[i % frames.length];
            i++;
        }
    }, 200);

    return interval;
}

export function stopSpinner(elementId, interval) {
    clearInterval(interval);

    const spinEl = document.getElementById(`${elementId}-spin`);
    if (spinEl) {
        spinEl.textContent = "✔";
        spinEl.style.color = "#00ff00";
    }
}