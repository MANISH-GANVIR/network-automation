/**
 * PROCESSING MODAL WITH SPINNER - FANCY GLASSMORPHISM
 */

class ProcessingModal {
    constructor() {
        this.modal = null;
        this.messageEl = null;
        this.isActive = false;
    }

    create() {
        if (this.modal) return;

        const html = `
            <div id="processingOverlay" class="processing-overlay">
                <div class="processing-modal">
                    <div class="spinner-ring"></div>
                    <div class="processing-text">
                        Update is Processing<span class="dots"></span>
                    </div>
                    <div class="processing-subtext">
                        Please wait !
                    </div>
                </div>
            </div>
        `;

        document.body.insertAdjacentHTML('beforeend', html);
        this.modal = document.getElementById('processingOverlay');
        this.addCSS();
    }

    addCSS() {
        if (document.getElementById('processingModalCSS')) return;

        const css = `
            <style id="processingModalCSS">
                .processing-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.5);
                    display: none;
                    justify-content: center;
                    align-items: center;
                    z-index: 9999;
                    backdrop-filter: blur(10px);
                }

                .processing-overlay.active {
                    display: flex;
                }

                .processing-modal {
                    background: rgba(26, 38, 52, 0.7);
                    backdrop-filter: blur(20px);
                    border-radius: 24px;
                    padding: 50px 70px;
                    text-align: center;
                    min-width: 380px;
                    box-shadow:
                        0 8px 32px rgba(0, 188, 212, 0.1),
                        inset 0 1px 1px rgba(255, 255, 255, 0.1),
                        0 32px 64px rgba(0, 0, 0, 0.4);
                    border: 1px solid rgba(0, 188, 212, 0.2);
                    animation: slideIn 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
                }

                @keyframes slideIn {
                    from {
                        transform: translateY(-40px) scale(0.95);
                        opacity: 0;
                    }
                    to {
                        transform: translateY(0) scale(1);
                        opacity: 1;
                    }
                }

                .spinner-ring {
                    width: 50px;
                    height: 50px;
                    margin: 0 auto 35px;
                    position: relative;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                }

                .spinner-ring::after {
                    content: '';
                    position: absolute;
                    width: 50px;
                    height: 50px;
                    border: 3px solid rgba(0, 188, 212, 0.15);
                    border-top: 3px solid #00bcd4;
                    border-right: 3px solid #00d4ff;
                    border-radius: 50%;
                    animation: spin 1.2s linear infinite;
                    box-shadow: 0 0 20px rgba(0, 188, 212, 0.3);
                }

                @keyframes spin {
                    0% {
                        transform: rotate(0deg);
                    }
                    100% {
                        transform: rotate(360deg);
                    }
                }

                .processing-text {
                    color: #00ffff;
                    font-size: 20px;
                    font-weight: 600;
                    margin-bottom: 12px;
                    letter-spacing: 0.8px;
                    text-shadow: 0 0 10px rgba(0, 188, 212, 0.5);
                    min-height: 28px;
                }

                .dots {
                    display: inline-block;
                    min-width: 20px;
                    text-align: left;
                }

                .dots::after {
                    content: '.';
                    animation: dots-blink 1.5s steps(4, end) infinite;
                    color: #00ffff;
                    font-weight: 600;
                }

                @keyframes dots-blink {
                    0% {
                        content: '';
                    }
                    25% {
                        content: '.';
                    }
                    50% {
                        content: '..';
                    }
                    75% {
                        content: '...';
                    }
                    100% {
                        content: '...';
                    }
                }

                .processing-subtext {
                    color: #7a9ab5;
                    font-size: 12px;
                    opacity: 0.9;
                    min-height: 20px;
                    letter-spacing: 0.3px;
                }
            </style>
        `;

        document.head.insertAdjacentHTML('beforeend', css);
    }

    show(message = "Please wait!") {
        this.create();
        this.modal.classList.add('active');
        this.isActive = true;
    }

    hide() {
        if (this.modal) this.modal.classList.remove('active');
        this.isActive = false;
    }

    setMessage(message) {
        if (this.messageEl) this.messageEl.textContent = message;
    }
}

const processingModal = new ProcessingModal();