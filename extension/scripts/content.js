/**
 * MailCheckr Content Script
 * Scrapes sender email from Gmail, monitors navigation changes,
 * and injects warning banners directly into the Gmail message pane.
 */

// Injected Alert Banner CSS
const bannerCss = `
.mailcheckr-banner {
    display: flex;
    flex-direction: column;
    background: linear-gradient(135deg, #1e293b, #0f172a);
    border-left: 6px solid #ef4444;
    border-radius: 8px;
    padding: 16px;
    margin: 15px 0;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    font-family: 'Inter', Arial, sans-serif;
    color: #f8fafc;
    animation: mcSlideDown 0.3s ease;
}
.mailcheckr-banner.medium-risk {
    border-left-color: #f59e0b;
}
.mailcheckr-banner-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
}
.mailcheckr-banner-title-area {
    display: flex;
    align-items: center;
    gap: 10px;
}
.mailcheckr-banner-icon {
    font-size: 20px;
}
.mailcheckr-banner-title {
    font-weight: 700;
    font-size: 14px;
    color: #f8fafc;
}
.mailcheckr-banner-actions {
    display: flex;
    gap: 10px;
}
.mailcheckr-banner-btn {
    background: #ef4444;
    color: white;
    border: none;
    border-radius: 4px;
    padding: 6px 12px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: opacity 0.2s;
}
.mailcheckr-banner-btn.medium-risk {
    background: #f59e0b;
}
.mailcheckr-banner-btn:hover {
    opacity: 0.9;
}
.mailcheckr-banner-btn-secondary {
    background: #334155;
    color: #cbd5e1;
    border: none;
    border-radius: 4px;
    padding: 6px 12px;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
}
.mailcheckr-banner-details {
    margin-top: 10px;
    padding-top: 10px;
    border-top: 1px solid #334155;
    font-size: 12px;
    color: #94a3b8;
    line-height: 1.5;
}
.mailcheckr-banner-details ul {
    margin: 5px 0 0 15px;
    padding: 0;
}
@keyframes mcSlideDown {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
}
`;

function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * Extracts the sender email of the CURRENTLY OPEN email in Gmail.
 * IMPORTANT: All queries are scoped to div[role="main"] (the open email pane),
 * NOT document — to avoid grabbing emails from the inbox list instead.
 * Classes .yP and .zF confirmed present via DOM diagnostic.
 */
function getCurrentEmail() {
    // Scope to the open email pane only — critical to avoid inbox list pollution
    const root = document.querySelector('div[role="main"]') || document;

    // Strategy 1: .yP / .zF — confirmed Gmail sender name classes with email= attribute
    for (const cls of ['.yP', '.zF', '.gD', '.go']) {
        const el = root.querySelector(cls + '[email]');
        if (el) {
            const val = el.getAttribute('email');
            if (val && val.includes('@')) return val.trim();
        }
    }

    // Strategy 2: Any span with email= attribute inside the open pane
    const emailAttrEl = root.querySelector('span[email]');
    if (emailAttrEl) {
        const val = emailAttrEl.getAttribute('email');
        if (val && val.includes('@')) return val.trim();
    }

    // Strategy 3: data-hovercard-id inside the open pane
    const hovercardEl = root.querySelector('[data-hovercard-id]');
    if (hovercardEl) {
        const val = hovercardEl.getAttribute('data-hovercard-id');
        if (val && val.includes('@')) return val.trim();
    }

    // Strategy 4: span[title] containing an email
    for (const el of root.querySelectorAll('span[title]')) {
        const t = el.getAttribute('title');
        if (t && t.includes('@') && t.includes('.')) return t.trim();
    }

    // Strategy 5: mailto: links in open pane
    for (const el of root.querySelectorAll('a[href^="mailto:"]')) {
        const addr = el.getAttribute('href').replace('mailto:', '').split('?')[0].trim();
        if (addr.includes('@')) return addr;
    }

    // Strategy 6: Brute-force — leaf span/div nodes whose entire text is an email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    for (const el of root.querySelectorAll('span, td')) {
        if (el.children.length === 0) {
            const text = (el.textContent || '').trim();
            if (emailRegex.test(text)) return text;
        }
    }

    return null;
}


/**
 * Remove existing alert banners.
 */
function removeWarningBanner() {
    const existing = document.getElementById("mailcheckr-alert-banner");
    if (existing) {
        existing.remove();
    }
}

/**
 * Injects a warning alert banner in Gmail.
 */
function injectWarningBanner(details) {
    removeWarningBanner();
    
    // Find Gmail's conversation header block or main message container
    const messageContainer = document.querySelector(".gE.iv.gt, .adn, div.a3s");
    if (!messageContainer) {
        console.warn("MailCheckr: Message container not found to insert alert banner.");
        return;
    }
    
    // Inject CSS styling
    if (!document.getElementById("mailcheckr-banner-styles")) {
        const style = document.createElement("style");
        style.id = "mailcheckr-banner-styles";
        style.textContent = bannerCss;
        document.head.appendChild(style);
    }
    
    const banner = document.createElement("div");
    banner.id = "mailcheckr-alert-banner";
    banner.className = `mailcheckr-banner ${details.severity === 'medium' ? 'medium-risk' : ''}`;
    
    const icon = details.severity === 'high' ? '⚠️' : '🔔';
    const riskLabel = details.severity === 'high' ? 'DANGEROUS' : 'SUSPICIOUS';
    
    banner.innerHTML = `
        <div class="mailcheckr-banner-header">
            <div class="mailcheckr-banner-title-area">
                <span class="mailcheckr-banner-icon">${icon}</span>
                <span class="mailcheckr-banner-title">MailCheckr Warning: Opened email is flagged as ${riskLabel}</span>
            </div>
            <div class="mailcheckr-banner-actions">
                <button class="mailcheckr-banner-btn-secondary" id="mc-toggle-details">Details</button>
                <button class="mailcheckr-banner-btn ${details.severity === 'medium' ? 'medium-risk' : ''}" id="mc-open-popup">Inspect</button>
                <button class="mailcheckr-banner-btn-secondary" id="mc-dismiss-banner">✕</button>
            </div>
        </div>
        <div class="mailcheckr-banner-details" id="mc-details-box" style="display: none;">
            <strong>Heuristic Threat Matches:</strong>
            <ul>
                ${details.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
            </ul>
        </div>
    `;
    
    // Insert banner above the email body
    messageContainer.parentNode.insertBefore(banner, messageContainer);
    
    // Bind actions
    banner.querySelector("#mc-toggle-details").addEventListener("click", () => {
        const box = banner.querySelector("#mc-details-box");
        box.style.display = box.style.display === 'none' ? 'block' : 'none';
    });
    
    banner.querySelector("#mc-dismiss-banner").addEventListener("click", () => {
        banner.remove();
    });
    
    banner.querySelector("#mc-open-popup").addEventListener("click", () => {
        chrome.runtime.sendMessage({ action: "requestPopupOpen" });
    });
}

// Track URL updates to remove old warning banner immediately upon navigation
let lastUrl = window.location.href;
setInterval(() => {
    if (window.location.href !== lastUrl) {
        lastUrl = window.location.href;
        removeWarningBanner();
        
        // Auto-extract and sync sender email on navigation changes
        const email = getCurrentEmail();
        if (email) {
            chrome.storage.local.set({ email: email });
        }
    }
}, 500);

// Watch for DOM changes to auto-extract sender email on Gmail SPA load
const observer = new MutationObserver(() => {
    const email = getCurrentEmail();
    if (email) {
        chrome.storage.local.set({ email: email });
    }
});
observer.observe(document.body, { childList: true, subtree: true });

// Listen for scanning messages from background scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getEmail") {
        let email = getCurrentEmail();
        if (email) {
            chrome.storage.local.set({ email: email }, () => {
                sendResponse({ email: email });
            });
        } else {
            sendResponse({ email: null });
        }
        return true; 
    }
    
    if (request.action === "emailScanned") {
        if (request.details && request.details.isSuspicious) {
            injectWarningBanner(request.details);
        } else {
            removeWarningBanner();
        }
        sendResponse({ success: true });
        return true;
    }
});
