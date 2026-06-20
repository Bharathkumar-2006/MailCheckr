document.addEventListener("DOMContentLoaded", function () {
    chrome.storage.local.get("token", (storageData) => {
        const token = storageData.token || localStorage.getItem("token");

        // Redirect to login if no token
        if (!token) {
            window.location.href = "login.html";
            return;
        }

        // Sync to chrome.storage.local if missing
        if (token && !storageData.token) {
            chrome.storage.local.set({ token });
        }

        // Initialize the popup logic
        initPopup(token);
    });
});

function initPopup(token) {
    // HTML Escaping Utility
    function escapeHtml(str) {
        if (!str) return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Helpers to color code security badge status (Green = pass, Yellow = neutral/warning, Red = fail)
    function getSecurityBadgeClass(status) {
        if (!status) return 'badge-warning';
        const s = status.toLowerCase();
        if (s === 'pass' || s === 'true' || s === 'yes') return 'badge-success';
        if (s === 'fail' || s === 'false' || s === 'no') return 'badge-danger';
        return 'badge-warning';
    }

    // --- TAB SWITCHING LOGIC ---
    const tabButtons = document.querySelectorAll(".tab-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const tabId = btn.getAttribute("data-tab");

            // Deactivate all tabs
            tabButtons.forEach(b => b.classList.remove("active"));
            tabContents.forEach(c => c.classList.remove("active"));

            // Activate current tab
            btn.classList.add("active");
            const targetContent = document.getElementById(tabId);
            if (targetContent) {
                targetContent.classList.add("active");
            }
        });
    });

    // --- DOM Elements ---
    const emailInput = document.getElementById("email-input");
    const fetchEmailBtn = document.getElementById("fetch-email-btn");
    const checkEmailBtn = document.getElementById("check-email-btn");
    const resultDisplay = document.getElementById("result");

    const headerInput = document.getElementById("header-input");
    const analyzeHeaderBtn = document.getElementById("analyze-header-btn");
    const headerResult = document.getElementById("header-result");

    const contentInput = document.getElementById("content-input");
    const scanLinksBtn = document.getElementById("scan-links-btn");
    const linkResult = document.getElementById("link-result");

    // --- SENDER EMAIL CHECKER (TAB 1) ---

    // Render reputation check data inside the result container
    function renderSenderReputation(data) {
        if (!data) return;
        const validBadge = data.valid 
            ? '<span class="badge badge-success">Valid</span>' 
            : '<span class="badge badge-danger">Invalid</span>';
        const disposableBadge = data.disposable
            ? '<span class="badge badge-danger">Disposable</span>'
            : '<span class="badge badge-success">Permanent</span>';
        
        let spamScoreClass = 'badge-success';
        if (data.fraud_score > 75) {
            spamScoreClass = 'badge-danger';
        } else if (data.fraud_score > 30) {
            spamScoreClass = 'badge-warning';
        }
        
        resultDisplay.innerHTML = `
            <div class="result-header">
                <strong>Check Report</strong>
                ${validBadge}
            </div>
            <div class="result-row">
                <span class="result-label">Disposable:</span>
                <span class="result-val">${disposableBadge}</span>
            </div>
            <div class="result-row">
                <span class="result-label">Deliverability:</span>
                <span class="result-val"><strong>${escapeHtml(data.deliverability || 'N/A')}</strong></span>
            </div>
            <div class="result-row">
                <span class="result-label">Fraud/Spam Score:</span>
                <span class="result-val">
                    <span class="badge ${spamScoreClass}">${data.fraud_score || 0} / 100</span>
                </span>
            </div>
            <div class="result-row">
                <span class="result-label">First Seen:</span>
                <span class="result-val mono">${escapeHtml((data.first_seen && data.first_seen.human) || 'Unknown')}</span>
            </div>
        `;
    }

    // Call local API server to check email reputation
    function performSenderCheck(email) {
        if (!email) return;
        resultDisplay.innerHTML = "<p style='color:var(--text-secondary); font-size:0.85rem;'>Checking email reputation...</p>";

        fetch("http://localhost:5000/api/check-email", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${token}`
            },
            body: JSON.stringify({ email })
        })
        .then(response => {
            if (!response.ok) throw new Error("Reputation check failed");
            return response.json();
        })
        .then(data => {
            renderSenderReputation(data);
        })
        .catch(error => {
            console.error("Error checking email reputation:", error);
            resultDisplay.innerHTML = "<p class='error-message'>Error checking email reputation. Make sure the API server is running.</p>";
        });
    }

    // Fetch and display the latest sender email from current tab
    function fetchLatestEmail() {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (!tabs || tabs.length === 0) {
                emailInput.placeholder = "Enter email manually";
                return;
            }

            const tab = tabs[0];

            // Only try to extract from Gmail tabs
            if (!tab.url || !tab.url.includes("mail.google.com")) {
                emailInput.placeholder = "Open a Gmail email first";
                return;
            }

            // Step 1: Try message-passing to already-loaded content script
            chrome.tabs.sendMessage(tab.id, { action: "getEmail" }, (response) => {
                if (chrome.runtime.lastError) {
                    // Content script not ready — fall through to direct injection
                }

                if (response && response.email) {
                    chrome.storage.local.set({ email: response.email });
                    emailInput.value = response.email;
                    return;
                }

                // Step 2: Fallback — inject script directly into the tab to scrape the DOM
                chrome.scripting.executeScript({
                    target: { tabId: tab.id },
                    func: () => {
                        // CRITICAL: scope to the open email pane, not the whole page
                        // Without this, querySelector grabs the FIRST email in the inbox list
                        const root = document.querySelector('div[role="main"]') || document;

                        // .yP and .zF are confirmed Gmail sender name classes (from DOM audit)
                        for (const cls of ['.yP', '.zF', '.gD', '.go']) {
                            const el = root.querySelector(cls + '[email]');
                            if (el) {
                                const v = el.getAttribute('email');
                                if (v && v.includes('@')) return v.trim();
                            }
                        }
                        // Any span[email] inside the open pane
                        const emailEl = root.querySelector('span[email]');
                        if (emailEl) {
                            const v = emailEl.getAttribute('email');
                            if (v && v.includes('@')) return v.trim();
                        }
                        // data-hovercard-id inside the open pane
                        const hoverEl = root.querySelector('[data-hovercard-id]');
                        if (hoverEl) {
                            const v = hoverEl.getAttribute('data-hovercard-id');
                            if (v && v.includes('@')) return v.trim();
                        }
                        // span[title] with @ inside open pane
                        for (const el of root.querySelectorAll('span[title]')) {
                            const t = el.getAttribute('title');
                            if (t && t.includes('@') && t.includes('.')) return t.trim();
                        }
                        // mailto: links inside open pane
                        for (const el of root.querySelectorAll('a[href^="mailto:"]')) {
                            const addr = el.getAttribute('href').replace('mailto:', '').split('?')[0].trim();
                            if (addr.includes('@')) return addr;
                        }
                        // Leaf node text scan inside open pane
                        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
                        for (const el of root.querySelectorAll('span, td')) {
                            if (el.children.length === 0) {
                                const text = (el.textContent || '').trim();
                                if (emailRegex.test(text)) return text;
                            }
                        }
                        return null;
                    }

                }, (results) => {
                    if (chrome.runtime.lastError) {
                        emailInput.placeholder = "Enter email manually";
                        return;
                    }
                    const email = results && results[0] && results[0].result;
                    if (email) {
                        chrome.storage.local.set({ email });
                        emailInput.value = email;
                    } else {
                        emailInput.placeholder = "Email not found — enter manually";
                    }
                });
            });
        });
    }


    // Load stored email if available
    chrome.storage.local.get("email", (data) => {
        if (data.email) {
            emailInput.value = data.email;
        } else {
            fetchLatestEmail();
        }
    });

    fetchEmailBtn.addEventListener("click", fetchLatestEmail);
    checkEmailBtn.addEventListener("click", () => {
        const email = emailInput.value.trim();
        if (!email) {
            resultDisplay.innerHTML = "<p class='error-message'>Please enter an email.</p>";
            return;
        }
        performSenderCheck(email);
    });

    // --- EMAIL HEADER ANALYZER (TAB 2) ---

    function performHeaderAnalysis(rawHeaders) {
        if (!rawHeaders) {
            headerResult.innerHTML = "";
            return;
        }

        try {
            // Parse headers
            const parsed = parseHeaders(rawHeaders);
            
            // Extract attributes
            const fromField = getFirstHeaderValue(parsed, 'from') || 'Unknown';
            const returnPath = getFirstHeaderValue(parsed, 'return-path') || 'N/A';
            const senderIp = extractSenderIp(parsed);
            
            // Extract security configurations
            const spf = getSpfResult(parsed);
            const dkim = getDkimResult(parsed);
            const dmarc = getDmarcResult(parsed);
            
            // Extract received chain
            const receivedList = getHeaderValues(parsed, 'received');
            const hops = receivedList.map(item => parseReceivedHeader(item)).reverse(); // Chronological order

            // Generate HTML for Security indicators
            const spfClass = getSecurityBadgeClass(spf);
            const dkimClass = getSecurityBadgeClass(dkim);
            const dmarcClass = getSecurityBadgeClass(dmarc);
            
            let receivedHtml = '';
            if (hops.length === 0) {
                receivedHtml = '<p style="color:var(--text-muted); font-size:0.8rem;">No routing hops detected in headers.</p>';
            } else {
                receivedHtml = `<div class="timeline">`;
                hops.forEach((hop, index) => {
                    receivedHtml += `
                        <div class="timeline-item">
                            <div class="timeline-marker"></div>
                            <div class="timeline-content">
                                <div class="timeline-header">
                                    <span>Hop ${index + 1}: ${escapeHtml(hop.from)}</span>
                                    <span class="timeline-ip">${escapeHtml(hop.ip)}</span>
                                </div>
                                <div class="timeline-body">
                                    Received by: <strong>${escapeHtml(hop.by)}</strong>
                                </div>
                                <div class="timeline-time">${escapeHtml(hop.time)}</div>
                            </div>
                        </div>
                    `;
                });
                receivedHtml += `</div>`;
            }

            headerResult.innerHTML = `
                <div class="security-indicators">
                    <div class="indicator-card">
                        <div class="indicator-label">SPF</div>
                        <span class="badge ${spfClass}">${escapeHtml(spf)}</span>
                    </div>
                    <div class="indicator-card">
                        <div class="indicator-label">DKIM</div>
                        <span class="badge ${dkimClass}">${escapeHtml(dkim)}</span>
                    </div>
                    <div class="indicator-card">
                        <div class="indicator-label">DMARC</div>
                        <span class="badge ${dmarcClass}">${escapeHtml(dmarc)}</span>
                    </div>
                </div>

                <div class="result-header">
                    <strong>Header Details</strong>
                </div>
                <div class="result-row">
                    <span class="result-label">From:</span>
                    <span class="result-val"><strong>${escapeHtml(fromField)}</strong></span>
                </div>
                <div class="result-row">
                    <span class="result-label">Return-Path:</span>
                    <span class="result-val mono">${escapeHtml(returnPath)}</span>
                </div>
                <div class="result-row">
                    <span class="result-label">Sender IP:</span>
                    <span class="result-val">
                        <span class="badge badge-success" style="text-transform:none; font-family:monospace;">${escapeHtml(senderIp)}</span>
                    </span>
                </div>

                <div class="received-chain-title">Received Routing Chain</div>
                ${receivedHtml}
            `;
        } catch (err) {
            console.error("Header analysis error:", err);
            headerResult.innerHTML = "<p class='error-message'>Error parsing headers. Please make sure they are correct.</p>";
        }
    }

    analyzeHeaderBtn.addEventListener("click", () => {
        const rawHeaders = headerInput.value.trim();
        if (!rawHeaders) {
            headerResult.innerHTML = "<p class='error-message'>Please paste raw email headers to analyze.</p>";
            return;
        }
        performHeaderAnalysis(rawHeaders);
    });

    // --- LINK SCANNER (TAB 3) ---

    function performLinkScan(content) {
        if (!content) {
            linkResult.innerHTML = "";
            return;
        }

        try {
            const scannedUrls = scanUrls(content);
            
            if (scannedUrls.length === 0) {
                linkResult.innerHTML = `
                    <div style="text-align:center; padding:15px; color:var(--text-secondary); font-size:0.85rem;">
                        No links detected in the provided email content.
                    </div>
                `;
                return;
            }

            let rowsHtml = '';
            scannedUrls.forEach(res => {
                let riskClass = 'badge-success';
                if (res.risk === 'High') {
                    riskClass = 'badge-danger';
                } else if (res.risk === 'Medium') {
                    riskClass = 'badge-warning';
                }

                const reasonsList = res.reasons.join(', ');
                
                rowsHtml += `
                    <tr>
                        <td class="col-url">
                            <a href="${escapeHtml(res.url)}" target="_blank" title="${escapeHtml(res.url)}">${escapeHtml(res.url)}</a>
                        </td>
                        <td class="col-risk">
                            <span class="badge ${riskClass}">${escapeHtml(res.risk)}</span>
                        </td>
                        <td class="col-reason">${escapeHtml(reasonsList)}</td>
                    </tr>
                `;
            });

            linkResult.innerHTML = `
                <div class="result-header">
                    <strong>Link Scan Report</strong>
                    <span class="badge badge-warning" style="text-transform:none;">Found: ${scannedUrls.length} links</span>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Risk</th>
                                <th>Reason</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rowsHtml}
                        </tbody>
                    </table>
                </div>
            `;
        } catch (err) {
            console.error("Link scanning error:", err);
            linkResult.innerHTML = "<p class='error-message'>Error occurred while scanning links.</p>";
        }
    }

    scanLinksBtn.addEventListener("click", () => {
        const content = contentInput.value.trim();
        if (!content) {
            linkResult.innerHTML = "<p class='error-message'>Please paste email content to scan.</p>";
            return;
        }
        performLinkScan(content);
    });

    // --- AUTO-POPULATE & AUTO-SCAN FROM BACKGROUND RESULT ---
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || tabs.length === 0) return;
        const url = tabs[0].url;
        if (!url || !url.includes("mail.google.com")) return;
        
        // Extract message ID from URL hash
        const hashIndex = url.indexOf('#');
        if (hashIndex === -1) return;
        const hash = url.substring(hashIndex + 1);
        const parts = hash.split('/');
        const activeMessageId = parts[parts.length - 1];
        
        // Message ID validation
        const msgIdRegex = /^[a-zA-Z0-9-_]{16,}$/;
        if (!msgIdRegex.test(activeMessageId)) return;
        
        // Load details from chrome.storage.local
        chrome.storage.local.get("scannedEmailDetails", (storageData) => {
            const details = storageData.scannedEmailDetails;
            if (details && details.messageId === activeMessageId) {
                console.log("Auto-filling results from background scan for Message ID: " + activeMessageId);
                
                // 1. Sender Checker Tab
                emailInput.value = details.sender || '';
                if (details.senderReputation) {
                    renderSenderReputation(details.senderReputation);
                } else if (details.sender) {
                    performSenderCheck(details.sender);
                }
                
                // 2. Header Analyzer Tab
                headerInput.value = details.rawHeaders || '';
                performHeaderAnalysis(details.rawHeaders);
                
                // 3. Link Scanner Tab
                contentInput.value = details.emailBody || '';
                performLinkScan(details.emailBody);
            }
        });
    });

    // --- LOGOUT LOGIC ---
    document.getElementById("logout-btn").addEventListener("click", () => {
        localStorage.removeItem("token");
        chrome.storage.local.remove(["email", "token", "scannedEmailDetails"], () => {
            window.location.href = "login.html";
        });
    });
}
