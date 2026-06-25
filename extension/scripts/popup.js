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

    const spyPixelResult = document.getElementById("spy-pixel-result");
    const journeyResult  = document.getElementById("journey-result");
    const replyTrapBanner = document.getElementById("reply-to-trap-banner");

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

        fetch("https://mailcheckr.onrender.com/api/check-email", {
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
        let activeMessageId = parts[parts.length - 1];
        
        // Strip query parameters
        activeMessageId = activeMessageId.split('?')[0];

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

                // 4. Reply-To Trap (Sender tab banner)
                if (details.replyToTrap) renderReplyToTrap(details.replyToTrap);

                // 5. Spy Pixel Tab
                if (details.trackingPixels !== undefined) renderSpyPixels(details.trackingPixels);

                // 6. Journey Tab
                if (details.journeyHops && details.journeyHops.length > 0) renderJourney(details.journeyHops);
            } else {
                // Background scan not done yet — show loading states
                spyPixelResult.innerHTML = '<div class="empty-state">⏳ Scanning email for spy pixels...</div>';
                journeyResult.innerHTML  = '<div class="empty-state">⏳ Tracing email journey...</div>';
            }
        });
    });

    // Listen for background scan completion — re-render new tabs when data arrives
    // This fixes the race condition where popup opens before geolocation finishes
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local' || !changes.scannedEmailDetails) return;
        const details = changes.scannedEmailDetails.newValue;
        if (!details) return;

        // Re-render all dynamic panels with fresh data
        if (details.replyToTrap)   renderReplyToTrap(details.replyToTrap);
        if (details.trackingPixels !== undefined) renderSpyPixels(details.trackingPixels);
        if (details.journeyHops && details.journeyHops.length > 0) renderJourney(details.journeyHops);

        // Also update sender email if not yet populated
        if (details.sender && !emailInput.value) emailInput.value = details.sender;

        console.log('MailCheckr popup: re-rendered from background scan update.');
    });




    // --- LOGOUT LOGIC ---
    document.getElementById("logout-btn").addEventListener("click", () => {
        localStorage.removeItem("token");
        chrome.storage.local.remove(["email", "token", "scannedEmailDetails"], () => {
            window.location.href = "login.html";
        });
    });

    // ============================================================
    // FEATURE 2: REPLY-TO TRAP RENDERER
    // ============================================================
    function renderReplyToTrap(trap) {
        if (!trap || !trap.replyToPresent) {
            replyTrapBanner.style.display = 'none';
            return;
        }
        if (!trap.isTrap && !trap.emailMismatch && !trap.returnPathMismatch) {
            replyTrapBanner.style.display = 'none';
            return;
        }

        const riskIcon = trap.isTrap ? '🚨' : '⚠️';
        const riskTitle = trap.isTrap ? 'Reply-To Trap Detected!' : 'Reply-To Mismatch';

        replyTrapBanner.style.display = 'block';
        replyTrapBanner.innerHTML = `
            <div class="reply-trap-header">
                <span class="reply-trap-icon">${riskIcon}</span>
                <span class="reply-trap-title">${riskTitle}</span>
            </div>
            <div class="reply-trap-body">
                <p style="margin-bottom:8px; font-size:0.78rem;">Replying to this email will send your response to a <strong>different address</strong> than the sender — a common Business Email Compromise (BEC) attack technique.</p>
                <div class="reply-trap-row">
                    <span class="reply-trap-label">From:</span>
                    <span class="reply-trap-val">${escapeHtml(trap.fromEmail)}</span>
                </div>
                <div class="reply-trap-row">
                    <span class="reply-trap-label">Reply-To:</span>
                    <span class="reply-trap-val danger">${escapeHtml(trap.replyToEmail)}</span>
                </div>
                ${trap.returnPathMismatch ? `<div class="reply-trap-row">
                    <span class="reply-trap-label">Return-Path:</span>
                    <span class="reply-trap-val danger">${escapeHtml(trap.returnPath)}</span>
                </div>` : ''}
            </div>
        `;
    }

    // ============================================================
    // FEATURE 1: SPY PIXEL RENDERER
    // ============================================================
    function renderSpyPixels(pixels) {
        if (!pixels || pixels.length === 0) {
            spyPixelResult.innerHTML = `
                <div class="pixel-summary safe">
                    <div class="pixel-summary-icon">✅</div>
                    <div class="pixel-summary-text">
                        <div class="pixel-count">No Trackers Detected</div>
                        <div class="pixel-desc">This email does not appear to contain any known tracking pixels or spy images.</div>
                    </div>
                </div>`;
            return;
        }

        const spyCount  = pixels.filter(p => p.isTinyPixel).length;
        const knowCount = pixels.filter(p => !p.isTinyPixel).length;
        const summaryClass = spyCount > 0 ? 'danger' : 'warning';
        const summaryIcon  = spyCount > 0 ? '<span class="spy-pulse">🕵️</span>' : '⚠️';
        const summaryText  = spyCount > 0
            ? `${spyCount} invisible spy pixel${spyCount > 1 ? 's' : ''} found — you are being tracked!`
            : `${knowCount} known marketing tracker${knowCount > 1 ? 's' : ''} detected.`;

        const cards = pixels.map(p => {
            const riskClass = p.isTinyPixel ? 'high-risk' : (p.hasTrackingPath ? '' : 'low-risk');
            const tags = [
                p.isTinyPixel    ? '<span class="tracker-tag spy">Spy Pixel</span>' : '',
                p.hasTrackingPath ? '<span class="tracker-tag path">Tracking Path</span>' : '',
                (!p.isTinyPixel && !p.hasTrackingPath) ? '<span class="tracker-tag known">Known Service</span>' : ''
            ].filter(Boolean).join('');

            return `
                <div class="tracker-card ${riskClass}">
                    <div class="tracker-card-header">
                        <span class="tracker-name">${escapeHtml(p.name)}</span>
                        <span class="tracker-category">${escapeHtml(p.category)}</span>
                    </div>
                    <div class="tracker-tags">${tags}</div>
                    <div class="tracker-url" title="${escapeHtml(p.url)}">${escapeHtml(p.url)}</div>
                </div>`;
        }).join('');

        spyPixelResult.innerHTML = `
            <div class="pixel-summary ${summaryClass}">
                <div class="pixel-summary-icon">${summaryIcon}</div>
                <div class="pixel-summary-text">
                    <div class="pixel-count">${pixels.length} Tracker${pixels.length > 1 ? 's' : ''} Found</div>
                    <div class="pixel-desc">${summaryText}</div>
                </div>
            </div>
            ${cards}`;
    }

    // ============================================================
    // FEATURE 3: EMAIL JOURNEY RENDERER
    // ============================================================
    function countryCodeToFlag(cc) {
        if (!cc || cc.length !== 2) return '🌐';
        return cc.toUpperCase().replace(/./g, ch =>
            String.fromCodePoint(ch.charCodeAt(0) + 127397)
        );
    }

    function renderJourney(hops) {
        if (!hops || hops.length === 0) {
            journeyResult.innerHTML = '<div class="empty-state">No routing information found in this email\'s headers.</div>';
            return;
        }

        // Calculate summary stats
        const countries   = [...new Set(hops.filter(h => h.geo && h.geo.country).map(h => h.geo.country))];
        const anomalies   = hops.filter(h => h.isSuspicious).length;
        const totalMs     = hops[hops.length-1]?.timestampMs && hops[0]?.timestampMs
                            ? hops[hops.length-1].timestampMs - hops[0].timestampMs
                            : null;
        const totalTime   = totalMs !== null ? formatHopDelay(totalMs) : 'Unknown';

        const anomalyWarning = anomalies > 0
            ? `<div class="journey-warning">⚠️ ${anomalies} timestamp anomaly detected — possible forged email header.</div>`
            : '';

        const statsHtml = `
            <div class="journey-stats">
                <div class="journey-stat">
                    <div class="journey-stat-value">${hops.length}</div>
                    <div class="journey-stat-label">Total Hops</div>
                </div>
                <div class="journey-stat">
                    <div class="journey-stat-value">${countries.length}</div>
                    <div class="journey-stat-label">Countries</div>
                </div>
                <div class="journey-stat">
                    <div class="journey-stat-value">${totalTime}</div>
                    <div class="journey-stat-label">Total Transit</div>
                </div>
                <div class="journey-stat">
                    <div class="journey-stat-value" style="color:${anomalies > 0 ? 'var(--color-danger)' : 'var(--color-success)'}">${anomalies > 0 ? anomalies + ' ⚠' : '✓'}</div>
                    <div class="journey-stat-label">Anomalies</div>
                </div>
            </div>`;

        const hopsHtml = hops.map((hop, idx) => {
            const isOrigin = idx === 0;
            const isFinal  = idx === hops.length - 1;
            const dotClass = hop.isSuspicious ? 'suspicious' : (isOrigin ? 'origin' : (isFinal ? 'final' : ''));

            const delayClass = hop.delayFormatted === 'Origin' ? 'origin-tag'
                             : hop.isSuspicious ? 'anomaly'
                             : (hop.delayMs > 60000 ? 'slow' : 'fast');

            const geoHtml = hop.geo ? `
                <div class="hop-geo">
                    <span class="hop-flag">${countryCodeToFlag(hop.geo.countryCode)}</span>
                    <span class="hop-location">${escapeHtml(hop.geo.city ? hop.geo.city + ', ' + hop.geo.country : hop.geo.country)}</span>
                    ${hop.geo.org ? `<span class="hop-org">${escapeHtml(hop.geo.org.substring(0, 30))}</span>` : ''}
                </div>` : '';

            const anomalyLabel = hop.isSuspicious
                ? `<div class="hop-anomaly-label">⚠️ Negative delay — timestamp may be forged</div>` : '';

            const serverLabel = hop.from && hop.from !== 'unknown'
                ? escapeHtml(hop.from)
                : (hop.by && hop.by !== 'unknown' ? escapeHtml(hop.by) : 'Unknown Server');

            return `
                <div class="hop-item">
                    <div class="hop-dot ${dotClass}"></div>
                    <div class="hop-card ${hop.isSuspicious ? 'suspicious-hop' : ''}">
                        <div class="hop-card-header">
                            <div class="hop-server">${isOrigin ? '🚀 ' : (isFinal ? '📬 ' : '🔀 ')}${serverLabel}</div>
                            <div class="hop-delay ${delayClass}">${hop.delayFormatted}</div>
                        </div>
                        ${hop.ip ? `<div class="hop-ip">${escapeHtml(hop.ip)}</div>` : ''}
                        ${geoHtml}
                        ${anomalyLabel}
                    </div>
                </div>`;
        }).join('');

        journeyResult.innerHTML = anomalyWarning + statsHtml + `<div class="journey-timeline">${hopsHtml}</div>`;
    }
}
