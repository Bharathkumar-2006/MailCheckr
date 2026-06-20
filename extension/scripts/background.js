// Load extension utility scanners (path is relative to extension root)
importScripts("scripts/utils.js");

let lastScannedMsgId = null;
let lastScannedTime = 0;

chrome.runtime.onInstalled.addListener(() => {
    console.log("Email Safety Checker Extension Installed");
});

// Listen to tab updates to track URL changes in Gmail (SPA navigation)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        handleUrlChange(tabId, changeInfo.url);
    }
});

// Listen to runtime messages (e.g. from injected Gmail warning banners)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "requestPopupOpen") {
        chrome.action.openPopup(() => {
            if (chrome.runtime.lastError) {
                console.warn("Could not open popup programmatically: ", chrome.runtime.lastError.message);
                sendResponse({ success: false, error: chrome.runtime.lastError.message });
            } else {
                sendResponse({ success: true });
            }
        });
        return true; // Keep channel open for async response
    }
});

/**
 * Parses URL updates to detect opened Gmail messages.
 */
function handleUrlChange(tabId, url) {
    if (!url || !url.includes("mail.google.com")) return;
    
    // Extract message ID from hash
    const hashIndex = url.indexOf('#');
    if (hashIndex === -1) return;
    
    const hash = url.substring(hashIndex + 1);
    const parts = hash.split('/');
    let lastPart = parts[parts.length - 1];

    // Strip any query parameters (like ?compose=1)
    lastPart = lastPart.split('?')[0];
    
    // Check if the hash segment is a valid message ID (minimum 16 chars)
    const msgIdRegex = /^[a-zA-Z0-9-_]{16,}$/;
    if (!msgIdRegex.test(lastPart)) return;
    
    const messageId = lastPart;
    
    // Avoid double scanning within 2 seconds
    if (lastScannedMsgId === messageId && Date.now() - lastScannedTime < 2000) {
        return;
    }
    
    lastScannedMsgId = messageId;
    lastScannedTime = Date.now();

    
    // Extract account user index (u/0, u/1, etc.)
    const uMatch = url.match(/\/mail\/u\/(\d+)\//);
    const userIndex = uMatch ? uMatch[1] : '0';
    
    processEmailMessage(tabId, userIndex, messageId);
}

/**
 * Fetches and processes raw headers and content from Gmail show original endpoint.
 * NOTE: The ?view=om endpoint returns an HTML page with the raw MIME email
 * wrapped inside a <pre> tag. We must extract it before parsing.
 */
function processEmailMessage(tabId, userIndex, messageId) {
    const rawUrl = `https://mail.google.com/mail/u/${userIndex}/?view=om&th=${messageId}`;

    console.log(`Fetching raw email source for Message ID: ${messageId}`);

    fetch(rawUrl)
        .then(response => {
            if (!response.ok) throw new Error('Unable to fetch raw message source');
            return response.text();
        })
        .then(html => {
            // Gmail wraps the raw MIME source inside a <pre> element.
            // We must extract it before parsing headers and body.
            let rawMime = '';
            const preMatch = html.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i);
            if (preMatch) {
                // Decode HTML entities Gmail encodes in the pre block
                rawMime = preMatch[1]
                    .replace(/&lt;/g, '<')
                    .replace(/&gt;/g, '>')
                    .replace(/&amp;/g, '&')
                    .replace(/&quot;/g, '"')
                    .replace(/&#39;/g, "'");
            } else {
                // Fallback: some endpoints return raw MIME directly
                rawMime = html;
            }

            // Split at the first blank line (MIME separator between headers and body)
            let headersText = '';
            let bodyText = '';

            const crlfSep = rawMime.indexOf('\r\n\r\n');
            const lfSep   = rawMime.indexOf('\n\n');

            if (crlfSep !== -1) {
                headersText = rawMime.substring(0, crlfSep);
                bodyText    = rawMime.substring(crlfSep + 4);
            } else if (lfSep !== -1) {
                headersText = rawMime.substring(0, lfSep);
                bodyText    = rawMime.substring(lfSep + 2);
            } else {
                headersText = rawMime;
            }

            // Decode base64-encoded body parts (common in HTML emails)
            // Detect Content-Transfer-Encoding: base64 in headers
            const isBase64 = /content-transfer-encoding:\s*base64/i.test(headersText);
            if (isBase64) {
                try {
                    // Strip whitespace from base64 then decode
                    const b64 = bodyText.replace(/\s+/g, '');
                    bodyText = atob(b64);
                } catch (e) {
                    // Not valid base64, keep as-is
                }
            }

            // For multipart emails, extract all HTML parts
            if (/content-type:\s*multipart/i.test(headersText)) {
                bodyText = extractMultipartBody(rawMime);
            }

            analyzeScrapedEmail(tabId, messageId, headersText, bodyText);
        })
        .catch(err => {
            console.error('Error processing email message in background:', err);
        });
}

/**
 * Extracts all text/html and text/plain parts from a MIME multipart message.
 * Returns the concatenated decoded content.
 */
function extractMultipartBody(rawMime) {
    // Find boundary
    const boundaryMatch = rawMime.match(/boundary="?([^"\r\n;]+)"?/i);
    if (!boundaryMatch) return rawMime;

    const boundary = boundaryMatch[1];
    const parts = rawMime.split(new RegExp('--' + boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

    let combined = '';
    for (const part of parts) {
        const isHtml  = /content-type:\s*text\/html/i.test(part);
        const isPlain = /content-type:\s*text\/plain/i.test(part);
        if (!isHtml && !isPlain) continue;

        const sep = part.indexOf('\n\n');
        if (sep === -1) continue;
        let body = part.substring(sep + 2);

        const isBase64 = /content-transfer-encoding:\s*base64/i.test(part);
        const isQP     = /content-transfer-encoding:\s*quoted-printable/i.test(part);

        if (isBase64) {
            try { body = atob(body.replace(/\s+/g, '')); } catch (e) {}
        } else if (isQP) {
            body = body
                .replace(/=\r?\n/g, '')
                .replace(/=([0-9A-F]{2})/gi, (_, p1) => String.fromCharCode(parseInt(p1, 16)));
        }

        combined += body + '\n';
    }
    return combined || rawMime;
}



/**
 * Extracts sender email from "Name <email@domain.com>" format.
 */
function extractEmail(fromField) {
    if (!fromField) return '';
    const match = fromField.match(/<([^>]+)>/);
    if (match) return match[1].trim();
    return fromField.trim();
}

/**
 * Audits parsed email structures and compiles security indicators.
 */
function analyzeScrapedEmail(tabId, messageId, headersText, bodyText) {
    try {
        const parsedHeaders = parseHeaders(headersText);

        const fromField   = getFirstHeaderValue(parsedHeaders, 'from') || '';
        const senderEmail = extractEmail(fromField);
        const senderIp    = extractSenderIp(parsedHeaders);

        const spf   = getSpfResult(parsedHeaders);
        const dkim  = getDkimResult(parsedHeaders);
        const dmarc = getDmarcResult(parsedHeaders);

        // Scan links in body
        const linksResult = scanUrls(bodyText);

        // Feature 1: Spy pixel detection
        const trackingPixels = detectTrackingPixels(bodyText);

        // Feature 2: Reply-To trap detection
        const replyToTrap = detectReplyToTrap(parsedHeaders);

        // Feature 3: Email journey extraction
        const journeyHops = extractEmailJourney(parsedHeaders);

        // Geolocate IPs in journey hops (using free ip-api.com)
        const geoPromises = journeyHops.map(hop => {
            if (!hop.ip || hop.ip === 'unknown') return Promise.resolve(hop);
            // Skip private/loopback IPs
            if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1)/.test(hop.ip)) {
                return Promise.resolve({ ...hop, geo: { country: 'Local/Private', city: '', org: '' } });
            }
            return fetch(`http://ip-api.com/json/${hop.ip}?fields=country,countryCode,regionName,city,org,status`)
                .then(r => r.json())
                .then(geo => ({ ...hop, geo: geo.status === 'success' ? geo : null }))
                .catch(() => hop);
        });

        Promise.all(geoPromises).then(geoHops => {
            // Read auth token to check sender reputation
            chrome.storage.local.get('token', (storageData) => {
                const token = storageData.token;
                if (token && senderEmail) {
                    fetch('http://localhost:5000/api/check-email', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${token}`
                        },
                        body: JSON.stringify({ email: senderEmail })
                    })
                    .then(res => { if (!res.ok) throw new Error('Reputation API check failed'); return res.json(); })
                    .then(senderReputation => {
                        compileAndSaveResults(tabId, messageId, headersText, bodyText, parsedHeaders, fromField, senderEmail, senderIp, spf, dkim, dmarc, linksResult, senderReputation, trackingPixels, replyToTrap, geoHops);
                    })
                    .catch(err => {
                        console.error('Reputation API fetch failed:', err);
                        compileAndSaveResults(tabId, messageId, headersText, bodyText, parsedHeaders, fromField, senderEmail, senderIp, spf, dkim, dmarc, linksResult, null, trackingPixels, replyToTrap, geoHops);
                    });
                } else {
                    compileAndSaveResults(tabId, messageId, headersText, bodyText, parsedHeaders, fromField, senderEmail, senderIp, spf, dkim, dmarc, linksResult, null, trackingPixels, replyToTrap, geoHops);
                }
            });
        });

    } catch (err) {
        console.error('Error during background email analysis:', err);
    }
}

/**
 * Aggregates threat scores, triggers warning popup, and dispatches in-page alert messaging.
 */
function compileAndSaveResults(tabId, messageId, headersText, bodyText, parsedHeaders, fromField, senderEmail, senderIp, spf, dkim, dmarc, linksResult, senderReputation, trackingPixels, replyToTrap, journeyHops) {
    const spfFail   = spf  === 'fail';
    const dkimFail  = dkim === 'fail';
    const dmarcFail = dmarc === 'fail';
    const authFail  = spfFail || dkimFail || dmarcFail;

    const hasHighRiskLinks   = linksResult.some(l => l.risk === 'High');
    const hasSpyPixels       = (trackingPixels || []).some(p => p.isTinyPixel);
    const hasReplyToTrap     = replyToTrap && replyToTrap.isTrap;

    let reputationFail = false;
    if (senderReputation) {
        reputationFail = (senderReputation.fraud_score > 75) ||
                         (senderReputation.disposable === true || senderReputation.disposable === 'true');
    }

    const isSuspicious = authFail || hasHighRiskLinks || reputationFail || hasReplyToTrap;
    const severity = (spfFail || dmarcFail || hasHighRiskLinks || hasReplyToTrap ||
                     (senderReputation && senderReputation.fraud_score > 85))
                     ? 'high' : (isSuspicious ? 'medium' : 'low');

    const reasons = [];
    if (spfFail)        reasons.push('SPF check failed (sender identity unverified)');
    if (dkimFail)       reasons.push('DKIM signature verification failed (email content modified)');
    if (dmarcFail)      reasons.push('DMARC alignment check failed (spoofing indicator)');
    if (hasHighRiskLinks) reasons.push('Contains high-risk link indicators (Punycode, raw IP address, or brand impersonation)');
    if (hasReplyToTrap) reasons.push(`Reply-To trap detected — replies go to ${replyToTrap.replyToEmail} (${replyToTrap.replyToDomain}), not the sender`);
    if (hasSpyPixels)   reasons.push(`Contains ${(trackingPixels || []).filter(p => p.isTinyPixel).length} hidden spy pixel(s) tracking when you open this email`);
    if (senderReputation) {
        if (senderReputation.fraud_score > 75)
            reasons.push(`Sender email has a high fraud score (${senderReputation.fraud_score}/100)`);
        if (senderReputation.disposable === true || senderReputation.disposable === 'true')
            reasons.push('Sender email address is from a disposable domain');
    }

    const scannedDetails = {
        messageId,
        sender: senderEmail,
        fromField,
        rawHeaders: headersText,
        emailBody: bodyText,
        spf,
        dkim,
        dmarc,
        senderIp,
        linksResult,
        senderReputation,
        trackingPixels:  trackingPixels  || [],
        replyToTrap:     replyToTrap     || null,
        journeyHops:     journeyHops     || [],
        isSuspicious,
        severity,
        reasons
    };

    // Save to storage
    chrome.storage.local.set({ scannedEmailDetails: scannedDetails, email: senderEmail }, () => {
        console.log(`Saved email scan details for Message ID: ${messageId}. Suspicious: ${isSuspicious}`);

        // Notify content script of the active tab
        chrome.tabs.sendMessage(tabId, { action: 'emailScanned', details: scannedDetails }, () => {
            if (chrome.runtime.lastError) { /* Fail silently */ }
        });

        // Trigger automated popup if suspicious
        if (isSuspicious) {
            chrome.storage.local.get('lastAlertedMsgId', (alertData) => {
                if (alertData.lastAlertedMsgId !== messageId) {
                    chrome.storage.local.set({ lastAlertedMsgId: messageId }, () => {
                        chrome.action.openPopup(() => {
                            if (chrome.runtime.lastError) {
                                console.warn('Could not auto-open popup:', chrome.runtime.lastError.message);
                            }
                        });
                    });
                }
            });
        }
    });
}


