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
    // Example: https://mail.google.com/mail/u/0/#inbox/FMfcgxwKjKqDkMdxvSjDqbG
    const hashIndex = url.indexOf('#');
    if (hashIndex === -1) return;
    
    const hash = url.substring(hashIndex + 1);
    const parts = hash.split('/');
    const lastPart = parts[parts.length - 1];
    
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
 */
function processEmailMessage(tabId, userIndex, messageId) {
    const rawUrl = `https://mail.google.com/mail/u/${userIndex}/?view=om&th=${messageId}`;
    
    console.log(`Fetching raw email source for Message ID: ${messageId}`);
    
    fetch(rawUrl)
        .then(response => {
            if (!response.ok) throw new Error("Unable to fetch raw message source");
            return response.text();
        })
        .then(text => {
            // Split raw email into headers and body
            const doubleNewlineIndex = text.indexOf('\r\n\r\n');
            let headersText = '';
            let bodyText = '';
            
            if (doubleNewlineIndex !== -1) {
                headersText = text.substring(0, doubleNewlineIndex);
                bodyText = text.substring(doubleNewlineIndex + 4);
            } else {
                const doubleLfIndex = text.indexOf('\n\n');
                if (doubleLfIndex !== -1) {
                    headersText = text.substring(0, doubleLfIndex);
                    bodyText = text.substring(doubleLfIndex + 2);
                } else {
                    headersText = text;
                }
            }
            
            analyzeScrapedEmail(tabId, messageId, headersText, bodyText);
        })
        .catch(err => {
            console.error("Error processing email message in background:", err);
        });
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
        
        const fromField = getFirstHeaderValue(parsedHeaders, 'from') || '';
        const senderEmail = extractEmail(fromField);
        const senderIp = extractSenderIp(parsedHeaders);
        
        const spf = getSpfResult(parsedHeaders);
        const dkim = getDkimResult(parsedHeaders);
        const dmarc = getDmarcResult(parsedHeaders);
        
        // Scan links in body (automatically decodes quoted-printable)
        const linksResult = scanUrls(bodyText);
        
        // Read auth token from local storage to check sender reputation in background
        chrome.storage.local.get("token", (storageData) => {
            const token = storageData.token;
            if (token && senderEmail) {
                fetch("http://localhost:5000/api/check-email", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${token}`
                    },
                    body: JSON.stringify({ email: senderEmail })
                })
                .then(res => {
                    if (!res.ok) throw new Error("Reputation API check failed");
                    return res.json();
                })
                .then(senderReputation => {
                    compileAndSaveResults(tabId, messageId, headersText, bodyText, parsedHeaders, fromField, senderEmail, senderIp, spf, dkim, dmarc, linksResult, senderReputation);
                })
                .catch(err => {
                    console.error("Reputation API fetch failed in background: ", err);
                    compileAndSaveResults(tabId, messageId, headersText, bodyText, parsedHeaders, fromField, senderEmail, senderIp, spf, dkim, dmarc, linksResult, null);
                });
            } else {
                compileAndSaveResults(tabId, messageId, headersText, bodyText, parsedHeaders, fromField, senderEmail, senderIp, spf, dkim, dmarc, linksResult, null);
            }
        });
    } catch (err) {
        console.error("Error during background email analysis:", err);
    }
}

/**
 * Aggregates threat scores, triggers warning popup, and dispatches in-page alert messaging.
 */
function compileAndSaveResults(tabId, messageId, headersText, bodyText, parsedHeaders, fromField, senderEmail, senderIp, spf, dkim, dmarc, linksResult, senderReputation) {
    const spfFail = spf === 'fail';
    const dkimFail = dkim === 'fail';
    const dmarcFail = dmarc === 'fail';
    const authFail = spfFail || dkimFail || dmarcFail;
    
    const hasHighRiskLinks = linksResult.some(link => link.risk === 'High');
    
    let reputationFail = false;
    if (senderReputation) {
        reputationFail = (senderReputation.fraud_score > 75) || (senderReputation.disposable === true || senderReputation.disposable === 'true');
    }
    
    const isSuspicious = authFail || hasHighRiskLinks || reputationFail;
    const severity = (spfFail || dmarcFail || hasHighRiskLinks || (senderReputation && senderReputation.fraud_score > 85)) ? 'high' : (isSuspicious ? 'medium' : 'low');
    
    const reasons = [];
    if (spfFail) reasons.push("SPF check failed (sender identity unverified)");
    if (dkimFail) reasons.push("DKIM signature verification failed (email content modified)");
    if (dmarcFail) reasons.push("DMARC alignment check failed (spoofing indicator)");
    if (hasHighRiskLinks) reasons.push("Contains high-risk link indicators (Punycode, raw IP address, or brand impersonation)");
    if (senderReputation) {
        if (senderReputation.fraud_score > 75) reasons.push(`Sender email has a high fraud score (${senderReputation.fraud_score}/100)`);
        if (senderReputation.disposable === true || senderReputation.disposable === 'true') reasons.push("Sender email address is from a disposable domain");
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
        isSuspicious,
        severity,
        reasons
    };
    
    // Save to storage
    chrome.storage.local.set({ scannedEmailDetails: scannedDetails, email: senderEmail }, () => {
        console.log(`Saved email scan details for Message ID: ${messageId}. Suspicious: ${isSuspicious}`);
        
        // Notify content script of the active tab
        chrome.tabs.sendMessage(tabId, { action: "emailScanned", details: scannedDetails }, (response) => {
            if (chrome.runtime.lastError) {
                // Fail silently if content script is not ready
            }
        });
        
        // Trigger automated popup if suspicious
        if (isSuspicious) {
            chrome.storage.local.get("lastAlertedMsgId", (alertData) => {
                if (alertData.lastAlertedMsgId !== messageId) {
                    chrome.storage.local.set({ lastAlertedMsgId: messageId }, () => {
                        chrome.action.openPopup(() => {
                            if (chrome.runtime.lastError) {
                                console.warn("Could not auto-open popup: ", chrome.runtime.lastError.message);
                            } else {
                                console.log("Auto-opened extension popup.");
                            }
                        });
                    });
                }
            });
        }
    });
}
