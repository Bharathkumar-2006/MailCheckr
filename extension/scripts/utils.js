/**
 * MailCheckr Core Utilities
 * Contains email header parsing, security verification checks,
 * and malicious URL scanning algorithms.
 */

/**
 * Parses raw email headers string into an object of key-value pairs.
 * Unfolds multi-line folded headers.
 * Handles multiple values for repeating headers (like 'Received').
 * 
 * @param {string} rawHeaders 
 * @returns {Object}
 */
function parseHeaders(rawHeaders) {
    if (!rawHeaders || typeof rawHeaders !== 'string') return {};
    
    const headerMap = {};
    // Split by CRLF or LF
    const lines = rawHeaders.split(/\r?\n/);
    let currentKey = null;
    
    for (const line of lines) {
        if (line.trim() === '') continue;
        
        // If line starts with space or tab, it's a folded header line
        if (/^[ \t]/.test(line)) {
            if (currentKey) {
                headerMap[currentKey] += ' ' + line.trim();
            }
        } else {
            const colonIndex = line.indexOf(':');
            if (colonIndex !== -1) {
                currentKey = line.substring(0, colonIndex).trim().toLowerCase();
                const val = line.substring(colonIndex + 1).trim();
                
                if (headerMap[currentKey]) {
                    if (Array.isArray(headerMap[currentKey])) {
                        headerMap[currentKey].push(val);
                    } else {
                        headerMap[currentKey] = [headerMap[currentKey], val];
                    }
                } else {
                    headerMap[currentKey] = val;
                }
            }
        }
    }
    return headerMap;
}

/**
 * Returns all values for a header key as an array.
 */
function getHeaderValues(headerMap, key) {
    const val = headerMap[key.toLowerCase()];
    if (!val) return [];
    return Array.isArray(val) ? val : [val];
}

/**
 * Returns the first value of a header key.
 */
function getFirstHeaderValue(headerMap, key) {
    const val = headerMap[key.toLowerCase()];
    if (!val) return '';
    return Array.isArray(val) ? val[0] : val;
}

/**
 * Helper to parse a single result field (e.g. spf, dkim, dmarc) from Authentication-Results.
 */
function parseAuthResult(authHeader, type) {
    if (!authHeader) return 'none';
    const regex = new RegExp(`\\b${type}=([a-zA-Z\-]+)`, 'i');
    const match = authHeader.match(regex);
    return match ? match[1].toLowerCase() : 'none';
}

/**
 * Extracts the SPF result.
 */
function getSpfResult(headers) {
    const authHeaders = getHeaderValues(headers, 'authentication-results');
    for (const auth of authHeaders) {
        const res = parseAuthResult(auth, 'spf');
        if (res !== 'none') return res;
    }
    
    // Fallback: check Received-SPF header
    const spfHeaders = getHeaderValues(headers, 'received-spf');
    for (const spf of spfHeaders) {
        const firstWord = spf.trim().split(/\s+/)[0].toLowerCase();
        if (['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'].includes(firstWord)) {
            return firstWord;
        }
    }
    return 'none';
}

/**
 * Extracts the DKIM result.
 */
function getDkimResult(headers) {
    const authHeaders = getHeaderValues(headers, 'authentication-results');
    for (const auth of authHeaders) {
        const res = parseAuthResult(auth, 'dkim');
        if (res !== 'none') return res;
    }
    return 'none';
}

/**
 * Extracts the DMARC result.
 */
function getDmarcResult(headers) {
    const authHeaders = getHeaderValues(headers, 'authentication-results');
    for (const auth of authHeaders) {
        const res = parseAuthResult(auth, 'dmarc');
        if (res !== 'none') return res;
    }
    return 'none';
}

/**
 * Extracts the Sender IP address from headers.
 * Looks in Authentication-Results, Received-SPF, or the topmost Received header.
 */
function extractSenderIp(headers) {
    // 1. Try to get IP from Authentication-Results SPF part
    const authResults = getHeaderValues(headers, 'authentication-results');
    for (const auth of authResults) {
        const ipMatch = auth.match(/\bip(?:addr)?=([a-fA-F0-9\.:]+)\b/i);
        if (ipMatch) return ipMatch[1];
    }
    
    // 2. Try to get IP from Received-SPF
    const receivedSpf = getHeaderValues(headers, 'received-spf');
    for (const spf of receivedSpf) {
        const ipMatch = spf.match(/designates\s+([a-fA-F0-9\.:]+)/i);
        if (ipMatch) return ipMatch[1];
    }
    
    // 3. Try to extract IP from the topmost Received header
    const receivedHeaders = getHeaderValues(headers, 'received');
    if (receivedHeaders.length > 0) {
        // Look for IP in brackets in the topmost Received header
        const ipMatch = receivedHeaders[0].match(/\[([a-fA-F0-9\.:]+)\]/);
        if (ipMatch) return ipMatch[1];
        
        // Fallback: any IP
        const anyIpMatch = receivedHeaders[0].match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        if (anyIpMatch) return anyIpMatch[0];
    }
    
    return 'Unknown';
}

/**
 * Parses details from a single Received header.
 */
function parseReceivedHeader(headerStr) {
    if (!headerStr || typeof headerStr !== 'string') {
        return { from: 'Unknown', by: 'Unknown', ip: 'Unknown', time: 'Unknown', raw: '' };
    }
    const parts = headerStr.split(';');
    const body = parts[0];
    const timeStr = parts.length > 1 ? parts[parts.length - 1].trim() : '';
    
    // Extract "from" domain/info
    // e.g. from mail-sender.example.com (mail-sender.example.com [192.0.2.1])
    const fromMatch = body.match(/from\s+([^\s(]+)(?:\s+\(([^)]+)\))?/i);
    let fromDomain = 'Unknown';
    let fromDetails = '';
    let ip = '';
    
    if (fromMatch) {
        fromDomain = fromMatch[1];
        fromDetails = fromMatch[2] || '';
        // Look for IP in the details or general body
        const ipMatch = fromDetails.match(/\[([a-fA-F0-9\.:]+)\]/) || body.match(/\[([a-fA-F0-9\.:]+)\]/);
        if (ipMatch) {
            ip = ipMatch[1];
        }
    }
    
    // Extract "by" domain
    const byMatch = body.match(/by\s+([^\s]+)/i);
    const byDomain = byMatch ? byMatch[1] : 'Unknown';
    
    return {
        from: fromDomain,
        by: byDomain,
        ip: ip || 'Unknown',
        time: timeStr,
        raw: headerStr
    };
}

/**
 * Normalizes lookalike characters back to standard alphanumeric representations.
 */
function normalizeDomain(str) {
    if (!str) return '';
    return str
        .replace(/0/g, 'o')
        .replace(/[1li]/g, 'l')
        .replace(/3/g, 'e')
        .replace(/[4@]/g, 'a')
        .replace(/[5$]/g, 's')
        .replace(/7/g, 't');
}

/**
 * Extracts the base registered domain name from a full hostname.
 * Handles common multi-level TLDs (e.g. co.uk, com.br).
 */
function getBaseDomain(hostname) {
    if (!hostname) return '';
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    
    const secondToLast = parts[parts.length - 2];
    const last = parts[parts.length - 1];
    
    const commonSecondTlds = ['co', 'com', 'org', 'net', 'edu', 'gov', 'mil', 'ac'];
    const commonTlds = ['uk', 'br', 'cn', 'jp', 'au', 'nz', 'za', 'in', 'us', 'ca'];
    
    if (commonSecondTlds.includes(secondToLast) && commonTlds.includes(last)) {
        return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
}

/**
 * Checks for typosquatting,combo-squatting, or subdomain spoofing on a brand name.
 */
function checkLookalike(hostname, baseDomain) {
    const brands = [
        'google', 'paypal', 'microsoft', 'apple', 'netflix', 'amazon', 
        'facebook', 'instagram', 'twitter', 'linkedin', 'yahoo', 'outlook', 
        'zoom', 'dropbox', 'gmail', 'bankofamerica', 'chase', 'wellsfargo', 'citi'
    ];
    
    const registeredName = baseDomain.split('.')[0];
    const normalizedRegisteredName = normalizeDomain(registeredName);
    
    for (const brand of brands) {
        if (registeredName === brand) {
            continue; // Safe: official domain
        }
        
        // 1. Character substitution (e.g. paypa1.com -> paypal)
        if (normalizedRegisteredName === normalizeDomain(brand) && registeredName !== brand) {
            return `Lookalike domain attempting to impersonate a popular brand (${brand}) via character substitution.`;
        }
        
        // 2. Combo-squatting (e.g. paypal-security.com)
        if (registeredName.includes(brand) && registeredName !== brand) {
            return `Lookalike domain attempting to impersonate a popular brand (${brand}) by combining it with other words.`;
        }
        
        // 3. Subdomain spoofing (e.g. paypal.com.phishingsite.com)
        if (hostname.includes(brand) && !baseDomain.includes(brand)) {
            return `Lookalike domain attempting to impersonate a popular brand (${brand}) using subdomain spoofing.`;
        }
    }
    return null;
}

/**
 * Scans a single URL and runs security audits on it.
 */
function analyzeUrl(url) {
    let hostname = '';
    try {
        const parsedUrl = new URL(url);
        hostname = parsedUrl.hostname.toLowerCase();
    } catch (e) {
        // Fallback for relative or malformed URLs
        const hostMatch = url.match(/https?:\/\/([^/:\s]+)/i);
        hostname = hostMatch ? hostMatch[1].toLowerCase() : '';
    }
    
    if (!hostname) {
        return {
            url: url,
            risk: 'Low',
            reasons: ['Unable to parse domain structure.'],
            findings: []
        };
    }
    
    const findings = [];
    
    // 1. IP-address-based URL check
    const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const isIp = ipv4Regex.test(hostname) || hostname.startsWith('[') || /^[a-f0-9:]+$/.test(hostname);
    if (isIp) {
        findings.push({
            risk: 'High',
            reason: 'Uses a raw IP address instead of a domain name.'
        });
    }
    
    // 2. Punycode check
    const isPunycode = hostname.startsWith('xn--');
    if (isPunycode) {
        findings.push({
            risk: 'High',
            reason: 'Uses Punycode encoding, which can be used to spoof legitimate domains.'
        });
    }
    
    // Domain-specific rules (skip if raw IP address)
    if (!isIp) {
        // 3. URL shorteners
        const shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'rebrand.ly', 
            'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 
            'su.pr', 'ow.ly', 'shorturl.at', 'tiny.cc', 'lnk.to', 't.ly'
        ];
        const baseDomain = getBaseDomain(hostname);
        const isShortener = shorteners.includes(baseDomain) || shorteners.includes(hostname);
        if (isShortener) {
            findings.push({
                risk: 'Medium',
                reason: 'Uses a URL shortener which hides the final destination.'
            });
        }
        
        // 4. Suspicious TLDs
        const suspiciousTlds = [
            'zip', 'mov', 'fit', 'tk', 'ml', 'ga', 'cf', 'gq', 
            'country', 'stream', 'download', 'xin', 'gdn', 
            'racing', 'jetzt', 'win', 'top', 'xyz', 'loan', 
            'click', 'link', 'work', 'date', 'party', 'science'
        ];
        const parts = hostname.split('.');
        const tld = parts[parts.length - 1];
        if (suspiciousTlds.includes(tld)) {
            findings.push({
                risk: 'Medium',
                reason: `Uses a top-level domain (.${tld}) frequently associated with spam or malicious activity.`
            });
        }
        
        // 5. Lookalike domains
        const lookalikeReason = checkLookalike(hostname, baseDomain);
        if (lookalikeReason) {
            findings.push({
                risk: 'High',
                reason: lookalikeReason
            });
        }
    }
    
    // Compile combined risk level
    let risk = 'Low';
    const reasons = findings.map(f => f.reason);
    
    const hasHigh = findings.some(f => f.risk === 'High');
    const hasMedium = findings.some(f => f.risk === 'Medium');
    
    if (hasHigh) {
        risk = 'High';
    } else if (hasMedium) {
        risk = 'Medium';
    }
    
    return {
        url: url,
        risk: risk,
        reasons: reasons.length > 0 ? reasons : ['No suspicious indicators detected.']
    };
}

/**
 * Scans email content for URLs and performs security assessment on each.
 * 
 * @param {string} emailContent 
 * @returns {Array} Scan results
 */
/**
 * Decodes quoted-printable string (common in raw email bodies).
 */
function decodeQuotedPrintable(str) {
    if (!str) return '';
    return str
        .replace(/=\r?\n/g, '') // Remove soft line breaks
        .replace(/=([0-9A-F]{2})/gi, (match, p1) => {
            return String.fromCharCode(parseInt(p1, 16));
        });
}

function scanUrls(emailContent) {
    if (!emailContent || typeof emailContent !== 'string') return [];
    
    // Decode quoted-printable formats
    const decodedContent = decodeQuotedPrintable(emailContent);
    
    // Regex matching URLs
    const urlRegex = /https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g;
    let matches = decodedContent.match(urlRegex) || [];
    
    // Fallback: If no http/https URLs are matched, but the content looks like a single raw domain or IP
    if (matches.length === 0) {
        const trimmed = decodedContent.trim();
        const domainRegex = /^[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{0,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$/i;
        if (domainRegex.test(trimmed)) {
            matches = ['http://' + trimmed];
        }
    }
    
    // Deduplicate and clean trailing punctuation
    const cleanedUrls = matches.map(url => url.replace(/[.,;:!?)]+$/, ''));
    const uniqueUrls = [...new Set(cleanedUrls)];
    
    return uniqueUrls.map(url => analyzeUrl(url));
}

// ============================================================
// FEATURE 1: SPY PIXEL / TRACKING PIXEL DETECTOR
// ============================================================

const TRACKING_SERVICES = [
    { pattern: /mailchimp\.com/i, name: 'Mailchimp', category: 'Marketing' },
    { pattern: /sendgrid\.(net|com)/i, name: 'SendGrid', category: 'Email Delivery' },
    { pattern: /constantcontact\.com/i, name: 'Constant Contact', category: 'Marketing' },
    { pattern: /hubspot\.com/i, name: 'HubSpot', category: 'CRM' },
    { pattern: /marketo\.(com|net)/i, name: 'Marketo', category: 'Marketing' },
    { pattern: /mktoresp\.com/i, name: 'Marketo', category: 'Marketing' },
    { pattern: /salesforce\.com/i, name: 'Salesforce', category: 'CRM' },
    { pattern: /convertkit\.com/i, name: 'ConvertKit', category: 'Marketing' },
    { pattern: /mailgun\.(org|com)/i, name: 'Mailgun', category: 'Email Delivery' },
    { pattern: /postmarkapp\.com/i, name: 'Postmark', category: 'Email Delivery' },
    { pattern: /mandrillapp\.com/i, name: 'Mandrill', category: 'Email Delivery' },
    { pattern: /cmail\d+\.com/i, name: 'Campaign Monitor', category: 'Marketing' },
    { pattern: /campaignmonitor\.com/i, name: 'Campaign Monitor', category: 'Marketing' },
    { pattern: /getresponse\.com/i, name: 'GetResponse', category: 'Marketing' },
    { pattern: /aweber\.com/i, name: 'AWeber', category: 'Marketing' },
    { pattern: /infusionsoft\.com/i, name: 'Infusionsoft', category: 'CRM' },
    { pattern: /emarsys\.com/i, name: 'Emarsys', category: 'Marketing' },
    { pattern: /listrak\.com/i, name: 'Listrak', category: 'Marketing' },
    { pattern: /klaviyo\.com/i, name: 'Klaviyo', category: 'Marketing' },
    { pattern: /drip\.com/i, name: 'Drip', category: 'Marketing' },
    { pattern: /activecampaign\.com/i, name: 'ActiveCampaign', category: 'Marketing' },
    { pattern: /mailjet\.com/i, name: 'Mailjet', category: 'Email Delivery' },
    { pattern: /sendinblue\.com/i, name: 'Sendinblue', category: 'Marketing' },
    { pattern: /brevo\.com/i, name: 'Brevo', category: 'Marketing' },
    { pattern: /pardot\.com/i, name: 'Pardot', category: 'CRM' },
    { pattern: /exacttarget\.com/i, name: 'ExactTarget', category: 'CRM' },
    { pattern: /eloqua\.com/i, name: 'Oracle Eloqua', category: 'Marketing' },
    { pattern: /responsys\.com/i, name: 'Oracle Responsys', category: 'Marketing' },
    { pattern: /icontact\.com/i, name: 'iContact', category: 'Marketing' },
    { pattern: /verticalresponse\.com/i, name: 'VerticalResponse', category: 'Marketing' },
    { pattern: /dotdigital\.com/i, name: 'Dotdigital', category: 'Marketing' },
    { pattern: /selligent\.com/i, name: 'Selligent', category: 'Marketing' },
    { pattern: /returnoath\.com/i, name: 'Oath Ads', category: 'Advertising' },
    { pattern: /doubleclick\.net/i, name: 'Google DoubleClick', category: 'Advertising' },
    { pattern: /google-analytics\.com/i, name: 'Google Analytics', category: 'Analytics' },
    { pattern: /analytics\.google\.com/i, name: 'Google Analytics', category: 'Analytics' },
    { pattern: /mixpanel\.com/i, name: 'Mixpanel', category: 'Analytics' },
    { pattern: /segment\.com/i, name: 'Segment', category: 'Analytics' },
    { pattern: /amplitude\.com/i, name: 'Amplitude', category: 'Analytics' },
];

/**
 * Detects spy/tracking pixels embedded in email HTML.
 * Identifies known tracker services and suspicious 1x1 invisible images.
 * @param {string} rawBody - Raw email body (HTML)
 * @returns {Array<{name, category, url, isTinyPixel, risk}>}
 */
function detectTrackingPixels(rawBody) {
    if (!rawBody || typeof rawBody !== 'string') return [];

    const trackers = [];
    const seen = new Set();

    // Match all <img> tags
    const imgRegex = /<img([^>]*)>/gi;
    let match;
    while ((match = imgRegex.exec(rawBody)) !== null) {
        const attrs = match[1];

        // Extract src
        const srcMatch = attrs.match(/src=["']([^"']+)["']/i);
        if (!srcMatch) continue;
        const src = srcMatch[1];

        // Detect 1x1 pixel dimensions in attributes
        const wMatch = attrs.match(/width=["']?(\d+)["']?/i);
        const hMatch = attrs.match(/height=["']?(\d+)["']?/i);
        const w = wMatch ? parseInt(wMatch[1]) : null;
        const h = hMatch ? parseInt(hMatch[1]) : null;
        const isTinyPixel = (w !== null && w <= 1) || (h !== null && h <= 1);

        // Check URL path for tracking signals
        const hasTrackingPath = /\/(track|pixel|open|beacon|read-receipt|spy|email-open|wf\/)|(\ ?.*track)/i.test(src);

        // Check against known tracker list
        let matchedService = null;
        for (const svc of TRACKING_SERVICES) {
            if (svc.pattern.test(src)) { matchedService = svc; break; }
        }

        if (isTinyPixel || matchedService || hasTrackingPath) {
            const key = matchedService ? matchedService.name : src.substring(0, 60);
            if (!seen.has(key)) {
                seen.add(key);
                const risk = isTinyPixel ? 'high' : (matchedService ? 'medium' : 'low');
                trackers.push({
                    name: matchedService ? matchedService.name : 'Unknown Tracker',
                    category: matchedService ? matchedService.category : 'Surveillance',
                    url: src,
                    isTinyPixel,
                    hasTrackingPath,
                    risk
                });
            }
        }
    }

    return trackers;
}

// ============================================================
// FEATURE 2: REPLY-TO TRAP DETECTOR
// ============================================================

/**
 * Detects Reply-To trap attacks — where Reply-To differs from From.
 * This is the #1 Business Email Compromise (BEC) technique.
 * @param {Object} parsedHeaders
 * @returns {Object} Detection result
 */
function detectReplyToTrap(parsedHeaders) {
    const fromField   = getFirstHeaderValue(parsedHeaders, 'from')     || '';
    const replyToField = getFirstHeaderValue(parsedHeaders, 'reply-to') || '';
    const returnPathField = getFirstHeaderValue(parsedHeaders, 'return-path') || '';

    const emailRegex = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/;

    const fromEmail    = (fromField.match(emailRegex)       || [''])[0].toLowerCase();
    const replyToEmail = (replyToField.match(emailRegex)    || [''])[0].toLowerCase();
    const returnPath   = (returnPathField.match(emailRegex) || [''])[0].toLowerCase();

    const fromDomain    = fromEmail    ? fromEmail.split('@')[1]    : '';
    const replyToDomain = replyToEmail ? replyToEmail.split('@')[1] : '';
    const returnDomain  = returnPath   ? returnPath.split('@')[1]   : '';

    const replyToPresent = !!replyToEmail;
    const domainMismatch = replyToPresent && fromDomain && replyToDomain && fromDomain !== replyToDomain;
    const emailMismatch  = replyToPresent && fromEmail  && replyToEmail  && fromEmail  !== replyToEmail;
    const returnPathMismatch = returnPath && fromDomain && returnDomain && fromDomain !== returnDomain;

    let riskLevel = 'safe';
    let reasons = [];

    if (domainMismatch) {
        riskLevel = 'high';
        reasons.push(`Reply-To domain (${replyToDomain}) differs from sender domain (${fromDomain})`);
    } else if (emailMismatch) {
        riskLevel = 'medium';
        reasons.push(`Reply-To address (${replyToEmail}) differs from sender (${fromEmail})`);
    }

    if (returnPathMismatch) {
        if (riskLevel === 'safe') riskLevel = 'medium';
        reasons.push(`Return-Path domain (${returnDomain}) differs from sender domain (${fromDomain})`);
    }

    return {
        isTrap: domainMismatch,
        replyToPresent,
        fromEmail,
        replyToEmail,
        returnPath,
        fromDomain,
        replyToDomain,
        domainMismatch,
        emailMismatch,
        returnPathMismatch,
        riskLevel,
        reasons
    };
}

// ============================================================
// FEATURE 3: EMAIL JOURNEY HOP EXTRACTOR
// ============================================================

/**
 * Formats a millisecond delay into a human-readable string.
 */
function formatHopDelay(ms) {
    if (ms < 0)       return '⚠ time anomaly';
    if (ms < 1000)    return `${ms}ms`;
    if (ms < 60000)   return `${Math.round(ms / 1000)}s`;
    if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
    return `${Math.round(ms / 3600000)}h`;
}

/**
 * Parses all Received headers into structured routing hops.
 * Orders them chronologically (oldest first = origin first).
 * @param {Object} parsedHeaders
 * @returns {Array<{from, by, ip, timestamp, delayFormatted, isSuspicious}>}
 */
function extractEmailJourney(parsedHeaders) {
    const receivedHeaders = getHeaderValues(parsedHeaders, 'received');
    if (!receivedHeaders || receivedHeaders.length === 0) return [];

    const hops = receivedHeaders.map(header => {
        const hop = { raw: header, from: '', by: '', ip: '', timestamp: '', timestampMs: null };

        // Extract 'from' hostname
        const fromMatch = header.match(/from\s+([^\s(]+)/i);
        if (fromMatch) hop.from = fromMatch[1].replace(/;$/, '').trim();

        // Extract 'by' hostname
        const byMatch = header.match(/by\s+([^\s(;]+)/i);
        if (byMatch) hop.by = byMatch[1].replace(/;$/, '').trim();

        // Extract IP address from brackets
        const ipMatch = header.match(/\[([\d.]+)\]/);
        if (ipMatch) hop.ip = ipMatch[1];

        // Extract timestamp from the part after the final ;
        const dateMatch = header.match(/;\s*(.+)$/);
        if (dateMatch) {
            const parsed = new Date(dateMatch[1].trim());
            if (!isNaN(parsed.getTime())) {
                hop.timestampMs = parsed.getTime();
                hop.timestamp = parsed.toUTCString();
            }
        }

        return hop;
    });

    // Received headers are newest-first — reverse to get origin-first
    hops.reverse();

    // Calculate delays and flag suspicious hops
    for (let i = 0; i < hops.length; i++) {
        if (i === 0) { hops[i].delayFormatted = 'Origin'; continue; }
        const prev = hops[i - 1];
        if (hops[i].timestampMs && prev.timestampMs) {
            const diff = hops[i].timestampMs - prev.timestampMs;
            hops[i].delayMs = diff;
            hops[i].delayFormatted = formatHopDelay(diff);
            hops[i].isSuspicious = diff < 0; // Negative delay = forged timestamp
        } else {
            hops[i].delayFormatted = 'unknown';
        }
    }

    return hops;
}

// Dual-environment export block for node testing environment compatibility
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        parseHeaders,
        getHeaderValues,
        getFirstHeaderValue,
        parseAuthResult,
        getSpfResult,
        getDkimResult,
        getDmarcResult,
        extractSenderIp,
        parseReceivedHeader,
        normalizeDomain,
        getBaseDomain,
        checkLookalike,
        analyzeUrl,
        scanUrls,
        decodeQuotedPrintable,
        detectTrackingPixels,
        detectReplyToTrap,
        extractEmailJourney
    };
}
