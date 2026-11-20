// PhishGuard AI - Client-Side DOM Content & Form Heuristic Inspector
(function() {
    // Only analyze top-level window
    if (window.top !== window.self) return;

    function inspectDOM() {
        const hostname = window.location.hostname.toLowerCase();
        const pathname = window.location.pathname.toLowerCase();
        const pageText = document.body ? document.body.innerText.toLowerCase() : "";

        const findings = [];
        let domRisk = 0;

        // 1. Password Field Analysis
        const passwordInputs = document.querySelectorAll('input[type="password"]');
        const hasPasswordField = passwordInputs.length > 0;

        // 2. Sensitive Form / Brand Spoofing Analysis
        const targetBrands = [
            { name: "Google", domains: ["google.com", "accounts.google.com"], keywords: ["sign in with google", "continue with google", "google account"] },
            { name: "Facebook", domains: ["facebook.com", "m.facebook.com"], keywords: ["log into facebook", "connect with facebook", "facebook login"] },
            { name: "Microsoft", domains: ["microsoft.com", "live.com", "login.microsoftonline.com"], keywords: ["sign in to your account", "microsoft account", "office 365"] },
            { name: "PayPal", domains: ["paypal.com"], keywords: ["log in to your paypal", "pay with paypal"] },
            { name: "Apple", domains: ["apple.com", "idmsa.apple.com"], keywords: ["sign in with apple", "apple id"] }
        ];

        let spoofedBrand = null;
        for (const brand of targetBrands) {
            const isOfficialDomain = brand.domains.some(d => hostname === d || hostname.endsWith('.' + d));
            if (!isOfficialDomain) {
                // Check if page claims to be this brand or has obvious branding phrases
                const matchesKeyword = brand.keywords.some(kw => pageText.includes(kw));
                // Also check images/alt tags for logo spoofing
                const hasLogoAlt = Array.from(document.querySelectorAll('img')).some(img => {
                    const alt = (img.alt || "").toLowerCase();
                    const src = (img.src || "").toLowerCase();
                    return alt.includes(brand.name.toLowerCase() + " logo") || src.includes(brand.name.toLowerCase() + "_logo");
                });

                if (matchesKeyword || hasLogoAlt) {
                    spoofedBrand = brand.name;
                    findings.push(`Suspected fake ${brand.name} login interface on unauthorized domain (${hostname})`);
                    domRisk += 45;
                    break;
                }
            }
        }

        // 3. Insecure Password Transmission (Password form posting to HTTP or external domain)
        if (hasPasswordField) {
            findings.push("Contains sensitive password input field");
            domRisk += 15;

            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                const action = (form.getAttribute('action') || "").trim().toLowerCase();
                if (action.startsWith('http://')) {
                    findings.push("Insecure Form: Password transmitted over unencrypted HTTP");
                    domRisk += 30;
                } else if (action.startsWith('//') || (action.startsWith('https://') && !action.includes(hostname))) {
                    findings.push(`External Form Action: Form submits credentials off-site (${action.substring(0, 35)}...)`);
                    domRisk += 25;
                }
            });
        }

        // 4. Hidden iframes or deceptive overlays
        const iframes = document.querySelectorAll('iframe');
        if (iframes.length > 5) {
            findings.push(`High number of embedded iframes detected (${iframes.length})`);
            domRisk += 10;
        }

        // Send inspection findings back to background service worker
        if (findings.length > 0) {
            chrome.runtime.sendMessage({
                action: "dom_inspection_result",
                url: window.location.href,
                domRisk: Math.min(100, domRisk),
                findings: findings,
                hasPasswordField: hasPasswordField,
                spoofedBrand: spoofedBrand
            });
        }
    }

    // Run inspection after page loads or DOM changes
    if (document.readyState === "complete" || document.readyState === "interactive") {
        setTimeout(inspectDOM, 800);
    } else {
        window.addEventListener("DOMContentLoaded", () => setTimeout(inspectDOM, 800));
    }
})();
