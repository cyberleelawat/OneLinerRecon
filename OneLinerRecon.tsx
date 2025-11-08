import React, { useState, useCallback, useMemo, useEffect } from 'react';

// --- CONSTANTS AND DATA DEFINITIONS ---
const NEON_GREEN = '#00FF7F';
const NEON_CYAN = '#00D1FF';
const APP_TITLE = "OneLinerRecon";
const OWNER = "Virendra Kumar";
const COMPANY = "Cyber Leelawat";
const LEGAL_DISCLAIMER = "⚠️ Only use on systems you own or have permission to test. OneLinerRecon is for educational and authorized security research only.";
const FIRA_CODE_FONT = "'Fira Code', 'JetBrains Mono', monospace";

// TypeScript Interfaces (defined as types for simplicity in a single file)
type Page = 'OneLinerCommand' | 'GoogleDorker' | 'GithubDorker';
type Impact = 'Non-intrusive' | 'Intrusive';

interface Command {
  id: string;
  command: string;
  description: string;
  impact: Impact;
}

interface CommandCategory {
  title: string;
  commands: Command[];
}

interface DorkCategory {
    title: string;
    dorks: string[];
}

// Emulating the content of templates/commands.json
const ONE_LINER_TEMPLATES: CommandCategory[] = [
    {
        title: 'Subdomain Enumeration',
        commands: [
            { id: 'sub1', command: 'assetfinder --subs-only <target> | tee subdomains.txt', description: 'Finds unique subdomains using assetfinder.', impact: 'Non-intrusive' },
            { id: 'sub2', command: 'subfinder -d <target> -silent | tee subdomains.txt', description: 'Discovers subdomains using Subfinder (multiple sources).', impact: 'Non-intrusive' },
            { id: 'sub3', command: 'amass enum -d <target> -o subdomains.txt', description: 'Advanced reconnaissance with Amass.', impact: 'Non-intrusive' },
            { id: 'sub4', command: 'curl -s https://crt.sh/?q=%25.<target> | grep -P -o "[\w\d.-]+\\.<target>" | sort -u | tee subdomains.txt', description: 'Extracts subdomains from crt.sh certificate transparency logs.', impact: 'Non-intrusive' },
        ],
    },
    {
        title: 'ASN & IP Discovery',
        commands: [
            { id: 'ip1', command: 'whois <target> | grep -E "NetRange|CIDR|ASN"', description: 'Performs basic WHOIS lookup for network details.', impact: 'Non-intrusive' },
            { id: 'ip2', command: 'dig +short <target> | xargs -I {} sh -c "echo {} && whois -h whois.radb.net {} | grep origin"', description: 'Gets IP and looks up the ASN using RADb.', impact: 'Non-intrusive' },
            { id: 'ip3', command: 'naabu -host <target> -silent | tee live_hosts.txt', description: 'Fast port scan to identify live hosts and open ports (pre-cursor to IP discovery).', impact: 'Intrusive' },
        ],
    },
    {
        title: 'Live Host Discovery',
        commands: [
            { id: 'live1', command: 'cat subdomains.txt | httprobe | tee live_targets.txt', description: 'Checks for active HTTP/S servers from a list of subdomains.', impact: 'Intrusive' },
            { id: 'live2', command: 'cat subdomains.txt | naabu -p 80,443,8000,8080,8443 -silent | httpx -silent | tee live_targets.txt', description: 'Combines Naabu (port check) and Httpx (protocol detection).', impact: 'Intrusive' },
            { id: 'live3', command: 'nmap -iL subdomains.txt -sn -PE -n -oG live_nmap.txt', description: 'Performs a fast ping scan to find live hosts (requires nmap).', impact: 'Intrusive' },
        ],
    },
    {
        title: 'URL Collection & Analysis',
        commands: [
            { id: 'url1', command: 'cat subdomains.txt | gau | tee urls.txt', description: 'Gathers URLs from Wayback Machine, CommonCrawl, etc. (Go-tool).', impact: 'Non-intrusive' },
            { id: 'url2', command: 'cat subdomains.txt | waybackurls | tee urls.txt', description: 'Fetches historical URLs from the Wayback Machine.', impact: 'Non-intrusive' },
            { id: 'url3', command: 'cat urls.txt | grep "=" | uro -o params.txt', description: 'Filters collected URLs to extract unique ones containing query parameters.', impact: 'Non-intrusive' },
        ],
    },
    {
        title: 'Vulnerability Scanning',
        commands: [
            { id: 'vuln1', command: 'nuclei -l live_targets.txt -t cves/ -o nuclei_cve_results.txt', description: 'Scans live hosts for known CVEs using Nuclei templates.', impact: 'Intrusive' },
            { id: 'vuln2', command: 'nmap -iL live_targets.txt -p- -sV --script vuln -oA nmap_vuln_scan', description: 'Aggressive nmap scan for common vulnerabilities and service versions.', impact: 'Intrusive' },
        ],
    },
    {
        title: 'Sensitive File Discovery',
        commands: [
            { id: 'sens1', command: 'ffuf -w wordlist/files/big.txt -u https://<target>/FUZZ -mc 200,301,403', description: 'Fuzzes common sensitive files and directories.', impact: 'Intrusive' },
            { id: 'sens2', command: 'curl -s https://<target>/.git/config', description: 'Direct check for exposed Git configuration file.', impact: 'Non-intrusive' },
            { id: 'sens3', command: 'searchsploit --nmap nmap_results.xml --html', description: 'Uses Searchsploit to check for known exploits based on Nmap XML output (requires Nmap and Searchsploit).', impact: 'Non-intrusive' },
        ],
    },
    {
        title: 'Hidden Parameter Discovery',
        commands: [
            { id: 'param1', command: 'cat urls.txt | grep "=" | xargs -I {} python3 ParamSpider.py -d "{}" -o params.txt', description: 'Extracts parameters using ParamSpider.', impact: 'Non-intrusive' },
            { id: 'param2', command: 'ffuf -w Seclists/Discovery/Web-Content/burp-parameter-names.txt -u https://<target>/?FUZZ=1', description: 'Fuzzes for hidden parameters in the main URL.', impact: 'Intrusive' },
        ],
    },
    {
        title: 'Directory & File Bruteforcing',
        commands: [
            { id: 'dir1', command: 'gobuster dir -u https://<target> -w /usr/share/wordlists/dirb/common.txt -t 50', description: 'Bruteforces common directories and files with Gobuster.', impact: 'Intrusive' },
            { id: 'dir2', command: 'ffuf -w /usr/share/wordlists/dirb/big.txt -u https://<target>/FUZZ -mc all -recursion', description: 'Fast, recursive directory bruteforcing with FFUF.', impact: 'Intrusive' },
        ],
    },
    {
        title: 'WordPress Security Testing',
        commands: [
            { id: 'wp1', command: 'wpscan --url https://<target> --enumerate p --api-token <TOKEN>', description: 'Scans for vulnerable plugins (requires API token).', impact: 'Intrusive' },
            { id: 'wp2', command: 'wpscan --url https://<target> --enumerate u', description: 'Enumerates WordPress users.', impact: 'Intrusive' },
            { id: 'wp3', command: 'curl -s https://<target>/wp-admin/install.php', description: 'Checks if the installation script is still accessible.', impact: 'Non-intrusive' },
        ],
    },
    {
        title: 'CORS Testing',
        commands: [
            { id: 'cors1', command: 'cors-tester -u https://<target> -v', description: 'Tests common CORS misconfigurations (requires specialized tool).', impact: 'Intrusive' },
            { id: 'cors2', command: 'curl -s -I -H "Origin: evil.com" https://<target>', description: 'Manual check for * or reflected Origin header.', impact: 'Non-intrusive' },
        ],
    },
    {
        title: 'Subdomain Takeover',
        commands: [
            { id: 'takeover1', command: 'subzy run --target <target> --hide_failed', description: 'Checks for common subdomain takeover vulnerabilities.', impact: 'Non-intrusive' },
            { id: 'takeover2', command: 'nuclei -l subdomains.txt -t sub/takeovers/', description: 'Checks all subdomains for takeover templates using Nuclei.', impact: 'Non-intrusive' },
        ],
    },
    {
        title: 'Git Repository Disclosure',
        commands: [
            { id: 'git1', command: 'git-dumper https://<target>/.git/ output_dir', description: 'Attempts to download an exposed .git repository (requires git-dumper).', impact: 'Intrusive' },
            { id: 'git2', command: 'curl -s https://<target>/.git/HEAD', description: 'Quick check if the .git directory is accessible.', impact: 'Non-intrusive' },
        ],
    },
    {
        title: 'SSRF Testing',
        commands: [
            { id: 'ssrf1', command: 'nuclei -l urls.txt -t ssrf/ -o ssrf_results.txt', description: 'Tests collected URLs for SSRF using Nuclei templates.', impact: 'Intrusive' },
            { id: 'ssrf2', command: 'ffuf -w SecLists/Payloads/SSRF/ssrf-payloads.txt -u https://<target>/api/v1?url=FUZZ', description: 'Fuzzes an identified URL parameter with common SSRF payloads.', impact: 'Intrusive' },
        ],
    },
    {
        title: 'Open Redirect Testing',
        commands: [
            { id: 'openr1', command: 'nuclei -l urls.txt -t redirect/ -o redirect_results.txt', description: 'Tests collected URLs for Open Redirects using Nuclei.', impact: 'Intrusive' },
            { id: 'openr2', command: 'cat urls.txt | grep "url=" | qsreplace "https://evil.com"', description: 'Identifies and modifies URL parameters to test for open redirects.', impact: 'Non-intrusive' },
        ],
    },
    {
        title: 'LFI Testing',
        commands: [
            { id: 'lfi1', command: 'nuclei -l urls.txt -t lfi/ -o lfi_results.txt', description: 'Tests collected URLs for LFI using Nuclei templates.', impact: 'Intrusive' },
            { id: 'lfi2', command: 'ffuf -w SecLists/Fuzzing/LFI/LFI-etc-passwd.txt -u https://<target>/index.php?file=FUZZ', description: 'Fuzzes a file parameter with common LFI payloads.', impact: 'Intrusive' },
        ],
    },
    {
        title: 'Additional Tools',
        commands: [
            { id: 'add1', command: 'dnsx -l subdomains.txt -resp -silent | tee dns_records.txt', description: 'Performs DNS resolution on all subdomains and records response.', impact: 'Non-intrusive' },
            { id: 'add2', command: 'katana -list live_targets.txt -silent -o crawl_results.txt', description: 'Deep crawling of all live targets (Go-tool).', impact: 'Intrusive' },
            { id: 'add3', command: 'dirsearch -u https://<target> -e php,html,js', description: 'Searches for common extensions using Dirsearch.', impact: 'Intrusive' },
        ],
    },
];

const GOOGLE_DORK_TEMPLATES: DorkCategory[] = [
    {
        title: 'Sensitive Files & Logs',
        dorks: [
            'site:<target> ext:env OR "DB_PASSWORD" OR "api_key"',
            'site:<target> intext:"index of /backup"',
            'site:<target> inurl:wp-config.txt OR inurl:web.config',
            'site:<target> filetype:log OR filetype:sql OR filetype:bak',
        ],
    },
    {
        title: 'Login/Admin Interfaces',
        dorks: [
            'site:<target> inurl:admin OR inurl:login OR intitle:"dashboard"',
            'site:<target> intext:"Powered by WordPress admin"',
            'site:<target> intitle:"phpMyAdmin"',
        ],
    },
    {
        title: 'Exposed Directories',
        dorks: [
            'site:<target> intitle:"index of" "parent directory"',
            'site:<target> intitle:"index of" | inurl:ftp',
        ],
    },
    {
        title: 'Public Docs & PDFs',
        dorks: [
            'site:<target> filetype:pdf confidential OR internal',
            'site:<target> filetype:xlsx "user list"',
        ],
    },
    {
        title: 'Error & Debug Messages',
        dorks: [
            'site:<target> intext:"A PHP Error was encountered"',
            'site:<target> intext:"Stack trace" OR "at sun.reflect.NativeMethodAccessorImpl"',
        ],
    },
];

const GITHUB_DORK_TEMPLATES: DorkCategory[] = [
    {
        title: 'API Keys & Secrets',
        dorks: [
            'org:<target> "aws_secret_access_key" in:file',
            'org:<target> "firebaseConfig" in:file',
            'org:<target> "password" filename:.env',
            'org:<target> "private key" extension:pem',
        ],
    },
    {
        title: 'Configuration Files',
        dorks: [
            'org:<target> filename:config extension:yml OR extension:xml',
            'org:<target> filename:.bashrc OR filename:.zshrc',
            'org:<target> "internal_users" extension:json',
        ],
    },
    {
        title: 'Code Snippets & Emails',
        dorks: [
            'org:<target> "todo:" in:file',
            'org:<target> "@<target>" in:file', // Example: '@example.com'
            'org:<target> "Hardcoded IP" in:file',
        ],
    },
];

// --- UTILITY FUNCTIONS ---

/** Copies text to clipboard and shows a temporary notification. */
const copyToClipboard = (text: string, setToast: (msg: string) => void) => {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            setToast('Copied to clipboard!');
        }).catch(err => {
            console.error('Could not copy text: ', err);
            setToast('Failed to copy. See console.');
        });
    } else {
        // Fallback for older browsers (document.execCommand is deprecated but more widely supported in some limited environments like certain iframes)
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed'; // Prevents scrolling to bottom
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            setToast('Copied to clipboard!');
        } catch (err) {
            setToast('Failed to copy. See console.');
        }
        document.body.removeChild(textarea);
    }
};

/**
 * Replaces the <target> placeholder in a command string.
 * @param command - The command string.
 * @param target - The user-provided target.
 * @returns The command with the target substituted.
 */
const replaceTarget = (command: string, target: string): string => {
    if (!target) return command;
    // Replace <target> case-insensitively globally.
    return command.replace(/<target>/gi, target.trim());
};


// --- UI COMPONENTS ---

/** Toast Notification Component */
const Toast: React.FC<{ message: string; visible: boolean; }> = ({ message, visible }) => (
    <div
        className={`fixed bottom-5 right-5 z-50 px-4 py-2 rounded-lg text-sm transition-all duration-300 shadow-xl
            ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}
            bg-gray-800 text-[${NEON_GREEN}] border border-[${NEON_GREEN}] shadow-[0_0_15px_rgba(0,255,127,0.5)]`}
        style={{ fontFamily: FIRA_CODE_FONT }}
    >
        {message}
    </div>
);

/** Nav Bar Component */
const NavBar: React.FC<{ currentPage: Page, setCurrentPage: (page: Page) => void }> = ({ currentPage, setCurrentPage }) => {
    const navItems: { label: string; page: Page }[] = [
        { label: 'OneLiner Command', page: 'OneLinerCommand' },
        { label: 'Google Dorker', page: 'GoogleDorker' },
        { label: 'Github Dorker', page: 'GithubDorker' },
    ];

    const getNavItemClass = (page: Page) =>
        currentPage === page
            ? `border-b-2 border-[${NEON_GREEN}] text-[${NEON_GREEN}] shadow-[0_2px_10px_rgba(0,255,127,0.7)]`
            : `text-gray-400 hover:text-[${NEON_CYAN}] hover:border-b-2 hover:border-[${NEON_CYAN}] transition duration-200`;

    return (
        <header className="fixed top-0 left-0 w-full z-40 bg-gray-900/90 backdrop-blur-sm shadow-lg shadow-black/50">
            <div className="container mx-auto px-4 py-3 flex flex-col md:flex-row justify-between items-center">
                <div className="text-left mb-2 md:mb-0">
                    <h1 className={`text-2xl font-bold text-[${NEON_GREEN}]`} style={{ fontFamily: FIRA_CODE_FONT }}>
                        {APP_TITLE}
                    </h1>
                    <p className={`text-xs text-gray-500`} style={{ fontFamily: FIRA_CODE_FONT }}>
                        by {OWNER} &middot; {COMPANY}
                    </p>
                </div>
                <nav className="flex space-x-4">
                    {navItems.map(item => (
                        <button
                            key={item.page}
                            onClick={() => setCurrentPage(item.page)}
                            className={`p-2 uppercase text-sm font-medium tracking-wider ${getNavItemClass(item.page)}`}
                            style={{ fontFamily: FIRA_CODE_FONT }}
                        >
                            {item.label}
                        </button>
                    ))}
                </nav>
            </div>
        </header>
    );
};

/** Reusable Dork/Command Display Card */
const DorkCard: React.FC<{
    title: string;
    items: string[];
    target: string;
    setToast: (msg: string) => void;
    page: Page;
}> = ({ title, items, target, setToast, page }) => {

    const disclaimer = page === 'GoogleDorker'
        ? "Disclaimer: Dorks are searches, not attacks. Use within legal scope."
        : "Ethical Note: GitHub Dorking can reveal sensitive data. Use responsibly and authorized scopes only.";

    return (
        <div className={`
            bg-gray-800/50 backdrop-blur-md rounded-xl p-6 mb-8
            border border-[${NEON_CYAN}] shadow-lg
            shadow-[0_0_20px_rgba(0,209,255,0.2)] transition duration-300 hover:shadow-[0_0_30px_rgba(0,209,255,0.4)]
            w-full
        `}>
            <h3 className={`text-xl font-semibold mb-4 text-[${NEON_CYAN}] border-b border-[${NEON_CYAN}]/30 pb-2`} style={{ fontFamily: FIRA_CODE_FONT }}>
                {title}
            </h3>
            <ul className="space-y-4">
                {items.map((dork, index) => {
                    const finalDork = replaceTarget(dork, target);
                    const isGoogle = page === 'GoogleDorker';
                    const link = isGoogle
                        ? `https://www.google.com/search?q=${encodeURIComponent(finalDork)}`
                        : `https://github.com/search?q=${encodeURIComponent(finalDork)}&type=Code`;

                    return (
                        <li key={index} className="flex flex-col sm:flex-row items-start sm:items-center space-y-2 sm:space-y-0 sm:space-x-4">
                            <span
                                className="flex-1 text-sm p-2 rounded bg-black/70 border border-gray-700/50 text-gray-200 break-all"
                                style={{ fontFamily: FIRA_CODE_FONT }}
                            >
                                {finalDork}
                            </span>
                            <div className="flex space-x-2">
                                <button
                                    onClick={() => copyToClipboard(finalDork, setToast)}
                                    className={`p-2 rounded-lg text-xs bg-gray-900 text-[${NEON_GREEN}] border border-[${NEON_GREEN}]/70 hover:bg-[${NEON_GREEN}] hover:text-gray-900 transition duration-150 whitespace-nowrap`}
                                    title="Copy Query"
                                >
                                    Copy
                                </button>
                                <a
                                    href={link}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className={`p-2 rounded-lg text-xs bg-gray-900 text-[${NEON_CYAN}] border border-[${NEON_CYAN}]/70 hover:bg-[${NEON_CYAN}] hover:text-gray-900 transition duration-150 whitespace-nowrap`}
                                    title={`Open in ${isGoogle ? 'Google' : 'GitHub'}`}
                                >
                                    {isGoogle ? 'Search Google' : 'Search GitHub'}
                                </a>
                            </div>
                        </li>
                    );
                })}
            </ul>
            <p className="mt-4 text-xs text-red-400/80 italic" style={{ fontFamily: FIRA_CODE_FONT }}>
                {disclaimer}
            </p>
        </div>
    );
};

/** Command Card with Checkbox and Impact Label */
const CommandCard: React.FC<{
    category: CommandCategory;
    target: string;
    setToast: (msg: string) => void;
    selectedCommands: Command[];
    toggleCommand: (cmd: Command) => void;
}> = ({ category, target, setToast, selectedCommands, toggleCommand }) => {
    return (
        <div className={`
            bg-gray-800/50 backdrop-blur-md rounded-xl p-6 mb-8
            border border-[${NEON_GREEN}] shadow-lg
            shadow-[0_0_20px_rgba(0,255,127,0.2)] transition duration-300 hover:shadow-[0_0_30px_rgba(0,255,127,0.4)]
            w-full
        `}>
            <h3 className={`text-xl font-semibold mb-4 text-[${NEON_GREEN}] border-b border-[${NEON_GREEN}]/30 pb-2`} style={{ fontFamily: FIRA_CODE_FONT }}>
                {category.title}
            </h3>
            <div className="space-y-5">
                {category.commands.map(cmd => {
                    const finalCommand = replaceTarget(cmd.command, target);
                    const isSelected = selectedCommands.some(s => s.id === cmd.id);
                    const impactClass = cmd.impact === 'Intrusive'
                        ? 'bg-red-900/50 text-red-300 border-red-700'
                        : `bg-green-900/50 text-green-300 border-[${NEON_GREEN}]`;

                    return (
                        <div key={cmd.id} className="relative p-3 rounded-lg border border-gray-700/50 hover:bg-gray-700/30 transition duration-150">
                            <div className="flex justify-between items-start space-x-3 mb-2">
                                <span
                                    className={`text-xs px-2 py-1 rounded-full ${impactClass} border font-medium`}
                                    style={{ fontFamily: FIRA_CODE_FONT }}
                                >
                                    {cmd.impact}
                                </span>
                                <div className="flex items-center space-x-2">
                                    <label
                                        className={`flex items-center cursor-pointer transition duration-150 p-1 rounded-md ${isSelected ? `bg-[${NEON_GREEN}]/20` : 'hover:bg-gray-700'}`}
                                        title="Add to Preview"
                                    >
                                        <input
                                            type="checkbox"
                                            checked={isSelected}
                                            onChange={() => toggleCommand(cmd)}
                                            className={`form-checkbox h-4 w-4 rounded transition duration-150 cursor-pointer text-[${NEON_GREEN}] bg-gray-900 border-gray-600 focus:ring focus:ring-[${NEON_GREEN}]/50`}
                                        />
                                    </label>
                                    <button
                                        onClick={() => copyToClipboard(finalCommand, setToast)}
                                        className={`p-1.5 rounded-lg text-xs bg-gray-900 text-[${NEON_GREEN}] border border-[${NEON_GREEN}]/70 hover:bg-[${NEON_GREEN}] hover:text-gray-900 transition duration-150`}
                                        title="Copy Command"
                                    >
                                        {/* Lucide icon: ClipboardCopy */}
                                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                                    </button>
                                </div>
                            </div>
                            <code className={`text-sm text-gray-200 break-all block`} style={{ fontFamily: FIRA_CODE_FONT }}>
                                {finalCommand}
                            </code>
                            <p className="text-xs text-gray-400 mt-2 italic border-t border-gray-700/50 pt-2">
                                {cmd.description}
                            </p>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

/** Command Preview Area (for OneLiner Command) */
const CommandPreview: React.FC<{
    target: string;
    selectedCommands: Command[];
    setToast: (msg: string) => void;
    clearSelection: () => void;
}> = ({ target, selectedCommands, setToast, clearSelection }) => {
    const combinedScript = useMemo(() => {
        if (!target) {
            return "# Enter a target domain above to generate the script...\n";
        }
        if (selectedCommands.length === 0) {
            return `# No commands selected yet. Check the boxes below to build your script for ${target}!\n`;
        }

        const header = `#!/bin/bash\n# OneLinerRecon Script for Target: ${target}\n# Generated on: ${new Date().toLocaleString()}\n\n`;

        const scriptContent = selectedCommands.map(cmd => {
            const finalCommand = replaceTarget(cmd.command, target);
            return `# [Impact: ${cmd.impact}] ${cmd.description}\n${finalCommand}\n`;
        }).join('\n');

        return header + scriptContent;
    }, [selectedCommands, target]);

    const handleDownload = useCallback(() => {
        const filename = `recon-${target || 'target'}.sh`;
        const blob = new Blob([combinedScript], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setToast(`Downloaded ${filename}!`);
    }, [combinedScript, target, setToast]);

    return (
        <div className={`
            sticky top-20 bg-gray-900/90 backdrop-blur-sm rounded-xl p-4 md:p-6
            border border-[${NEON_CYAN}] shadow-2xl shadow-black/80
            transition duration-300 hover:shadow-[0_0_30px_rgba(0,209,255,0.4)]
        `}>
            <h2 className={`text-xl font-bold mb-3 text-[${NEON_CYAN}]`} style={{ fontFamily: FIRA_CODE_FONT }}>
                Command Preview
            </h2>
            <div className="flex space-x-2 mb-4">
                <button
                    onClick={() => copyToClipboard(combinedScript, setToast)}
                    disabled={selectedCommands.length === 0}
                    className={`flex-1 p-2 rounded-lg text-sm transition duration-150 ${selectedCommands.length > 0
                        ? `bg-[${NEON_GREEN}] text-gray-900 hover:bg-opacity-80`
                        : 'bg-gray-700 text-gray-400 cursor-not-allowed'
                        }`}
                >
                    Copy Script
                </button>
                <button
                    onClick={handleDownload}
                    disabled={selectedCommands.length === 0 || !target}
                    className={`flex-1 p-2 rounded-lg text-sm transition duration-150 ${selectedCommands.length > 0 && target
                        ? `bg-[${NEON_CYAN}] text-gray-900 hover:bg-opacity-80`
                        : 'bg-gray-700 text-gray-400 cursor-not-allowed'
                        }`}
                >
                    Download {target ? `recon-${target}.sh` : 'Script'}
                </button>
                <button
                    onClick={clearSelection}
                    disabled={selectedCommands.length === 0}
                    className={`p-2 rounded-lg text-sm transition duration-150 ${selectedCommands.length > 0
                        ? 'bg-gray-700 text-white hover:bg-gray-600'
                        : 'bg-gray-800 text-gray-500 cursor-not-allowed'
                        }`}
                    title="Clear Selection"
                >
                    {/* Lucide icon: Trash2 */}
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"></path><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                </button>
            </div>
            <pre
                className="overflow-auto max-h-[300px] p-3 rounded bg-black border border-gray-700 text-gray-100 whitespace-pre-wrap"
                style={{ fontFamily: FIRA_CODE_FONT }}
            >
                {combinedScript}
            </pre>
        </div>
    );
};

// --- PAGE COMPONENTS ---

/** Section 1: OneLiner Command Page */
const OneLinerPage: React.FC<{ target: string; setToast: (msg: string) => void }> = ({ target, setToast }) => {
    const [selectedCommands, setSelectedCommands] = useState<Command[]>([]);

    const toggleCommand = useCallback((cmd: Command) => {
        setSelectedCommands(prev =>
            prev.some(s => s.id === cmd.id)
                ? prev.filter(s => s.id !== cmd.id)
                : [...prev, cmd]
        );
    }, []);

    const clearSelection = useCallback(() => setSelectedCommands([]), []);

    // Clear selection when target changes to prevent mistakes
    useEffect(() => {
        clearSelection();
    }, [target]); // eslint-disable-line react-hooks/exhaustive-deps

    return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Command Preview (Column 1 or Full Width on mobile) */}
            <div className="lg:col-span-1 order-1 lg:order-2">
                <CommandPreview
                    target={target}
                    selectedCommands={selectedCommands}
                    setToast={setToast}
                    clearSelection={clearSelection}
                />
            </div>

            {/* Command Cards (Columns 2 & 3 or Full Width on mobile) */}
            <div className="lg:col-span-2 order-2 lg:order-1">
                {ONE_LINER_TEMPLATES.map(category => (
                    <CommandCard
                        key={category.title}
                        category={category}
                        target={target}
                        setToast={setToast}
                        selectedCommands={selectedCommands}
                        toggleCommand={toggleCommand}
                    />
                ))}
            </div>
        </div>
    );
};

/** Section 2: Google Dorker Page */
const GoogleDorkerPage: React.FC<{ target: string; setToast: (msg: string) => void }> = ({ target, setToast }) => (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        {GOOGLE_DORK_TEMPLATES.map(category => (
            <DorkCard
                key={category.title}
                title={category.title}
                items={category.dorks}
                target={target}
                setToast={setToast}
                page="GoogleDorker"
            />
        ))}
    </div>
);

/** Section 3: Github Dorker Page */
const GithubDorkerPage: React.FC<{ target: string; setToast: (msg: string) => void }> = ({ target, setToast }) => (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        {GITHUB_DORK_TEMPLATES.map(category => (
            <DorkCard
                key={category.title}
                title={category.title}
                items={category.dorks}
                target={target}
                setToast={setToast}
                page="GithubDorker"
            />
        ))}
    </div>
);


// --- MAIN APP COMPONENT ---

const App: React.FC = () => {
    const [currentPage, setCurrentPage] = useState<Page>('OneLinerCommand');
    const [target, setTarget] = useState<string>('example.com');
    const [toastMessage, setToastMessage] = useState<string>('');
    const [isToastVisible, setIsToastVisible] = useState<boolean>(false);

    // Toast logic
    const setToast = useCallback((msg: string) => {
        setToastMessage(msg);
        setIsToastVisible(true);
        const timer = setTimeout(() => setIsToastVisible(false), 3000);
        return () => clearTimeout(timer);
    }, []);

    // Dynamic render of current page content
    const renderPage = useMemo(() => {
        switch (currentPage) {
            case 'OneLinerCommand':
                return <OneLinerPage target={target} setToast={setToast} />;
            case 'GoogleDorker':
                return <GoogleDorkerPage target={target} setToast={setToast} />;
            case 'GithubDorker':
                return <GithubDorkerPage target={target} setToast={setToast} />;
            default:
                return null;
        }
    }, [currentPage, target, setToast]);

    // Tailwind Custom Colors/Font Style (using arbitrary values for easy definition)
    const customStyles = {
        '--neon-green': NEON_GREEN,
        '--neon-cyan': NEON_CYAN,
        '--fira-code': FIRA_CODE_FONT,
    };

    return (
        <div
            className="min-h-screen bg-gray-950 text-white"
            style={customStyles}
        >
            <NavBar currentPage={currentPage} setCurrentPage={setCurrentPage} />

            <main className="container mx-auto px-4 pt-28 pb-10">

                {/* Legal Disclaimer Banner */}
                <div className={`
                    p-3 mb-8 rounded-lg text-center font-bold text-sm
                    bg-red-900/40 text-red-300 border border-red-700
                    shadow-md shadow-red-900/50
                `} style={{ fontFamily: FIRA_CODE_FONT }}>
                    {LEGAL_DISCLAIMER}
                </div>

                {/* Target Input Area */}
                <div className={`
                    mb-10 p-6 rounded-xl bg-gray-900/70 backdrop-blur-md
                    border border-[${NEON_GREEN}] shadow-xl shadow-[0_0_20px_rgba(0,255,127,0.2)]
                    flex flex-col md:flex-row items-center space-y-4 md:space-y-0 md:space-x-4
                `}>
                    <label className={`text-lg text-[${NEON_GREEN}] font-medium shrink-0`} style={{ fontFamily: FIRA_CODE_FONT }}>
                        Target Domain:
                    </label>
                    <input
                        type="text"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        placeholder="e.g., example.com (no https://)"
                        className={`
                            flex-grow w-full md:w-auto p-3 rounded-lg
                            bg-black/70 border border-gray-700
                            text-white text-lg placeholder-gray-500
                            focus:outline-none focus:border-[${NEON_CYAN}] focus:shadow-[0_0_10px_rgba(0,209,255,0.5)]
                        `}
                        style={{ fontFamily: FIRA_CODE_FONT }}
                    />
                </div>

                {/* Page Content */}
                {renderPage}
            </main>

            {/* Footer */}
            <footer className={`
                w-full bg-gray-900/90 backdrop-blur-sm p-4 text-center text-xs text-gray-500
                border-t border-gray-800 shadow-[0_0_20px_rgba(0,0,0,0.5)]
            `} style={{ fontFamily: FIRA_CODE_FONT }}>
                &copy; 2025 {COMPANY} | Built by {OWNER}
            </footer>

            <Toast message={toastMessage} visible={isToastVisible} />
        </div>
    );
};

export default App;
// The main component is named App and is the default export.