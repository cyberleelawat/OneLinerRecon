# 🕵️‍♂️ OneLinerRecon  

**OneLinerRecon** 
```
ek powerful recon automation tool hai jo bug bounty hunters aur penetration testers ke liye design kiya gaya hai.  
Is tool ka main purpose hai ek single click me **Reconnaissance Commands**, **Google Dorks**, aur **GitHub Dorks** generate karna — bas target domain daalo aur tool tumhe sab ready-made queries de dega!
```
🔗 **Live Demo:**
```
(https://cyberleelawat.github.io/OneLinerRecon/)
```
---

## 🚀 Features

### 🧠 1. One-Liner Recon Commands
```
- Subdomain Enumeration  
- ASN & IP Discovery  
- Live Host Discovery  
- URL Collection & Analysis  
- Passive Vulnerability Scanning  
```
Example:
```bash
subfinder -d target.com -silent | httpx -silent -mc 200
assetfinder target.com | sort -u
```
2. Google Dork Generator
Bas domain daalo aur tool tumhe ready-made dorks dega jaise:
```
site:target.com inurl:admin|login|portal|cpanel
site:target.com "password" | "token" | "secret"
site:target.com ext:sql|bak|zip|rar|7z|tar.gz
```
3. GitHub Dork Generator
GitHub par sensitive files dhoondhne ke liye one-liners:
```
"target.com" filename:.env
"target.com" filename:config
"target.com" password
"target.com" api_key
"target.com" "private key"
```
How to Use
Visit the live site:
👉 https://cyberleelawat.github.io/OneLinerRecon/
```
Enter your target domain (e.g., example.com)

Click Generate — and get:
Recon one-liners
Google dorks
GitHub dorks
Copy any command with Copy Command / Copy Dork button and paste directly into your terminal or search bar.
```
Categories Included
Category	Description
```
Subdomain Enumeration	Find hidden subdomains using subfinder, assetfinder, etc.
ASN & IP Discovery	Extract ASN, IP, and DNS info of target.
Live Host Discovery	Identify active hosts using httpx and nmap.
URL Collection	Collect URLs from gau, waybackurls, etc.
Passive Vulnerability Scanning	Use tools like whatweb to detect technologies.
Google Dorking	Generate powerful search queries for info gathering.
GitHub Dorking	Find leaked credentials or sensitive files in GitHub repos.
```
Developer Info
```
Created By: Virendra Kumar
Company: Cyber Leelawat
Website: https://cyberleelawat.github.io
```
Disclaimer
```
This project is built for educational and ethical hacking purposes only.
Do not use this tool on any target without proper authorization.
The author is not responsible for any misuse or illegal activity.
```
Support the Project

If you like this project:
```
Star this repo on GitHub
Share it with your hacker friends
Follow @CyberLeelawat for more tools and updates
