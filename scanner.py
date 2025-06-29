import re

def scan_page(soup, base_url):
    print(f"[Scan] {base_url}")

    suspicious = []

    for script in soup.find_all('script'):
        code = script.string or ''
        if 'eval(' in code or 'unescape(' in code or re.search(r'[a-zA-Z]{20,}', code):
            suspicious.append("Obfuscated JavaScript")

    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.startswith('on'):
                suspicious.append(f"Inline JS event: {attr}")

    for iframe in soup.find_all('iframe'):
        if 'display:none' in str(iframe.get('style', '')):
            suspicious.append("Hidden iframe")

    if suspicious:
        print(f"  🚨 Suspicious content:")
        for s in suspicious:
            print(f"    ⚠️ {s}")
    else:
        print(f"  ✅ No major red flags found.")

    return suspicious
