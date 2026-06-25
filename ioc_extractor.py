import re

def extract_urls(text):
    """Extracts unique URLs from the given text."""
    if not text:
        return []
    # Regex to match basic http/https URLs
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    urls = url_pattern.findall(text)
    
    # Normalize 'www.' to 'http://www.' for consistent processing if needed
    normalized_urls = []
    for u in urls:
        if u.startswith('www.'):
            normalized_urls.append('http://' + u)
        else:
            normalized_urls.append(u)
            
    return list(set(normalized_urls))
