import os
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from utils.ioc_extractor import extract_urls
from utils.vt_lookup import check_url
from utils.risk_engine import calculate_risk
from utils.content_analyzer import analyze_content

load_dotenv()
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    text_content = ""
    
    # Handle file upload
    if 'email_file' in request.files:
        file = request.files['email_file']
        if file.filename != '':
            text_content += file.read().decode('utf-8', errors='ignore') + "\n"
            
    # Handle text input
    if 'email_text' in request.form:
        text_content += request.form['email_text'] + "\n"
        
    if not text_content.strip():
        return jsonify({"error": "No input provided. Please upload a file or paste text."}), 400
        
    # 1. Content Analysis
    content_risk_data = analyze_content(text_content)
        
    # 2. URL Extraction and Analysis
    urls = extract_urls(text_content)
    
    url_results = []
    highest_url_risk_level = 0
    risk_mapping = {"Clean": 0, "Unrated": 0, "Unknown": 0, "Suspicious": 1, "High": 2, "Critical": 3}
    overall_url_risk = "Clean"
    
    for url in urls:
        # Limit to 5 URLs to prevent rate limiting issues with VT API
        if len(url_results) >= 5:
            break
            
        vt_data = check_url(url)
        risk_data = calculate_risk(vt_data)
        
        url_results.append({
            "url": url,
            "vt_data": vt_data,
            "risk": risk_data
        })
        
        current_risk_level = risk_mapping.get(risk_data["risk"], 0)
        if current_risk_level > highest_url_risk_level:
            highest_url_risk_level = current_risk_level
            overall_url_risk = risk_data["risk"]
            
    # 3. Overall Verdict
    content_risk_level = risk_mapping.get(content_risk_data["risk"], 0)
    
    if highest_url_risk_level >= content_risk_level:
        overall_risk = overall_url_risk
    else:
        overall_risk = content_risk_data["risk"]
        
    return jsonify({
        "status": "success",
        "message": "Analysis complete.",
        "content_analysis": content_risk_data,
        "url_results": url_results,
        "overall_risk": overall_risk
    })

if __name__ == '__main__':
    app.run(debug=True)
