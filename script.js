document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('analyze-form');
    const submitBtn = document.getElementById('submit-btn');
    const btnText = submitBtn.querySelector('.btn-text');
    const spinner = submitBtn.querySelector('.spinner');
    const resultsContainer = document.getElementById('results-container');
    const overallRiskBadge = document.getElementById('overall-risk-badge');
    const summaryMessage = document.getElementById('summary-message');
    const urlsList = document.getElementById('urls-list');
    const fileInput = document.getElementById('email_file');
    const fileLabel = document.querySelector('.file-label');

    // Update file label when file is selected
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            fileLabel.innerHTML = `<span class="file-icon">✅</span> ${e.target.files[0].name}`;
            fileLabel.style.borderColor = 'var(--primary-color)';
        } else {
            fileLabel.innerHTML = `<span class="file-icon">📄</span> Upload Email File (.eml, .txt)`;
            fileLabel.style.borderColor = 'var(--glass-border)';
        }
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Reset state
        resultsContainer.classList.add('hidden');
        submitBtn.disabled = true;
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');
        urlsList.innerHTML = '';
        
        const formData = new FormData(form);
        
        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'An error occurred during analysis.');
            }
            
            displayResults(data);
            
        } catch (error) {
            alert(error.message);
        } finally {
            submitBtn.disabled = false;
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
        }
    });
    
    function displayResults(data) {
        summaryMessage.textContent = data.message;
        
        // Set overall risk badge
        overallRiskBadge.textContent = data.overall_risk;
        overallRiskBadge.className = 'risk-badge';
        overallRiskBadge.classList.add(data.overall_risk.toLowerCase());
        
        // Set content risk badge
        const contentRiskBadge = document.getElementById('content-risk-badge');
        const contentFindings = document.getElementById('content-findings');
        contentFindings.innerHTML = '';
        
        if (data.content_analysis) {
            contentRiskBadge.textContent = data.content_analysis.risk;
            contentRiskBadge.className = 'risk-badge';
            contentRiskBadge.classList.add(data.content_analysis.risk.toLowerCase());
            
            if (data.content_analysis.findings.length > 0) {
                data.content_analysis.findings.forEach(finding => {
                    const findingItem = document.createElement('div');
                    findingItem.className = `finding-item ${data.content_analysis.risk.toLowerCase()}`;
                    
                    const matchesHtml = finding.matches.map(m => `<span class="match-tag">"${escapeHtml(m)}"</span>`).join('');
                    
                    findingItem.innerHTML = `
                        <div class="finding-category">${escapeHtml(finding.category)}</div>
                        <div class="finding-matches">${matchesHtml}</div>
                    `;
                    contentFindings.appendChild(findingItem);
                });
            } else {
                contentFindings.innerHTML = '<div class="summary-message">No suspicious language patterns detected.</div>';
            }
        }
        
        // Render URL results
        urlsList.innerHTML = '';
        if (data.url_results && data.url_results.length > 0) {
            data.url_results.forEach(item => {
                const urlItem = document.createElement('div');
                urlItem.className = 'url-item';
                
                const stats = item.vt_data.stats || {};
                const malicious = stats.malicious || 0;
                const suspicious = stats.suspicious || 0;
                const harmless = stats.harmless || 0;
                const undetected = stats.undetected || 0;
                
                urlItem.innerHTML = `
                    <div class="url-header">
                        <span class="url-text">${escapeHtml(item.url)}</span>
                        <span class="risk-badge ${item.risk.risk.toLowerCase()}" style="font-size: 0.75rem">${item.risk.risk}</span>
                    </div>
                    <div class="url-reason">${escapeHtml(item.risk.reason)}</div>
                    ${item.vt_data.status === 'success' ? `
                    <div class="url-stats">
                        <span class="stat mal">🛑 ${malicious} Malicious</span>
                        <span class="stat sus">⚠️ ${suspicious} Suspicious</span>
                        <span class="stat ok">✅ ${harmless} Harmless</span>
                        <span class="stat">⚪ ${undetected} Undetected</span>
                    </div>
                    ` : `<div class="url-stats">${escapeHtml(item.vt_data.message || item.vt_data.error || "No VT Data")}</div>`}
                `;
                
                urlsList.appendChild(urlItem);
            });
        } else {
            urlsList.innerHTML = '<div class="summary-message">No URLs found in the content.</div>';
        }
        
        resultsContainer.classList.remove('hidden');
        resultsContainer.scrollIntoView({ behavior: 'smooth' });
    }
    
    function escapeHtml(unsafe) {
        if (!unsafe) return '';
        return unsafe
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }
});
