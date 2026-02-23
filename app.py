import os
from dotenv import load_dotenv
import requests
import base64
from flask import Flask, render_template, request

load_dotenv()

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True  # Forces template refresh

VT_API_KEY = os.getenv("VT_API_KEY")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/quiz')
def quiz():
    return render_template('quiz.html')

import time

@app.route('/checker', methods=['GET', 'POST'])
def url_checker():
    results = None
    user_url = None

    if request.method == 'POST':
        user_url = request.form.get('url_to_scan')
        headers = {"x-apikey": VT_API_KEY}
        vt_url = "https://www.virustotal.com/api/v3/urls"
        payload = {"url": user_url}

        submit_response = requests.post(vt_url, data=payload, headers=headers)

        if submit_response.status_code == 200:
            analysis_id = submit_response.json()['data']['id']
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            report_response = requests.get(report_url, headers=headers)

            if report_response.status_code == 200:
                report_data = report_response.json().get('data', {})
                attributes = report_data.get('attributes', {})
                stats = attributes.get('stats', {})

                m_count = stats.get('malicious', 0)
                s_count = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)
                undetected = stats.get('undetected', 0)
                total_engines = m_count + s_count + harmless + undetected

                # Pull per-engine results and filter to only flagging ones
                all_results = attributes.get('results', {})
                flagged_engines = [
                    {
                        "engine": engine_name,
                        "category": data.get("category", "unknown"),
                        "result": data.get("result", "N/A")
                    }
                    for engine_name, data in all_results.items()
                    if data.get("category") in ("malicious", "suspicious")
                ]

                # Overall verdict
                verdict = "SAFE"
                if m_count > 0:
                    verdict = "DANGEROUS"
                elif s_count > 0:
                    verdict = "SUSPICIOUS"

                results = {
                    "verdict": verdict,
                    "malicious": m_count,
                    "suspicious": s_count,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total_engines": total_engines,
                    "flagged_engines": flagged_engines,   # list of dicts
                    "reputation": attributes.get('reputation', 0),
                    "status": attributes.get('status', 'N/A'),
                }
            else:
                results = {"error": f"Could not retrieve report (status {report_response.status_code})."}
        else:
            results = {"error": f"Failed to submit URL (status {submit_response.status_code}). Check your API key or limits."}

    return render_template('url-checker.html', results=results, url=user_url)





@app.route('/services')
def services():
    return render_template('services.html')

if __name__ == '__main__':
    app.run(debug=True)