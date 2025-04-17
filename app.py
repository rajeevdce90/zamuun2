import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
from flask import Flask, render_template, request, jsonify
import os
from werkzeug.utils import secure_filename
import pandas as pd
import json
import io
import base64
from datetime import datetime
from analyze_logs import analyze_temporal_patterns, analyze_traffic_patterns, analyze_security_patterns, analyze_system_patterns

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

ALLOWED_EXTENSIONS = {'csv', 'json'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def analyze_logs(file_path):
    file_extension = file_path.rsplit('.', 1)[1].lower()
    
    if file_extension == 'csv':
        df = pd.read_csv(file_path, parse_dates=['receive_time', 'time_generated'])
    elif file_extension == 'json':
        df = pd.read_json(file_path)
    
    # Get total events
    total_events = len(df)
    valid_events = df.dropna(subset=['type', 'time_generated']).shape[0]
    
    # Get time range
    time_range = {
        'start': df['time_generated'].min().isoformat() if not df['time_generated'].empty else None,
        'end': df['time_generated'].max().isoformat() if not df['time_generated'].empty else None
    }
    
    # Get event distribution
    event_distribution = df['type'].value_counts().to_dict()
    
    # Get top actions
    actions = df['action'].value_counts().head(10).to_dict() if 'action' in df.columns else {}
    
    # Get top source IPs
    source_ips = df['src'].value_counts().head(10).to_dict() if 'src' in df.columns else {}
    
    # Get top users (if available)
    users = df['user'].value_counts().head(10).to_dict() if 'user' in df.columns else {}
    
    # Create event distribution chart
    plt.figure(figsize=(10, 6))
    df['type'].value_counts().plot(kind='pie', autopct='%1.1f%%')
    plt.title('Event Distribution')
    
    event_dist_img = io.BytesIO()
    plt.savefig(event_dist_img, format='png', bbox_inches='tight')
    event_dist_img.seek(0)
    event_dist_b64 = base64.b64encode(event_dist_img.getvalue()).decode()
    plt.close()
    
    # Create events over time chart
    plt.figure(figsize=(12, 6))
    df.groupby(['type', pd.Grouper(key='time_generated', freq='1H')]).size().unstack().plot(kind='line')
    plt.title('Events Over Time')
    plt.xlabel('Time')
    plt.ylabel('Number of Events')
    plt.xticks(rotation=45)
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    
    events_time_img = io.BytesIO()
    plt.savefig(events_time_img, format='png', bbox_inches='tight')
    events_time_img.seek(0)
    events_time_b64 = base64.b64encode(events_time_img.getvalue()).decode()
    plt.close()
    
    return {
        'total_events': total_events,
        'valid_events': valid_events,
        'time_range': time_range,
        'event_distribution': event_distribution,
        'actions': actions,
        'top_users': users,
        'top_source_ips': source_ips,
        'visualizations': {
            'event_distribution': event_dist_b64,
            'events_over_time': events_time_b64
        }
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    try:
        # Create uploads directory if it doesn't exist
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analyze the log file
        results = analyze_logs(filepath)
        
        # Clean up the uploaded file
        os.remove(filepath)
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 