import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
import json
import sys
import base64
import io
from datetime import datetime

def analyze_logs(file_path):
    """Analyze log file and return results as JSON"""
    # Read the file
    file_extension = file_path.split('.')[-1].lower()
    
    if file_extension == 'csv':
        df = pd.read_csv(file_path, parse_dates=['timestamp'])
    elif file_extension == 'json':
        df = pd.read_json(file_path)
    else:
        raise ValueError('Unsupported file format')

    # Get total events and valid events
    total_events = len(df)
    valid_events = df.dropna(subset=['log_type', 'timestamp']).shape[0]
    
    # Get time range
    time_range = {
        'start': df['timestamp'].min().isoformat() if not df['timestamp'].empty else None,
        'end': df['timestamp'].max().isoformat() if not df['timestamp'].empty else None
    }
    
    # Get event distribution
    event_distribution = df['log_type'].value_counts().to_dict()
    
    # Get top actions
    actions = df['action'].value_counts().head(10).to_dict() if 'action' in df.columns else {}
    
    # Get top source IPs
    source_ips = df['src_ip'].value_counts().head(10).to_dict() if 'src_ip' in df.columns else {}
    
    # Get top users
    users = df['user'].value_counts().head(10).to_dict() if 'user' in df.columns else {}
    
    # Create event distribution chart
    plt.figure(figsize=(10, 6))
    df['log_type'].value_counts().plot(kind='pie', autopct='%1.1f%%')
    plt.title('Event Distribution')
    
    event_dist_img = io.BytesIO()
    plt.savefig(event_dist_img, format='png', bbox_inches='tight')
    event_dist_img.seek(0)
    event_dist_b64 = base64.b64encode(event_dist_img.getvalue()).decode()
    plt.close()
    
    # Create events over time chart
    plt.figure(figsize=(12, 6))
    df.groupby(['log_type', pd.Grouper(key='timestamp', freq='h')]).size().unstack().plot(kind='line')
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

    # Add additional analysis
    app_distribution = df['app'].value_counts().head(10).to_dict() if 'app' in df.columns else {}
    
    return {
        'total_events': total_events,
        'valid_events': valid_events,
        'time_range': time_range,
        'event_distribution': event_distribution,
        'actions': actions,
        'top_users': users,
        'top_source_ips': source_ips,
        'top_applications': app_distribution,
        'visualizations': {
            'event_distribution': event_dist_b64,
            'events_over_time': events_time_b64
        }
    }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({'error': 'Please provide a file path'}))
        sys.exit(1)
    
    try:
        results = analyze_logs(sys.argv[1])
        print(json.dumps(results))
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1) 