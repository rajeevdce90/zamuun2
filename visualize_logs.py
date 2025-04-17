import json
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import pandas as pd
from collections import defaultdict

def load_data(filename='parsed_logs.json'):
    with open(filename, 'r') as f:
        return json.load(f)

def create_event_distribution_plot(data):
    # Count events by category
    category_counts = defaultdict(int)
    for event in data:
        category_counts[event['cim_category']] += 1
    
    # Create bar plot
    plt.figure(figsize=(12, 6))
    categories = list(category_counts.keys())
    counts = list(category_counts.values())
    
    bars = plt.bar(categories, counts)
    plt.title('Distribution of Events by CIM Category')
    plt.xlabel('CIM Category')
    plt.ylabel('Number of Events')
    plt.xticks(rotation=45)
    
    # Add value labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}',
                ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig('event_distribution.png')
    plt.close()

def create_action_distribution_plot(data):
    # Count actions by category
    action_by_category = defaultdict(lambda: defaultdict(int))
    for event in data:
        category = event['cim_category']
        action = event['data']['action']
        action_by_category[category][action] += 1
    
    # Create stacked bar plot
    df = pd.DataFrame(action_by_category).fillna(0)
    ax = df.plot(kind='bar', stacked=True, figsize=(12, 6))
    plt.title('Distribution of Actions by CIM Category')
    plt.xlabel('Action Type')
    plt.ylabel('Number of Events')
    plt.legend(title='CIM Category', bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig('action_distribution.png')
    plt.close()

def create_temporal_distribution_plot(data):
    # Convert timestamps to datetime and count events by hour
    timestamps = []
    categories = []
    for event in data:
        timestamp = datetime.strptime(event['data']['timestamp'], '%Y-%m-%dT%H:%M:%S.%f')
        timestamps.append(timestamp)
        categories.append(event['cim_category'])
    
    df = pd.DataFrame({'timestamp': timestamps, 'category': categories})
    df['hour'] = df['timestamp'].dt.hour
    
    # Create line plot
    plt.figure(figsize=(12, 6))
    for category in df['category'].unique():
        category_data = df[df['category'] == category]
        hourly_counts = category_data.groupby('hour').size()
        plt.plot(hourly_counts.index, hourly_counts.values, label=category, marker='o')
    
    plt.title('Temporal Distribution of Events by CIM Category')
    plt.xlabel('Hour of Day')
    plt.ylabel('Number of Events')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig('temporal_distribution.png')
    plt.close()

def create_app_distribution_plot(data):
    # Count applications by category
    app_by_category = defaultdict(lambda: defaultdict(int))
    for event in data:
        category = event['cim_category']
        app = event['data']['app']
        app_by_category[category][app] += 1
    
    # Create heatmap
    df = pd.DataFrame(app_by_category).fillna(0)
    plt.figure(figsize=(12, 8))
    sns.heatmap(df, annot=True, fmt='g', cmap='YlOrRd')
    plt.title('Application Usage by CIM Category')
    plt.xlabel('CIM Category')
    plt.ylabel('Application')
    plt.tight_layout()
    plt.savefig('app_distribution.png')
    plt.close()

def main():
    # Set style
    plt.style.use('seaborn-v0_8')  # Using a valid style name
    
    # Load data
    data = load_data()
    
    # Create visualizations
    print("Generating visualizations...")
    create_event_distribution_plot(data)
    create_action_distribution_plot(data)
    create_temporal_distribution_plot(data)
    create_app_distribution_plot(data)
    print("Visualizations have been saved as PNG files.")

if __name__ == "__main__":
    main() 