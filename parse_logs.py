import re
import csv
from typing import Dict, List, Optional, Tuple
import json
from datetime import datetime
import pytz
from collections import defaultdict
import ipaddress
import os

# CIM Categories and their field mappings
CIM_CATEGORIES = {
    'Network_Traffic': {
        'indicators': ['TRAFFIC', 'traffic', 'network', 'flow', 'session', 'tcp', 'udp', 'protocol'],
        'field_mapping': {
            'timestamp': 'timestamp',
            'src_ip': 'src_ip',
            'dst_ip': 'dst_ip',
            'app': 'application',
            'action': 'action',
            'details': 'event_description',
            'log_type': 'event_type',
            'transport': 'transport',
            'bytes': 'bytes',
            'packets': 'packets'
        }
    },
    'Authentication': {
        'indicators': ['USER', 'auth', 'login', 'user', 'authentication', 'auth-success', 'auth-failure'],
        'field_mapping': {
            'timestamp': 'timestamp',
            'src_ip': 'src_ip',
            'user': 'user',
            'app': 'application',
            'action': 'action',
            'details': 'event_description',
            'log_type': 'event_type',
            'authentication_method': 'auth_method',
            'authentication_service': 'auth_service'
        }
    },
    'System': {
        'indicators': ['SYSTEM', 'config', 'status', 'system-restart', 'METADATA', 'HIPMATCH'],
        'field_mapping': {
            'timestamp': 'timestamp',
            'src_ip': 'src_ip',
            'dst_ip': 'dst_ip',
            'user': 'user',
            'app': 'application',
            'action': 'action',
            'details': 'event_description',
            'log_type': 'event_type',
            'system_id': 'system_id'
        }
    },
    'Threat_Detection': {
        'indicators': ['THREAT', 'threat', 'alert', 'vulnerability', 'security'],
        'field_mapping': {
            'timestamp': 'timestamp',
            'src_ip': 'src_ip',
            'dst_ip': 'dst_ip',
            'user': 'user',
            'app': 'application',
            'action': 'action',
            'details': 'event_description',
            'log_type': 'event_type',
            'signature': 'signature',
            'severity': 'severity'
        }
    },
    'Change_Analysis': {
        'indicators': ['config-change', 'resource-utilization', 'SRC', 'change', 'modify'],
        'field_mapping': {
            'timestamp': 'timestamp',
            'system_id': 'system_id',
            'change_type': 'change_type',
            'command': 'command',
            'severity': 'severity',
            'system_name': 'system_name',
            'object_category': 'object_category',
            'change_id': 'change_id'
        }
    },
    'Malware': {
        'indicators': ['malware', 'spyware', 'virus', 'ransomware', 'trojan'],
        'field_mapping': {
            'timestamp': 'timestamp',
            'src_ip': 'src_ip',
            'dest_ip': 'dest_ip',
            'severity': 'severity',
            'signature_group': 'signature_group',
            'signature': 'signature',
            'action': 'action',
            'threat_name': 'threat_name',
            'transport': 'transport'
        }
    }
}

class ValidationResult:
    def __init__(self, is_valid: bool, errors: List[str] = None, warnings: List[str] = None):
        self.is_valid = is_valid
        self.errors = errors or []
        self.warnings = warnings or []

class ParsedEvent:
    def __init__(self, event_data: Dict, validation_result: ValidationResult, cim_category: str):
        self.data = event_data
        self.validation = validation_result
        self.cim_category = cim_category
        self.original_line = event_data.get('original_line', '')

class LogParser:
    def __init__(self):
        # Initialize statistics tracking
        self.stats = {
            'total_lines': 0,
            'parsed_lines': 0,
            'failed_lines': 0,
            'by_type': defaultdict(int),
            'by_cim_category': defaultdict(int),
            'field_usage': defaultdict(lambda: defaultdict(int)),
            'validation': {
                'valid_events': 0,
                'invalid_events': 0,
                'warnings': 0,
                'errors_by_category': defaultdict(lambda: defaultdict(int)),
                'error_details': defaultdict(list)
            },
            'timestamp_ranges': {
                'earliest': None,
                'latest': None
            }
        }
        
        # Initialize event storage
        self.valid_events = []
        self.invalid_events = []

    def validate_ip(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True, None
        except ValueError as e:
            return False, str(e)

    def validate_fields(self, event: Dict, cim_category: str) -> ValidationResult:
        """Validate fields based on CIM category requirements"""
        errors = []
        warnings = []
        
        # Basic field presence validation
        required_fields = ['timestamp', 'log_type', 'action']
        for field in required_fields:
            if field not in event or not event[field]:
                errors.append(f"Missing required field: {field}")

        # IP address validation
        if 'src_ip' in event:
            is_valid, error = self.validate_ip(event['src_ip'])
            if not is_valid:
                errors.append(f"Invalid source IP: {error}")

        if 'dst_ip' in event:
            is_valid, error = self.validate_ip(event['dst_ip'])
            if not is_valid:
                errors.append(f"Invalid destination IP: {error}")

        # Action validation
        valid_actions = ['allow', 'deny', 'drop', 'alert', 'block']
        if 'action' in event and event['action'].lower() not in valid_actions:
            warnings.append(f"Unusual action value: {event['action']}")

        return ValidationResult(len(errors) == 0, errors, warnings)

    def identify_cim_category(self, event: Dict) -> str:
        """Identify the CIM category for an event"""
        log_type = event.get('log_type', '').upper()
        details = event.get('details', '').lower()
        action = event.get('action', '').lower()
        
        # Direct mapping for known log types
        type_mapping = {
            'TRAFFIC': 'Network_Traffic',
            'USER': 'Authentication',
            'SYSTEM': 'System',
            'THREAT': 'Threat_Detection'
        }
        
        if log_type in type_mapping:
            return type_mapping[log_type]
            
        # Analyze event details for category indicators
        for category, info in CIM_CATEGORIES.items():
            for indicator in info['indicators']:
                if (indicator.lower() in log_type.lower() or
                    indicator.lower() in details.lower() or
                    indicator.lower() in action.lower()):
                    return category
        
        return 'Unknown'

    def process_event(self, event: Dict) -> ParsedEvent:
        """Process and validate a single event"""
        # Identify CIM category
        cim_category = self.identify_cim_category(event)
        self.stats['by_cim_category'][cim_category] += 1
        
        # Validate fields
        validation_result = self.validate_fields(event, cim_category)
        
        # Update statistics
        if validation_result.is_valid:
            self.stats['validation']['valid_events'] += 1
            self.valid_events.append(ParsedEvent(event, validation_result, cim_category))
        else:
            self.stats['validation']['invalid_events'] += 1
            self.invalid_events.append(ParsedEvent(event, validation_result, cim_category))
            
        # Track field usage
        for field in event:
            if event[field]:
                self.stats['field_usage'][cim_category][field] += 1
        
        return ParsedEvent(event, validation_result, cim_category)

    def parse_file(self, input_file: str, output_dir: str = 'parsed_output'):
        """Parse the PA logs file"""
        os.makedirs(output_dir, exist_ok=True)
        
        with open(input_file, 'r') as f:
            reader = csv.DictReader(f)
            self.stats['total_lines'] = 0
            
            for row in reader:
                self.stats['total_lines'] += 1
                self.stats['parsed_lines'] += 1
                
                # Track event type statistics
                log_type = row['log_type']
                self.stats['by_type'][log_type] += 1
                
                # Process the event
                self.process_event(row)
                
                # Track timestamp ranges
                try:
                    timestamp = datetime.strptime(row['timestamp'], '%Y-%m-%dT%H:%M:%S.%f')
                    if not self.stats['timestamp_ranges']['earliest'] or timestamp < self.stats['timestamp_ranges']['earliest']:
                        self.stats['timestamp_ranges']['earliest'] = timestamp
                    if not self.stats['timestamp_ranges']['latest'] or timestamp > self.stats['timestamp_ranges']['latest']:
                        self.stats['timestamp_ranges']['latest'] = timestamp
                except ValueError:
                    pass

        # Save results
        self.save_results(output_dir)
        return self.valid_events, self.invalid_events

    def save_results(self, output_dir: str):
        """Save parsing results to files"""
        # Save valid events
        with open(os.path.join(output_dir, 'valid_events.json'), 'w') as f:
            json.dump([{
                'data': event.data,
                'cim_category': event.cim_category
            } for event in self.valid_events], f, indent=2)

        # Save invalid events
        with open(os.path.join(output_dir, 'invalid_events.json'), 'w') as f:
            json.dump([{
                'data': event.data,
                'cim_category': event.cim_category,
                'errors': event.validation.errors,
                'warnings': event.validation.warnings
            } for event in self.invalid_events], f, indent=2)

        # Save statistics
        with open(os.path.join(output_dir, 'statistics.json'), 'w') as f:
            json.dump({
                'total_lines': self.stats['total_lines'],
                'parsed_lines': self.stats['parsed_lines'],
                'failed_lines': self.stats['failed_lines'],
                'by_type': dict(self.stats['by_type']),
                'by_cim_category': dict(self.stats['by_cim_category']),
                'field_usage': dict(self.stats['field_usage']),
                'validation': self.stats['validation']
            }, f, indent=2)

    def print_stats(self):
        """Print enhanced statistics with validation details and CIM compliance coverage"""
        print("\nParsing Statistics:")
        print("=" * 50)
        print(f"Total lines processed: {self.stats['total_lines']}")
        print(f"Successfully parsed: {self.stats['parsed_lines']}")
        print(f"Failed to parse: {self.stats['failed_lines']}")
        
        print("\nEvent Type Distribution:")
        print("-" * 30)
        for event_type, count in self.stats['by_type'].items():
            print(f"{event_type}: {count}")
        
        print("\nCIM Category Distribution:")
        print("-" * 30)
        for category, count in self.stats['by_cim_category'].items():
            print(f"\n{category}:")
            print(f"  Total Events: {count}")
            if category in self.stats['field_usage']:
                total_fields = len(CIM_CATEGORIES.get(category, {}).get('field_mapping', {}))
                used_fields = len(self.stats['field_usage'][category])
                coverage = (used_fields / total_fields * 100) if total_fields > 0 else 0
                print(f"  Field Coverage: {coverage:.1f}%")
                print("  Fields Used:")
                for field, usage_count in self.stats['field_usage'][category].items():
                    print(f"    - {field}: {usage_count} occurrences")
        
        print("\nValidation Results:")
        print("-" * 30)
        print(f"Valid events: {self.stats['validation']['valid_events']}")
        print(f"Invalid events: {self.stats['validation']['invalid_events']}")
        
        if self.stats['timestamp_ranges']['earliest'] and self.stats['timestamp_ranges']['latest']:
            print("\nTime Range:")
            print(f"Earliest: {self.stats['timestamp_ranges']['earliest']}")
            print(f"Latest: {self.stats['timestamp_ranges']['latest']}")
            duration = self.stats['timestamp_ranges']['latest'] - self.stats['timestamp_ranges']['earliest']
            print(f"Duration: {duration}")

def main():
    parser = LogParser()
    print("Starting log parsing...")
    # Parse PA_logs_1000.csv and save results to parsed_logs.json
    valid_events, invalid_events = parser.parse_file('PA_logs_1000.csv')
    
    # Save to parsed_logs.json
    with open('parsed_logs.json', 'w') as f:
        json.dump([{
            'data': event.data,
            'cim_category': event.cim_category
        } for event in valid_events], f, indent=2)
    
    parser.print_stats()

if __name__ == "__main__":
    main() 