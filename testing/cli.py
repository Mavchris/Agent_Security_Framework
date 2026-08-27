"""
CLI for Agent Vulnerability Testing
Like Nessus/Nmap for AI Agents
"""

import argparse
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent_scanner import AgentVulnerabilityScanner
from agent_wrappers import get_agent_wrapper

def main():
    parser = argparse.ArgumentParser(
        description='Agent Vulnerability Scanner - Test AI agents for security threats'
    )
    
    # Scan mode
    parser.add_argument(
        '--scan-agent',
        type=str,
        help='Scan agent (mock, mistral, claude, gpt-4, etc.)'
    )
    
    # Output options
    parser.add_argument(
        '--output',
        type=str,
        help='Output file (json/csv)'
    )
    
    # Limit threats
    parser.add_argument(
        '--limit',
        type=int,
        help='Limit number of threats to test'
    )
    
    # Verbose
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    # Legacy options (keep for compatibility)
    parser.add_argument('--type', type=str, help='Filter by threat type')
    parser.add_argument('--source', type=str, help='Filter by source')
    parser.add_argument('--db', type=str, default='data/threats.db', help='Database path')
    
    args = parser.parse_args()
    
    # SCAN MODE (NEW)
    if args.scan_agent:
        print(f"\nAgent Vulnerability Scanner")
        print(f"==============================\n")

        # Get the requested agent
        if args.scan_agent == 'mistral':
            # Use Ollama directly (no SDK needed)
            from agent_wrappers import OllamaWrapper
            agent = OllamaWrapper(model='mistral')
            print(f"Using Mistral via Ollama (localhost:11434)\n")
        elif args.scan_agent == 'mock':
            agent = get_agent_wrapper('mock')
            print(f"Using MockAgent\n")
        else:
            # Try other agents
            try:
                agent = get_agent_wrapper(args.scan_agent)
                print(f"Using {args.scan_agent}\n")
            except ImportError as e:
                print(f"[ERROR] Agent type '{args.scan_agent}' not available")
                print(f"   Error: {e}")
                print(f"   Available: mock, mistral (via Ollama), claude, gpt-4, llama, huggingface")
                return 1
            except Exception as e:
                print(f"[ERROR] Error loading agent: {e}")
                return 1
        
        scanner = AgentVulnerabilityScanner(agent, db_path=args.db)
        
        # Run scan
        results = scanner.scan_all_threats(verbose=args.verbose, limit=args.limit)
        
        # Print summary
        scanner.print_summary()
        
        # Export
        if args.output:
            if args.output.endswith('.json'):
                scanner.export_json(args.output)
            elif args.output.endswith('.csv'):
                scanner.export_csv(args.output)
        
        return 0

    else:
        parser.print_help()
        return 1

if __name__ == '__main__':
    sys.exit(main())
