"""
Agent Tester CLI
Command-line interface pour tester les agents
"""

import sys
import argparse
from agent_tester import AgentVulnerabilityTester, MockAgent

def main():
    """Main CLI function"""
    
    parser = argparse.ArgumentParser(
        description='Agent Security Intelligence Framework - Vulnerability Tester',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Test mock agent
  python cli.py --test-mock
  
  # Test specific threat type
  python cli.py --test-mock --type prompt_injection
  
  # Test specific source
  python cli.py --test-mock --source GitHub
  
  # Export custom filename
  python cli.py --test-mock --export my_assessment.json
        '''
    )
    
    parser.add_argument('--test-mock', action='store_true',
                       help='Test with mock agent (for demo)')
    
    parser.add_argument('--type', type=str, default=None,
                       help='Test specific threat type (prompt_injection, tool_abuse, etc.)')
    
    parser.add_argument('--source', type=str, default=None,
                       help='Test threats from specific source (CVE, GitHub, ArXiv, MITRE, Shodan, OpenCTI)')
    
    parser.add_argument('--export', type=str, default=None,
                       help='Export report to JSON file')
    
    parser.add_argument('--db', type=str, default='data/threats.db',
                       help='Path to threats database')
    
    args = parser.parse_args()
    
    # Select agent
    if args.test_mock:
        print("\n🤖 Using MOCK AGENT for demonstration\n")
        agent = MockAgent()
    else:
        print("\n❌ Please provide an agent (--test-mock for demo)")
        sys.exit(1)
    
    # Create tester
    tester = AgentVulnerabilityTester(agent, db_path=args.db)
    
    # Run tests
    if args.type:
        print(f"\n🧪 Testing threat type: {args.type}")
        tester.test_by_type(args.type)
    elif args.source:
        print(f"\n🧪 Testing source: {args.source}")
        tester.test_by_source(args.source)
    else:
        print("\n🧪 Running full assessment against all threats...")
        tester.run_all_tests()
    
    # Print report
    tester.print_report()
    
    # Export if requested
    if args.export:
        filename = tester.export_report(args.export)
        print(f"\n💾 Report exported to: {filename}")
    else:
        filename = tester.export_report()
        print(f"\n💾 Report exported to: {filename}")


if __name__ == "__main__":
    main()