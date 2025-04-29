#!/usr/bin/env python3
import os
import sys
import markdown2

# Add current directory to path
sys.path.insert(0, os.path.abspath('.'))

# Import our module
from phantomrecon.agents.report_logic import _generate_html_report

# Test markdown content
test_md = """
# Test PhantomRecon Report

## 1. Overview
This is a test report to verify HTML generation.

## 2. Sample Code Block
```python
def test_function():
    print("This is a test")
    return True
```

## 3. Sample Table
| Header 1 | Header 2 | Header 3 |
|----------|----------|----------|
| Value 1  | Value 2  | Value 3  |
| Value 4  | Value 5  | Value 6  |

## 4. Nested Lists
- Item 1
  - Nested 1.1
  - Nested 1.2
- Item 2
  - Nested 2.1
    - Deep nested 2.1.1

## 5. Sample Findings
- **Potential SQLi:** SQL injection found
  - URL: `http://example.com/vulnerable.php?id=1`
  - Identified Point(s):
    - `Parameter: id`
  - Sqlmap Output Snippet:
```
Parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
```
"""

# Generate HTML
print("Generating test HTML report...")
output_file = "test_report.html"

result = _generate_html_report(test_md, output_file)

if result.get("status") == "success":
    print(f"Success! HTML report saved to: {output_file}")
else:
    print(f"Error: {result.get('message', 'Unknown error')}") 