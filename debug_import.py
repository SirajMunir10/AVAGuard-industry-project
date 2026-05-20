import sys
import os
import avaguard_core
print(f"avaguard_core file: {avaguard_core.__file__}")
try:
    from avaguard_core import checks
    print("checks found")
except ImportError as e:
    print(f"checks NOT found: {e}")

print("sys.path:")
for p in sys.path:
    print(f"  {p}")
