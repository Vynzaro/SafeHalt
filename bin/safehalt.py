#!/usr/bin/python3
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, "/usr/local/lib")

from safehalt.cli import main

raise SystemExit(main())
