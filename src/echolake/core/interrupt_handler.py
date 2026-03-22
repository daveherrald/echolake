"""Force immediate exit on Ctrl+C."""

import signal
import sys
import os


def setup_interrupt_handler():
    """Set up signal handler that forces immediate exit."""
    def force_exit(signum, frame):
        """Force immediate exit on SIGINT."""
        print("\n⚠️  Interrupted. Exiting...", file=sys.stderr, flush=True)
        os._exit(130)
    
    signal.signal(signal.SIGINT, force_exit)
