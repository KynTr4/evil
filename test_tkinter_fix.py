#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to verify the Tkinter error fix works properly
"""

import tkinter as tk
from tkinter import messagebox
import threading
import time
import sys
import os

# Add the gui directory to the path to import our fixed module
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'gui'))

from evil_twin_gui import EvilTwinGUI

def test_messagebox_after_destroy():
    """Test that shows the original problem and verifies the fix"""
    print("Testing Tkinter messagebox error fix...")
    
    # Create a test window
    root = tk.Tk()
    root.title("Test Window")
    root.geometry("400x300")
    
    # Create EvilTwinGUI instance (but don't show full GUI)
    app = EvilTwinGUI(root)
    
    def delayed_check_tools():
        """Simulate the scenario where check_tools is called after window destruction"""
        time.sleep(2)  # Wait 2 seconds
        print("Calling check_tools after window might be destroyed...")
        try:
            app.check_tools()
            print("✅ check_tools completed without error!")
        except Exception as e:
            print(f"❌ Error occurred: {e}")
    
    def delayed_destroy():
        """Destroy window after 1 second"""
        time.sleep(1)
        print("Destroying window...")
        root.quit()
        root.destroy()
    
    # Start both threads
    destroy_thread = threading.Thread(target=delayed_destroy)
    check_thread = threading.Thread(target=delayed_check_tools)
    
    destroy_thread.daemon = True
    check_thread.daemon = True
    
    destroy_thread.start()
    check_thread.start()
    
    print("Starting test - window will be destroyed in 1 second, check_tools called in 2 seconds...")
    
    try:
        root.mainloop()
    except:
        pass
    
    # Wait for check thread to complete
    check_thread.join(timeout=5)
    
    print("Test completed!")

if __name__ == "__main__":
    test_messagebox_after_destroy()