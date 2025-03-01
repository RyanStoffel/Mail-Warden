import os
import sys
from tkinter import Tk

# Make sure we can import our own modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# Now we can import from our package
from src.ui.main_window import MainWindow


def main():
    # Initialize Tkinter and our application
    root = Tk()
    root.title("Mail-Warden")

    # Apply light theme
    root.configure(bg="#f0f0f0")

    # Create the application instance
    app = MainWindow(root)

    # Start the Tkinter event loop
    root.mainloop()


if __name__ == "__main__":
    main()
