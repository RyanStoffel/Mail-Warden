import os
import platform
import subprocess
import sys


def print_header(text):
    print("\n" + "=" * 60)
    print(f" {text}")
    print("=" * 60)


def check_python_version():
    print_header("Checking Python Version")

    version = sys.version_info
    print(f"Python version: {sys.version}")

    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8 or higher is required.")
        return False
    else:
        print("✅ Python version is compatible.")
        return True


def install_python_dependencies():
    print_header("Installing Python Dependencies")

    requirements = [
        "click",
        "imaplib2",
        "joblib",
        "nltk",
        "numpy",
        "pycryptodome",
        "PyQt5",
        "python-magic",
        "python-whois",
        "regex",
        "scikit-learn",
        "scipy",
        "threadpoolctl",
        "tqdm",
    ]

    for package in requirements:
        print(f"Installing {package}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"✅ {package} installed successfully.")
        except subprocess.CalledProcessError:
            print(f"❌ Failed to install {package}.")
            return False

    print("All Python dependencies installed successfully.")
    return True


def download_nltk_resources():
    print_header("Downloading NLTK Resources")

    try:
        import nltk

        resources = ["punkt", "stopwords", "words", "punkt_tab"]

        for resource in resources:
            print(f"Downloading {resource}...")
            nltk.download(resource, quiet=True)
            print(f"✅ {resource} downloaded successfully.")

        print("All NLTK resources downloaded successfully.")
        return True
    except Exception as e:
        print(f"❌ Failed to download NLTK resources: {e}")
        return False


def check_system_dependencies():
    print_header("Checking System Dependencies")

    system = platform.system()

    if system == "Linux":
        try:
            subprocess.check_call(["ldconfig", "-p"], stdout=subprocess.DEVNULL)
            print("✅ System libraries appear to be available.")
            return True
        except:
            print("❌ Unable to verify system libraries.")
            print("You may need to install libmagic: sudo apt-get install libmagic1")
            return False

    elif system == "Darwin":  # macOS
        if os.path.exists("/usr/local/lib/libmagic.dylib") or os.path.exists(
            "/opt/homebrew/lib/libmagic.dylib"
        ):
            print("✅ libmagic appears to be installed.")
            return True
        else:
            print("❌ libmagic may not be installed.")
            print("You may need to install it: brew install libmagic")
            return False

    elif system == "Windows":
        print(
            "✅ On Windows, using python-magic-bin (no system dependencies required)."
        )
        return True

    else:
        print("⚠️ Unknown operating system. Can't verify system dependencies.")
        print("You may need to manually install libmagic for your operating system.")
        return True


def run_basic_tests():
    print_header("Running Basic Tests")

    modules_to_test = [
        "PyQt5.QtWidgets",
        "nltk",
        "magic",
        "whois",
        "cryptography.fernet",
    ]

    all_passed = True

    for module in modules_to_test:
        try:
            __import__(module)
            print(f"✅ {module}: Import successful")
        except ImportError as e:
            print(f"❌ {module}: Import failed - {e}")
            all_passed = False

    if all_passed:
        print("\nAll basic tests passed successfully.")
    else:
        print("\nSome tests failed. See above for details.")

    return all_passed


def main():
    print_header("Mail-Warden Setup Helper")

    if not check_python_version():
        print("\n❌ Setup failed: Incompatible Python version.")
        sys.exit(1)

    if not install_python_dependencies():
        print("\n⚠️ Some Python dependencies could not be installed.")
        choice = input("Continue anyway? (y/n): ")
        if choice.lower() != "y":
            sys.exit(1)

    if not download_nltk_resources():
        print("\n⚠️ Some NLTK resources could not be downloaded.")
        choice = input("Continue anyway? (y/n): ")
        if choice.lower() != "y":
            sys.exit(1)

    check_system_dependencies()

    if run_basic_tests():
        print_header("Setup Complete")
        print("You can now run Mail-Warden with: python run.py")
    else:
        print_header("Setup Incomplete")
        print("Some issues were detected. You may still try running Mail-Warden,")
        print("but you might encounter errors. Please resolve the issues above first.")


if __name__ == "__main__":
    main()
