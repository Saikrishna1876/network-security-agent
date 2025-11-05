import os
import sys
import importlib

# Add the detectors directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), "detectors"))


def run_detector(detector_name):
    try:
        detector_module = importlib.import_module(detector_name)
        if hasattr(detector_module, "run"):
            print(f"Running {detector_name} detector...")
            detector_module.run()
        else:
            print(f"Warning: Detector {detector_name} does not have a 'run' function.")
    except ImportError:
        print(f"Error: Could not import detector {detector_name}.")
    except Exception as e:
        print(f"Error running {detector_name} detector: {e}")


def main():
    detectors = [
        "arp_monitor_all",
        "ddos_detector",
        "dns_spoof_detector",
        "malware_c2_detector",
        "phishing_detector",
    ]

    for detector in detectors:
        run_detector(detector)


if __name__ == "__main__":
    main()
