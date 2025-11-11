import os
import sys
import importlib
import multiprocessing
import time

# Add the detectors directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), "detectors"))

# Dictionary to hold detector processes
detector_processes = {}
detector_stop_events = {}


def detector_worker(detector_name, stop_event):
    try:
        detector_module = importlib.import_module(detector_name)
        if hasattr(detector_module, "run"):
            print(f"Starting {detector_name} detector...")
            # Assuming the run function can be gracefully stopped or checks a stop_event
            # For now, we'll just run it. Actual graceful shutdown would require modifying detector modules.
            detector_module.run(
                stop_event
            )  # Pass stop_event to the detector's run function
            print(f"{detector_name} detector finished.")
        else:
            print(f"Warning: Detector {detector_name} does not have a 'run' function.")
    except ImportError:
        print(f"Error: Could not import detector {detector_name}.")
    except Exception as e:
        print(f"Error running {detector_name} detector: {e}")


def start_detector(detector_name):
    if (
        detector_name in detector_processes
        and detector_processes[detector_name].is_alive()
    ):
        print(f"Detector {detector_name} is already running.")
        return

    print(f"Attempting to start {detector_name}...")
    stop_event = multiprocessing.Event()
    process = multiprocessing.Process(
        target=detector_worker, args=(detector_name, stop_event)
    )
    process.start()
    detector_processes[detector_name] = process
    detector_stop_events[detector_name] = stop_event
    print(f"Detector {detector_name} started.")


def stop_detector(detector_name):
    if (
        detector_name in detector_processes
        and detector_processes[detector_name].is_alive()
    ):
        print(f"Attempting to stop {detector_name}...")
        detector_stop_events[detector_name].set()  # Signal the detector to stop
        detector_processes[detector_name].join(
            timeout=5
        )  # Wait for the process to terminate
        if detector_processes[detector_name].is_alive():
            print(
                f"Warning: Detector {detector_name} did not terminate gracefully. Terminating forcefully."
            )
            detector_processes[detector_name].terminate()
            detector_processes[detector_name].join()
        print(f"Detector {detector_name} stopped.")
        del detector_processes[detector_name]
        del detector_stop_events[detector_name]
    else:
        print(f"Detector {detector_name} is not running.")


def list_detectors():
    print("\n--- Registered Detectors ---")
    all_detectors = [
        "arp_monitor_all",
        "ddos_detector",
        "dns_spoof_detector",
        "malware_c2_detector",
        "phishing_detector",
    ]
    for detector in all_detectors:
        status = (
            "Running"
            if detector in detector_processes
            and detector_processes[detector].is_alive()
            else "Stopped"
        )
        print(f"- {detector}: {status}")
    print("--------------------------\n")


def main():
    detectors_list = [
        "arp_monitor_all",
        "ddos_detector",
        "dns_spoof_detector",
        "malware_c2_detector",
        "phishing_detector",
    ]

    print("Welcome to the Detector Manager!")
    print("Available commands: start <detector_name>, stop <detector_name>, list, exit")

    # Start all detectors initially
    for detector in detectors_list:
        start_detector(detector)
        time.sleep(0.5)  # Give a small delay between starting detectors

    try:
        while True:
            command = input("Enter command: ").strip().split()
            if not command:
                continue

            action = command[0].lower()
            if action == "start" and len(command) > 1:
                start_detector(command[1])
            elif action == "stop" and len(command) > 1:
                stop_detector(command[1])
            elif action == "list":
                list_detectors()
            elif action == "exit":
                print("Stopping all running detectors before exiting...")
                for detector_name in list(detector_processes.keys()):
                    stop_detector(detector_name)
                break
            else:
                print(
                    "Invalid command. Please use 'start <detector_name>', 'stop <detector_name>', 'list', or 'exit'."
                )
            time.sleep(0.1)  # Small delay to prevent busy-waiting
    except KeyboardInterrupt:
        print(
            "\nKeyboardInterrupt detected. Stopping all running detectors before exiting..."
        )
        for detector_name in list(detector_processes.keys()):
            stop_detector(detector_name)
    finally:
        # Ensure all processes are terminated on exit
        for detector_name, process in detector_processes.items():
            if process.is_alive():
                print(f"Forcefully terminating {detector_name}...")
                process.terminate()
                process.join()
        print("Exiting Detector Manager.")


if __name__ == "__main__":
    main()
