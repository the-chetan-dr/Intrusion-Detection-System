import os
import time
import fnmatch
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.events import FileCreatedEvent, FileDeletedEvent, FileMovedEvent, FileModifiedEvent

from monitor import monitor_network_connections, monitor_system_processes
from detector import AdvancedAnomalyDetector


class IDPSEventHandler(FileSystemEventHandler):
    def __init__(self, ignore_patterns=None, anomaly_detector=None):
        super().__init__()
        self.ignore_patterns = ignore_patterns or []
        self.anomaly_detector = anomaly_detector

    def _get_event_type(self, event):
        if isinstance(event, FileCreatedEvent):
            return 0
        elif isinstance(event, FileDeletedEvent):
            return 1
        elif isinstance(event, FileMovedEvent):
            return 2
        elif isinstance(event, FileModifiedEvent):
            return 3
        else:
            return -1

    def _get_event_vector(self, event):
        event_type = self._get_event_type(event)
        if event_type == -1:
            return None

        file_size = 0
        if os.path.exists(event.src_path):
            file_size = os.path.getsize(event.src_path)

        return [event_type, file_size]

    def should_ignore(self, path):
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def log_event(self, event_type, path):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        os.makedirs("./logs", exist_ok=True)  # Ensure logs folder exists
        with open("./logs/file_log.txt", "a") as log_file:
            log_file.write(f"{timestamp} - {event_type} - {path}\n")

    def on_created(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been created.")
        self.log_event("created", event.src_path)

    def on_deleted(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been deleted.")
        self.log_event("deleted", event.src_path)

    def on_moved(self, event):
        if self.should_ignore(event.src_path) and self.should_ignore(event.dest_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been moved to {event.dest_path}.")
        self.log_event("moved", f"{event.src_path} -> {event.dest_path}")

    def on_modified(self, event):
        if self.should_ignore(event.src_path):
            return
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)
        print(f"Alert! {event.src_path} has been modified.")
        self.log_event("modified", event.src_path)


def main():
    # Ensure logs folder exists
    os.makedirs("./logs", exist_ok=True)

    # Directories to watch
    paths = ["./lab"]
    for path in paths:
        os.makedirs(path, exist_ok=True)  # Ensure folder exists

    ignore_patterns = ["*.tmp", "*.log"]

    # Initialize anomaly detector
    anomaly_detector = AdvancedAnomalyDetector(threshold=10, time_window=60)

    # Initialize watchdog event handler
    event_handler = IDPSEventHandler(ignore_patterns=ignore_patterns, anomaly_detector=anomaly_detector)
    observer = Observer()

    for path in paths:
        observer.schedule(event_handler, path, recursive=True)

    observer.start()

    # Start network monitoring thread
    network_monitor_thread = threading.Thread(target=monitor_network_connections, daemon=True)
    network_monitor_thread.start()

    # Start system process monitoring thread
    process_monitor_thread = threading.Thread(target=monitor_system_processes, daemon=True)
    process_monitor_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down IDS/IPS...")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
