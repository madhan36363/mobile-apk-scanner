import hashlib
import os
from androguard.core.bytecodes.apk import APK

# Function to calculate SHA-256 hash of the file
def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to perform heuristic-based analysis of the APK file
def heuristic_analysis(apk_file):
    apk = APK(apk_file) 
    permissions = apk.get_permissions()

    # List of dangerous permissions
    dangerous_permissions = [
        "android.permission.SEND_SMS",  # Sending SMS
        "android.permission.READ_SMS",  # Reading SMS
        "android.permission.CALL_PHONE",  # Making calls
        "android.permission.ACCESS_FINE_LOCATION",  # GPS
        "android.permission.RECORD_AUDIO",  # Microphone access
        "android.permission.CAMERA"  # Camera access
    ]

    # Check for suspicious permissions
    suspicious_permissions = [perm for perm in permissions if perm in dangerous_permissions]

    # Check for potentially malicious activities
    suspicious_activities = []
    if "android.permission.INTERNET" in permissions and "android.permission.READ_CONTACTS" in permissions:
        suspicious_activities.append("Potential data exfiltration: INTERNET and READ_CONTACTS permissions detected.")

    return {
        "suspicious_permissions": suspicious_permissions,
        "suspicious_activities": suspicious_activities
    }

# Function to perform basic APK file analysis
def analyze_apk(file_path):
    # Calculate file hash
    file_hash = calculate_sha256(file_path)

    # Perform heuristic analysis
    analysis_result = heuristic_analysis(file_path)

    # Prepare the scan summary
    scan_summary = {
        "File Path": os.path.abspath(file_path),
        "SHA-256 Hash": file_hash,
        "Suspicious Permissions": analysis_result["suspicious_permissions"] or "None",
        "Suspicious Activities": analysis_result["suspicious_activities"] or "None"
    }

    return scan_summary

# Example Usage
apk_file_path = "path_to_your_apk_file.apk"  # Replace with the actual APK file path
scan_result = analyze_apk(apk_file_path)

# Display the scan result
import json
print(json.dumps(scan_result, indent=4))
