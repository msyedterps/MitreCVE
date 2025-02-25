import argparse
import json
import logging
import os

# Configure logging (more concise)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

PLATFORM_MAPPING = {
    "containers": ["container", "containers", "docker", "podman", "kubernetes"]
}

def normalize_platform(platform):
    return platform.lower() if platform else ""

def process_mitre(json_file_path, platform):  # Removed args parameter as it's not used
    try:
        with open(json_file_path, 'r') as f:
            mitre_data = json.load(f)
    except FileNotFoundError:
        logging.error(f"File not found: {json_file_path}")
        return None
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format in: {json_file_path}")
        return None

    def get_expanded_platforms(target_platform):
        return PLATFORM_MAPPING.get(target_platform, [target_platform])

    def platform_check(mitre_object, target_platform):
        expanded_platforms = get_expanded_platforms(target_platform)
        object_platforms = mitre_object.get("x_mitre_platforms", [])

        if not object_platforms:
            logging.debug(f"Technique {mitre_object.get('name', 'Unknown')} excluded: Missing x_mitre_platforms") # Handle missing name
            return False

        for expanded_platform in expanded_platforms:
            for object_platform in object_platforms:
                if normalize_platform(object_platform) == normalize_platform(expanded_platform):
                    logging.debug(f"Technique {mitre_object.get('name', 'Unknown')} retained due to platform match: {expanded_platform}") # Handle missing name
                    return True

        logging.debug(f"Technique {mitre_object.get('name', 'Unknown')} excluded: No platform match") # Handle missing name
        return False

    filtered_objects = [
        mitre_object
        for mitre_object in mitre_data.get("objects", [])
        if mitre_object.get("type") == "attack-pattern" and platform_check(mitre_object, platform)
    ]  # More concise list comprehension

    if not filtered_objects:
        logging.warning(f"No relevant techniques found for platform {platform}")
        return None

    # Construct the filtered data dictionary (more robust handling of missing fields)
    filtered_data = {
        "objects": filtered_objects,
        "type": mitre_data.get("type", "Unknown"),  # Provide default values
        "id": mitre_data.get("id", "Unknown"),
        "spec_version": mitre_data.get("spec_version", "Unknown")
    }

    return filtered_data


def main():
    parser = argparse.ArgumentParser(description="Process MITRE ATT&CK JSON files for a specific platform.")
    parser.add_argument("json_file_path", help="Path to the MITRE ATT&CK JSON file")
    parser.add_argument("platform", help="Target platform (e.g., containers, Windows, Linux)")
    parser.add_argument("--output_dir", default="output", help="Directory to save processed MITRE ATT&CK data (default: output)")
    args = parser.parse_args()

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True) # Create output directory and avoid error if it already exists

    file_name = os.path.basename(args.json_file_path)
    output_file_path = os.path.join(output_dir, file_name)

    try:
        logging.info(f"Starting MITRE ATT&CK processing for {args.json_file_path}")
        processed_data = process_mitre(args.json_file_path, args.platform) # Removed args parameter

        if processed_data:  # Simplified condition check
            logging.info(f"Found relevant techniques for platform {args.platform}")
            with open(output_file_path, "w") as outfile:
                json.dump(processed_data, outfile, indent=4)
            print(f"Processed data saved to: {output_file_path}")
        else:
            logging.warning(f"No relevant techniques found in {args.json_file_path} for platform {args.platform}")
            print("No relevant techniques found.")

    except Exception as e:
        logging.exception(f"Failed to process MITRE ATT&CK file: {e}")  # Use logging.exception for stack trace
        print(f"Error processing MITRE ATT&CK file: {e}")


if __name__ == "__main__":
    main()
