from huggingface_hub import snapshot_download
import os
import tarfile

# ==========================
# Change these values
# ==========================
DATASET_GROUP = "arvo"
TASK_ID = "34138"

# Where the dataset files will be downloaded
LOCAL_DIR = os.path.expanduser("~/cybergym_data")

# HuggingFace dataset name
REPO_ID = "sunblaze-ucb/cybergym"


def extract_tar(tar_path, extract_to):
    """
    Extracts a .tar.gz file into a given folder.
    """
    if not os.path.exists(tar_path):
        print(f"ERROR: Could not find {tar_path}")
        return

    os.makedirs(extract_to, exist_ok=True)

    print(f"Extracting {tar_path} into {extract_to}...")

    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path=extract_to)

    print("Done extracting.")


def main():
    # Example path:
    # data/arvo/781/*
    task_pattern = f"data/{DATASET_GROUP}/{TASK_ID}/*"

    print(f"Downloading CyberGym task: {DATASET_GROUP}/{TASK_ID}")
    print(f"Saving into: {LOCAL_DIR}")

    snapshot_download(
        repo_id=REPO_ID,
        repo_type="dataset",
        local_dir=LOCAL_DIR,
        allow_patterns=[task_pattern]
    )

    # Full path to the downloaded task folder
    task_dir = os.path.join(LOCAL_DIR, "data", DATASET_GROUP, TASK_ID)

    if not os.path.exists(task_dir):
        print(f"ERROR: Task folder was not found: {task_dir}")
        return

    print("\nDownloaded files:")
    for filename in os.listdir(task_dir):
        print(" ", filename)

    # Paths to tar files
    repo_vul_tar = os.path.join(task_dir, "repo-vul.tar.gz")
    repo_fix_tar = os.path.join(task_dir, "repo-fix.tar.gz")

    # Output folders
    vulnerable_dir = os.path.join(task_dir, "vulnerable")
    fixed_dir = os.path.join(task_dir, "fixed")

    # Create folders
    os.makedirs(vulnerable_dir, exist_ok=True)
    os.makedirs(fixed_dir, exist_ok=True)

    # Extract tar files
    print("\nExtracting repositories...")
    extract_tar(repo_vul_tar, vulnerable_dir)
    extract_tar(repo_fix_tar, fixed_dir)

    print("\nFinished setup.")
    print(f"Task folder: {task_dir}")
    print(f"Vulnerable repo: {vulnerable_dir}")
    print(f"Fixed repo: {fixed_dir}")


if __name__ == "__main__":
    main()