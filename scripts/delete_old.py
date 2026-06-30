import shutil
from pathlib import Path


def main():
    root_dir = Path(__file__).parent.parent
    folders_to_delete = ["backend", "frontend", "docker"]
    
    print(f"Cleaning up legacy folders in: {root_dir}")
    
    for folder in folders_to_delete:
        folder_path = root_dir / folder
        if folder_path.exists() and folder_path.is_dir():
            print(f"Deleting {folder}...")
            shutil.rmtree(folder_path)
            print(f"Successfully deleted {folder}")
        else:
            print(f"Folder {folder} not found or already deleted.")
            
    print("\nCleanup complete!")

if __name__ == "__main__":
    main()
