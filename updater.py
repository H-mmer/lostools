# updater.py

"""
Module for updating the tool from a remote repository.
"""

import os
import sys
import subprocess
import yaml
import shutil
from git import Repo
from colorama import Fore, Style
from utils import clear_screen
from color import Color

def run_update():
    """
    Checks for updates and updates the tool if a newer version is available.
    """
    def load_config():
        config_path = "config.yml"
        if not os.path.isfile(config_path):
            print(Color.YELLOW + "[!] Configuration file not found.")
            exit()

        with open(config_path, "r") as file:
            try:
                config = yaml.safe_load(file)
            except Exception as e:
                print(Color.YELLOW + f"[!] Error loading configuration file: {e}")
                exit()

        global appIdentifier, appRepo, appDir, appExecName
        try:
            appIdentifier = config['app']['identifier']
            appRepo = config['app']['repository']
            appDir = config['app']['directory']
            appExecName = config['app']['executable']
        except KeyError as e:
            print(Color.YELLOW + f"[!] Missing key in configuration file: {e}")
            exit()

        if not os.path.isdir(appDir):
            print(Color.YELLOW + f"[!] The directory specified in config.yml does not exist: {appDir}")
            exit()

    def get_remote_version(repo_url):
        try:
            repo = Repo.clone_from(repo_url, 'temp_repo', depth=1)
            latest_commit = repo.head.commit
            shutil.rmtree('temp_repo')
            return latest_commit.hexsha
        except Exception as e:
            print(Color.YELLOW + f"[!] Error accessing remote repository: {e}")
            exit()

    def get_local_version(file_path):
        if os.path.isfile(file_path):
            return os.popen(f"git log -1 --format=%H {file_path}").read().strip()
        return None

    def update_file():
        try:
            print(Color.GREEN + "[i] Updating file...")
            temp_repo_dir = 'temp_repo'
            if os.path.isdir(temp_repo_dir):
                shutil.rmtree(temp_repo_dir)
            Repo.clone_from(appRepo, temp_repo_dir)
            source_file = os.path.join(temp_repo_dir, appExecName)
            if os.path.isfile(source_file):
                shutil.copy(source_file, appDir)
                print(Color.GREEN + "[i] Update completed.")
                clear_screen()
            else:
                print(Color.YELLOW + "[!] File to update not found in the repository.")
            shutil.rmtree(temp_repo_dir) 
        except Exception as e:
            print(Color.RED + f"[!] Error during update: {e}")
            exit()

    def run():
        load_config()
        local_version = get_local_version(os.path.join(appDir, appExecName))
        remote_version = get_remote_version(appRepo)

        if local_version != remote_version:
            print(Color.GREEN + "[i] An update is available.")
            update_file()
        else:
            print(Color.YELLOW + "[i] No update is needed.")

    if __name__ == "__main__":
        run()
