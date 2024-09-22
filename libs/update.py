import os
import shutil
from git import Repo
import yaml

def load_config():
    config_path = "config.yml"
    if not os.path.isfile(config_path):
        print("Configuration file not found.")
        exit()

    with open(config_path, "r") as file:
        config = yaml.safe_load(file)
        return config

def update_file(config):
    repo_url = config['app']['repository']
    app_dir = config['app']['directory']
    app_exec = config['app']['executable']
    
    temp_repo_dir = 'temp_repo'
    if os.path.isdir(temp_repo_dir):
        shutil.rmtree(temp_repo_dir)
    Repo.clone_from(repo_url, temp_repo_dir)
    
    source_file = os.path.join(temp_repo_dir, app_exec)
    if os.path.isfile(source_file):
        shutil.copy(source_file, app_dir)
        print("Update completed.")
    shutil.rmtree(temp_repo_dir)

def run_update():
    config = load_config()
    update_file(config)
