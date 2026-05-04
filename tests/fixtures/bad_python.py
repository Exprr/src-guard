# Bad Python file
import pickle
import subprocess

API_KEY = "dh6f-78dh-sh34-nd82" # High entropy, should be caught
PLACEHOLDER = "your_api_key_here" # Low entropy, should be ignored

def unsafe_exec(data):
    eval(data) # Medium
    pickle.loads(data) # High
    subprocess.run("ls", shell=True) # High

def logic(x):
    assert x > 0 # Low
    return x
