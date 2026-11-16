import os

def load_template_file(root_dir, rel_path):
    # Vulnerable: string concatenation allows ../ traversal
    full_path = root_dir + '/' + rel_path
    with open(full_path, 'r', encoding='utf-8') as f:
        return f.read()
