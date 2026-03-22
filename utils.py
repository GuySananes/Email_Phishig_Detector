def load_email(path):
    """
    Reads the email content from a text file.
    Returns the content as a string, or None if the file is not found.
    """
    try:
        with open(path, 'r', encoding='utf-8') as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: Could not find the file at '{path}'")
        return None