import datetime
import requests
from tqdm import tqdm

def build_query(opts):
    """
    Builds a URL query string from the given options dictionary.

    This function takes a dictionary of options and constructs a query string that can be appended to a URL.
    Each key-value pair in the dictionary is converted to a query parameter. If the value is `None`, the key-value pair is skipped.
    The resulting query string starts with a '?' followed by the parameters.

    Args:
        opts (dict): A dictionary where keys are parameter names and values are parameter values.

    Returns:
        str: A query string that can be appended to a URL.
    """
    s = ""
    for k, v in opts.items():
        if v is not None:
            s = s + f"&{k}={v}"
    # now replace first & with ? to append to url
    s = '?' + s[1:]
    return s

def download_file(url, location):
    """
    This function downloads a file from a given URL and saves it to a specified location.

    Parameters:
    url (str): The URL of the file to download.
    location (str): The path where the downloaded file should be saved.

    Returns:
    None. The function prints a success message if the file is downloaded successfully. If an error occurs during the download, the function prints an error message.

    Raises:
    requests.exceptions.HTTPError: If an HTTP error occurs.
    requests.exceptions.ConnectionError: If a connection error occurs.
    requests.exceptions.Timeout: If a timeout error occurs.
    requests.exceptions.RequestException: If a request error occurs.
    Exception: If any other error occurs.
    """
    try:
        response = requests.get(url, stream=True, verify=False)
        response.raise_for_status()  # Ensure we got a valid response.

        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024
        t=tqdm(total=total_size, unit='iB', unit_scale=True)

        with open(location, 'wb') as output_file:
            for chunk in response.iter_content(chunk_size=8192):
                t.update(len(chunk))
                output_file.write(chunk)
        t.close()

        print(f"File downloaded successfully at {location}")

    except requests.exceptions.HTTPError as errh:
        print ("Http Error:",errh)
    except requests.exceptions.ConnectionError as errc:
        print ("Error Connecting:",errc)
    except requests.exceptions.Timeout as errt:
        print ("Timeout Error:",errt)
    except requests.exceptions.RequestException as err:
        print ("Something went wrong",err)
    except Exception as e:
        print("An error occured", e)

def format_iso_string(iso: str) -> str:
    """
    Converts an ISO 8601 formatted datetime string to a local datetime string in the format "%Y-%m-%d %H:%M".

    Parameters:
    iso (str): An ISO 8601 formatted datetime string.

    Returns:
    str: A datetime string in the format "%Y-%m-%d %H:%M".
    """    
    iso = iso.replace("Z", "")
    dt = datetime.fromisoformat(iso)
    return dt.strftime("%Y-%m-%d %H:%M")

def process_datetime_fields(data, collection_field='resources', datetime_fields=None):
    """
    Processes datetime fields in a collection within the given data structure.

    Args:
        data (dict): The data containing the collection.
        collection_field (str): The key in the data representing the collection to process.
        datetime_fields (list): A list of field names to process as datetime.

    Returns:
        dict: The data with processed datetime fields.
    """
    if datetime_fields is None:
        datetime_fields = []

    for resource in data.get(collection_field, []):
        for field in datetime_fields:
            if field in resource and resource[field] is not None:
                dt = datetime.datetime.fromisoformat(resource[field].replace("Z", "+00:00"))
                resource[field] = dt.strftime("%Y-%m-%d %H:%M")
    return data

def shorten_id(id_string, stub):
    """
    Shortens a string representation of an ID if it exceeds a length of 10 characters.

    Parameters:
    id_string (str): The ID string to be shortened.
    stub (int): The number of characters to keep at the start and end of the string.

    Returns:
    str: The shortened ID string if its length exceeds 10 characters, otherwise returns the original ID string.

    Example:
    If id_string = "12345678901234" and stub = 3, the function will return "123...234".
    If id_string = "12345" and stub = 3, the function will return "12345" as its length does not exceed 10 characters.
    """
    if len(id_string) > 10:
        shortened = id_string[:stub] + '...' + id_string[-stub:]
        return shortened
    else:
        return id_string

def yes_no_input(prompt):
    """
    Prompts the user for a yes/no response and returns a boolean.

    Args:
        prompt: The prompt to display to the user.

    Returns:
        True if the user enters yes/y, False if no/n.
        Repeats the prompt if the input is invalid.
    """
    while True:
        user_input = input(f"{prompt} (yes/no or y/n): ").lower()
        if user_input in ("yes", "y"):
            return True
        elif user_input in ("no", "n"):
            return False
        else:
            print("Invalid input. Please enter yes, no, y, or n.")
