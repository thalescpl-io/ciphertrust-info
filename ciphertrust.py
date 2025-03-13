import click
import datetime
import json
import requests
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException
from rich import print
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning, MaxRetryError, NewConnectionError, SSLError



# GLOBALS  --------------------------------------------------------------------
disable_warnings(InsecureRequestWarning)

# FUNCTIONS  ------------------------------------------------------------------
def authenticate(host, username, password, domain, authdomain):
    """
    Authenticate the user using the provided credentials and returns a jwt token

    Parameters:
    host (str): The host URL
    username (str): The username
    password (str): The password
    domain (str): The domain
    authdomain (str): The authentication domain

    Returns:
    str: The jwt token if authentication is successful, None otherwise
    """
    
    url = f"https://{host}/api/v1/auth/tokens"
    headers = {'Content-Type': 'application/json'}
    data = {
        "grant_type": "password",
        "username": username,
        "password": password,
        "domain": domain,
        "auth_domain": authdomain
    }
    
    try:
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        response.raise_for_status()
        
        if response.status_code == 200:
            click.echo(click.style(f"Connected: {authdomain}|{username} @ {host}\\{domain}" , fg='green', bold=True))
            print('\n')
            return response.json().get('jwt')
        else:
            click.echo(click.style("Failed to authenticate\n" , fg='red', bold=True))
            print(response.status_code)
            return None
    except HTTPError as http_err:
        click.echo(click.style(f"HTTP error occurred:\n{http_err}\n", fg='red', bold=True))
    except ConnectionError as conn_err:
        click.echo(click.style(f"Connection error occurred:\n{conn_err}\n", fg='red', bold=True))
    except Timeout as timeout_err:
        click.echo(click.style(f"Timeout error occurred:\n{timeout_err}\n", fg='red', bold=True))
    except NewConnectionError as new_conn_err:
        click.echo(click.style(f"New connection error occurred:\n{new_conn_err}\n", fg='red', bold=True))
    except MaxRetryError as max_retry_err:
        click.echo(click.style(f"Max retry error occurred:\n{max_retry_err}\n", fg='red', bold=True))
    except SSLError as ssl_err:
        click.echo(click.style(f"SSL error occurred:\n{ssl_err}\n", fg='red', bold=True))
    except RequestException as req_err:
        click.echo(click.style(f"Request exception occurred:\n{req_err}\n", fg='red', bold=True))
    except Exception as ex:
        click.echo(click.style(f"An unexpected error occurred:\n{ex}\n", fg='red', bold=True))
    
    return None

    # authenticate

def api_get_noauth(host, api):
    """
    Sends a GET request to the specified API and returns the response data

    Parameters:
    host (str): The host URL
    api (str): The endpoint of the API

    Returns:
    dict: The response data if the request is successful, None otherwise
    """

    url = f"https://{host}/api/{api}"
    response = requests.get(url, verify=False)

    if response.status_code == 200:
        return response.json()
    else:
        print("Failed to get data from API")
        print(response.status_code)
        return None
    # api_get_noauth

def api_get(host, api, jwt):
    """
    This function sends a GET request to a specified API and returns the response.

    Parameters:
    host (str): The host of the API.
    api (str): The endpoint of the API.
    jwt (str): The JSON Web Token for authentication.

    Returns:
    dict or None: If the GET request is successful, it returns the JSON response as a dictionary. If the request fails, it prints an error message and returns None.
    """
    url = f"https://{host}/api{api}"
    headers = {'Authorization': f'Bearer {jwt}'}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print("Failed to get data from API")
        print(response.status_code)
        return None
    # api_get

def filter_by_date(response, days):
    """
    Filters resources in the response based on a date threshold.

    Parameters:
    response (dict): The dictionary containing resources to filter.
    days (int): The number of days to use as a threshold for filtering.

    Returns:
    dict: A new dictionary containing only the resources that meet the date criteria.
    """
    # Calculate the target date by subtracting 'days' from the current date
    target_date = datetime.datetime.now() - datetime.timedelta(days=days)
    click.echo(click.style(f"Inactive since: {target_date.strftime("%Y-%m-%d %H:%M")}:", fg='yellow', bold=True))
    filtered_resources = []
    
    for resource in response.get('resources', []):
        last_login_str = resource.get('last_login')
        if last_login_str is None:
            # If last_login is None, include the resource
            filtered_resources.append(resource)
        else:
            try:
                last_login = datetime.datetime.strptime(last_login_str, "%Y-%m-%d %H:%M")
                # Check if last_login is outside the target date range
                if last_login <= target_date:
                    filtered_resources.append(resource)
            except ValueError as e:
                print(f"Error parsing date: {e} for resource: {resource}")
    
    # Create a new response object with the filtered resources and maintain the original structure
    new_response = response.copy()
    new_response['resources'] = filtered_resources
    new_response['total'] = len(new_response['resources'])
    return new_response

def flatten_entries(data, subfield):
    """
    This function flattens the nested 'details' dictionaries in the 'resources' list of the input data dictionary.
    
    Parameters:
    data (dict): The input data dictionary. It should contain a <subfield> key with a list of dictionaries. Each dictionary in the <subfield> list can optionally contain a 'details' key with a nested dictionary.
    subfield (str): The string name of a sub data element. 
    Returns:
    dict: A copy of the input data dictionary, but with the 'details' dictionaries in the 'resources' list flattened. If a 'details' dictionary contains a key that already exists in the parent dictionary, the key-value pair from the 'details' dictionary is ignored.
    """    
    flattened_data = data.copy()  # Start with a copy of the data
    flattened_resources = []
    for resource in data.get('resources', []):
        flattened_resource = resource.copy()  # Start with a copy of the resource
        details = flattened_resource.pop(subfield, {})  # Remove 'details' from the resource
        for key, value in details.items():
            if key not in flattened_resource:  # Only add detail if the key doesn't conflict
                flattened_resource[key] = value
        flattened_resources.append(flattened_resource)
    flattened_data['resources'] = flattened_resources  # Replace 'resources' in the data with the flattened resources
    return flattened_data

def get_ca_subject(host, jwt, id, type='local'):
    """
    Retrieves the subject of a certificate authority (CA) based on the provided ID and type.

    Parameters:
    host (str): The host URL of the API.
    jwt (str): The JSON Web Token for authentication.
    id (str): The unique identifier of the CA.
    type (str): The type of CA, either 'local' or 'external'. Default is 'local'.

    Returns:
    str: The subject of the certificate authority if the request is successful.
    None: If the request fails, it returns None and prints an error message.

    The function sends a GET request to the specified API endpoint and returns
    the subject of the CA. If the request fails, it prints the status code of the response.

    API Endpoint:
    - For local CA: /v1/ca/local-cas/{id}
    - For external CA: /v1/ca/external-cas/{id}
    """
    if type == 'local':
        api = f'/v1/ca/local-cas/{id}'
    if type == 'external':
        api = f'/v1/ca/external-cas/{id}'
    url = f"https://{host}/api{api}"
    headers = {'Authorization': f'Bearer {jwt}'}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return str(response.json().get('subject'))
    else:
        click.echo(click.style("Failed to get certificate authority subject\n" , fg='yellow', bold=True))
        click.echo(click.style(f"{response.status_code}\n" , fg='yellow', bold=True))
        return None
    # get_ca_name

def get_client_groups(host, jwt, client_id):
    """
    Retrieves the client groups a specific client is a member of.

    Parameters:
    host (str): The host URL of the API.
    jwt (str): The JSON Web Token for authentication.
    client_id (str): The unique identifier of the client.

    Returns:
    list: A list of client group names that the client is a member of. Returns an empty list if the client is not a member of any groups.

    The function sends a GET request to the specified API endpoint to retrieve client group information. 
    If the response indicates that the client is a member of any groups, their names are extracted and returned.
    """
    member_of = []
    api = f"/v1/transparent-encryption/clients/{client_id}/clientgroups"

    resp = api_get(host, api, jwt)
    if resp['total'] > 0:
        for resource in resp['resources']:
            member_of.append(resource['name'])
    return member_of

def get_resource_limit(host, api, jwt):
    """
    Retrieves the total number of resources available from a specified API endpoint.

    Parameters:
    host (str): The host URL of the API.
    api (str): The specific API endpoint to query.
    jwt (str): The JSON Web Token for authentication.

    Returns:
    str: The total number of resources as a string if the request is successful.
    None: If the request fails, it returns None and prints an error message.

    The function sends a GET request to the specified API endpoint. If the request is successful,
    it extracts and returns the 'total' number of resources from the JSON response. If the request
    fails, it prints an error message and the status code of the response.
    """
    url = f"https://{host}/api{api}"
    headers = {'Authorization': f'Bearer {jwt}'}
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        return str(response.json().get('total'))
    else:
        print("Failed to get data from API")
        print(response.status_code)
        return None
    # get_resource_limit

def print_totals(resp):
    """
    Print the total number of resources shown versus available in the response.

    This function compares the 'limit' value in the response dictionary to the 'total' value,
    and prints how many resources are currently being shown out of the total available resources.

    Parameters:
    resp (dict): A dictionary containing the response data with 'limit' and 'total' fields.

    Outputs:
    Prints the number of resources being shown out of the total available to the console.

    Example:
    If resp has 'limit' = 20 and 'total' = 100, it will print: "Showing 20 of 100".
    If resp has 'limit' = 150 and 'total' = 100, it will print: "Showing 100 of 100".
    """
    if resp['limit'] <= resp['total']:
        print(f"Showing {resp['limit']} of {resp['total']}")
    else:
        print(f"Showing {resp['total']} of {resp['total']}")

def sort_response_keys(resp, collection, sort_field):
    if collection is None:
        return resp
    else:
        resp[collection] = sorted(resp[collection], key=lambda x: x[sort_field])
        return resp
