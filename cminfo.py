import click
import datetime
import getpass
import json
import requests
import sys
import urllib3
from dotenv import load_dotenv
from rich.table import Table
from rich.console import Console
from rich.text import Text
from rich import print
from tqdm import tqdm  # for file download progress bar



# GLOBALS  --------------------------------------------------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
VERSION = '1.5.1'

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

    response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
    if response.status_code == 200:
        click.echo(click.style(f"Connected: {authdomain}|{username} @ {host}\\{domain}" , fg='green', bold=True))
        print('\n')
        return response.json().get('jwt')
    else:
        print("Failed to authenticate")
        print(response.status_code)
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

def build_query(opts):
    # Ex. form: ?limit=10&algorithm=AES
    s = ""
    for k, v in opts.items():
        if v is not None:
            s = s + f"&{k}={v}"
    # now replace first & with ? to append to url
    s= '?' + s[1:]
    return s

def convert_datetime_fields(data, datetime_fields):
    for resource in data.get('resources', []):  # TODO: parameterize collection field
        for field in datetime_fields:
            if field in resource and resource[field] is not None:
                dt = datetime.datetime.fromisoformat(resource[field].replace("Z", "+00:00"))
                resource[field] = dt.strftime("%Y-%m-%d %H:%M")
    return data

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

# def fill_empty_response(r):
#     empty = json.loads('{"skip":0,"limit":0,"total":0,"resources":[{"id":null,"uri":null,"createdAt":null,"name":null,"updatedAt":null,"activationDate":null,"deactivationDate":null,"state":null,"usage":null,"usageMask":12,"meta":null,"objectType":null,"aliases":[],"sha1Fingerprint":null,"sha256Fingerprint":null,"defaultIV":null,"version":null,"algorithm":null,"size":null,"unexportable":null,"undeletable":null,"neverExported":null,"neverExportable":null,"emptyMaterial":null,"uuid":null,"muid":null,"keyCheckValue":null}]}')
#     if r['resources'] is None:
#         return empty
#     else:
#         return r

def get_resource_limit(host, api, jwt):
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

def iso_to_local(iso):
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

def page_response(resp):
    skip = resp['skip']
    limit = resp['limit']
    total = resp['total']

    while total is None or skip < total:
        #resp = get_data(skip=skip, limit=limit)
        if total is None:
            total = resp['total']

        for resource in resp['resources']:
            print(resource)

        # increment skip by limit for the next page
        skip += limit

def print_table(column_list, resp, key_field=None, field_color_map=None, column_color_map=None):
    """
    This function prints a table of data with colored fields to the console.

    Parameters:
    column_list (list): A list of column names to be included in the table.
    resp (dict): A dictionary containing the data to be printed.
    key_field (str, optional): The key in the resp dictionary containing the data to be printed. If None, all data in resp is printed.
    field_color_map (dict, optional): A dictionary mapping field values to colors. If a field value matches a key in field_color_map, it is printed in the corresponding color.
    column_color_map (dict, optional): A dictionary mapping column names to colors. If a column name matches a key in column_color_map, all values in that column are printed in the corresponding color.

    Outputs:
    This function does not return any value. It prints the data to the console in a table format with colored fields.
    """
    console = Console()
    
    # Create a table with a magenta header.
    table = Table(show_header=True, header_style="bold magenta")
    
    # Add columns to the table based on the provided column list.
    for column in column_list:
        table.add_column(column)
    
    # If a key field is provided and exists in the response, process the items in it.
    if key_field is not None and key_field in resp:
        for item in resp[key_field]:
            # Convert each item in the column list to a string, or " - " if it doesn't exist or exists but is None.
            original_row_data = [str(item[column]) if item.get(column) is not None else " - " for column in column_list]
            # If a field color map or column color map is provided, color the fields.
            if field_color_map or column_color_map:
                colored_row_data = []
                for column, data in zip(column_list, original_row_data):
                    # If a field color map is provided and the item exists in it, use its color.
                    if field_color_map and str(item.get(column)) in field_color_map:
                        color = field_color_map.get(str(item.get(column)))
                    # If a column color map is provided, use its color.
                    elif column_color_map:
                        color = column_color_map.get(column, 'white')
                    # Otherwise, default to white.
                    else:
                        color = 'white'
                    
                    # Color the data and add it to the colored row data.
                    colored_data = f"[{color}] {data} [/{color}]"
                    colored_row_data.append(colored_data)
                
                # Add the colored row data to the table.
                table.add_row(*colored_row_data)
            else:
                # If no color maps are provided, add the original row data to the table.
                table.add_row(*original_row_data)
    
    # Print the table to the console.
    console.print(table)

def print_totals(resp):
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


# CLI  ------------------------------------------------------------------------
@click.version_option(version=VERSION, prog_name='cminfo')
@click.group()
@click.pass_context
@click.option('-h', '--host', prompt=True, help='CipherTrust node FQDN or IP', envvar='CM_HOST')
@click.option('-u', '--username', prompt=True, help='Username', default='admin', envvar='CM_USER')
@click.option('-p', '--password', prompt=True, hide_input=True, help='Password', envvar='CM_PW')
@click.option('-d', '--domain', prompt=True, help='Domain', default='root', envvar='CM_DOMAIN')
@click.option('-a', '--authdomain', prompt=True, help='Authentication domain', default='root', envvar='CM_AUTHDOMAIN')
@click.option('--debug', is_flag=True, default=False)
def cli(ctx, host, username, password, domain, authdomain, debug):
    ctx.ensure_object(dict)

    if debug:
        click.echo(click.style(f"CLI HOST: {host}\n" , fg='yellow', bold=True))

    ctx.obj['host'] = host
    ctx.obj['jwt'] = authenticate(host, username, password, domain, authdomain)
    
    if ctx.obj['jwt'] is None:
        again = yes_no_input("Do you want to reauthenticate?")
        if again:
            host = input("Host: ")
            username = input("User: ")
            password =  getpass.getpass("Password (hidden): ")
            domain = input("Domain: ")
            authdomain = input("Auth Domain: ")
            ctx.obj['jwt'] = authenticate(host, username, password, domain, authdomain)
        else:
            click.echo(click.style("Exiting...\n" , fg='red', bold=True))
            sys.exit(0)

    if debug:
        click.echo(click.style(f"AUTH JWT: {ctx.obj['jwt']}\n" , fg='yellow', bold=True))

# CLI:ALARM  --------------------------------------------------------------------
@cli.group()
@click.pass_context
def alarm(ctx):
    pass

# CLI:ALARM:LIST
@alarm.command()
@click.pass_context
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of objects to show', default='20', envvar='CM_LIMIT')
@click.option('--state', type=click.Choice(['on', 'off'], case_sensitive=False))
@click.option('--severity', type=click.Choice(['info', 'warning', 'error', 'critical'], case_sensitive=False))
def list(ctx, limit, state, severity):
    opts = dict([('limit', limit), ('state', state), ('severity', severity)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/system/alarms{query}')
    if resp['total'] > 0:
        print_totals(resp)

        field_color_map = {
            'on': 'green',
            'off': 'red',
            'info': 'cyan',
            'warning': 'yellow',
            'error': 'red',
            'critical': 'red',
            'True': 'green',
            'False': 'red'
        }
        datetime_fields = ["triggeredAt"]
        resp = convert_datetime_fields(resp, datetime_fields)
        resp = flatten_entries(resp, 'details')
        column_list=['triggeredAt','state','severity', 'name', 'message', 'success', 'username', 'client_ip']
        print_table(column_list, resp, 'resources', field_color_map, None)
    else:
        click.echo(click.style("no matching resources", fg='yellow', bold=True))

# CLI:DOWNLOAD  --------------------------------------------------------------------
@cli.group()
def download():
    pass

# CLI:DOWNLOAD:KSCTL
@download.command()
@click.option('-h', '--host', prompt='Host name', help='Download from this CipherTrust node', envvar='CM_HOST')
@click.option('-p', '--path', prompt='Full download location including file name', help='Download file to this directory', default='./ksctl.zip')
def ksctl(host, path):
    download_file(f'https://{host}/downloads/ksctl_images.zip', path)

# CLI:KEY  --------------------------------------------------------------------
@cli.group()
@click.pass_context
def key(ctx):
    pass

# CLI:KEY:LIST
@key.command()
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of objects to show', default='20', envvar='CM_LIMIT')
@click.option('-s', '--state', type=click.Choice(['Pre-Active','Active','Deactivated','Destroyed','Compromised','Destroyed Compromised'], case_sensitive=False))
@click.option('-a', '--type', type=click.Choice(['AES', 'RSA', 'EC', 'OPAQUE'], case_sensitive=False))
@click.option('--sort', type=click.Choice(['name', 'version', 'state', 'algorithm', 'exportable', 'deletable'], case_sensitive=False))
@click.option('--latest', is_flag=True, default=False, help='Show only the latest key version')
@click.pass_context
def list(ctx, limit, state, type, sort, latest):
    # /v1/vault/keys2?limit=10&algorithm=AES
    if latest:
        opts = dict([('limit', limit), ('state', state), ('algorithm', type), ('version', '-1')])
    else:
        opts = dict([('limit', limit), ('state', state), ('algorithm', type)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/vault/keys2{query}')

    if resp['total'] > 0:
        print_totals(resp)

        if sort is None:
            sort = 'name'
        if sort == 'exportable' or sort == 'deletable':
            sort = 'un' + sort
        resp = sort_response_keys(resp, 'resources', sort)

        column_list = ["name", "version", "state", "algorithm", "unexportable", "undeletable", "labels"]
        field_color_map = {
                'Active': 'green',
                'Pre-Active': 'cyan',
                'Deactivated': 'yellow',
                'Destroyed': 'red',
                'Compromised': 'red',
                'Destroyed Compromised': 'red',
                'True': 'green',
                'False': 'red'
        }

        # Process and format the 'labels' field for output
        for resource in resp['resources']:
            labels = resource.get('labels', {})
            if labels:
                formatted_labels = ', '.join([f'{k}={v}' for k, v in labels.items()])
            else:
                formatted_labels = ' - '
            resource['labels'] = formatted_labels
        # data extraction done, now print the results
        print_table(column_list, resp, 'resources', field_color_map, None)
    else:
        click.echo(click.style("no matching resources", fg='yellow', bold=True))

# CLI:KEY:DATES
@key.command()
@click.pass_context
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of objects to show', default='20', envvar='CM_LIMIT')
@click.option('-s', '--state', type=click.Choice(['Pre-Active','Active','Deactivated','Destroyed','Compromised','Destroyed Compromised'], case_sensitive=False))
@click.option('-t', '--type', type=click.Choice(['AES', 'RSA', 'EC', 'OPAQUE'], case_sensitive=False))
def dates(ctx, limit, state, type):
    opts = dict([('limit', limit), ('state', state), ('algorithm', type)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/vault/keys2{query}')
    if resp['total'] > 0:
        print_totals(resp)

        datetime_fields = ["createdAt", "updatedAt", "activationDate", "deactivationDate", "compromiseDate"]
        resp = convert_datetime_fields(resp, datetime_fields)

        column_list = ["name", "version", "createdAt", "updatedAt", "activationDate", "deactivationDate", "compromiseDate"]

        field_color_map = None
        column_color_map={
            "activationDate": "green",
            "updatedAt": "yellow",
            "deactivationDate": "red",
            "compromiseDate": "red"
        }

        print_table(column_list, resp, 'resources', field_color_map, column_color_map)
    else:
        click.echo(click.style("no matching resources", fg='yellow', bold=True))

# CLI:KEY:LABELS
@key.command()
@click.pass_context
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of objects to show', default='20', envvar='CM_LIMIT')
def labels(ctx, limit):
    opts = dict([('limit', limit)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/vault/key-labels{query}')
    print_totals(resp)

    console = Console()
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Label")
    table.add_column("Value")

    if resp['resources'] is None:
        table.add_row('-','-')
    else:
        for resource in resp['resources']:  # returns array of json docs
            for key, value in resource.items():
                table.add_row(key, resource[key])
    console.print(table)

# CLI:USER  -------------------------------------------------------------------
@cli.group()
@click.pass_context
def user(ctx):
    pass

# CLI:USER:INACTIVE
@user.command()
@click.pass_context
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of objects to show', default='20', envvar='CM_LIMIT')
@click.option('-d', '--days', prompt='Last login window in days', help='Consider inactive if not logged in during this window', default='30')
def inactive(ctx, limit, days):
    opts = dict([('limit', limit)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/usermgmt/users{query}')
    datetime_fields = ["created_at", "updated_at", "last_login", "last_failed_login_at", "password_changed_at"]
    resp = convert_datetime_fields(resp, datetime_fields)
    resp = filter_by_date(resp, int(days))
    print_totals(resp)
    
    column_list = ["name", "user_id", "logins_count", "failed_logins_count", "last_login", "last_failed_login_at", "password_changed_at"]
    column_color_map = {
            'last_failed_login_at': 'red',
            'password_changed_at': 'yellow'
    }
    print_table(column_list, resp, 'resources', None, column_color_map)

# CLI:USER:LOGINS
@user.command()
@click.pass_context
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of objects to show', default='20', envvar='CM_LIMIT')
def logins(ctx, limit):
    opts = dict([('limit', limit)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/usermgmt/users{query}')
    print_totals(resp)

    datetime_fields = ["created_at", "updated_at", "last_login", "last_failed_login_at", "password_changed_at"]
    resp = convert_datetime_fields(resp, datetime_fields)

    column_list = ["name", "user_id", "logins_count", "failed_logins_count", "last_login", "last_failed_login_at", "password_changed_at"]
    column_color_map = {
            'last_failed_login_at': 'red',
            'password_changed_at': 'yellow'
    }
    print_table(column_list, resp, 'resources', None, column_color_map)

# CLI:SCHEDULE  --------------------------------------------------------------------
@cli.group()
@click.pass_context
def schedule(ctx):
    pass

# CLI:SCHEDULE:LIST
@schedule.command()
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of objects to show', default='20', envvar='CM_LIMIT')
@click.option('--sort', type=click.Choice(['name', 'version', 'state', 'algorithm', 'exportable', 'deletable'], case_sensitive=False))
@click.pass_context
def list(ctx, limit, sort):
    opts = dict([('limit', limit)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/scheduler/job-configs{query}')
    # resp = flatten_entries(resp, 'job_config_params')

    if resp['total'] > 0:
        print_totals(resp)

        if sort is None: sort = 'name'
        if sort == 'exportable' or sort == 'deletable': sort = 'un'+sort
        resp = sort_response_keys(resp, 'resources', sort)

        column_list = ["operation", "name", "run_at", "run_on", "disabled"]
        field_color_map = {
                'True': 'green',
                'False': 'red'
        }
        print_table(column_list, resp, 'resources', field_color_map, None)
    else:
        click.echo(click.style("no matching schedule configs", fg='yellow', bold=True))

# CLI:SERVICE  --------------------------------------------------------------------
@cli.group()
@click.pass_context
def service(ctx):
    pass

# CLI:SERVICE:LIST
@service.command()
@click.pass_context
def list(ctx):
    resp = api_get_noauth(ctx.obj['host'], '/v1/system/services/status')
    resp = sort_response_keys(resp, 'services', 'name')
    column_list = ["name", "status"]
    color_map = {
        "started": "green",
        "starting": "yellow",
        "disabled": "red",
        "error": "red"
    }
    print_table(column_list, resp, 'services', color_map, None)

# CLI:SYSTEM  --------------------------------------------------------------------
@cli.group()
@click.pass_context
def system(ctx):
    pass

# CLI:SYSTEM:INFO
@system.command()
@click.pass_context
def info(ctx):
    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api='/v1/system/info')

    table = Table(show_header=False)

    table.add_column("Key", style="cyan")
    table.add_column("Value")

    table.add_row('node', Text(ctx.obj['host'], style='yellow'))
    for key, value in resp.items():
        table.add_row(key, str(value))

    console = Console()
    console.print(table)

# MAIN  -----------------------------------------------------------------------
if __name__ == '__main__':
    load_dotenv()
    cli(obj={})