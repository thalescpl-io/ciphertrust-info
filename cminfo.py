import click
import json
from ciphertrust import authenticate
from ciphertrust import api_get_noauth
from ciphertrust import api_get
from ciphertrust import filter_by_date
from ciphertrust import flatten_entries
from ciphertrust import get_ca_subject
from ciphertrust import get_client_groups
from ciphertrust import print_totals
from ciphertrust import sort_response_keys
from dotenv import load_dotenv
from getpass import getpass
from rich.table import Table
from rich.console import Console
from rich.text import Text
from rich import print
from sys import exit
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning, MaxRetryError, NewConnectionError, SSLError
from utils import build_query
from utils import download_file
from utils import process_datetime_fields
from utils import shorten_id
from utils import yes_no_input


# GLOBALS  --------------------------------------------------------------------
disable_warnings(InsecureRequestWarning)
VERSION = '2.0.1'

# FUNCTIONS  ------------------------------------------------------------------
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

def print_binaries_table(response_data, column_list, color_map):
    """
    Prints a table of authorization binaries with colored fields to the console.

    Parameters:
    response_data (dict): A dictionary containing the response data with an 'auth_binaries' field.
    column_list (list): A list of column names to be included in the table.
    color_map (dict): A dictionary mapping field values to colors. If a field value matches a key in color_map, it is printed in the corresponding color.

    Raises:
    ValueError: If the response_data does not contain an 'auth_binaries' field or is not a dictionary.

    Outputs:
    This function does not return any value. It prints the data to the console in a table format with colored fields.

    The function processes the 'auth_binaries' field in the response_data, which is expected to be a JSON string representing a list of dictionaries. 
    It parses this JSON string and adds each item to the table, coloring the fields according to the provided color_map. 
    If there is an error decoding the JSON string, it prints an error message to the console.
    """
    # Ensure the response structure is correct
    if not isinstance(response_data, dict) or 'auth_binaries' not in response_data:
        raise ValueError("Response object must contain an 'auth_binaries' field.")
    
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")

    for column in column_list:
        table.add_column(column)
    
    auth_binaries = response_data.get('auth_binaries', '')
    if auth_binaries:
        try:
            auth_binaries_data = json.loads(auth_binaries)
            for item in auth_binaries_data:
                row = []
                for column in column_list:
                    value = str(item.get(column, ''))
                    color = color_map.get(value, 'white')
                    row.append(f"[{color}]{value}[/{color}]")
                table.add_row(*row)
        except json.JSONDecodeError:
            console.print("[red]Error decoding auth_binaries[/red]")
    console.print(table)


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
    
    while ctx.obj['jwt'] is None:
        again = yes_no_input("Do you want to reauthenticate?")
        if again:
            host = input("Host: ")
            username = input("User: ")
            password =  getpass("Password (hidden): ")
            domain = input("Domain: ")
            authdomain = input("Auth Domain: ")
            ctx.obj['jwt'] = authenticate(host, username, password, domain, authdomain)
        else:
            click.echo(click.style("Exiting...\n" , fg='red', bold=True))
            exit(0)

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
        resp = process_datetime_fields(data=resp, collection_field='resources', datetime_fields=datetime_fields)
        resp = flatten_entries(resp, 'details')
        column_list=['triggeredAt','state','severity', 'name', 'message', 'success', 'username', 'client_ip']
        print_table(column_list, resp, 'resources', field_color_map, None)
    else:
        click.echo(click.style("no matching resources", fg='yellow', bold=True))


# CLI:CTE  --------------------------------------------------------------------
@cli.group()
@click.pass_context
def cte(ctx):
    pass

@cte.group()
@click.pass_context
def client(ctx):
    pass

# CLI:CTE:CLIENT:LIST
@client.command()
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of clients to show', default='10', envvar='CM_LIMIT')
@click.pass_context
def list(ctx, limit):
    opts = dict([('limit', limit)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/transparent-encryption/clients{query}')
    if resp['total'] > 0:
        column_list = ["client_health_status", "name", "client_version", "os_type", "enabled_capabilities", "protection_mode", "profile_name", "client_groups", "id"]
        field_color_map = {
                'True': 'green',
                'False': 'red',
                'HEALTHY': 'green',
                'UNREGISTERED': 'yellow'
        }

        for resource in resp['resources']:
            client_group_list = get_client_groups(
                host=ctx.obj['host'], 
                jwt=ctx.obj['jwt'],
                client_id=resource['id']
                )
            resource['client_groups'] = client_group_list
        # data extraction done, now print the results
        print_totals(resp)
        print_table(column_list, resp, 'resources', field_color_map, None)
    else:
        click.echo(click.style("no matching resources", fg='yellow', bold=True))

# CLI:CTE:CLIENT:HEALTH
@client.command()
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of clients to show', default='10', envvar='CM_LIMIT')
@click.pass_context
def health(ctx, limit):
    opts = dict([('limit', limit)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/transparent-encryption/clients{query}')
    if resp['total'] > 0:
        column_list = ["client_health_status", "name", "num_errors", "num_warnings", "num_gp_errors", "errors", "warnings", "gp_errors"]
        field_color_map = {
                'True': 'green',
                'False': 'red',
                'HEALTHY': 'green',
                'UNREGISTERED': 'yellow', 
                'UNHEALTHY': 'red',
                'OFFLINE': 'red'
        }

        # data extraction done, now print the results
        print_totals(resp)
        print_table(column_list, resp, 'resources', field_color_map, None)
    else:
        click.echo(click.style("no matching resources", fg='yellow', bold=True))

# CLI:CTE:CLIENT:AUTH
@client.command()
@click.option('-c', '--client', prompt='Client name', help='client name or identifier', required=True)
@click.pass_context
def auth(ctx, client):
    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/transparent-encryption/clients/{client}')
    column_list = ["privilege", "filename"]
    field_color_map = {
            'True': 'green',
            'False': 'red',
            'lock': 'red',
            'exempt': 'yellow',
            'authenticator': 'cyan',
            'authenticator_euid': 'magenta'
    }
    print_binaries_table(resp, column_list, field_color_map)


# CLI:CTE:GUARDPOINTS
@cte.command()
@click.option('-c', '--client', prompt='Client name', help='client name or identifier', required=True)
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of clients to show', default='10', envvar='CM_LIMIT')
@click.pass_context
def guardpoints(ctx, client, limit):
    opts = dict([('limit', limit)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/transparent-encryption/clients/{client}/guardpoints{query}')
    if resp['total'] > 0:
        column_list = ["guard_enabled", "guard_point_state", "guard_path", "policy_name", "guard_point_type", "automount_enabled", "cifs_enabled", "mfa_enabled", "early_access"]
        field_color_map = {
                'True': 'green',
                'False': 'red'
        }

        # data extraction done, now print the results
        click.echo(click.style(f"Guardpoints on {client}", fg='yellow', bold=True))
        print_totals(resp)
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

# CLI:INTERFACE  --------------------------------------------------------------------
@cli.group()
@click.pass_context
def interface(ctx):
    pass

# CLI:INTERFACE:LIST
@interface.command()
@click.option('-t', '--type', type=click.Choice(['kmip', 'nae', 'ssh', 'web'], case_sensitive=False))
@click.option('--sort', type=click.Choice(['port', 'interface_type', 'enabled', 'minimum_tls_version'], case_sensitive=False))
@click.pass_context
def list(ctx, type, sort):
    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/configs/interfaces')
    if resp['total'] > 0:
        if sort is None:
            sort = 'port'
        resp = sort_response_keys(resp, 'resources', sort)
        
        column_list = ["port", "interface_type", "enabled", "mode", "minimum_tls_version", "cert_user_field", "trusted_cas"]
        field_color_map = {
                'True': 'green',
                'False': 'red',
                'no-tls-pw-opt': 'red',
                'no-tls-pw-req': 'red',
                'unauth-tls-pw-opt': 'red'
        }

        # Get subject strings for trusted CAs
        for resource in resp['resources']:
            ca_dict = resource.get('trusted_cas', {})
            
            formatted_cas = []
            # Process local CAs
            local_cas = ca_dict.get('local', [])
            for ca in local_cas:
                subject = get_ca_subject(ctx.obj['host'], ctx.obj['jwt'], ca, type='local')
                formatted_cas.append(subject)

            # Process external CAs
            external_cas = ca_dict.get('external', [])
            for ca in external_cas:
                subject = get_ca_subject(ctx.obj['host'], ctx.obj['jwt'], ca, type='external')
                formatted_cas.append(subject)

            # Handle case where no CAs found
            if not formatted_cas:
                formatted_cas.append('')

            resource['trusted_cas'] = formatted_cas

        # data extraction done, now print the results
        print_totals(resp)
        print_table(column_list, resp, 'resources', field_color_map, None)
    else:
        click.echo(click.style("no matching resources", fg='yellow', bold=True))


# CLI:KEY  --------------------------------------------------------------------
@cli.group()
@click.pass_context
def key(ctx):
    pass

# CLI:KEY:IDS
@key.command()
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of objects to show', default='10', envvar='CM_LIMIT')
@click.option('-t', '--truncate', help='only show first and last X characters (default 8)', default=8)
@click.option('-s', '--state', type=click.Choice(['Pre-Active','Active','Deactivated','Destroyed','Compromised','Destroyed Compromised'], case_sensitive=False))
@click.option('-a', '--type', type=click.Choice(['AES', 'RSA', 'EC', 'OPAQUE'], case_sensitive=False))
@click.option('--sort', type=click.Choice(['name', 'version', 'state', 'algorithm', 'exportable', 'deletable'], case_sensitive=False))
@click.option('--latest', is_flag=True, default=False, help='Show only the latest key version')
@click.pass_context
def ids(ctx, limit, truncate, state, type, sort, latest):
    if latest:
        opts = dict([('limit', limit), ('state', state), ('algorithm', type), ('version', '-1')])
    else:
        opts = dict([('limit', limit), ('state', state), ('algorithm', type)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/vault/keys2{query}')

    if resp['total'] > 0:
        if sort is None:
            sort = 'name'
        if sort == 'exportable' or sort == 'deletable':
            sort = 'un' + sort
        resp = sort_response_keys(resp, 'resources', sort)

        column_list = ["state", "version", "name", "id", "uuid", "muid", "sha256Fingerprint"]
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

        # Process and format the 'id', 'uuid', 'muid', 'sha256Fingerprint' field for output
        for resource in resp['resources']:
            for key in ['id', 'uuid', 'muid', 'sha256Fingerprint']:
                if key in resource:
                    resource[key] = shorten_id(id_string=resource[key], stub=truncate)
  
        # data extraction done, now print the results
        print_totals(resp)
        click.echo(click.style(f"Showing first...last {truncate} characters", fg='yellow', bold=True))
        print_table(column_list, resp, 'resources', field_color_map, None)
    else:
        click.echo(click.style("no matching resources", fg='yellow', bold=True))

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

        column_list = ["name", "version", "state", "algorithm", "size", "unexportable", "undeletable", "labels"]
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
        resp = process_datetime_fields(data=resp, collection_field='resources', datetime_fields=datetime_fields)

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

# CLI:KEY:WEAK
@key.command()
@click.option('-l', '--limit', prompt='Query limit', help='Maximum number of objects to show', default='20', envvar='CM_LIMIT')
@click.option('-a', '--type', type=click.Choice(['AES', 'RSA', 'EC', 'OPAQUE'], case_sensitive=False))
@click.option('--sort', type=click.Choice(['name', 'version', 'state', 'algorithm', 'exportable', 'deletable'], case_sensitive=False))
@click.option('--latest', is_flag=True, default=False, help='Show only the latest key version')
@click.pass_context
def weak(ctx, limit, type, sort, latest):
    if latest:
        opts = dict([('limit', limit), ('algorithm', type), ('version', '-1')])
    else:
        opts = dict([('limit', limit), ('algorithm', type)])
    query = build_query(opts)

    resp = api_get(host=ctx.obj['host'], jwt=ctx.obj['jwt'], api=f'/v1/vault/keys2{query}')

    if resp['total'] > 0:
        if sort is None:
            sort = 'name'
        if sort == 'exportable' or sort == 'deletable':
            sort = 'un' + sort
        resp = sort_response_keys(resp, 'resources', sort)

        column_list = ["name", "version", "state", "algorithm", "size", "unexportable", "undeletable", "labels"]
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

        # Process each key type and filter for weak lengths
        weak_keys = {
            'skip': 0,
            'limit': int(limit),
            'total': 0,
            'resources': []
        }
        # Define criteria for weak keys
        weak_criteria = {
            'AES': 256,
            'RSA': 2048,
            'EC': 256
        }

        # Filter and process weak keys
        for resource in resp['resources']:
            # Process and format the 'labels' field for output
            labels = resource.get('labels', {})
            if labels:
                formatted_labels = ', '.join([f'{k}={v}' for k, v in labels.items()])
            else:
                formatted_labels = ' - '
            resource['labels'] = formatted_labels

            algorithm = resource.get('algorithm')
            size = resource.get('size')
            if algorithm in weak_criteria and size < weak_criteria[algorithm]:
                weak_keys['resources'].append(resource)
                weak_keys['total'] += 1

        # data extraction done, now print the results
        print_totals(weak_keys)
        print_table(column_list, weak_keys, 'resources', field_color_map, None)
    else:
        click.echo(click.style("no matching resources", fg='yellow', bold=True))


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
    resp = process_datetime_fields(data=resp, collection_field='resources', datetime_fields=datetime_fields)
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
    resp = process_datetime_fields(data=resp, collection_field='resources', datetime_fields=datetime_fields)

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