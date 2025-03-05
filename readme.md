![Alt text](./images/banner.png)

# CMInfo

CMINFO is a Python utility that presents CipherTrust information in an easy to visualize format.

Traditionally, the standard **ksctl** CLI tool returns all results as JSON structured output. This requires parsing the JSON with various methods to present information in a consumable format.

For example, to output a sorted list of keys with interesting fields, you could do the following in a bash shell:

```bash
ksctl keys list | jq -r '[.resources[] | {name: .name, algorithm: .algorithm, state: .state}] | sort_by(.name) | .[] | "\(.name), \(.algorithm), \(.state)"'
```

With _cminfo_, the same results are displayed with:

```bash
cminfo.py key list
```

![Alt text](./images/key-list.png)

## Contents

- [Installation](#installation)
- [Authentication](#authentication)
- [Usage](#usage)
  - [Alarm](#alarm)
  - [Download](#download)
  - [Interface](#interface)
  - [Key](#key)
  - [User](#user)
  - [Schedule](#schedule)
  - [Service](#service)
  - [System](#system)
- [Roadmap](#roadmap)

## Installation

### Prerequisites

- Python 3.6+
- Required Python libraries:
  - `click`
  - `json`
  - `requests`
  - `urllib3`
  - `datetime`
  - `python-dotenv`
  - `rich`
  - `tqdm`

### Install Dependencies

You can install the required libraries using pip:

```bash
pip install -r requirements.txt
```

It is recommended to create a separate environment first using **venv** or **conda**.

## Optional - Generate Binary

Compiled binaries can be generated using PyInstaller or cx_Freeze.
For example, using PyInstaller:

```bash
pyinstaller -i .\images\logo.ico --onefile .\cminfo.py
```

## Authentication

**cminfo** can use parameters, .env file, or environment variables for authentication into CipherTrust.

### Option 1: No environment and no parameters

Run without any authentication information in the environment or passed on the CLI, cminfo will prompt for appropriate values.

### Option 2: CLI parameters

If run with CLI parameters, cminfo will override any defaults or values received from the environment.

```bash
Usage: cminfo.py [OPTIONS] COMMAND [ARGS]...

Options:
  -h, --host TEXT        CipherTrust node FQDN or IP
  -u, --username TEXT    Username
  -p, --password TEXT    Password
  -d, --domain TEXT      Domain
  -a, --authdomain TEXT  Authentication domain
  --debug
  --version              Show the version and exit.
  --help                 Show this message and exit.
```

For example, the command:

``` bash
python .\cminfo.py -h cm1.aperture.lab -u admin -d root -a root key list
```

This prompts only for the password since the other values were provided as parameters.

### Option 3: Environment variables

cminfo will check for a **.env** file in the same directory. This file may provide defaults to the following:

``` bash
CM_HOST=
CM_USER=
CM_PW=
CM_DOMAIN=root
CM_AUTHDOMAIN=root
CM_LIMIT=100
```

The same values can also be pulled from the shell environment if no .env file is present.

## Usage

### Alarm

---

#### Alarm List

To list alarms, use the following command:

```bash
Usage: cminfo.py alarm list [OPTIONS]

Options:
  -l, --limit TEXT                Maximum number of objects to show
  --state [on|off]
  --severity [info|warning|error|critical]
  --help                          Show this message and exit.

```

![Alt text](./images/alarm-list.png)

### Download

---

#### Download KSCTL

This is a convenience function to download the ksctl tool package from the CipherTrust Manager.

**NOTE:** **cminfo** does not required ksctl to function.

```bash
Usage: cminfo.py download ksctl [OPTIONS]

Options:
  -h, --host TEXT  Download from this CipherTrust node
  -p, --path TEXT  Download file to this directory
  --help           Show this message and exit.
```

![Alt text](./images/download-ksctl.png)

### Interface

---

#### Interface List

To list protocol interfaces, use the following command:

```bash
Usage: cminfo.py interface list [OPTIONS]

Options:
  -t, --type [kmip|nae|ssh|web]
  --sort [port|interface_type|enabled|minimum_tls_version]
  --help                          Show this message and exit.

```

![Alt text](./images/interface-list.png)

### Key

---

#### Key Dates

To list key dates, use the following command:

```bash
Usage: cminfo.py key dates [OPTIONS]

Options:
  -l, --limit TEXT                Maximum number of objects to show
  -s, --state [Pre-Active|Active|Deactivated|Destroyed|Compromised|Destroyed Compromised]
  -t, --type [AES|RSA|EC|OPAQUE]
  --help                          Show this message and exit.

```

![Alt text](./images/key-dates.png)

#### Key Labels

Display all key labels currently applied to keys.

```bash
Usage: cminfo.py key labels [OPTIONS]

Options:
  -l, --limit TEXT  Maximum number of objects to show
  --help            Show this message and exit.
```

![Alt text](./images/key-labels.png)

#### Key List

List all keys. Supports filtering by algorithm and state. Sorting is supported by column name.

```bash
Usage: cminfo.py key list [OPTIONS]

Options:
  -l, --limit TEXT                Maximum number of objects to show
  -s, --state [Pre-Active|Active|Deactivated|Destroyed|Compromised|Destroyed Compromised]
  -a, --type [AES|RSA|EC|OPAQUE]
  --sort [name|version|state|algorithm|exportable|deletable]
  --latest                        Show only the latest key version
  --help                          Show this message and exit.
```

![Alt text](./images/key-list.png)

#### Key Weak

List all weak keys. Supports filtering by algorithm. Sorting is supported by column name.

```bash
Usage: cminfo.py key list [OPTIONS]

Options:
  -l, --limit TEXT                Maximum number of objects to show
  -a, --type [AES|RSA|EC|OPAQUE]
  --sort [name|version|state|algorithm|exportable|deletable]
  --latest                        Show only the latest key version
  --help                          Show this message and exit.
```

![Alt text](./images/key-weak.png)

### Schedule

---

#### Schedule List

Show all schedule configurations.

```bash
Usage: cminfo.py schedule list [OPTIONS]

Options:
  -l, --limit TEXT                Maximum number of objects to show
  --sort [name|version|state|algorithm|exportable|deletable]
```

![Alt text](./images/schedule-list.png)

### Service

---

#### Service List

Show the state of all CipherTrust microservices.

```bash
Usage: cminfo.py service list [OPTIONS]

Options:
  --help                          Show this message and exit.
```

![Alt text](./images/service-list.png)

### System

---

#### System Info

To CipherTrust node information, use the following command:

```bash
Usage: cminfo.py system info

Options:
  --help                          Show this message and exit.

```

![Alt text](./images/system-info.png)

### User

---

#### User Inactive

Show users not logged in for the past X days.

```bash
Usage: cminfo.py user inactive [OPTIONS]

Options:
  -l, --limit TEXT  Maximum number of objects to show
  -d, --days TEXT   Consider inactive if not logged in during this window
  --help            Show this message and exit.
```

![Alt text](./images/user-inactive.png)

#### User Logins

Show login information for each user.

```bash
Usage: cminfo.py user logins [OPTIONS]

Options:
  -l, --limit TEXT  Maximum number of objects to show
  --help            Show this message and exit.
```

![Alt text](./images/user-logins.png)

## Roadmap

[Feature Requests and Enhancements](https://github.com/thalescpl-io/ciphertrust-info/issues?q=is%3Aissue%20state%3Aopen%20type%3AFeature)
