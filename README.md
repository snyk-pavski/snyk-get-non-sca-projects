# Get Snyk non-SCA Projects 

Lists all non-SCA Snyk Projects across multiple Snyk Organisations in a Group.

## Features

`get_projects.py` - gathers project information for entire Snyk Orgnisation. Uses [Snyk's REST API](https://apidocs.snyk.io/).

## Configuration

Install dependencies
```sh
pip install -r requirements.txt
```

Update variables in `get_projects.py`. Get the latest API Version from [Snyk's REST API](https://apidocs.snyk.io/)
```py
API_VERSION = "2024-08-15"
RATE_LIMIT_DELAY = 0.2 (in seconds)
```

## Usage

### Gather project information 

Run the script locally

```sh
python3 get_projects.py --group YOUR_GROUP_ID --token YOUR_API_TOKEN
```

Script will output `project_data.json` file. Projects will be grouped by Snyk Organisation. Example below:

```json
[
    "Org_Name": [
        {
            "project_name": "Org_Name/Project_Name(main)",
            "snyk_product": "Snyk_Code",
            "created": "2024-09-10T09:07:36.798Z",
            "org_name": "Org_Name",
            "org_id": "xxx",
            "project_id": "xxx",
            "project_type": "sast",
            "status": "active",
            "origin": "azure-repos"
        },
    ]
]
