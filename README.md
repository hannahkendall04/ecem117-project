# F25 ECE M117 Project
This project aims to introduce a library that helps mitigate privacy vulnerabilities in systems that utilize the Model Context Protocol (MCP). 

## Setup

**Prerequisites**
- Have Ollama installed on the machine on which you'd like to use the security package/library. Instructions on how to install Ollama can be found <a href="https://ollama.com/">here</a>.
    - Pull the llama3.1 model (or some other model) onto your machine using the command `ollama pull llama3.1`
- Create a virtual environment and install the necessary packages using the following commands:
```python 
python -m venv .venv

# windows
.venv/Scripts/activate 
# mac/linux 
source .venv/bin/activate 

# install packages 
pip install -r requirements.txt
```
- You must have Google authentication set up to run the test MCP client and server as well as a Gemini API key. One way to set up authentication/API keys is as follows:
    - Create a .env file in the top level directory
    - Go to the google developer console and create a new project: https://console.cloud.google.com/
    - Go to the APIs and Services page for the project 
    - Click the 'Enable APIs and services' and enable the following APIs:
        - Generative Language (Gemini) API
        - Gmail API
    - Go back to the APIs and Services page and select the 'Credentials' tab
    - Click 'Create Credentials' > 'API key'
        - Restrict the API key to only be able to access the Generative Language API
        - Copy your generated API key into the .env file in the form: `GEMINI_API_KEY=<your_api_key>`
    - Click 'Create Credentials' > 'OAuth client ID'
        - Application type: Desktop app
        - Input a name for the client and click 'Create'
        - Click 'Download JSON' and safe the file to `credentials.json` in the top level directory of this repository
    - Click 'OAuth consent screen' > 'Audience' 
        - Any any emails of users you would like to be able to authenticate with 
    - Click 'OAuth consent screen' > 'Data Access' 
        - Add all the Gmail read/write scopes
    - Setup default application credentials (getting the conf file)
        - Go to the credentials page
        - Click on the service account at the very bottom (you may need to set it up first if this is your first time)
        - Then you go to the keys tab and click add key > create a new key > json
        - Then you download the json file and rename it to “conf”
            - Save this to a file called `conf` in the directory of the mcp that you are running (ie. `vulnerable_mcp` vs `secure_mcp`)
        - dd the following line to your .env file: `GOOGLE_APPLICATION_CREDENTIALS="conf"`


## Usage Notes 
If you are in the root, make sure to `cd` into the mcp directory that you want to run:
```shell
# the mcp without our imported library
cd vulnerable_mcp

# the mcp with our library imported
cd secure_mcp
```

To run the MCP client:

```shell 
# in another terminal
export MCP_CLIENT_ROLE=sender
python mcp_client.py
```

To run the MCP server:

```shell 
export MCP_CLIENT_ROLE=reader
python mcp_server.py
```

To run the testing script for the library:

```shell
python testing.py
```
