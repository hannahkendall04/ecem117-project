'''
Model Context Protocol Sanitization Based Security Library.
Provides security layers for potential vulnerability points on MCP based systems:
    1) Hosted on MCP client - sanitizes outgoing traffic from MCP client to MCP server
    2) Hosted on MCP server - sanitizes incoming prompts, incoming information from external systems, and outgoing information.

This library contains components that can be used independently or together, depending on the level of control 
a developer has over their MCP clients/servers.
'''
from langchain_ollama import ChatOllama
import json
import zlib

class MCPClientSanitizer():
    '''
    Sanitization class for use between MCP client and external LLMs. Methods are used to identify,
    extract, and store sensitive information being passed from MCP clients to external LLMs. Can
    also be used for non-MCP based systems utilizing external LLMs. 

    Prerequisites: 
        - Ollama must be installed on the machine the MCP client is being run on.
        - You must pull a model image from Ollama. The default is the gpt-oss model, but this can be
          changed by altering the model parameter when initializing the class instance.
    '''
    
    def __init__(self, model="llama3.1"):
        self.local_model = ChatOllama(
            model=model,
            format="json"
        )
        self.params = {}
    

    def sanitize_content(self, content: str) -> str:
        '''
        Sanitize client content using local LLM. Store sensitize parameters for later use.
        Arguments:
            content: the content to be sanitized
        Returns:
            string containing the sanitized content
        ''' 

        identification_prompt = f"""
        You will be given a user query. Your job is ONLY to identify sensitive values.

        Return a JSON object with a single field "sensitive_values", containing a list of strings. These strings must be the exact sensitive values found in the query.

        Sensitive values include:
        - Names of people
        - Email addresses
        - Phone numbers
        - Physical addresses
        - Usernames
        - Passwords
        - API keys, tokens, secrets
        - Account numbers
        - Private company names
        - Age
        - Any identifying, credential, or security-related value

        Rules:
        - Do NOT rewrite or modify the input query.
        - Do NOT call any tools.
        - Do NOT hash anything.
        - If there are no sensitive values, return an empty list.

        Output format (strict):

        {{
            "sensitive_values": [
                "value1",
                "value2",
                ...
            ]
        }}

        Input query:
        {content}
        """

        try:
            response = self.local_model.invoke(identification_prompt)
        except Exception as e:
            print(f"Error generating response: {e}")
            exit(-1)

        count = 0

        while response.content == '' and count <= 3:
            # try three times to identify sensitive values
            response = self.local_model.invoke(identification_prompt)
            count += 1

        try:
            data = json.loads(response.content)
            sensitive_values = data["sensitive_values"]

        except Exception as e:
            print(f"Error identifying sensitive values: {e}")
            print(response)
            exit(-1)
        
        params = {}
        inverse_params = {}
        for val in sensitive_values:
            bytes = val.encode("utf-8")
            hashed = zlib.crc32(bytes)
            params.update({str(hashed): val})
            inverse_params.update({val: str(hashed)})

        self.params.update(params)

        modified_query = content 
        for key, val in inverse_params.items():
            modified_query = modified_query.replace(key, val)
        
        return modified_query
    
    def embed_sensitive_info(self, content: str): 
        '''
        Function to re-embed stored sensitive information into MCP/model response.
        Args:
            content: parameterized content to embed sensitive information into 
        Returns:
            string containing the original content embedded with stored sensitive information
        '''

        modified_content = content 

        for key, val in self.params.items():
            modified_content = modified_content.replace(key, val)
        
        # clear params from dictionary 
        self.params.clear()

        return modified_content

class MCPServerSanitizer():
    pass