'''
Model Context Protocol Sanitization Based Security Library.
Provides security layers for three potential vulnerability points on MCP based systems:
    1) Between MCP client and MCP server - sanitizes outgoing traffic from MCP client to MCP server
    2) Between MCP client and external LLM - sanitizes outgoing traffic from MCP client to external LLM
    3) On MCP server - sanitizes incoming prompts, incoming information from external systems, and outgoing information.

This library contains components that can be used independently or together, depending on the level of control 
a developer has over their MCP clients/servers.
'''
from langchain_ollama import ChatOllama
from security_tools import compute_checksum
import json

class MCPClientLLMSanitizer():
    '''
    Sanitization class for use between MCP client and external LLMs. Methods are used to identify,
    extract, and store sensitive information being passed from MCP clients to external LLMs. Can
    also be used for non-MCP based systems utilizing external LLMs. 

    Prerequisites: 
        - Ollama must be installed on the machine the MCP client is being run on.
        - You must pull a model image from Ollama. The default is the gpt-oss model, but this can be
          changed by altering the model parameter when initializing the class instance.
    '''
    
    def __init__(self, model="gpt-oss"):
        self.local_model = ChatOllama(
            model=model
        ).bind_tools([compute_checksum])
        self.params = {}
    

    def sanitize_content(self, content: str):
        '''
        Sanitize client content using local LLM. Store sensitize parameters for later use.
        Arguments:
            content: the content to be sanitized
        ''' 

        response = self.local_model.invoke(
            "You will be given a user query. Your task is to detect all sensitive information in the query and output two items:"
            "modified_output - The original query with each sensitive item replaced by a unique parameter token (e.g., {{PARAM_1}}, {{PARAM_2}}, etc.)."
            "The text around the sensitive information must remain unchanged."
            "Parameter tokens must be deterministic within the response, but need not follow a particular format besides being unique."
            "params  A dictionary mapping each parameter token to the original sensitive value."
            "Treat the following as sensitive and eligible for parameterization:"
            "   - Names of people"
            "   - Email addresses"
            "   - Phone numbers"
            "   - Physical addresses"
            "   - Usernames"
            "   - Passwords"
            "   - API keys, tokens, secrets"
            "   - Account numbers (bank, student ID, etc.)"
            "   - Company names (when clearly private or specific to a person)"
            "   - Any other identifying or security-related values"
            "If no sensitive information is present, output the query unchanged and return an empty dictionary."
            "Your response must be valid JSON with this structure:"
            "{"
            "    'modified_output': '<text with parameters>',"
            "    'params': {"
            "        '<PARAM_1>': '<original_value>',"
            "        '<PARAM_2>': '<original_value>',"
            "        ..."
            "    }"
            "}"
            "PARAM_1 and PARAM_2 should be computed using the compute_checksum tool."
            "Do not rewrite or improve the query beyond parameter replacements."
            "Do not invent sensitive information—only replace what appears."
            "Every sensitive element must be mapped to a separate parameter."
            "Maintain all punctuation, spacing, and capitalization from the original query."
            "Parameter tokens should only replace the sensitive values themselves, not surrounding context."
            f"\nInput: {content}"
        )

        print(response)

        obj = json.loads(response.content)

        self.params.update(obj)

        return obj["modified_output"]



class MCPClientServerSanitizer():
    pass 


class MCPServerSanitizer():
    pass