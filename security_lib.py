'''
MCP Security Library.
Provides security layers for three potential vulnerability points on MCP based systems:
    1) Between MCP client and MCP server - sanitizes outgoing traffic from MCP client to MCP server
    2) Between MCP client and external LLM - sanitizes outgoing traffic from MCP client to external LLM
    3) On MCP server - sanitizes incoming prompts, incoming information from external systems, and outgoing information.

This library contains components that can be used independently or together, depending on the level of control 
a developer has over their MCP clients/servers.
'''



class MCPClientLLMSanitizer():
    pass 


class MCPClientServerSanitizer():
    pass 


class MCPServerSanitizer():
    pass