from security_lib import MCPClientLLMSanitizer

if __name__ == "__main__":
    mcp_client_test = MCPClientLLMSanitizer()

    test_query = '''
        Can you help me draft an email to my business partner that contains the following credentials for a project we're working on? The username is TESTUSER and the password is TESTPASS.
    '''


    mcp_client_test.sanitize_content(test_query)