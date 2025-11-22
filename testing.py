from lib.security_lib import MCPClientSanitizer


def test_client():
    mcp_client_test = MCPClientSanitizer()

    test_query = "Can you help me draft an email to my business partner that contains the following credentials for a project we're working on? The username is TESTUSER and the password is TESTPASS."
    print(f"Original query: {test_query}\n")

    sanitized_query = mcp_client_test.sanitize_content(test_query)
    print(f"Sanitized query: {sanitized_query}\n")

    embedded_query = mcp_client_test.embed_sensitive_info(sanitized_query)
    print(f"Embedded query: {embedded_query}\n")


if __name__ == "__main__":
    test_client()