from lib.security_lib import MCPClientSanitizer
from langchain_ollama import ChatOllama


def test_client():
    mcp_client_test = MCPClientSanitizer()
    model = ChatOllama(model='gpt-oss')

    test_query = "Can you help me draft an email to my business partner, Sally, who is 27, that contains the following credentials for a project we're working on? The username is TESTUSER and the password is TESTPASS."
    print(f"Original query: {test_query}\n")

    sanitized_query = mcp_client_test.sanitize_content(test_query)
    print(f"Sanitized query: {sanitized_query}\n")

    response = model.invoke(sanitized_query)

    print(f"Initial response: {response.content}\n")

    embedded_response = mcp_client_test.embed_sensitive_info(response.content)
    print(f"Embedded response: {embedded_response}\n")


if __name__ == "__main__":
    test_client()