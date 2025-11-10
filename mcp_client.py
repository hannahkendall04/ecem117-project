from langchain_mcp_adapters.client import MultiServerMCPClient  
from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import asyncio

client = MultiServerMCPClient(  
    {
        "maemailth": {
            "transport": "stdio",  # Local subprocess communication
            "command": "python",
            # Absolute path to your mcp_server.py file
            "args": ["./mcp_server.py"],
        }
    }
)

async def run_agent():
    tools = await client.get_tools()  
    print(tools)
    agent = create_agent(
        model,
        tools  
    )
    prompt = input("Enter email prompt: ")
    draft_response = await agent.ainvoke(
        {"messages": [{"role": "user", "content": "draft an email!"}]}
    )
    print(draft_response)

if __name__ == '__main__':
    load_dotenv()
    model = ChatGoogleGenerativeAI(model="gemini-2.0-flash") 

    asyncio.run(run_agent())