from langchain_mcp_adapters.client import MultiServerMCPClient  
from langchain.agents import create_agent
from langchain_google_genai import ChatGoogleGenerativeAI
from dotenv import load_dotenv
import asyncio

client = MultiServerMCPClient(  
    {
        "email": {
            "transport": "stdio",  # Local subprocess communication
            "command": "python",
            # Absolute path to your mcp_server.py file
            "args": ["./mcp_server.py"],
        }
    }
)

async def run_agent():
    tools = await client.get_tools()  
    print("### TOOLS ###")
    print(tools)
    print("#############")
    agent = create_agent(
        model,
        tools  
    )
    # prompt = input("Enter email prompt: ")
    # draft_response = await agent.ainvoke(
    #     {
    #         "messages": [
    #             {
    #                 "role": "user", 
    #                 "content": "Call the tool provided to you regarding email sending! Do not ask for additional information before calling this tool."
    #             }
    #         ]
    #     }
    # )
    # print(draft_response)

if __name__ == '__main__':
    load_dotenv()
    model = ChatGoogleGenerativeAI(model="gemini-2.0-flash") 

    asyncio.run(run_agent())