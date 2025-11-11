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

    agent = create_agent(
        model,
        tools  
    )

    print("View or send emails")
    print("\t1) Send\n\t2) Find")
    option = input("Select an option: ")

    if option == "1":
        # send an email
        query = input("Describe the message you'd like to send: ")
        send_prompt = f"""
            Use the tools provided to you and the following description to send an email. 
            You can use the description as inspiration for what to send, you do not need to copy it verbatim into the tool.
            You do not need to know the recipient or the sender, those are provided in the tools.
            If no subject area is provided, generate one you find appropriate.

            Email description: {query}
        """
        draft_response = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user", 
                        "content": send_prompt
                    }
                ]
            }
        )
        print(draft_response["messages"][-1].content)

    elif option == "2":
        # search for emails 
        query = input("Specify what information you are looking for: ")
        search_prompt = f"""
        Use the tools provided to you and the following description to find information from emails in a gmail inbox. 
        You do not need to know the gmail user, that information is provided in the tool.
        If the description contains a question, make you sure you answer the question directly in your response.

        Search description: {query}

        """
        search_response = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user", 
                        "content": search_prompt
                    }
                ]
            }
        )
        print(search_response["messages"][-1].content)
        # print(search_response) # for debugging

    else:
        print(f"{option} is not valid.")

if __name__ == '__main__':
    load_dotenv()
    model = ChatGoogleGenerativeAI(model="gemini-2.0-flash") 

    asyncio.run(run_agent())