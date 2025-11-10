from langchain.agents import create_agent 
from lanchain.ollama import ChatOllama



def setup():
    '''
    Setup local LLM.
    '''
    llm = ChatOllama(
        model="gpt-oss",
        tools=[test_tool]
    )


def test_tool():
    '''
    Basic test tool. 
    '''
