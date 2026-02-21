import os
import asyncio
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

load_dotenv()

async def test_api():
    print("=== API DIAGNOSTIC START ===")
    
    # 1. Test Gemini
    g_key = os.getenv("GEMINI_API_KEY")
    g_model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
    print(f"\n[1/2] Testing Gemini: {g_model}")
    try:
        llm = ChatGoogleGenerativeAI(
            model=g_model,
            google_api_key=g_key,
            temperature=0.1
        )
        resp = await llm.ainvoke([HumanMessage(content="Hello, respond with 'OK' if you can hear me.")])
        print(f"Gemini SUCCESS: {resp.content}")
    except Exception as e:
        print(f"Gemini FAILURE: {str(e)}")

    # 2. Test OpenAI
    o_key = os.getenv("OPENAI_API_KEY")
    o_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    print(f"\n[2/2] Testing OpenAI: {o_model}")
    try:
        llm = ChatOpenAI(
            model=o_model,
            api_key=o_key,
            temperature=0.1
        )
        resp = await llm.ainvoke([HumanMessage(content="Hello, respond with 'OK' if you can hear me.")])
        print(f"OpenAI SUCCESS: {resp.content}")
    except Exception as e:
        print(f"OpenAI FAILURE: {str(e)}")

    print("\n=== API DIAGNOSTIC END ===")

if __name__ == "__main__":
    asyncio.run(test_api())
