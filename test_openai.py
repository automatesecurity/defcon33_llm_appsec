import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

def test_openai():
    # Load environment variables
    load_dotenv()
    
    # Check if API key is set
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ OPENAI_API_KEY not found in .env file")
        return False
    
    print("✅ OPENAI_API_KEY found")
    
    try:
        # Initialize the model
        llm = ChatOpenAI(
            model="gpt-3.5-turbo",
            temperature=0.1,
            max_tokens=100
        )
        print("✅ ChatOpenAI initialized successfully")
        
        # Test a simple query
        response = llm.invoke("Say 'Hello, LangChain OpenAI test successful!' in one sentence.")
        print(f"✅ Response received: {response.content}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    print("Testing OpenAI LangChain integration...")
    success = test_openai()
    if success:
        print("\n🎉 Test passed! OpenAI integration is working.")
    else:
        print("\n💥 Test failed! Check your setup.") 