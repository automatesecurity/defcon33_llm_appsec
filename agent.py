import os
import git
import asyncio
from dotenv import load_dotenv
from langchain_aws import ChatBedrock
from langchain.agents import create_react_agent, AgentExecutor
from langchain_core.prompts import PromptTemplate
from langchain.tools import Tool
from langchain import hub
from call_graph_analyzer import create_call_graph_tool
from sast_analyzer import create_sast_agent_executor

async def main():
    # Load environment variables
    load_dotenv()
    
    # Clone repository
    repo_url = "https://github.com/redpointsec/vtm.git"
    repo_path = "./repo"

    if os.path.isdir(repo_path) and os.path.isdir(os.path.join(repo_path, ".git")):
        print("Directory already contains a git repository.")
    else:
        try:
            repo = git.Repo.clone_from(repo_url, repo_path)
            print(f"Repository cloned into: {repo_path}")
        except Exception as e:
            print(f"An error occurred while cloning the repository: {e}")
    
    # Initialize ChatBedrock
    llm = ChatBedrock(
        model_id="us.anthropic.claude-3-5-haiku-20241022-v1:0",
        model_kwargs={
            "temperature": 0.2,
            "max_tokens": 4096
        }
    )
    
    # Create call graph analysis tool
    call_graph_func = create_call_graph_tool(repo_path)
    
    # Create SAST agent executor
    sast_agent_executor, sast_analyzer = create_sast_agent_executor(repo_path, llm)
    
    print("AI Agent initialized!")
    print("Starting analysis workflow...")
    
    # Step 1: Build call graph
    print("\n1. Building call graph...")
    call_graph_result = call_graph_func("build")
    print(f"Call graph result: {call_graph_result}")
    
    # Step 2: Get call graph JSON for context
    call_graph_json = call_graph_func("json")
    print(f"Call graph generated with {len(call_graph_json)} characters of data")
    
    # Step 3: Run SAST analysis
    print("\n2. Starting async SAST analysis...")
    # Run the async SAST analysis directly
    sast_summary = await sast_analyzer.run_full_analysis()
    sast_result = {'output': sast_analyzer.get_findings_summary()}
    
    print("\n3. Analysis complete!")
    print("="*50)
    print("SAST ANALYSIS RESULTS:")
    print("="*50)
    print(sast_result['output'])
    
    # Step 4: Get detailed summary
    print("\n" + "="*50)
    print("DETAILED FINDINGS SUMMARY:")
    print("="*50)
    summary_result = {'output': sast_analyzer.get_findings_summary()}
    print(summary_result['output'])


if __name__ == "__main__":
    asyncio.run(main())