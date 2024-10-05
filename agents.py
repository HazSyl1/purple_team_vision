from crewai import Agent
from textwrap import dedent
import google.generativeai as genai
import os
from tasks import CustomTasks
from custom_tools import pdf_tool, txt_tool, json_tool, mdx_tool, file_read_tool
genai.configure(api_key="AIzaSyB9CROn-mLS56zciR0q51G8OXMg1Oh0MSQ")


class CustomAgents:
    def __init__(self):
        self.llm_google=genai.GenerativeModel('gemini-1.5-flash')
        print("LLM CONNECTED")

    def threat_intelligence_analyst(self):
        return Agent(
            role="Threat Intelligence Analyst",
            backstory=dedent(f""" You're a threat intelligence analyst at the best security services provider in the world.
      You're responsible for analyzing threat intelligence reports and extracting MITRE ATT&CK TTPs that can be used to build adversary emulation campaigns."""),
            goal=dedent(f"Extract MITRE ATT&CK TTPs from reports"),
            allow_delegation=False,
            tools=[pdf_tool, txt_tool],
            verbose=True,
            llm=self.llm_google,
        )
    


    # def agent_2_name(self):
    #     return Agent(
    #         role="Define agent 2 role here",
    #         backstory=dedent(f"""Define agent 2 backstory here"""),
    #         goal=dedent(f"""Define agent 2 goal here"""),
    #         # tools=[tool_1, tool_2],
    #         allow_delegation=False,
    #         verbose=True,
    #         llm=self.llm_google,
    #     )
