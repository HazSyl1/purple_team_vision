from crewai import Task
from textwrap import dedent


# This is an example of how to define custom tasks.
# You can define as many tasks as you want.
# You can also define custom agents in agents.py
class CustomTasks:
    def __tip_section(self):
        return "If you do your BEST WORK, I'll give you promotion."

    def extract_ttps_task(self, agent,var1):
        return Task(
            description=dedent(
                f"""
            Analyze the provided DFIR report and extract the relevant MITRE ATT&CK TTPs.
    Ensure that all identified tactics, techniques, and procedures are mapped correctly to the MITRE framework.
    REPORT: {var1}
        """
            ),
            agent=agent,
            expected_output=dedent(f"""
						  Generate a general cyber security report for the given documentation.
						  The report should include a list of MITRE TTPs.
                          Provide a JSON file containing a list of extracted TTPs with their corresponding techniques and descriptions.
						  """),
        )

    # def task_2_name(self, agent):
    #     return Task(
    #         description=dedent(
    #             f"""
    #         Take the input from task 1 and do something with it.
                                       
    #         {self.__tip_section()}

    #         Make sure to do something else.
    #     """
    #         ),
    #         agent=agent,
    #     )
