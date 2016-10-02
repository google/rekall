import time
import os


from rekall import plugin
from rekall_agent import flow


class Hunt(flow.Flow):
    schema = [
        dict(name="queue", default="All",
             doc="Which queue to schedule the hunt on."),
    ]

    def validate(self):
        if not self.queue:
            raise plugin.InvalidArgs("A hunt queue must be provided.")
