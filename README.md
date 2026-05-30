# Load Balancer Worker Server

This worker server acts as an endpoint and framework for the load balancer to forward requests to. While the load balancer is written in C++ the worker server is written in python. Originally when I developed this, I planned to use it to handle AI workloads for pyTorch models.

# Retrospective

There are many things I would do now to improve both the structure and efficiency of this code. Moving forward I plan to apply the lessons I learned making this project to new projects down the line.  In the future I might redo this project or one similar and make it more general purpose and portable.
