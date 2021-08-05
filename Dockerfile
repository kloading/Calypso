# Container image that runs your code
FROM docker5gmedia/python-curl-jq:latest

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY . .

RUN python -m pip install --upgrade pip
RUN pip install pyyaml
RUN pip install z3-solver

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/entrypoint.sh"]
