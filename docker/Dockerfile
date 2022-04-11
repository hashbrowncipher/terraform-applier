FROM ubuntu:22.04
RUN apt-get update && apt-get install -y ca-certificates python3-pip && rm -r /var/lib/apt/lists /var/cache/apt
RUN pip install awslambdaric
COPY terraform /usr/local/bin
COPY plugins /usr/lib/terraform/providers
COPY code /code
COPY app.py /usr/local/lib/python3.10/dist-packages
ENTRYPOINT [ "/usr/bin/python3", "-m", "awslambdaric"]
CMD ["app.handler"]
