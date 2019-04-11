FROM python:2.7-slim

# Create app directory
RUN mkdir -p /app
WORKDIR /app

# Bundle app source
COPY index.py requirements.txt /app/

# Install packages
RUN pip install -r requirements.txt

EXPOSE 53
EXPOSE 53/udp
CMD [ "python", "index.py" ]
