FROM python:3.11
ADD wg-bridge.py .
ENTRYPOINT ["python3", "-u", "wg-bridge.py"] 
