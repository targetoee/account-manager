FROM python:3.9-slim

ADD api.log /api.log
ADD requirement.txt /requirement.txt
ADD app.py /app.py

RUN pip install -r requirement.txt
EXPOSE 5000

ENV FLASK_APP=app.py

CMD ["flask", "run", "--host=0.0.0.0"]
