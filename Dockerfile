FROM python:2.7.10
ADD . .
RUN pip install -r ./requirements.txt
ENV PYTHONUNBUFFERED 1
CMD gunicorn -b 0.0.0.0:8080 -w 4 make-it-so:app --log-file -
