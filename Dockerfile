FROM python:2-alpine

WORKDIR /precog

COPY requirements.txt /precog/

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/community" >> \
         /etc/apk/repositories && \
    apk add --update alpine-sdk python-dev ca-certificates supervisor nginx && \
    pip install -r requirements.txt && \
    apk del --purge alpine-sdk python-dev

COPY templates /precog/templates/
COPY git.py href.py make-it-so.py test.py util.py /precog/

COPY conf/supervisor.conf /etc/supervisor/conf.d/supervisord.conf
COPY conf/nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /run/nginx /var/log/supervisor

EXPOSE 8080
CMD ["/usr/bin/supervisord","-c","/etc/supervisor/conf.d/supervisord.conf"]
