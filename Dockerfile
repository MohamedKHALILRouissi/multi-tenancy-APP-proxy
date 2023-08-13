FROM nginx:stable-alpine-slim

RUN apk add --no-cache supervisor

WORKDIR /app

COPY ./src .

COPY ./nginx-config/nginx.conf /etc/nginx/

COPY ./nginx-config/conf.d /etc/nginx/conf.d/


RUN apk add --no-cache --update py3-pip certbot && \
    pip3 install --no-cache --upgrade pip && \
    pip3 install --no-cache flask certbot-nginx


COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 3000

CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
