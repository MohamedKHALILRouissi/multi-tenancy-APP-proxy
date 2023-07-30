# use the nginx:1.15-alpine as the base image , i will make this more dynamic 
FROM nginx:1.15-alpine

# installing supervisor to manage multiple proccess in unix system 
RUN apk add --no-cache supervisor

WORKDIR /app

COPY ./src .

# installing the required packages (flask , pip ) 
RUN apk add --no-cache python3 && \
    python3 -m ensurepip && \
    rm -r /usr/lib/python*/ensurepip && \
    pip3 install --no-cache --upgrade pip && \
    pip3 install --no-cache flask

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 3000

CMD ["supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
